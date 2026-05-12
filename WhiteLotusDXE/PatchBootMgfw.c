#include "PatchBootMgfw.h"

// Hook handler for ImgArchStartBootApplication
// Called when bootmgfw.efi or bootmgr.exe starts a boot application
// Restores original function, patches winload/winresume, then calls original
STATIC EFI_STATUS EFIAPI HookedBootManagerImgArchStartBootApplication(
  PBL_APPLICATION_ENTRY AppEntry,
  VOID* ImageBase,
  UINT32 ImageSize,
  UINT32 BootOption,
  PBL_RETURN_ARGUMENTS ReturnArguments,
  VOID* OriginalFunction,
  CONST UINT8* OriginalFunctionBytes
) {
  // Restore the original function bytes before patching and calling
  CopyWpMem(OriginalFunction, OriginalFunctionBytes, sizeof(gHookTemplate));

  // Validate PE headers
  CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);
  INPUT_FILETYPE FileType = Unknown;
  if (NtHeaders == NULL)
  {
    Print(L"\r\n[WhiteLotus] PE image at 0x%p with size 0x%lx is invalid!\n",
      ImageBase, ImageSize);
    goto CallOriginal;
  }

  FileType = GetInputFileType(ImageBase, (UINTN)ImageSize);
  if (FileType != WinloadEfi && FileType != BootmgrEfi)
  {
    goto CallOriginal;
  }

  // This is bootmgfw.efi - proceed to patch winload.efi
  DEBUG((DEBUG_INFO, "[WhiteLotus] We got winload.efi!\n"));
  PatchWinload(ImageBase, NtHeaders);

CallOriginal:
  // Call the original boot application entry
  return ((t_ImgArchStartBootApplication_Eight)OriginalFunction)(
      AppEntry, ImageBase, ImageSize, BootOption, ReturnArguments
    );
}

// 8-parameter variant of the hook for bootmgfw
// Wraps the common 10-parameter handler with appropriate arguments
STATIC EFI_STATUS EFIAPI HookedBootmgrImgArchStartBootApplication_Eight(
  IN PBL_APPLICATION_ENTRY AppEntry,
  IN VOID* ImageBase,
  IN UINT32 ImageSize,
  IN UINT32 BootOption,
  OUT PBL_RETURN_ARGUMENTS ReturnArguments
) {
  return HookedBootManagerImgArchStartBootApplication(AppEntry, ImageBase, ImageSize, BootOption, ReturnArguments,
    gOriginalBootmgfwImgArchStartBootApplication, gBootmgfwImgArchStartBootApplicationBackup);
}

// Main entry point for patching bootmgfw.efi or bootmgr.efi
// Locates ImgArchStartBootApplication and installs a hook
EFI_STATUS EFIAPI PatchBootMgfw(INPUT_FILETYPE FileType, CONST VOID* ImageBase, UINTN ImageSize) {
  // Determine target file name for logging
  CONST BOOLEAN PatchingBootmgrEfi = FileType == BootmgrEfi;
  CONST CHAR16* ShortFileName = PatchingBootmgrEfi ? L"bootmgr" : L"bootmgfw";
  EFI_STATUS Status;

  // Validate PE headers
  CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);
  if (NULL == NtHeaders)
  {
    Status = EFI_LOAD_ERROR;
    Print(L"\r\n[WhiteLotus] %S.efi PE image at 0x%p with size 0x%llx is invalid!\n",
      ShortFileName, ImageBase, ImageSize);
    return EFI_SUCCESS;
  }

  // Get version info for logging
  UINT16 MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;
  Status = GetPeFileVersionInfo(ImageBase, &MajorVersion, &MinorVersion, &BuildNumber, &Revision, NULL);
  if (EFI_ERROR(Status)) {
    Print(L"\r\nWARNING: failed to obtain %S.efi version info. Status: %llx\r\n", ShortFileName, Status);
  }
  else {
    Print(L"\r\nPatching %S.efi v%u.%u.%u.%u...\r\n", ShortFileName, MajorVersion, MinorVersion, BuildNumber, Revision);
  }

  // Locate ImgArchStartBootApplication in bootmgfw.efi
  // Function name varies by Windows version:
  // - Windows 10 1809+ (Build 17763+): ImgArchStartBootApplication
  // - Earlier versions: ImgArchEfiStartBootApplication
  CONST CHAR16* FunctionName = BuildNumber >= 17134 ? L"ImgArchStartBootApplication" : L"ImgArchEfiStartBootApplication";
  CONST PEFI_IMAGE_SECTION_HEADER CodeSection = IMAGE_FIRST_SECTION(NtHeaders);
  UINT8* Found = NULL;
  Status = FindPattern(SigImgArchStartBootApplication, 0xCC, sizeof(SigImgArchStartBootApplication),
    (UINT8*)ImageBase + CodeSection->VirtualAddress, CodeSection->SizeOfRawData, (VOID**)&Found);
  if (EFI_ERROR(Status))
  {
    Print(L"\r\nFailed to find %S!%S signature. Status: %llx\r\n", ShortFileName, FunctionName, Status);
    return EFI_NOT_FOUND;
  }

  // Find the start of the function (prologue)
  VOID **pOriginalAddress = &gOriginalBootmgfwImgArchStartBootApplication;
  *pOriginalAddress = (VOID*)FindFunctionStart(ImageBase, NtHeaders, Found);
  CONST VOID* OriginalAddress = *pOriginalAddress;
  if (NULL == OriginalAddress)
  {
    Print(L"\r\nFailed to find %S!%S function start [signature at 0x%p].\r\n", ShortFileName, FunctionName, (VOID*)Found);
    Status = EFI_NOT_FOUND;
    return Status;
  }

  // Install the hook
  VOID* HookAddress = (VOID*)&HookedBootmgrImgArchStartBootApplication_Eight;
  UINT8* BackupAddress = gBootmgfwImgArchStartBootApplicationBackup;

  DEBUG((DEBUG_INFO, "[WhiteLotus] Found %S!%S at 0x%p.\n", ShortFileName, FunctionName, (VOID*)OriginalAddress));
  DEBUG((DEBUG_INFO, "[WhiteLotus] Hooked %S at 0x%p.\n", FunctionName, HookAddress));

  // Raise TPL to prevent interruption during memory writes
  CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
  // Backup original bytes for restoration
  CopyMem(BackupAddress, (VOID*)OriginalAddress, sizeof(gHookTemplate));

  // Write hook template to target function
  CopyWpMem((VOID*)OriginalAddress, gHookTemplate, sizeof(gHookTemplate));
  // Write hook address at offset within the template
  CopyWpMem((UINT8*)OriginalAddress + gHookTemplateAddressOffset, (UINTN*)&HookAddress, sizeof(UINTN));

  gBS->RestoreTPL(Tpl);
  DEBUG((DEBUG_INFO, "[PatchBootManager] ImgArchStartBootApplication was hooked!\n"));

  return EFI_SUCCESS;
}
