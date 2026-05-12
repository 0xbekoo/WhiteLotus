#include "WhiteLotus.h"

CONST UINT8 gHookTemplate[] =
{
#if defined(MDE_CPU_X64)
    0x48, 0xB8,                                     // mov rax, <imm64>
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#elif defined(MDE_CPU_IA32)
    0xB8,                                           // mov eax, <imm32>
    0x00, 0x00, 0x00, 0x00,
#endif
    0x50,                                           // push rax/eax
    0xC3                                            // ret
};

typedef
EFI_STATUS
(EFIAPI*
t_ImgArchStartBootApplication_Eight)(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	);

typedef
EFI_STATUS
(EFIAPI*
t_ImgArchStartBootApplication_Vista)(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	);

VOID* /*t_ImgArchStartBootApplication_XX*/ gOriginalBootmgfwImgArchStartBootApplication = NULL;
UINT8 gBootmgfwImgArchStartBootApplicationBackup[sizeof(gHookTemplate)] = { 0 };

VOID* /*t_ImgArchStartBootApplication_XX*/ gOriginalBootmgrImgArchStartBootApplication = NULL;
UINT8 gBootmgrImgArchStartBootApplicationBackup[sizeof(gHookTemplate)] = { 0 };

#if defined(MDE_CPU_X64)
CONST UINTN gHookTemplateAddressOffset = 2;
#elif defined(MDE_CPU_IA32)
CONST UINTN gHookTemplateAddressOffset = 1;
#endif


// Signature for [bootmgfw|bootmgr]!ImgArch[Efi]StartBootApplication
STATIC CONST UINT8 SigImgArchStartBootApplication[] = {
	//0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x20
    0x41, 0xB8, 0x09, 0x00, 0x00, 0xD0
};
