#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <wchar.h>

static const GUID EspPartitionTypeGuid = {
    0xC12A7328, 0xF81F, 0x11D2,
    { 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B }
};


#define MAX_PATH 260

#define EFI_VARIABLE_NON_VOLATILE        0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS  0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS      0x00000004
#define TARGET_ATTRIBUTES \
    (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)

#define MEDIA_DEVICE_PATH          0x04
#define MEDIA_FILEPATH_DP          0x04
#define END_DEVICE_PATH_TYPE       0x7F
#define END_ENTIRE_DEVICE_PATH_SUBTYPE 0xFF

#define LOAD_OPTION_ACTIVE         0x00000001

#pragma pack(push, 1)
typedef struct {
    UINT8  Type;
    UINT8  SubType;
    UINT8  Length[2];
} EFI_DEVICE_PATH_PROTOCOL;
#pragma pack(pop)