#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <stdio.h>
#include "loader.h"

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, NT_UNICODE_STRING, * PNT_UNICODE_STRING;

typedef struct _NT_OBJECT_ATTRIBUTES {
    ULONG              Length;
    HANDLE             RootDirectory;
    PNT_UNICODE_STRING ObjectName;
    ULONG              Attributes;
    PVOID              SecurityDescriptor;
    PVOID              SecurityQualityOfService;
} NT_OBJECT_ATTRIBUTES, * PNT_OBJECT_ATTRIBUTES;

typedef struct _NT_CURDIR {
    NT_UNICODE_STRING DosPath;
    HANDLE            Handle;
} NT_CURDIR;

typedef struct _NT_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} NT_STRING;

#define RTL_MAX_DRIVE_LETTERS 32
typedef struct _NT_DRIVE_LETTER_CURDIR {
    USHORT    Flags;
    USHORT    Length;
    ULONG     TimeStamp;
    NT_STRING DosPath;
} NT_DRIVE_LETTER_CURDIR;

typedef struct _NT_RTL_USER_PROCESS_PARAMETERS {
    ULONG  MaximumLength;
    ULONG  Length;
    ULONG  Flags;
    ULONG  DebugFlags;
    HANDLE ConsoleHandle;
    ULONG  ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    NT_CURDIR         CurrentDirectory;
    NT_UNICODE_STRING DllPath;
    NT_UNICODE_STRING ImagePathName;
    NT_UNICODE_STRING CommandLine;
    PVOID             Environment;
    ULONG StartingX, StartingY, CountX, CountY;
    ULONG CountCharsX, CountCharsY, FillAttribute;
    ULONG WindowFlags, ShowWindowFlags;
    NT_UNICODE_STRING      WindowTitle;
    NT_UNICODE_STRING      DesktopInfo;
    NT_UNICODE_STRING      ShellInfo;
    NT_UNICODE_STRING      RuntimeData;
    NT_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];
    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
} NT_RTL_USER_PROCESS_PARAMETERS, * PNT_RTL_USER_PROCESS_PARAMETERS;

typedef enum _NT_PS_CREATE_STATE {
    PsCreateInitialState = 0,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} NT_PS_CREATE_STATE;

typedef struct _NT_PS_CREATE_INFO {
    SIZE_T             Size;
    NT_PS_CREATE_STATE State;
    union {
        struct { ULONG InitFlags; ACCESS_MASK AdditionalFileAccess; } InitState;
        struct { HANDLE FileHandle; } FailSection;
        struct { USHORT DllCharacteristics; } ExeFormat;
        struct { HANDLE IFEOKey; } ExeName;
        struct {
            ULONG     OutputFlags;
            HANDLE    FileHandle;
            HANDLE    SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG     UserProcessParametersWow64;
            ULONG     CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG     PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG     ManifestSize;
        } SuccessState;
    };
} NT_PS_CREATE_INFO, * PNT_PS_CREATE_INFO;

typedef struct _NT_PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union { ULONG_PTR Value; PVOID ValuePtr; };
    PSIZE_T ReturnLength;
} NT_PS_ATTRIBUTE;

typedef struct _NT_PS_ATTRIBUTE_LIST {
    SIZE_T         TotalLength;
    NT_PS_ATTRIBUTE Attributes[1];
} NT_PS_ATTRIBUTE_LIST, * PNT_PS_ATTRIBUTE_LIST;

#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_INPUT       0x00020000
#define PsAttributeImageName_NUM 4
#define NT_PS_ATTRIBUTE_IMAGE_NAME 0x20005  
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001

typedef VOID(NTAPI* pfn_RtlInitUnicodeString)(PNT_UNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* pfn_RtlCreateProcessParametersEx)(
    PNT_RTL_USER_PROCESS_PARAMETERS*, PNT_UNICODE_STRING, PNT_UNICODE_STRING,
    PNT_UNICODE_STRING, PNT_UNICODE_STRING, PVOID, PNT_UNICODE_STRING,
    PNT_UNICODE_STRING, PNT_UNICODE_STRING, PNT_UNICODE_STRING, ULONG);
typedef NTSTATUS(NTAPI* pfn_RtlDestroyProcessParameters)(PNT_RTL_USER_PROCESS_PARAMETERS);
typedef NTSTATUS(NTAPI* pfn_NtCreateUserProcess)(
    PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
    PNT_OBJECT_ATTRIBUTES, PNT_OBJECT_ATTRIBUTES,
    ULONG, ULONG,
    PNT_RTL_USER_PROCESS_PARAMETERS, PNT_PS_CREATE_INFO, PNT_PS_ATTRIBUTE_LIST);
