# WhiteLotus

> **WARNING: This project is for educational and research purposes only. The author does not condone or support any illegal use of this software. Use responsibly and only in environments where you have explicit permission to do so.**

---

## Tested Environment

| Component | Version |
|-----------|---------|
| Windows   | _TBD_   |
| UEFI BIOS | _TBD_   |
| Architecture | x64 (AMD64) only |

> **Note:** This project is exclusively designed for x64 (AMD64) systems. ARM, ARM64, and x86 (32-bit) architectures are not supported.

---

## Project Overview

WhiteLotus is a UEFI-based security research project that demonstrates Driver Signature Enforcement (DSE) bypass techniques through byte-level patching of Windows boot components. The project operates at the firmware level, intercepting and modifying Windows boot manager (`bootmgfw.efi`), winload (`winload.efi`), and the Windows kernel (`ntoskrnl.exe`) to disable code signing requirements.

The project consists of two main components that work together to achieve unsigned kernel-mode code execution:

1. **WhiteLotusDXE** - A UEFI DXE driver that hooks into the Windows boot chain
2. **WhiteLotusEXE** - A Windows-side loader that deploys the DXE driver to the EFI System Partition (ESP)

---

## Project Structure

```
WhiteLotus/
├── WhiteLotusDXE/     # UEFI DXE Driver (main research component)
└── WhiteLotusEXE/     # Windows Loader (deployment mechanism)
```

---

## WhiteLotusDXE

**WhiteLotusDXE** is a UEFI DXE (Driver eXecution Environment) driver that operates before the Windows kernel loads. This component is the core of the project and implements the actual bypass logic.

### Key Features

- **LoadImage Hook**: Intercepts `EFI_BOOT_SERVICES->LoadImage()` to monitor all EFI binaries loaded during boot
- **Boot Manager Patching**: Locates and patches `bootmgfw.efi` (Windows Boot Manager) by hooking `ImgArchStartBootApplication`
- **Winload Patching**: Patches `winload.efi` by hooking `OslFwpKernelSetupPhase1` to intercept kernel loading
- **DSE Bypass**: Modifies `ntoskrnl.exe` to disable Driver Signature Enforcement by patching:
  - `SepInitializeCodeIntegrity` in CI.dll - Disables Code Integrity initialization
  - `SeValidateImageData` - Bypasses PE signature validation
- **VBS Disabling**: Sets `VbsPolicyDisabled` EFI variable to disable Virtualization-Based Security
- **Runtime Hook**: Hooks `SetVariable()` to hide modifications from runtime detection

### Architecture Flow

```
UEFI Firmware
    │
    ├─ WhiteLotusDXE loads as DXE driver
    │
    ├─ Hooks LoadImage() service
    │
    ├─ bootmgfw.efi loads → Hooked ImgArchStartBootApplication
    │       │
    │       └─ winload.efi loads → Hooked OslFwpKernelSetupPhase1
    │               │
    │               ├─ Patches ntoskrnl.exe (DSE bypass)
    │               │
    │               ├─ Disables VBS
    │               │
    │               └─ Boots Windows with unsigned driver support
    │
    └─ Windows Kernel loads with DSE disabled
```

### File Components

| File | Purpose |
|------|---------|
| `WhiteLotus.c` | Main entry point, LoadImage/SetVariable hooks |
| `PatchBootMgfw.c` | Patches bootmgfw.efi |
| `PatchWinload.c` | Patches winload.efi, disables VBS |
| `PatchKernel.c` | Patches ntoskrnl.exe/CI.dll for DSE bypass |
| `PE.c/h` | PE image parsing utilities |
| `Arch.h` | Architecture-specific definitions (CR0, MSR, etc.) |
| `Intern.h` | Internal synchronization primitives |

---

## WhiteLotusEXE

**WhiteLotusEXE** is a Windows-side loader that handles the deployment of the DXE driver to the EFI System Partition and configures UEFI boot entries to execute the driver.

### Sub-Components

#### Dropper

Drops and executes auxiliary payloads using native Windows APIs:

- **RC4 Decryption**: Decrypts embedded payloads in memory
- **Process Creation**: Uses `RtlCreateProcessParametersEx` and `NtCreateUserProcess` for stealthy process creation
- **Payload Management**: Drops `LoadEfi` to `%LOCALAPPDATA%` and executes UAC bypass module

#### LoadEfi

Handles UEFI-specific operations on a running Windows system:

- **ESP Detection**: Locates and mounts the EFI System Partition
- **Secure Boot Check**: Verifies Secure Boot status before proceeding
- **Boot Entry Hijacking**: Creates custom boot entry and modifies `BootOrder`/`BootNext` variables
- **Payload Installation**: Writes DXE driver to `EFI\CUSTOM\loader.efi` on ESP with proper flushing

### Key Operations

1. Enables `SeSystemEnvironmentPrivilege` for NVRAM access
2. Locates ESP via GPT partition type GUID
3. Decrypts embedded DXE payload
4. Writes payload to `ESP:\EFI\CUSTOM\loader.efi`
5. Creates `Boot0009` entry using Windows boot manager as template
6. Sets `BootNext` to new entry
7. Modifies `BootOrder` to prioritize new entry

---

<<<<<<< Updated upstream
### Modification 

The project currently does not require any modifications, but if changes are necessary for certain situations, follow these steps. 

The Dropper within the Executable project uses hard-coded bytes to load both UACME and LoaderEfi. However, these bytes are encrypted with RC4 and will be decrypted once the architecture is determined:

```c
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
```

The same applies to the LoadEfi project: the .efi file within the project is defined using hard-coded bytes and is decrypted during the initialization phase of the LoadEfi project.  

If you’ve made changes to the project and want to run it, here’s exactly what you need to do: If you’ve made changes to LoadEfi or Dropper, compile these projects, then use the EncryptTool tool included in the project to process the compiled LoadEfi or Dropper executable, retrieve the encrypted bytes, and replace them in the relevant header files. Since the projects will decrypt themselves automatically, simply adding the encrypted version will be sufficient. 

You can also use this same tool for the WhiteLotus.efi file (this is not required, but if necessary in certain situations, you can access the .efi file from the repo.

---

### **Running the Project**

> Since this project runs on systems with Secure Boot disabled, make sure Secure Boot is turned off.
> 
The project that needs to be run is the Dropper project. Do not manually launch the LoadEfi project in any way. The Dropper will handle this.

Additionally, the Dropper executable file does not require UAC permission. It can be launched with standard privileges. This way, the Dropper will run LoadEfi via UACME.
=======
## Execution

WhiteLotus operates entirely through **byte-level pattern matching and patching**. No source code modifications to Windows binaries are required.

### How Byte-Based Execution Works

#### 1. Pattern Scanning (Signature-Based Function Location)

Instead of relying on exported functions or fixed addresses, the project uses **byte signatures** to locate functions:

```c
// Example: Finding ImgArchStartBootApplication in bootmgfw.efi
FindPattern(
    SigImgArchStartBootApplication,  // Byte signature pattern
    0xCC,                              // Wildcard byte (ignore)
    sizeof(SigImgArchStartBootApplication),
    ImageBase + SectionRVA,
    SectionSize,
    &Found
);
```

This approach:
- Works across different Windows build numbers
- Automatically adapts to version differences
- Finds the correct function regardless of ASLR slide (after base is resolved)

#### 2. Function Prologue Detection

After finding a signature within a function, `FindFunctionStart()` scans backward to locate the actual function prologue (entry point).

#### 3. Inline Hooking via Byte Patching

The project installs hooks by:

1. **Backing up original bytes**: Saves original function prologue
2. **Writing hook template**: Overwrites with a jump/call stub
3. **Patching address**: Writes the hook target address into the template
4. **Restoring original**: Some hooks restore bytes before calling originals

```c
// Hook template structure (architectural)
// Preserves register state, calls handler, optionally restores

CopyWpMem(OriginalFunction, gHookTemplate, sizeof(gHookTemplate));
CopyWpMem(OriginalFunction + AddressOffset, &HookHandler, sizeof(HookHandler));
```

#### 4. Memory Protection Bypass

Before patching, the project handles memory protection:

```c
// Disable CR0.WP (Write Protect) temporarily
Cr0 = AsmReadCr0();
AsmWriteCr0(Cr0 & ~CR0_WP);

// Perform patch
CopyWpMem(Target, Patch, Size);

// Restore CR0
AsmWriteCr0(Cr0);
```

#### 5. TPL Elevation

To prevent interruption during patching:

```c
EFI_TPL OldTpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);
// Patch operations
gBS->RestoreTPL(OldTpl);
```

---

## Modification Guide

> **Important:** This project does not require recompilation. All modifications can be made at the byte level directly in the source files.

### Why No Recompilation is Needed

The project uses embedded byte arrays for:
- **Hook templates**: Assembly stubs that are written to memory
- **Signature patterns**: Byte sequences used for function location
- **Patch data**: Specific byte modifications applied to target functions

### Common Modifications

#### 1. Updating Signature Patterns

When Windows updates and old signatures no longer match, update the byte patterns in `Intern.c`:

```c
// Find the signature array in Intern.c
STATIC CONST UINT8 SigImgArchStartBootApplication[] = {
    0x48, 0x89, 0x5C, 0x24, 0x10,  // Function prologue
    // ... additional bytes
    0xCC, 0xCC, 0xCC               // Wildcards (ignored during search)
};
```

#### 2. Adjusting Hook Templates

The hook template in `Arch.h` may need adjustment for different Windows versions or architectures:

```c
// gHookTemplate contains the assembly bytes written to target function
// Modify this if function prologue length changes
```

#### 3. Updating Version Checks

Version-specific logic in `PatchBootMgfw.c`:

```c
// Windows 10 1809+ changed function names
CONST CHAR16* FunctionName = BuildNumber >= 17134
    ? L"ImgArchStartBootApplication"
    : L"ImgArchEfiStartBootApplication";
```

#### 4. Adding New Patch Targets

To patch additional functions:

1. Define new signature pattern in `Intern.c`
2. Add global variables for original function pointer and backup
3. Create hook handler function
4. Call patch installation in appropriate location

### Build Requirements

If you do need to recompile (e.g., changing logic, not just bytes):

- **WhiteLotusDXE**: EDK II development environment
- **WhiteLotusEXE**: Visual Studio with Windows SDK (x64)

### Testing Changes

1. Make byte-level changes to source files
2. Rebuild if logic changed (otherwise files can be used as-is)
3. Test in a controlled environment with virtualization (recommended)
4. Verify patches are applied correctly using a debugger or logging output

---

## Technical Notes

- **TPL Management**: All patching operations occur at `TPL_HIGH_LEVEL` to prevent race conditions
- **CRC32 Recalculation**: After modifying runtime service tables, CRC32 is recalculated to prevent BSOD
- **Virtual Address Mapping**: Events are registered for `EVT_SIGNAL_EXIT_BOOT_SERVICES` and `EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE` to properly handle pointer conversion
- **RC4 Encryption**: EXE payloads use RC4 with key `S3cr3t_K3y_2026!` for basic obfuscation
>>>>>>> Stashed changes

---

## License

See [LICENSE](./LICENSE) file for details.
