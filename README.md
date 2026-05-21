# WhiteLotus

> **WARNING: This project is for educational and research purposes only. The author does not condone or support any illegal use of this software. Use responsibly and only in environments where you have explicit permission to do so.**

## MSRC Research

WhiteLotus was developed as a proof-of-concept directly tied to an MSRC security research submission examining the Windows 11 upgrade enforcement mechanism (**setup.exe** / LabConfig registry bypass).

## Project Overview

Here's the WhiteLotus Demonstration (Vimeo Link): [WhiteLotus Demonstration](https://vimeo.com/1194274935?share=copy&fl=sv&fe=ci)

WhiteLotus is a UEFI-based security research project that demonstrates Driver Signature Enforcement (DSE) bypass techniques through byte-level patching of Windows boot components. The project operates at the firmware level, intercepting and modifying Windows Boot Manager (**bootmgfw.efi**), winload (**winload.efi**), and the Windows kernel (**ntoskrnl.exe**) to disable code signing requirements.

The project consists of two main components that work together to achieve unsigned kernel-mode code execution:

1. **WhiteLotusDXE** - A UEFI DXE driver that hooks into the Windows boot chain
2. **WhiteLotusEXE** - A Windows-side loader that deploys the DXE driver to the EFI System Partition (ESP)

## Project Structure

```
WhiteLotus/
├── WhiteLotusDXE/     # UEFI DXE Driver (main research component)
└── WhiteLotusEXE/     # Windows Loader (deployment mechanism)
```

## WhiteLotusDXE

**WhiteLotusDXE** is a UEFI DXE (Driver eXecution Environment) driver that operates before the Windows kernel loads. This component is the core of the project and implements the actual bypass logic.

### Key Features

- **LoadImage Hook**: Intercepts **EFI_BOOT_SERVICES->LoadImage()** to monitor all EFI binaries loaded during boot
- **Boot Manager Patching**: Locates and patches **bootmgfw.efi** (Windows Boot Manager) by hooking **ImgArchStartBootApplication**
- **Winload Patching**: Patches **winload.efi** by hooking **OslFwpKernelSetupPhase1** to intercept kernel loading
- **DSE Bypass**: Modifies **ntoskrnl.exe** to disable Driver Signature Enforcement by patching **CI.dll!CiInitialize**
- **VBS Disabling**: Sets **VbsPolicyDisabled** EFI variable to disable Virtualization-Based Security

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
| **WhiteLotus.c** | Main entry point, LoadImage/SetVariable hooks |
| **PatchBootMgfw.c** | Patches bootmgfw.efi |
| **PatchWinload.c** | Patches winload.efi, disables VBS |
| **PatchKernel.c** | Patches ntoskrnl.exe/CI.dll for DSE bypass |
| **PE.c/h** | PE image parsing utilities |
| **Arch.h** | Architecture-specific definitions (CR0, MSR, etc.) |
| **Intern.h** | Internal synchronization primitives |

## WhiteLotusEXE

**WhiteLotusEXE** is a Windows-side loader that handles the deployment of the DXE driver to the EFI System Partition and configures UEFI boot entries to execute the driver.

### Sub-Components

#### Dropper

Drops and executes auxiliary payloads using native Windows APIs:

- **RC4 Decryption**: Decrypts embedded payloads in memory
- **PEB Masquerade**: Modifies **ProcessParameters** and walks **PEB_LDR_DATA** to disguise the process as **explorer.exe** before triggering UAC
- **UAC Bypass**: Uses the **ICMLuaUtil** COM interface to launch LoadEfi with administrator privileges without a UAC prompt

#### LoadEfi

Handles UEFI-specific operations on a running Windows system:

- **ESP Detection**: Locates the EFI System Partition via GPT partition type GUID
- **Secure Boot Check**: Verifies Secure Boot status before proceeding
- **Boot Entry Creation**: Creates **Boot0009** entry and modifies **BootOrder** / **BootNext** variables
- **Payload Installation**: Writes DXE driver to **EFI\CUSTOM\loader.efi** on ESP

### Key Operations

1. Enables **SeSystemEnvironmentPrivilege** for NVRAM access
2. Locates ESP via GPT partition type GUID
3. Decrypts embedded DXE payload
4. Writes payload to **ESP:\EFI\CUSTOM\loader.efi**
5. Creates **Boot0009** entry using Windows boot manager as template
6. Sets **BootNext** to new entry
7. Modifies **BootOrder** to prioritize new entry

## Running the Project

> Since this project runs on systems with Secure Boot disabled, make sure Secure Boot is turned off.

The project that needs to be run is the **Dropper** project. Do not manually launch the LoadEfi project in any way. The Dropper will handle this.

Since the payloads are already hardcoded in the project, there is no need to provide an EFI driver. Simply compile it from the VS IDE and run the Dropper without admin privileges.

The Dropper executable does not require UAC permission. It can be launched with standard privileges. This way, the Dropper will run LoadEfi as admin within the project.

## License

See [LICENSE](./LICENSE) file for details.
