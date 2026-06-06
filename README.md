# WhiteLotus

A UEFI-based proof-of-concept demonstrating Driver Signature Enforcement (DSE) bypass through in-memory patching of the Windows boot chain on Windows 10/11 systems with Secure Boot disabled (X64).

Here you can find a material and demonstation for WhiteLotus in these links:
> Blog: [0xbekoo - WhiteLotus](https://0xbekoo.github.io/blogs/whitelotus/) <br>
> Demo: [WhiteLotus Demonstration](https://vimeo.com/1194274935?share=copy&fl=sv&fe=ci)

---

> [!WARNING]
> This project is strictly a proof-of-concept developed for security research and educational purposes. It was submitted to the Microsoft Security Response Center (MSRC) as part of a broader investigation into Windows 11's upgrade enforcement mechanism.
> 
> **Do not use this software on systems you do not own or have explicit written authorization to test.** Deploying bootkit-class tooling without proper authorization may constitute a criminal offense. The techniques demonstrated here — UAC bypass, UEFI boot entry manipulation, kernel integrity subversion — are presented solely to advance the understanding of platform security mechanisms and their limitations.
>
> This is not a weaponized implant, a persistence framework, or a tool intended for offensive use in any operational context. The author is not responsible for any unauthorized use or resulting liabilities and strongly advises against using this software outside of test environments. You assume all responsibility.


## Overview

WhiteLotus was developed as a direct companion to an MSRC submission examining how Windows 11's setup enforcement can be circumvented via the LabConfig registry bypass in **setup.exe**. While that research focused on OS upgrade gating, a more foundational question emerged in the process: what actually enforces driver signing at boot time, and how robust is that enforcement against a pre-OS adversary with physical access and Secure Boot disabled?

The answer involves three separate Windows components — **bootmgfw.efi**, **winload.efi**, and **ntoskrnl.exe** — that form a chain of trust from firmware handoff to kernel initialization. Each component verifies the integrity of the next before yielding control. WhiteLotus intercepts all three in sequence, applying minimal in-memory patches that sever this chain without touching anything on disk. By the time the OS finishes loading, the code integrity subsystem has been neutralized and unsigned kernel-mode drivers load as if signing requirements never existed.

The project is split into two parts. **WhiteLotusDXE** is a UEFI DXE (Driver Execution Environment) driver that runs before the OS loader takes over; it lives on the EFI System Partition and hooks the firmware's own boot services to intercept each boot component as it loads. **WhiteLotusEXE** is the Windows-side tooling that gets it there — handling privilege escalation, ESP detection, payload installation, and UEFI boot variable configuration from an unprivileged user session.

## How It Works

The core mechanism is straightforward: intercept each Windows boot component as it's loaded into memory, patch the code responsible for integrity enforcement before it executes, restore the original bytes, then let execution continue normally. Each stage hooks the next, forming a chain:

```
[Dropper.exe]
    |
    | RC4-decrypt LoadEfi, drop to %LOCALAPPDATA%
    | PEB/LDR masquerade as explorer.exe
    | ICMLuaUtil COM elevation (no UAC prompt)
    v
[LoadEfi.exe]  (HIGH integrity)
    |
    | Enable SeSystemEnvironmentPrivilege
    | Scan GPT for EFI System Partition
    | RC4-decrypt DXE driver, write to ESP:\EFI\CUSTOM\loader.efi
    | Create Boot0009, set BootNext, prepend to BootOrder
    v
[REBOOT]
    v
[WhiteLotusDXE]  (UEFI DXE phase, before ExitBootServices)
    |
    | Hook EFI Boot Services: LoadImage, SetVariable
    | Detect bootmgfw.efi load → PatchBootMgfw
    v
[bootmgfw.efi]
    |
    | ImgArchStartBootApplication → trampoline → PatchWinload
    | Disable VBS via EFI variable
    v
[winload.efi]
    |
    | OslFwpKernelSetupPhase1 → trampoline → PatchKernel
    v
[ntoskrnl.exe]
    |
    | SepInitializeCodeIntegrity: mov ecx,1 → xor ecx,ecx
    | SeValidateImageData: mov eax,0xC0000428 → mov eax,0
    v
[Windows] — DSE disabled, unsigned drivers load freely
```

The hook mechanism is a classic trampoline: the first bytes of the target function's prologue are overwritten with `mov rax, <addr>; push rax; ret` (12 bytes on x64). The original bytes are saved before patching; the hook fires, applies the next stage's patch, restores the saved bytes, then calls through — so the hooked function still runs correctly. Memory write-protection (CR0.WP) is cleared during the window and restored immediately after.

## Components

### WhiteLotusDXE

The DXE_RUNTIME driver hooks **EFI_BOOT_SERVICES.LoadImage** and **EFI_BOOT_SERVICES.SetVariable** at the service table level using interlocked pointer swaps. When the hooked **LoadImage** detects **bootmgfw.efi** being loaded — identified by matching the BCD bootmgr GUID (9DEA862C-5CDD-4E70-ACC1-F32B344D4795) in the image's resource directory — it triggers the first patch stage.

**PatchBootMgfw** locates **ImgArchStartBootApplication** using a byte-pattern signature scan with wildcard support, then backtracks to the function prologue via the PE exception directory's unwind data. The trampoline replaces the prologue in-place. This intercept fires just before the boot manager hands off execution to winload.efi, giving the driver a window to patch the loader before it runs.

**PatchWinload** operates identically against **OslFwpKernelSetupPhase1** in winload.efi. It additionally sets the VbsPolicyDisabled EFI variable to suppress Virtualization-Based Security before the kernel has a chance to initialize it — a necessary step on systems where VBS would otherwise interfere with in-memory patching at the kernel level.

**PatchKernel** resolves **CiInitialize** through ntoskrnl.exe's IAT (imported from **CI.dll**), then scans the PAGE section for two patterns. The first targets **SepInitializeCodeIntegrity** — the function responsible for arming the code integrity subsystem at kernel startup — specifically the **mov ecx, 1** instruction that enables CI enforcement, which is replaced with **xor ecx, ecx**. The second targets **SeValidateImageData**, overwriting the STATUS_INVALID_IMAGE_HASH (0xC0000428) return path with STATUS_SUCCESS. Both are single-instruction overwrites; the surrounding code is left untouched.

### WhiteLotusEXE

**Dropper** runs without elevation. It RC4-decrypts the embedded **LoadEfi** payload to **%LOCALAPPDATA%\loadefi.exe**, then silently elevates it by masquerading as **explorer.exe** through direct modification of the process's PEB (ProcessParameters.ImagePathName, ProcessParameters.CommandLine) and the corresponding PEB_LDR_DATA entries. With that identity in place, it invokes the **ICMLuaUtil** COM interface (**CLSID: 3E5FC7F9-9A51-4367-9063-A120244FBEC7**) via an elevation moniker. The COM infrastructure sees what appears to be an Explorer request and grants HIGH integrity without presenting a UAC prompt. PEB and LDR state are restored immediately after elevation succeeds.

**LoadEfi** handles the UEFI-side setup. It enables **SeSystemEnvironmentPrivilege** for firmware variable access, verifies Secure Boot is disabled by querying the **SecureBoot** EFI variable, then locates the EFI System Partition by iterating all volumes and scanning GPT partition tables via **IOCTL_DISK_GET_DRIVE_LAYOUT_EX** for the ESP type GUID (**C12A7328-F81F-11D2-BA4B-00A0C93EC93B**). The DXE driver is written to **ESP:\EFI\CUSTOM\loader.efi** with both file-level and volume-level cache flushes to ensure the write reaches disk before reboot. Finally, LoadEfi reads the existing Windows Boot Manager entry to extract its hardware device path prefix, constructs a new **Boot0009** option pointing to loader.efi, sets BootNext = 0x0009, and prepends Boot0009 to BootOrder.

## Requirements

- Windows 10 or 11 (x64)
- UEFI firmware
- Secure Boot must be **disabled**
- The Dropper does not require administrator privileges

## Building

**WhiteLotusDXE** is an EDK2 module. You don't need to build the WhiteLotusDXE project because in WhiteLotusEXE project i've used hardcoded bytes. So, you don't need to provide any .efi file etc.

**WhiteLotusEXE** targets Visual Studio — open **Dropper.vcxproj** and **LoadEfi.vcxproj** individually or include them in a solution. The compiled DXE and loader payloads (loader.h, payload.h) are already embedded as RC4-encrypted byte arrays; no separate packaging step is required.

## Usage

Since i've used hardcoded bytes and UAC bypass, compile just the Dropper project and run the resulting executable as a standard user. Do not launch LoadEfi.exe directly — the Dropper handles elevation and execution internally. After the Dropper completes, reboot the machine. On the next boot, the DXE driver executes automatically via the **Boot0009** entry.

## License

GPL-3.0 — see [LICENSE](./LICENSE).
