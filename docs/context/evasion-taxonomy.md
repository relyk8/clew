# Environment-sensitive execution gating in Windows malware

**Malware that queries its runtime environment and branches on the response uses a taxonomy of gating techniques that spans a defeatability spectrum from trivially hookable single-API calls to cryptographically hardened multi-message protocol exchanges.** This distinction — whether a gate can be opened by controlling the return value of one API call versus requiring a coordinated responder maintaining state across many calls — is the critical axis for API-response interposition fuzzers like AriadneX. The taxonomy below catalogs **54 distinct techniques** across 9 categories, with exact mechanisms, data shapes, statefulness properties, real-world family attribution, and defeatability classification. Each technique satisfies the inclusion criterion: malware issues a query to the OS, hardware, or network, receives a response, and conditionally branches.

The bottom line for fuzzer design: roughly **60% of cataloged techniques are stateless and single-call defeatable**, meaning an RL agent needs only to learn the correct return value for one intercepted call. About **25% require lightweight multi-call coordination** (2–5 calls with consistent state). The remaining **15% — concentrated in C2 communication gating — demand full protocol emulation or are cryptographically infeasible** to defeat without the C2 server's private key, representing a fundamental boundary for API-level interposition.

---

## §1 Debugger and analysis-tool detection

This category is the most thoroughly studied and most uniformly defeatable. Nearly all checks are stateless queries of kernel-maintained debugging state. MITRE ATT&CK tracks these under T1622 (Debugger Evasion).

### 1.1 PEB flag reads (API-mediated)

**IsDebuggerPresent** reads `PEB.BeingDebugged` (offset +0x2) and returns a BOOL. Data shape is boolean. Stateless. Used by Emotet, LockBit 3.0, Pikabot, Lumma Stealer, FormBook, Raspberry Robin, Dridex. **Single-call defeatable** — hook the API to return 0, or patch the PEB byte. WELL-DOCUMENTED (MITRE T1622, Check Point anti-debug reference, al-khaser).

**CheckRemoteDebuggerPresent** wraps `NtQueryInformationProcess` with `ProcessDebugPort` (class 7), writing TRUE/FALSE to an output BOOL. Stateless. Used by Emotet, banking trojans broadly. **Single-call defeatable**. WELL-DOCUMENTED.

### 1.2 PEB flag reads (direct memory access — no API to hook)

**Direct PEB.BeingDebugged** via `mov eax, [fs:0x30]` (x86) or `mov rax, [gs:0x60]` (x64), then reading the byte at offset +0x2. Data shape is byte. Stateless. Used by Themida, VMProtect, Furtim, LockBit 3.0, and most commercial packers. **Not defeatable by API hooking** — requires patching PEB memory directly (ScyllaHide approach). WELL-DOCUMENTED.

**PEB.NtGlobalFlag** at offset 0x68 (x86) / 0xBC (x64). When a process is created by a debugger, this DWORD is set to 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS). Stateless. Not set when a debugger attaches after creation. Used by Themida, VMProtect, al-khaser. **Not defeatable by API hooking** — requires PEB memory patch or launching with `_NO_DEBUG_HEAP=1`. WELL-DOCUMENTED.

**PEB.ProcessHeap flags**: `Heap.Flags` (offset ~0x0C/0x40 in x86/x64) and `Heap.ForceFlags` (~0x10/0x44). Under debugger, `Flags > HEAP_GROWABLE (2)` and `ForceFlags != 0`. Data shape is two DWORDs. Stateless. Themida, VMProtect. **Not defeatable by API hooking** — requires heap structure patching. WELL-DOCUMENTED.

**Key implication for AriadneX**: Techniques 1.2 bypass the API interposition layer entirely. They read process memory directly. An API-response fuzzer cannot intercept these without instrumenting memory reads at the instruction level (e.g., hardware breakpoints or dynamic binary instrumentation). PFuzzer (Bottura, D'Elia, Querzoni, EuroS&P 2025) addresses this by combining API hooking with environment mutation at the memory level.

### 1.3 NtQueryInformationProcess variants

All three information classes are queried through a single ntdll export, making them hookable at one point:

| Info Class | Value | Return Data | Debugger Response | Data Shape |
|---|---|---|---|---|
| ProcessDebugPort | 0x07 | DWORD_PTR | Nonzero (0xFFFFFFFF) | Integer |
| ProcessDebugFlags | 0x1F | DWORD | 0 (inverse logic) | Integer |
| ProcessDebugObjectHandle | 0x1E | HANDLE | Valid handle | Handle |

Stateless. Used by Furtim, Themida, VMProtect, LockBit 3.0, Dridex, FinSpy, Pikabot — "the majority of anti-debugging techniques observed in malware" involve NtQueryInformationProcess (per Afianian et al., ACM CSUR 2019). **Single-call defeatable** — ScyllaHide hooks `NtQueryInformationProcess` once and dispatches on the info class argument, forging all three responses. WELL-DOCUMENTED.

### 1.4 NtQuerySystemInformation — SystemKernelDebuggerInformation

`NtQuerySystemInformation` with class 0x23 returns `SYSTEM_KERNEL_DEBUGGER_INFORMATION` — a 2-byte struct with `DebuggerEnabled` and `DebuggerNotPresent` BOOLEANs. Detects kernel debuggers (WinDbg/KD). Stateless. VMProtect, Themida, SmokeLoader. **Single-call defeatable**. WELL-DOCUMENTED.

### 1.5 Hardware breakpoint detection

**GetThreadContext** (or `NtGetContextThread`) with `CONTEXT_DEBUG_REGISTERS` returns the CONTEXT structure (~1232 bytes on x64). Malware checks DR0–DR3 for nonzero values indicating hardware breakpoints. Data shape is fixed-size struct. Stateless. Themida, VMProtect, Kronos. **Single-call defeatable** — hook `NtGetContextThread`, zero DR0–DR3 in returned CONTEXT. WELL-DOCUMENTED.

### 1.6 Exception-based tricks

**CloseHandle invalid handle**: calling `CloseHandle((HANDLE)0x99999999)` inside `__try/__except` — under a debugger, the kernel raises `EXCEPTION_INVALID_HANDLE (0xC0000008)`; without, it returns FALSE silently. Data shape is boolean (exception vs. no exception). Stateless. VMProtect, al-khaser. **Single-call defeatable** — hook `NtClose` to suppress the exception. WELL-DOCUMENTED but described as "not widely used by malicious programs" (al-khaser documentation).

**OutputDebugString + GetLastError**: `SetLastError(X) → OutputDebugStringA("test") → GetLastError()` — if error code changed, debugger consumed the string. Data shape is integer. Formally stateless but involves 3 API calls requiring coordination. **Multi-call (3 APIs)**. **Deprecated on Vista+** where error code restoration made this unreliable. Emotet (legacy). WELL-DOCUMENTED as historical.

**INT 2D / INT 3**: inline interrupt instructions inside SEH handlers. Without debugger, exception dispatches to handler; with debugger, it swallows the exception. Data shape is boolean (handler called or not). **Not defeatable by API hooking** — requires configuring the debugger to pass exceptions to the application's SEH chain. Themida, Pikabot, various packers. WELL-DOCUMENTED.

**SetUnhandledExceptionFilter**: `SetUnhandledExceptionFilter(handler) → deliberate exception`. Internally, `UnhandledExceptionFilter` calls `NtQueryInformationProcess(ProcessDebugPort)` — if debugger present, the custom handler is suppressed. **Single-call defeatable** — hooking NtQueryInformationProcess(ProcessDebugPort) is sufficient since it's the underlying check. Themida, various protectors. WELL-DOCUMENTED.

### 1.7 Process and window enumeration

**CreateToolhelp32Snapshot + Process32First/Next** enumerates running processes. Malware compares `PROCESSENTRY32.szExeFile` against a blacklist: ollydbg.exe, x64dbg.exe, ida.exe, ida64.exe, windbg.exe, processhacker.exe, wireshark.exe, procmon.exe, etc. Data shape is struct with string field, iterated. Stateless (snapshot at query time) but **multi-call coordination required** — must hook CreateToolhelp32Snapshot + Process32First + Process32Next to filter blacklisted names. Alternatively, hook the single underlying `NtQuerySystemInformation(SystemProcessInformation)`. Furtim (extensive blacklist with delayed termination of analyst tools), LockBit 3.0, Andromeda, SmokeLoader, Emotet, Dridex. SUNBURST uses FNV-1A+XOR hashing of process names against a blocklist, making string comparison opaque. WELL-DOCUMENTED (MITRE T1057).

**FindWindowA/W** searches for debugger window class names ("OLLYDBG", "WinDbgFrameClass", "Qt5QWindowIcon" for x64dbg). Data shape is HWND (NULL = not found). Stateless. Lumma Stealer checks foreground window titles. **Single-call defeatable** — hook FindWindow to return NULL for blacklisted classes. WELL-DOCUMENTED.

### 1.8 Parent process and loaded module checks

**Parent process validation**: `NtQueryInformationProcess(ProcessBasicInformation)` to extract `InheritedFromUniqueProcessId`, then resolve parent name and compare against "explorer.exe". **Multi-call** (2 API calls minimum). Furtim, Andromeda. WELL-DOCUMENTED.

**GetModuleHandleA/W** for analysis DLLs: sbiedll.dll (Sandboxie), dbghelp.dll, api_log.dll, dir_watch.dll, vmcheck.dll. Returns HMODULE (NULL = not loaded). Stateless. **Single-call defeatable** — return NULL for blacklisted names. Furtim uses `LdrGetDllHandle` (ntdll) to evade Win32 hooks; also walks `PEB→Ldr→InMemoryOrderModuleList` directly, bypassing API hooks entirely. Andromeda, SmokeLoader, LockBit 3.0. WELL-DOCUMENTED.

---

## §2 Virtualization and sandbox artifact detection

VM detection is the most prevalent evasion category. A G DATA study (2019, 50K samples) found CPUID with leaf 0x40000000 as the single most-used VM detection method (**≥2.77% of all malware samples**). The Red Report 2026 ranks T1497 as the **4th most observed MITRE technique**. These techniques are overwhelmingly stateless and single-call defeatable individually, but sophisticated malware (Furtim: 400+ checks; GravityRAT: 7 orthogonal checks) chains many together, requiring coordinated interposition across all of them.

### 2.1 Registry artifact queries

**RegOpenKeyEx + RegQueryValueEx** against VM-indicative registry paths. Each call returns a string or key-existence boolean. **Stateless per query; single-call defeatable per query**.

| Registry Path | Artifact | Hypervisor |
|---|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` → "0" | Disk controller ID containing "VMware", "VBOX", "QEMU" | VMware/VBox/QEMU |
| `HKLM\HARDWARE\DESCRIPTION\System` → SystemBiosVersion | BIOS strings "VBOX", "VMWARE", "QEMU", "BOCHS" | Multiple |
| `HKLM\HARDWARE\ACPI\DSDT\VBOX__` | Key existence alone | VirtualBox |
| `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` | Key existence | VMware |
| `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions` | Key existence | VirtualBox |

Malware families: Furtim (uses `NtQueryAttributesFile` and Nt-level registry APIs to bypass Win32 hooks), GravityRAT, FinSpy/FinFisher (MD5-hashes vendor IDs before comparison), SmokeLoader, TrickBot, Emotet, Qakbot. WELL-DOCUMENTED (MITRE T1497.001, al-khaser, unprotect.it).

### 2.2 File and driver presence

**GetFileAttributesW** or **CreateFileW** probing for VM guest tool files. Data shape is boolean (file exists or `INVALID_FILE_ATTRIBUTES`). **Stateless, single-call defeatable**.

Key file paths: `C:\Windows\System32\drivers\VBoxMouse.sys`, `VBoxGuest.sys`, `vmhgfs.sys`, `vmmouse.sys`, `vmtoolsd.exe`, `qemu-ga.exe`. Furtim uses `NtQueryAttributesFile` to evade user-mode hooks and checks a massive list including sandbox-typical paths (`C:\sample.exe`, `C:\virus\virus.exe`). SUNBURST queries `Win32_SystemDriver` via WMI and hashes driver paths with FNV-1A+XOR. Locky, Cerber (v6+), SmokeLoader. WELL-DOCUMENTED.

### 2.3 MAC address OUI prefix

**GetAdaptersInfo** or **GetAdaptersAddresses** returns adapter information including the 6-byte physical address. Malware checks the first 3 bytes against known VM OUIs: **VMware** (00:0C:29, 00:50:56), **VirtualBox** (08:00:27), **Xen** (00:16:3E), **Hyper-V** (00:15:5D, 00:03:FF), **Parallels** (00:1C:42), **QEMU/KVM** (52:54:00). Data shape is 3-byte prefix comparison. **Stateless, single-call defeatable** — configure VM with non-VM MAC. GravityRAT, Furtim, Dridex, TrickBot, Locky. WELL-DOCUMENTED.

### 2.4 SMBIOS and firmware fingerprinting

**GetSystemFirmwareTable('RSMB')** retrieves raw SMBIOS data (types 0–3: BIOS, System, Baseboard, Chassis). Malware parses for manufacturer strings: "VMware", "VirtualBox", "QEMU", "innotek", "Bochs", "Xen", "KVM". Data shape is unbounded binary buffer requiring string search. **Stateless, single-call defeatable** — VMware supports `smbios.reflectHost = "TRUE"` to mirror host SMBIOS data. WELL-DOCUMENTED.

**WMI queries via COM** (`IWbemServices::ExecQuery`) query classes like `Win32_ComputerSystem` (Manufacturer, Model), `Win32_BIOS` (SerialNumber), `Win32_DiskDrive` (Model containing "VBOX HARDDISK" or "VMware Virtual"), and `Win32_BaseBoard`. Each WMI query is internally multi-call (COM initialization → locator → service connection → query → result enumeration) but semantically stateless — returns current system config. **Single-call defeatable** at the WMI provider level.

GravityRAT is notable for its **novel CPU temperature check** via `MSAcpi_ThermalZoneTemperature` WMI class — most hypervisors (VMware, VirtualBox, KVM, Xen, Hyper-V) return an error for this query because they do not emulate thermal sensors, revealing the VM (Cisco Talos, 2018). SUNBURST queries `Win32_SystemDriver` with FNV-1A+XOR hashed driver names for blocklist comparison (Mandiant, December 2020). FinSpy enumerates hardware devices and compares MD5-hashed vendor IDs against a predefined list (Microsoft Security Blog, 2018). Turla uses WMI for system profiling. WELL-DOCUMENTED.

### 2.5 CPUID instruction

The `CPUID` instruction is ring-3 accessible and returns hypervisor information in fixed 16-byte register sets:

- **Leaf 0** (vendor string): physical CPUs return "GenuineIntel" or "AuthenticAMD"; hypervisors may expose "KVMKVMKVM", "Microsoft Hv", "VMwareVMware", "XenVMMXenVMM", "VBoxVBoxVBox", "TCGTCGTCGTCG" (QEMU/TCG). Data shape: 12-byte string.
- **Leaf 1, ECX bit 31** (hypervisor present bit): per Intel/AMD specification, "physical CPUs (all existing and future) set this bit to zero." A `1` definitively indicates a hypervisor. Data shape: single bit.
- **Leaf 0x40000000** (hypervisor vendor ID): 12-byte vendor string. Only valid when leaf 1 ECX bit 31 = 1.

**Stateless, single-call defeatable** — hypervisors intercept CPUID VM-exits and can return arbitrary values. VMware: `cpuid.1.ecx="0---:----:----:----:----:----:----:----"` clears bit 31. VirtualBox: `VBoxManage modifyvm <VM> --paravirtprovider none`.

This is the **most prevalent single VM detection technique** per the G DATA 2019 study. QakBot, SmokeLoader, GravityRAT, Furtim, Dridex, TrickBot, Emotet, Cerber (v6+), Locky all use CPUID-based detection. WELL-DOCUMENTED.

### 2.6 RDTSC/RDTSCP timing

`RDTSC` before and after a code block (often including a `CPUID` instruction to force a VM exit) — the delta reveals VM overhead. On bare metal, the delta for a CPUID is typically **<1,000 cycles**; under a hypervisor, VM exit latency pushes it to **>100,000 cycles**. Threshold comparison against ~20,000 cycles discriminates reliably.

Data shape is scalar integer (cycle count delta). **Stateful** — inherently requires two temporally separated measurements. **Multi-call and the hardest VM detection technique to defeat** because: (1) TSC offsetting/scaling can mask VM exits but statistical analysis across many samples detects jitter; (2) nested timing (`RDTSC` around `RDTSC`) can detect TSC spoofing; (3) `RDTSCP` includes processor ID, complicating faking. VMware offers `monitor_control.virtual_rdtsc = "TRUE"` but sophisticated malware can still detect anomalies through statistical analysis.

Furtim, SmokeLoader, TrickBot, Emotet, GravityRAT, Cerber. WELL-DOCUMENTED (MITRE T1497.003).

### 2.7 Descriptor table tricks and VMware backdoor

**SIDT/SGDT/SLDT/STR** (Red Pill, No Pill, Scoopy Doo) store descriptor table register values. In older single-core VMs using binary translation, the IDT/GDT base addresses were relocated to non-standard ranges (VMware IDT at 0xFFxxxxxx, VirtualPC at 0xE8xxxxxx). Data shape is memory address. Stateless. **Largely obsolete** on modern multi-core systems with hardware-assisted virtualization (VT-x/AMD-V) and KPTI. Legacy malware from ~2004–2012. WELL-DOCUMENTED as historical (Rutkowska, "Red Pill," 2004; Paleari et al., "A Fistful of Red-Pills," WOOT 2009).

**VMware backdoor I/O port**: `IN` instruction on port 0x5658 with magic value 0x564D5868 ("VMXh") in EAX, command 0x0A in ECX. On physical hardware, `IN` is privileged and raises `#GP`; VMware intercepts it and sets EBX to the magic number. Malware wraps this in SEH. Data shape is boolean (exception vs. magic in EBX). **Stateless, single-call defeatable** — `isolation.tools.getVersion.disable = "TRUE"` disables the backdoor. QakBot (Lab52 analysis), Furtim (with NOP padding to thwart static signatures). WELL-DOCUMENTED.

---

## §3 User and host fingerprinting

### 3.1 Username and computer name

**GetUserNameW/A** returns the current username as a short string (≤256 chars). Malware compares against sandbox-indicative names: "sandbox", "malware", "virus", "sample", "test", "John Doe", "TEQUILABOOMBOOM", "CurrentUser", "analyst". **Stateless, single-call defeatable**. Emotet checks for "TEQUILABOOMBOOM", "John Doe", "Wilber", "admin/KLONE_X64-PC" co-located with sentinel files `C:\take_screenshot.ps1`, `C:\loaddll.exe` (Trend Micro 2017). Gootkit, OilRig/OopsIE (Unit 42, September 2018), SmokeLoader, SaintBot. WELL-DOCUMENTED (MITRE T1497.001).

**GetComputerNameW/A** returns hostname. Same pattern, same defeatability. WELL-DOCUMENTED.

### 3.2 Locale and language gating

**GetUserDefaultUILanguage**, **GetSystemDefaultUILanguage**, **GetUserDefaultLangID**, **GetKeyboardLayoutList** return LANGID (16-bit integer) or layout array. CIS-origin malware skips execution if locale indicates Russian (0x0419), Ukrainian (0x0422), Belarusian (0x0423), Kazakh, or other CIS languages. Each call is **stateless and single-call defeatable**.

**This is one of the most broadly adopted gating techniques in ransomware.** MITRE T1614.001 lists **35+ families** including:

- **GandCrab**: `GetUserDefaultUILanguage` + `GetSystemDefaultUILanguage`, terminates on CIS locales (Check Point Research 2018)
- **REvil/Sodinokibi**: `GetKeyboardLayoutList`, checks lower byte 0x18–0x44 covering Russian + CIS (Secureworks CTU; McAfee ATR 2019)
- **DarkSide**: Both `GetSystemDefaultUILanguage()` AND `GetUserDefaultLangID()`, also `NtQueryInstallUILanguage` comparing to 0x419 — **redundant multi-API check** requiring coordinated interposition of 2–3 independent calls (Cybereason 2021; Chuong Dong 2021)
- **Ryuk**: Registry `HKLM\...\Nls\Language` for 0x419/0x422/0x423 (CrowdStrike 2019)
- Also: Conti, LockBit 2.0, Maze (McAfee 2020), BlackByte, Cuba, Avaddon, SynAck, Clop, FIVEHANDS, JSWorm, RedLine Stealer, BlackBasta, Quantum

WELL-DOCUMENTED (MITRE T1614.001).

### 3.3 Domain membership

**NetGetJoinInformation** returns domain name + join status enum. **DsGetDcNameW** returns DC reachability as `DOMAIN_CONTROLLER_INFO` struct. Enterprise-targeting ransomware verifies domain membership before lateral movement. DarkSide calls `DsGetDcNameW`, `DsGetDcOpenW`, `DsGetDcNextW` (CyberGeeks 2021). **Stateless per call, single-call defeatable**. WELL-DOCUMENTED for DarkSide; ANECDOTAL for pure domain-join gating.

---

## §4 Hardware resource and user activity checks

### 4.1 CPU, RAM, and disk as sandbox discriminators

These three checks form a standard anti-sandbox trifecta. All are **stateless** and **single-call defeatable**, but McAfee Labs (2019, "Evolution of Malware Sandbox Evasion Tactics") documents malware migrating from these APIs to WMI-based equivalents specifically to defeat single-call API interposition.

| Resource | API | Data Shape | Threshold | Key Families |
|---|---|---|---|---|
| CPU count | `GetSystemInfo` → `SYSTEM_INFO.dwNumberOfProcessors` | DWORD in struct | < 2 | DarkSide, Black Basta, SmokeLoader, SUNBURST |
| RAM | `GlobalMemoryStatusEx` → `ullTotalPhys` | ULONGLONG in struct | < 1–2 GB | SmokeLoader, cryptominers broadly |
| Disk | `GetDiskFreeSpaceExW` | 3 × ULARGE_INTEGER | < 60–100 GB | Broadly observed |
| Disk (alt) | `CreateFileW(\\.\PhysicalDrive0)` → `DeviceIoControl(IOCTL_DISK_GET_LENGTH_INFO)` | `GET_LENGTH_INFORMATION` struct | < 60 GB | — |

The `DeviceIoControl` path is **two-call stateful** (handle from CreateFile must be passed to DeviceIoControl). All others are single-call. WELL-DOCUMENTED (MITRE T1497.001).

**Screen resolution**: `GetSystemMetrics(SM_CXSCREEN)` and `GetSystemMetrics(SM_CYSCREEN)` — sandboxes often use 800×600 or 1024×768 defaults. Two independent calls returning small integers. **Single-call each, but must return a consistent pair**. Beep malware (Minerva Labs 2023). WELL-DOCUMENTED.

### 4.2 User activity detection — the canonical stateful check

**GetCursorPos called repeatedly with Sleep between calls** is the paradigmatic multi-call stateful check. Malware samples the cursor position at two or more time points and branches on whether motion occurred:

- **Variant A** (too-fast detection): Two `GetCursorPos` calls with no delay — if cursor moved between them, the movement was simulated (too fast for a human). (FireEye 2014, "Hot Knives Through Butter")
- **Variant B** (no-user detection): Two `GetCursorPos` calls with `Sleep(N)` between — if cursor did NOT move, no real user is present.
- **GetLastInputInfo** returns the tick count of the last input event. Checking this over time determines idle duration.

Data shape is `POINT` struct (two integers) per call. **Inherently stateful** — requires temporally consistent sequences. **Multi-call, hardest category for API hooking** — the RL agent must synthesize realistic cursor position trajectories matching human movement patterns, with timing consistent with wall-clock elapsed time. Beep malware (17 evasion techniques, Minerva Labs 2023), broadly observed (MITRE T1497.002, FireEye 2014). WELL-DOCUMENTED.

### 4.3 Wear-and-tear artifacts

Recent documents enumeration (`SHGetFolderPath` + `FindFirstFile` in Recent), browser history/cookies, USB device history (`HKLM\SYSTEM\CurrentControlSet\Enum\USB` via registry enumeration), installed programs count, desktop icon count — all query distributed state that is empty in fresh sandbox installations. Miramirkhani et al. ("Spotless Sandboxes," IEEE S&P 2017) formalized this class and built statistical models to predict system age from artifact density. **Stateful multi-call** (registry/filesystem enumeration sequences). **Requires coordinated multi-call synthesis** — must populate realistic enumeration state. Yokoyama et al. ("SandPrint," RAID 2016) fingerprinted 76 sandboxes using **24+ features** of this type. WELL-DOCUMENTED academically; ANECDOTAL for specific family attribution beyond survey samples.

---

## §5 Time and date gating

### 5.1 Logic bombs — date-triggered execution

**GetSystemTime / GetLocalTime / GetSystemTimeAsFileTime / NtQuerySystemTime** return the current timestamp as a fixed-size struct (SYSTEMTIME: 16 bytes; FILETIME: 8 bytes). Malware compares against a hardcoded activation date or campaign window. **Stateless, single-call defeatable** — return a timestamp within the activation window.

- **Shamoon/DistTrack (2012)**: triggered at 11:08 AM, August 15, 2012 — wiped ~30,000 Saudi Aramco workstations (Kaspersky SecureList 2012)
- **Shamoon 2 (2016)**: trigger 2016/11/17 20:45 (end of Saudi work week) (Unit 42 2016)
- **Shamoon 3 (2018)**: trigger dates December 7 and 12, 2017 (set in the past for immediate activation — hit Saipem, 300+ servers) (Anomali Labs 2018)
- **Stuxnet**: date-based propagation cutoff windows (Symantec W32.Stuxnet Dossier v1.4, 2011; Langner, "To Kill a Centrifuge," 2013)

WELL-DOCUMENTED.

### 5.2 Uptime and sleep-patch detection

**GetTickCount / GetTickCount64** returns milliseconds since boot. Single uptime check (< 20–30 minutes → sandbox) is **stateless, single-call defeatable**. But **sleep-patch detection** — `GetTickCount → Sleep(600000) → GetTickCount → verify elapsed ≈ 600000` — is **stateful multi-call**. Sandboxes that fast-forward `Sleep` calls are detected when the tick delta doesn't match. FinFisher (ESET 2018), Attor spy platform (ESET 2019), broadly observed (MITRE T1497.003). WELL-DOCUMENTED.

### 5.3 NTP cross-validation

Some advanced malware queries NTP servers (UDP port 123 via `sendto`/`recvfrom`) to verify system time hasn't been manipulated. **Stateful multi-call** (network protocol). **Requires coordinated synthesis** — must intercept network calls and provide a consistent NTP response matching faked system time. ANECDOTAL for specific family attribution.

---

## §6 Filesystem and content gating

### 6.1 File presence and sentinel files

**GetFileAttributesW** or **CreateFileW** probing for specific files. Data shape is boolean. **Stateless, single-call defeatable**. Emotet checks for `C:\take_screenshot.ps1`, `C:\loaddll.exe`, `C:\email.doc`, `C:\a\foobar.bmp` and checks its own filename against "sample.", "mlwr_smple.", "artifact.exe" (Trend Micro 2017). WELL-DOCUMENTED.

### 6.2 Command-line argument gating

**GetCommandLineA/W** or **CommandLineToArgvW** returns the process command line as a short string. Many loaders require a specific password or argument to proceed — without it, the malware exits silently or executes a decoy path.

- **Emotet**: `argc > 3` triggers reinstallation path; 3rd parameter is a base64-encoded filepath (nikpx.github.io 2022)
- **QakBot**: batch scripts pass specific arguments (e.g., "regs" as %1) for regsvr32 invocation (Securonix 2022)
- **BazarLoader**: delivered via scripts with specific arguments (Zscaler 2021)

**Stateless, single-call defeatable** — return a crafted command line. The critical challenge is **discovering the correct argument value**, which may be campaign-specific, encrypted, or derived from email content. This is where RL-guided fuzzing could excel: the RL agent explores the space of possible command-line strings to discover which values trigger hidden paths. WELL-DOCUMENTED.

### 6.3 Registry-based configuration and mutex gating

**RegOpenKeyEx + RegQueryValueEx** reading configuration stored by previous malware stages. Data shape varies (string, DWORD, binary). **Two-call stateful** (Open → Query). DarkSide reads `SOFTWARE\Microsoft\Cryptography\MachineGuid` (CyberGeeks 2021). REvil stores config in registry after first execution (McAfee ATR 2019). WELL-DOCUMENTED.

**Mutex gating**: `OpenMutexA/W` checks if a named mutex exists (single-instance enforcement or infection marker). Data shape is boolean (NULL = not found). `OpenMutex` alone is **stateless, single-call defeatable**. `CreateMutexA/W + GetLastError` (checking `ERROR_ALREADY_EXISTS`) is **two-call stateful**. Backoff POS (mutex "nUndsa8301nskal"), Conficker, SpyEye, Zeus, TreasureHunter. WELL-DOCUMENTED (SANS, Virus Bulletin 2012).

### 6.4 Environment variable gating

**GetEnvironmentVariableW/A** checks for specific variables set by installers, other malware components, or expected system configuration. Data shape is short string. **Stateless, single-call defeatable**. Used as inter-stage IPC markers. ANECDOTAL for primary gating.

---

## §7 Network environment checks

### 7.1 Connectivity probes

**InternetGetConnectedState** returns a BOOL + flags bitmask (modem, LAN, proxy). **Stateless, trivially single-call defeatable** — return TRUE with `INTERNET_CONNECTION_LAN`. Nearly universal as a pre-C2 check: Emotet, TrickBot, Qakbot, Agent Tesla. WELL-DOCUMENTED.

**InternetCheckConnection** tests reachability of a specific URL (typically microsoft.com or google.com). Same pattern. Agent Tesla, FormBook. WELL-DOCUMENTED.

### 7.2 DNS resolution

**gethostbyname / getaddrinfo** resolves hostnames. For simple connectivity checks (resolve google.com), **stateless and single-call defeatable** — return a fake `hostent` with 8.8.8.8. For **DGA-based resolution** (Conficker: 50,000 domains/day; GameOver Zeus: 1,000/day; CryptoLocker, Dridex, Necurs, Locky, Emotet), the malware generates N domains, resolves each, and validates the response. This is **multi-call with medium difficulty** — the fuzzer must return believable IPs for algorithmically generated domains while allowing most to fail (NXDOMAIN). Some malware validates that resolved IPs are not in known sinkhole ranges. WELL-DOCUMENTED.

**DnsQuery_A/W** provides direct DNS queries including TXT records. **Single-call for A-record checks; multi-call for DNS TXT C2 channels** (see §8.3). PlugX (custom DNS servers), DNSMessenger, BazarLoader (DNS-over-HTTPS). WELL-DOCUMENTED.

### 7.3 IP geolocation

HTTP requests to geolocation APIs (ip-api.com, ipinfo.io, checkip.amazonaws.com) returning JSON with country codes. Malware parses the response and compares against a whitelist/blacklist (e.g., skip CIS countries, only target US/EU). **Multi-call** (full HTTP stack: Open → Connect → Request → Send → Receive → Read) but semantically simple — a fake HTTP responder returning valid-looking JSON with an acceptable country code suffices. Qakbot (geofencing), Dridex, Raccoon Stealer, Vidar, Agent Tesla, Rhadamanthys. WELL-DOCUMENTED.

### 7.4 ICMP and host reachability

**IcmpSendEcho** pings specific hosts. Data shape is `ICMP_ECHO_REPLY` struct. **Stateless, single-call defeatable** — return 1 reply with `Status=IP_SUCCESS`, RTT ~20ms. PlugX (ICMP C2 in 2013 variants), Winnti. WELL-DOCUMENTED.

---

## §8 C2 communication gating — the multi-message frontier

C2 communication gating represents the **hardest class of execution gates for API-response fuzzing** because it involves multi-message protocol state across chained API calls with semantic, structural, and often cryptographic validity requirements. This section details why each sub-category resists single-call interposition.

### 8.1 Why C2 gating is fundamentally different

Five properties distinguish C2 gating from all other categories:

- **Handle chaining**: `WinHttpOpen → WinHttpConnect → WinHttpOpenRequest` produces HINTERNET handles that subsequent calls consume. Each handle's validity depends on the prior call's success.
- **TLS state**: HTTPS C2 involves ClientHello → ServerHello → Certificate → KeyExchange → Finished internally. Schannel maintains cryptographic state across `InitializeSecurityContext` calls.
- **Semantic validity**: the HTTP response body must match the malware's expected protocol format — correct magic bytes, headers, length fields, and encoding.
- **Cryptographic verification**: many families verify responses using RSA/ECDSA signatures or AES decryption. Without the C2 server's private key, valid responses cannot be synthesized.
- **Multi-round exchanges**: registration → acknowledgment → command polling → response → module download — state must persist across request-response cycles.

### 8.2 HTTP/HTTPS C2 (WinHTTP and WinINet)

**WinHTTP chain**: `WinHttpOpen → WinHttpConnect(server, port) → WinHttpOpenRequest("POST", "/path") → WinHttpSendRequest(headers, body) → WinHttpReceiveResponse → WinHttpQueryHeaders → WinHttpReadData(buffer)`. Six or more calls, each depending on prior handles. TLS negotiation happens internally between Send and Receive.

**WinINet chain**: `InternetOpen → InternetConnect → HttpOpenRequest → HttpSendRequest → InternetReadFile`. Same handle-chaining pattern.

**Defeatability: multi-call, requires protocol-aware response synthesis.** The response must be correctly structured per the malware's parser:

- **Emotet (current)**: POST body = `ECDH_pubkey || AES256(SHA256(M) || M) || random_bytes`. Server response verified with ECDSA using an embedded verification key. Without the server's ECDSA private key, valid responses **cannot be generated** (Netskope, Elastic Security analysis).
- **Emotet (pre-2022)**: `RSA(AES128key) || SHA1(M) || AES128-CBC(M)` with 768-bit RSA, IV = 16 null bytes.
- **IcedID/BokBot**: cookie-based protocol (`__gads`, `_gid`, `_u`, `__io`, `_ga`, `_gat` cookies carry victim fingerprint). Response is GZIP payload containing RC4-double-encrypted DAT files — first 8 bytes = RC4 key for outer layer. Self-signed TLS certificates with "Internet Widgits Pty Ltd" pattern are pinned (Check Point).
- **Gozi/Ursnif**: HTTP with KINS format responses — specific binary structure with CRC validation.
- **Cobalt Strike**: response must match the Malleable C2 profile's server block transforms — the profile is essentially a grammar that dictates response formatting.
- **TrickBot**: HTTPS with structured commands and module-specific response formats.
- **Qakbot**: HTTPS with structured responses, RC4/AES encrypted configuration.

WELL-DOCUMENTED across all families listed.

### 8.3 DNS-based C2

**DnsQuery_A/W with DNS_TYPE_TXT** retrieves TXT records containing Base64-encoded commands or chunked binary data. **DNSMessenger** implements a full bidirectional protocol: (1) initial "SYN" query to establish the channel, (2) "MSG" queries with hash-based machine ID in subdomain labels and counter-based sequencing, (3) A-record validation before TXT processing (A record must match; 0.0.0.0 → stop), (4) response interpretation ("www" = proceed, "idle" = sleep, "stop" = cease). **Multi-call stateful protocol** requiring a fake DNS server that parses query hostnames, extracts machine IDs and sequence counters, and returns appropriately encoded responses.

Also: Feederbot, PlugX (DNS C2 module), BazarLoader (DNS-over-HTTPS). WELL-DOCUMENTED.

### 8.4 Raw socket and custom binary protocols

**WSAStartup → socket → connect → send → recv** with custom binary framing. Each family defines its own wire format:

**Gh0st RAT** (and 50+ variants): 13-byte header = 5-byte magic (default "Gh0st", but variants use "LURK0", "HTTPS", "cb1st", "Lyyyy", etc.) + 4-byte total packet size + 4-byte uncompressed size. Payload is zlib-compressed. Server acknowledgment must echo the correct magic word. Variants add XOR/RC4 encryption. SugarGh0st uses extended 8-byte headers. **73 opcodes** in the full version. Heartbeat/keepalive every ~10 seconds.

**PlugX (THOR/Korplug)**: initial handshake = random bytes; server must return exactly 16 bytes (0x24 bytes in newer variants starting with "20 00 00 00" containing plugin GUID). Supports TCP, UDP, HTTP, HTTPS, ICMP, DNS, and P2P protocols. Magic value changed from "PLUG" to "THOR" in recent variants. Up to 16 C2 servers configurable.

**Poison Ivy**: Gh0st-derived protocol with Camellia encryption overlay. Password-based key derivation (default "admin", 32-byte null-padded).

**Remcos**: RC4 encrypted with repeating 11-byte binary pattern as header. **NetWire**: AES encrypted, packet = length + 1-byte command + data, initial 32-byte seed + 16-byte IV + hardcoded password for AES key generation.

**Defeatability: multi-call, requires per-family protocol responder.** Cannot be defeated by hooking a single API. Each `recv()` must return data consistent with what was `send()`-ed. Encryption keys may be negotiated or hardcoded. The fuzzer must implement a protocol state machine per family. WELL-DOCUMENTED for all listed families.

### 8.5 Steganographic and dead-drop C2

**Steganographic C2**: download an image via standard HTTP, then extract hidden data using LSB manipulation, appended data after EOF markers, or EXIF metadata. Pixel extraction via GDI+ (`GdipBitmapGetPixel`). **Multi-call + specialized content generation** — must return a valid image with correctly embedded steganographic payload matching the extraction algorithm. Turla (Instagram comments with Zero Width Joiner characters encoding C2 addresses), Gatak/Stegoloader (PNG with hidden shellcode, RC4 encrypted, CRC32 verified), Duqu (encrypted data appended to JPG), Vawtrak (URLs hidden in favicon LSBs), Lazarus (BMP-based payloads), OilRig, ScarCruft/APT37. WELL-DOCUMENTED.

**Dead drop resolvers**: HTTP request to legitimate service (Pastebin, GitHub, Twitter, Steam, Telegram, YouTube, blockchain) for encoded C2 address. Two-stage: (1) resolve dead drop, (2) connect to extracted C2. **Medium difficulty** — HTTP stack emulation + response containing properly encoded C2 address at expected position. Simpler than full C2 emulation since it's typically one-time address resolution. APT41 (GitHub, Pastebin, TechNet), Turla (Instagram), COBALT MIRAGE/Drokbk (GitHub), RTM (LiveJournal RSS), Kimsuky, Vidar 2.0 (Pastebin → GitHub → Telegram/Steam). WELL-DOCUMENTED.

### 8.6 Encrypted handshakes and certificate pinning

**Encrypted C2 handshakes** using BCrypt/CryptoAPI: `BCryptGenerateKeyPair` → `BCryptSecretAgreement` (ECDH) → `BCryptEncrypt` (AES) → `BCryptVerifySignature` (ECDSA). Emotet (current): ECDH + AES-256 + ECDSA. TrickBot: RSA + AES. Qakbot: RSA session establishment. NetWire: AES with 32-byte seed.

**Defeatability: effectively impossible without private keys.** The C2 server's response must be encrypted with the negotiated session key AND signed with the server's private key (whose public counterpart is embedded in the binary). **Partial workaround**: hook `BCryptDecrypt`/`CryptDecrypt` post-decryption to inject fake plaintext, but this breaks signature verification if checked subsequently.

**TLS certificate pinning** via Schannel: `AcquireCredentialsHandle → InitializeSecurityContext (repeated) → EncryptMessage/DecryptMessage`. Malware verifies the server certificate against a pinned hash. Without the corresponding private key, the TLS handshake cannot complete. IcedID pins self-signed certificates. Cobalt Strike uses JKS keystores.

**Defeatability: near-impossible** without the pinned certificate's private key. MitM proxies fail. WELL-DOCUMENTED.

---

## §9 Installed software and WMI-based meta-checks

Several families bypass API-level hooks by routing environment queries through **WMI**, which constitutes a secondary query channel that API interposition may not cover. McAfee Labs (2019) explicitly documents the migration from `GlobalMemoryStatusEx` to `Win32_ComputerSystem.TotalPhysicalMemory` WMI queries as a response to sandbox API hooking. SmokeLoader checks `SystemCodeIntegrityInformation` via `NtQuerySystemInformation` for unsigned driver policy (common in sandboxes). SUNBURST's entire environment validation is WMI-based with hashed blocklists. **This migration pattern suggests that API-response fuzzers must also instrument WMI query results**, not just Win32 API returns.

**Installed software enumeration** via `RegOpenKeyEx` on `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` + `RegEnumKeyEx` + `RegQueryValueEx` is **stateful multi-call** (iterative enumeration). Must maintain consistent registry state across Open/Enum/Query sequences. OilRig/OopsIE (Unit 42 2018), Beep (Minerva Labs 2023). WELL-DOCUMENTED.

---

## Defeatability spectrum — the core analytical axis

The table below classifies all 54 techniques into four tiers of defeatability, which directly maps to AriadneX's interposition strategy:

**Tier 1 — Single-call, trivially hookable (≈24 techniques):** Each gate opens by controlling one API's return value. The RL agent's action space is the set of possible return values for that single call. Includes: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess (3 classes at one hook point), NtQuerySystemInformation(KernelDebugger), GetThreadContext, CloseHandle exception, SetUnhandledExceptionFilter, FindWindow, GetModuleHandle, all registry VM checks, file presence checks, MAC OUI, GetSystemFirmwareTable, WMI queries (at provider level), CPUID, VMware IN backdoor, GetUserName, GetComputerName, language/locale APIs, GetSystemInfo, GlobalMemoryStatusEx, GetDiskFreeSpaceExW, GetSystemMetrics, GetSystemTime/GetLocalTime, single GetTickCount, GetCommandLine, GetEnvironmentVariable, InternetGetConnectedState, InternetCheckConnection, gethostbyname (simple), IcmpSendEcho, OpenMutex.

**Tier 2 — Multi-call with lightweight coordination (≈12 techniques):** Requires consistent responses across 2–5 API calls, but no complex protocol state. Includes: process enumeration (3-call or single NtQuerySystemInformation hook), parent process validation (2+ calls), OutputDebugString trick (3 calls, deprecated), DarkSide redundant locale checks (2–3 calls), DeviceIoControl disk (2 calls), screen resolution pair (2 calls), registry config (2 calls), mutex create+check (2 calls), uptime sleep-patch detection (3 calls), installed software enumeration (N calls), USB/wear-and-tear enumeration (N calls), file content reading (2+ calls).

**Tier 3 — Full protocol emulation required (≈8 techniques):** Requires a protocol-aware responder maintaining state across many API calls with semantically valid content. Includes: HTTP/HTTPS C2 via WinHTTP (6+ calls), HTTP/HTTPS C2 via WinINet (5+ calls), raw socket custom protocols (Gh0st, PlugX, Poison Ivy — 4+ calls with per-family binary protocol), DNS TXT C2 (stateful DNS responder), DGA resolution with validation (N calls + port probing), IP geolocation HTTP chain (5–7 calls), dead drop resolvers (5–7 calls), RDTSC timing (2 instructions, hard to intercept at API level).

**Tier 4 — Cryptographically infeasible without keys (≈4 techniques):** Even full protocol emulation fails because responses require the C2 server's private key for encryption, signing, or certificate presentation. Includes: encrypted C2 handshakes (ECDH/RSA + ECDSA verification — Emotet, TrickBot), TLS certificate pinning (Schannel + pinned public key — IcedID, Cobalt Strike), steganographic C2 (requires knowledge of extraction algorithm + encryption key per sample — Turla, Gatak). **Partial workaround**: hook post-decryption APIs (`BCryptDecrypt` output buffer) to inject fake plaintext, bypassing the crypto layer entirely.

**Tier 1∗ — Not hookable via any API (4 techniques):** Direct PEB memory reads (BeingDebugged, NtGlobalFlag, ProcessHeap flags) and INT 2D/INT 3 exception tricks bypass the API layer entirely. These require **memory patching or DBI instrumentation**, which PFuzzer addresses through its environment mutation approach.

### What this means for AriadneX

The RL agent's reward function and action space should be stratified by tier. For **Tier 1**, the action space is simply the set of possible return values for one API — the RL agent should learn the "correct" (non-evasive) response quickly. For **Tier 2**, the agent must learn to maintain consistency across a small set of related calls — representable as a small state machine in the response synthesizer. **Tier 3** represents the boundary where API-level fuzzing hits diminishing returns — a complementary approach using protocol-template libraries (indexed by malware family) would be more effective than pure RL exploration of the response space. **Tier 4** requires a fundamentally different strategy: hooking at the decryption output rather than the encrypted input, which transforms an infeasible problem into a Tier 1 problem (control the plaintext buffer written by `BCryptDecrypt`).

The most impactful research contribution would be demonstrating that RL-guided fuzzing can systematically discover **Tier 1 and Tier 2** gates across diverse families without prior knowledge of the specific checks — effectively learning what PEB flags, registry values, usernames, disk sizes, and cursor trajectories unlock hidden execution paths. The Enviral system (EuroSec 2023) demonstrated that fuzzing environment query outcomes reveals **39% more hidden activity** and **67% more productive explorations**, validating this approach.

---

## Key academic foundations

The following papers form the direct lineage for AriadneX's approach:

**PFuzzer** (Bottura, D'Elia, Querzoni, IEEE EuroS&P 2025) is the most directly relevant prior work — it IS coverage-guided API-response fuzzing for malware. Tested on 1,078 PE32 samples from 239+ families, revealing additional behaviors in **42.39%** (457 samples). Uses dual coverage feedback (observable actions + internal code coverage) with epoch-based environment mutation policies.

**Botacin (ACM DTRAP 2024)** provides the systematization of knowledge for multipath malware tracing, finding that fuzzing discovers more paths than symbolic execution, guided fuzzing increases coverage but limits diversity, and forced execution maximizes path discovery but sacrifices soundness.

**Lindorfer, Kolbitsch, Milani Comparetti (RAID 2011)** coined "environment-sensitive malware" and introduced DISARM, establishing multi-sandbox behavioral comparison as a detection methodology.

**Kirat, Vigna, Kruegel ("BareCloud," USENIX Security 2014)** established bare-metal analysis as ground truth, detecting 5,835 evasive samples from 110,005 by comparing behavior across emulation, virtualization, and bare-metal platforms.

**Miramirkhani et al. ("Spotless Sandboxes," IEEE S&P 2017)** introduced wear-and-tear artifacts as an evasion class fundamentally resistant to API-level interposition.

**Paleari et al. ("A Fistful of Red-Pills," WOOT 2009)** and **Martignoni et al. ("Testing CPU Emulators," ISSTA 2009)** demonstrated automated generation of CPU emulator detection procedures via differential testing, showing the fundamental difficulty of achieving perfect emulation transparency.

**Balzarotti et al. ("Efficient Detection of Split Personalities in Malware," NDSS 2010)** formalized the "split personality" concept — malware showing divergent behavior across environments.

**Afianian et al. (ACM CSUR 2019)** provides the most comprehensive published taxonomy of evasion techniques and explicitly recommends "path exploration techniques" as having potential to thwart all evasive tactics — directly supporting the AriadneX rationale.

**Bunino (MSc thesis, Politecnico di Torino, 2022)** is the closest existing work to RL-guided malware analysis, training an RL agent to interact with a debugger to find hidden behaviors. This is an unpublished thesis (Huawei internship), not peer-reviewed.

**MORRIGU** (Mills & Legg, MDPI J. Cybersecur. Priv. 2020) developed automated sandbox reconfiguration for testing anti-evasion configurations across 251 samples. Note: MORRIGU does **not** use reinforcement learning — it uses systematic configuration variation with visual analytics.

---

## Conclusion

The taxonomy reveals a sharp **phase transition in defeatability** between environment-local queries (Tiers 1–2) and network-mediated protocol exchanges (Tiers 3–4). Environment-local gates — debugger flags, VM artifacts, resource thresholds, locale checks, timestamps — are overwhelmingly stateless and single-call defeatable because they query fixed system state through well-defined API boundaries. An RL agent learning to set these return values is exploring a tractable, mostly discrete action space. The hardest environment-local gate is **user activity simulation** (cursor trajectories over time), which requires temporally consistent continuous-valued sequences — a natural fit for RL policy learning.

The phase transition occurs at the network boundary. C2 communication gating requires not just correct individual responses but **protocol-coherent multi-message exchanges** with structural, semantic, and cryptographic constraints. Tier 4 techniques (encrypted handshakes with ECDSA verification) represent a **cryptographic impossibility boundary** for response synthesis — no amount of fuzzing can produce a valid ECDSA signature without the private key. The practical workaround — hooking post-decryption rather than pre-encryption — collapses Tier 4 back to Tier 1 at the cost of requiring the malware to execute its own crypto routines first.

Three emergent patterns deserve attention: (1) **API migration** — malware authors are shifting from hookable Win32 APIs to WMI and Nt-level syscalls specifically to defeat API interposition, meaning AriadneX must instrument multiple query channels; (2) **check composition** — families like Furtim (400+ checks) and GravityRAT (7 orthogonal checks) combine many individually defeatable gates into conjunctive conditions, requiring the fuzzer to simultaneously satisfy all of them; (3) **hash-based opacification** — SUNBURST and FinSpy hash their blacklist entries (FNV-1A+XOR, MD5 respectively), preventing static analysis from revealing what values trigger the gate, making dynamic fuzzing the only viable discovery mechanism.