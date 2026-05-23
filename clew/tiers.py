"""Derivation-status classification from capa rule output.

`derivation_status` answers: where is Clew's derivation pipeline with this
sample today? It is **not** a defeatability tier. The defeatability tier (a
property of an evasion technique) is the taxonomy concept used in
`docs/context/evasion-taxonomy.md` and surfaces per-candidate via the
schema's `evasion_tier` field.

Values:
- `fully_derivable`     at least one matched capa rule is in
                        CAPA_RULE_TO_APIS, AND every implied API is in
                        PFUZZER_68_APIS.
- `partially_derivable` at least one matched capa rule is mapped, AND at
                        least one implied API is outside PFUZZER_68_APIS.
                        Structurally empty under the current rule map.
- `no_mapped_signal`    no matched capa rule is in CAPA_RULE_TO_APIS
                        (covers both zero capa rules and only-unmapped
                        rules — both states mean Clew has no actionable
                        signal at this layer).
- `not_capa_detectable` decided outside this module (sample uses
                        techniques capa cannot detect). Never returned
                        by classify().

`classify()` no longer short-circuits on unmapped rules. The list of
unmapped rules is returned alongside the categorical so callers can act
on derivation backlog independently of the sample's classification.
"""
from __future__ import annotations

from typing import Iterable


# Empirically derived from Pfuzzer's public dataset (github.com/Sap4Sec/pfuzzer):
# every API surfaced in the "Mutations applied" section across all 1,078
# annotated samples, plus the canonical Windows-API members of the
# TimeDelayAPIs / TimeQueryAPIs meta-labels that Pfuzzer's trace output
# bundles. The paper (Sec 3.4) claims "a selection of 68 APIs counting
# A/E/ExA/ExW variants as one" — the literal symbol list is naturally
# larger when variants are split out.
#
# Notes:
# - CPUID and RDTSC are instructions, not APIs. Pfuzzer instruments them
#   via DBI but they don't belong in an API-name set.
# - IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess
#   are added because they are canonical anti-debug APIs covered by capa's
#   "check for debugger via API" rule and are routinely interposed by
#   Pfuzzer-class fuzzers (BluePill, Enviral) even when they don't show up
#   in this particular dataset's mutation logs.
# - GetModuleHandleA/W are added because they are the canonical anti-VM
#   string-fingerprint APIs that capa's "reference anti-VM strings" rule
#   family implies, and Pfuzzer-class fuzzers interpose on them.
PFUZZER_68_APIS: frozenset[str] = frozenset({
    # Anti-debug (canonical; covered by capa "check for debugger via API")
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    # Module / library lookup (canonical anti-VM string fingerprinting)
    "GetModuleHandleA",
    "GetModuleHandleW",
    # File system
    "CreateFileA",
    "CreateFileW",
    "NtCreateFile",
    "FindFirstFileA",
    "FindFirstFileW",
    "FindNextFileA",
    "FindNextFileW",
    "GetFileAttributesA",
    "GetFileAttributesW",
    "GetFileAttributesExA",
    "GetFileAttributesExW",
    "GetDiskFreeSpaceExA",
    "GetDiskFreeSpaceExW",
    "DeviceIoControl",
    # Module / process image
    "GetModuleFileNameA",
    "GetModuleFileNameW",
    "GetModuleFileNameExA",
    "GetModuleFileNameExW",
    "GetProcessImageFileNameA",
    "GetProcessImageFileNameW",
    "QueryFullProcessImageNameW",
    "K32GetModuleBaseNameA",
    "K32GetModuleBaseNameW",
    # User / system identity
    "GetUserNameA",
    "GetUserNameW",
    "GetUserNameExW",
    "GetComputerNameA",
    "GetComputerNameW",
    "GetComputerNameExA",
    "GetComputerNameExW",
    # Process enumeration
    "Process32First",
    "Process32FirstW",
    "Process32Next",
    "Process32NextW",
    # Window enumeration / fingerprinting
    "FindWindowA",
    "FindWindowW",
    "FindWindowExA",
    "FindWindowExW",
    "GetWindowTextA",
    "GetWindowTextW",
    "GetForegroundWindow",
    "GetCursorPos",
    # Registry
    "NtOpenKey",
    "NtQueryValueKey",
    "RegOpenKeyA",
    "RegOpenKeyW",
    "RegOpenKeyExA",
    "RegOpenKeyExW",
    "RegEnumKeyA",
    "RegEnumKeyW",
    "RegEnumKeyExA",
    "RegEnumKeyExW",
    "RegQueryValueExA",
    "RegQueryValueExW",
    "NtQueryDirectoryObject",
    "NtQuerySystemInformation",
    # Locale
    "GetSystemDefaultLCID",
    "GetUserDefaultLCID",
    "GetKeyboardLayout",
    # Hardware / system info
    "GetSystemInfo",
    "GetNativeSystemInfo",
    "GetSystemFirmwareTable",
    "GlobalMemoryStatusEx",
    "IsNativeVhdBoot",
    "SetupDiGetDeviceRegistryPropertyW",
    "EnumDisplayDevicesW",
    "IsProcessorFeaturePresent",
    "GetVolumeInformationA",
    "GetVolumeInformationW",
    # Networking / adapter info
    "GetAdaptersAddresses",
    "GetAdaptersInfo",
    "InternetGetConnectedState",
    "WNetGetProviderNameA",
    # Synchronization (used as VM/sandbox fingerprints via named mutexes)
    "CreateMutexA",
    "CreateMutexW",
    # Time query / delay (Pfuzzer trace label: TimeQueryAPIs / TimeDelayAPIs)
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "timeGetTime",
    "GetLocalTime",
    "GetSystemTime",
    "Sleep",
    "SleepEx",
})


CAPA_RULE_TO_APIS: dict[str, frozenset[str]] = {
    "check for debugger via API": frozenset({
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
    }),
    "check for time delay via GetTickCount": frozenset({
        "GetTickCount",
        "GetTickCount64",
    }),
    "find graphical window": frozenset({
        "FindWindowA",
        "FindWindowW",
        "FindWindowExA",
        "FindWindowExW",
    }),
    "reference analysis tools strings": frozenset(),
    "reference anti-VM strings": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting VMWare": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting VirtualBox": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting Qemu": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting Parallels": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting Xen": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting VirtualPC": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    # TODO: map remaining rules from canonical list. Unmapped rules surface
    # via the second return value of classify(); they no longer override the
    # categorical.
}


def classify(rule_names: Iterable[str]) -> tuple[str, list[str]]:
    """Return (derivation_status, sorted list of unmapped rule names).

    Behavior:
    - Splits `rule_names` into mapped vs unmapped against CAPA_RULE_TO_APIS.
    - If no rule is mapped, returns ("no_mapped_signal", unmapped). This
      covers both empty input and inputs that consist entirely of unmapped
      rules — in both cases Clew has no actionable signal at this layer.
    - Otherwise, unions the implied APIs of the mapped rules. If any API
      falls outside PFUZZER_68_APIS, returns "partially_derivable";
      otherwise "fully_derivable".
    - In all cases, the second return value is the sorted list of
      unmapped rule names — actionable derivation backlog, independent of
      the categorical.
    """
    rule_names = list(rule_names)
    unmapped = sorted(r for r in rule_names if r not in CAPA_RULE_TO_APIS)
    mapped = [r for r in rule_names if r in CAPA_RULE_TO_APIS]

    if not mapped:
        return ("no_mapped_signal", unmapped)

    all_apis: set[str] = set()
    for r in mapped:
        all_apis |= CAPA_RULE_TO_APIS[r]

    outside = all_apis - PFUZZER_68_APIS
    if outside:
        return ("partially_derivable", unmapped)
    return ("fully_derivable", unmapped)
