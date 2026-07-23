"""Derivation-status classification from capa rule output.

`derivation_status` answers: where is Clew's derivation pipeline with this
sample today? It is **not** a defeatability tier. The defeatability tier (a
property of an evasion technique) is the taxonomy concept that surfaces
per-candidate via the schema's `evasion_tier` field.

Rollup model: per-rule actionability decides the sample's categorical.
A rule is "actionable" iff it is in CAPA_RULE_TO_APIS AND all its implied
APIs are in TARGET_ENV_APIS. Sample-level rollup:

- `fully_derivable`     ≥1 matched rule, every matched rule is actionable
- `partially_derivable` ≥1 matched rule is actionable AND ≥1 is not
- `not_derivable`       ≥1 matched rule, no matched rules are actionable
                        (covers all-unmapped, all-outside-target, or mix
                        of those two failure modes)
- `no_capa_signal`      no matched rules at all (zero anti-analysis rules
                        fired). Also assigned outside this module to
                        samples where capa didn't successfully complete
                        (timeouts, capa errors) — same operational
                        outcome: no usable capa signal.

Every sample lands in exactly one bucket. The four values partition the
sample space cleanly with no overlap.

`classify()` does not short-circuit. The list of unmapped rules is
returned alongside the categorical so callers can size derivation
backlog independently of the sample's classification.
"""

from __future__ import annotations

from typing import Iterable

# Empirically derived from a public environmental-fuzzing dataset: every API
# surfaced in the "Mutations applied" section across all 1,078 annotated
# samples, plus the canonical Windows-API members of the TimeDelayAPIs /
# TimeQueryAPIs meta-labels that the source's trace output bundles. The source
# work claims "a selection of 68 APIs counting A/E/ExA/ExW variants as one".
# The literal symbol list is naturally larger when variants are split out.
#
# Coverage note: this set has 55 base APIs (counting variants as one) vs. the
# source's claimed 68. The 13-API gap is unrecoverable from the public
# materials, since the implementation source is not published and the 68 trace
# to prior work (BluePill / D'Elia 2020, Enviral / Gorter 2023) without an
# inline list. The dataset can only surface APIs that at least one sample
# actually called. APIs hooked but never triggered in the 1,078 samples will
# not appear here. Closing the gap is deferred v2 work. See the BluePill /
# Enviral papers if needed.
#
# Notes:
# - CPUID and RDTSC are instructions, not APIs. The source tool instruments
#   them via DBI but they don't belong in an API-name set.
# - IsDebuggerPresent / CheckRemoteDebuggerPresent / NtQueryInformationProcess
#   are added because they are canonical anti-debug APIs covered by capa's
#   "check for debugger via API" rule and are routinely interposed by
#   environmental fuzzers (BluePill, Enviral) even when they don't show up
#   in this particular dataset's mutation logs.
# - GetModuleHandleA/W are added because they are the canonical anti-VM
#   string-fingerprint APIs that capa's "reference anti-VM strings" rule
#   family implies, and environmental fuzzers interpose on them.
TARGET_ENV_APIS: frozenset[str] = frozenset(
    {
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
        # Time query / delay (source trace label: TimeQueryAPIs / TimeDelayAPIs)
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "timeGetTime",
        "GetLocalTime",
        "GetSystemTime",
        "Sleep",
        "SleepEx",
    }
)


CAPA_RULE_TO_APIS: dict[str, frozenset[str]] = {
    "check for debugger via API": frozenset(
        {
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
        }
    ),
    "check for time delay via GetTickCount": frozenset(
        {
            "GetTickCount",
            "GetTickCount64",
        }
    ),
    "find graphical window": frozenset(
        {
            "FindWindowA",
            "FindWindowW",
            "FindWindowExA",
            "FindWindowExW",
        }
    ),
    "reference analysis tools strings": frozenset(),
    "reference anti-VM strings": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting VMWare": frozenset(
        {"GetModuleHandleA", "GetModuleHandleW"}
    ),
    "reference anti-VM strings targeting VirtualBox": frozenset(
        {"GetModuleHandleA", "GetModuleHandleW"}
    ),
    "reference anti-VM strings targeting Qemu": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting Parallels": frozenset(
        {"GetModuleHandleA", "GetModuleHandleW"}
    ),
    "reference anti-VM strings targeting Xen": frozenset({"GetModuleHandleA", "GetModuleHandleW"}),
    "reference anti-VM strings targeting VirtualPC": frozenset(
        {"GetModuleHandleA", "GetModuleHandleW"}
    ),
    # TODO: map remaining rules from canonical list. Unmapped rules surface
    # via the second return value of classify(); they no longer override the
    # categorical.
}


def _rule_is_actionable(rule: str) -> bool:
    """True iff the rule is mapped to ≥1 API AND all implied APIs are in target list.

    An empty mapping (e.g. ``reference analysis tools strings``) means the
    rule fires on static features with no specific API to fuzz, so there is
    nothing to emit for the downstream fuzzer and the rule is not actionable.
    """
    if rule not in CAPA_RULE_TO_APIS:
        return False
    implied = CAPA_RULE_TO_APIS[rule]
    if not implied:
        return False
    return not (implied - TARGET_ENV_APIS)


def classify(rule_names: Iterable[str]) -> tuple[str, list[str]]:
    """Return (derivation_status, sorted list of unmapped rule names).

    Per-rule actionability rollup:
    - Every matched rule is actionable → "fully_derivable"
    - Mix of actionable and not-actionable rules → "partially_derivable"
    - No matched rules are actionable → "not_derivable"
    - No matched rules at all (empty input) → "no_capa_signal"

    The unmapped-rule list is returned alongside the categorical for
    sizing derivation backlog. Note: a rule can be not-actionable for two
    reasons (unmapped, or mapped with APIs outside TARGET_ENV_APIS); only
    the unmapped subset is reported here.
    """
    rule_names = list(rule_names)
    unmapped = sorted(r for r in rule_names if r not in CAPA_RULE_TO_APIS)

    if not rule_names:
        return ("no_capa_signal", [])

    actionable_count = sum(1 for r in rule_names if _rule_is_actionable(r))
    total = len(rule_names)

    if actionable_count == 0:
        return ("not_derivable", unmapped)
    if actionable_count == total:
        return ("fully_derivable", unmapped)
    return ("partially_derivable", unmapped)
