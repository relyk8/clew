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


# TODO: populate from Pfuzzer paper Table N (cite source).
# Starter set of obvious entries; expand during week 9 derivation work.
PFUZZER_68_APIS: frozenset[str] = frozenset({
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "GetModuleHandleA",
    "GetModuleHandleW",
    "GetProcAddress",
    "FindWindowA",
    "FindWindowW",
    "FindWindowExA",
    "FindWindowExW",
    "GetSystemInfo",
    "GetNativeSystemInfo",
    "IsProcessorFeaturePresent",
    "GlobalMemoryStatusEx",
    "GetCursorPos",
    "GetForegroundWindow",
    # TODO: complete from Pfuzzer Table N
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
