"""Tier classification from capa rule output.

Tier semantics (per docs/schema.md):
- tier_1: all implied APIs covered by Pfuzzer's 68
- tier_2: some inside, some outside
- tier_3: rule fired but no derivation logic (default for unmapped)
- tier_4: not capa-detectable (out of scope for this module)
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
    # TODO: map remaining rules from canonical list. For now, unmapped
    # rules trigger tier_3 via the default branch in classify().
}


def classify(rule_names: Iterable[str]) -> tuple[str, list[str]]:
    """Return (tier_classification, sorted list of unmapped rule names).

    Rules not in CAPA_RULE_TO_APIS are unmapped and force tier_3.
    Empty input: returns ("tier_1", []) — no evidence of evasion isn't
    a tier degradation signal at this layer; tier_4 is decided elsewhere.
    """
    rule_names = list(rule_names)
    unmapped = sorted(r for r in rule_names if r not in CAPA_RULE_TO_APIS)
    if unmapped:
        return ("tier_3", unmapped)

    if not rule_names:
        return ("tier_1", [])

    all_apis: set[str] = set()
    for r in rule_names:
        all_apis |= CAPA_RULE_TO_APIS[r]

    inside = all_apis & PFUZZER_68_APIS
    outside = all_apis - PFUZZER_68_APIS
    if outside and inside:
        return ("tier_2", [])
    if outside and not inside:
        return ("tier_2", [])
    return ("tier_1", [])
