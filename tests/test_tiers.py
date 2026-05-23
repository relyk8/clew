"""Derivation-status classification tests.

The renamed function (`classify`) returns derivation_status, not tier.
Status values: fully_derivable / partially_derivable / no_mapped_signal.
`not_capa_detectable` is decided outside this module and never produced
by classify().
"""
from __future__ import annotations

from clew import tiers


def test_classify_fully_derivable():
    # "check for debugger via API" maps to {IsDebuggerPresent,
    # CheckRemoteDebuggerPresent, NtQueryInformationProcess} — all in Pfuzzer 68.
    status, unmapped = tiers.classify(["check for debugger via API"])
    assert status == "fully_derivable"
    assert unmapped == []


def test_classify_partially_derivable(monkeypatch):
    # Construct a mapped rule whose API set straddles the Pfuzzer-68 boundary.
    fake_rule = "fake mixed rule"
    inside_api = "IsDebuggerPresent"  # in PFUZZER_68_APIS
    outside_api = "NotInPfuzzer68_xyz"
    assert inside_api in tiers.PFUZZER_68_APIS
    assert outside_api not in tiers.PFUZZER_68_APIS

    new_map = dict(tiers.CAPA_RULE_TO_APIS)
    new_map[fake_rule] = frozenset({inside_api, outside_api})
    monkeypatch.setattr(tiers, "CAPA_RULE_TO_APIS", new_map)

    status, unmapped = tiers.classify([fake_rule])
    assert status == "partially_derivable"
    assert unmapped == []


def test_classify_only_unmapped_rules():
    status, unmapped = tiers.classify(["totally invented rule name"])
    assert status == "no_mapped_signal"
    assert unmapped == ["totally invented rule name"]


def test_classify_empty():
    status, unmapped = tiers.classify([])
    assert status == "no_mapped_signal"
    assert unmapped == []


def test_classify_mapped_plus_unmapped_no_short_circuit():
    # Critical behavior check: an unmapped rule must NOT override the
    # categorical when the sample also has a mapped rule. The mapped rule
    # implies in-target APIs, so the sample is fully_derivable; the unmapped
    # rule lives in the second return value as derivation backlog.
    status, unmapped = tiers.classify([
        "check for debugger via API",
        "totally invented rule name",
    ])
    assert status == "fully_derivable"
    assert unmapped == ["totally invented rule name"]


def test_classify_unmapped_list_is_sorted():
    status, unmapped = tiers.classify(["zzz rule", "aaa rule", "mmm rule"])
    assert status == "no_mapped_signal"
    assert unmapped == ["aaa rule", "mmm rule", "zzz rule"]
