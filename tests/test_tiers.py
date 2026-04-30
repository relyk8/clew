"""Tier classification tests."""
from __future__ import annotations

from clew import tiers


def test_classify_tier_1():
    # check for debugger via API maps to {IsDebuggerPresent,
    # CheckRemoteDebuggerPresent, NtQueryInformationProcess} — all in Pfuzzer 68.
    tier, unmapped = tiers.classify(["check for debugger via API"])
    assert tier == "tier_1"
    assert unmapped == []


def test_classify_tier_2(monkeypatch):
    # Construct a mapped rule whose API set straddles the Pfuzzer 68 boundary.
    fake_rule = "fake mixed rule"
    inside_api = "IsDebuggerPresent"  # in PFUZZER_68_APIS
    outside_api = "NotInPfuzzer68_xyz"
    assert inside_api in tiers.PFUZZER_68_APIS
    assert outside_api not in tiers.PFUZZER_68_APIS

    new_map = dict(tiers.CAPA_RULE_TO_APIS)
    new_map[fake_rule] = frozenset({inside_api, outside_api})
    monkeypatch.setattr(tiers, "CAPA_RULE_TO_APIS", new_map)

    tier, unmapped = tiers.classify([fake_rule])
    assert tier == "tier_2"
    assert unmapped == []


def test_classify_tier_3_unmapped():
    tier, unmapped = tiers.classify(["totally invented rule name"])
    assert tier == "tier_3"
    assert unmapped == ["totally invented rule name"]


def test_classify_empty():
    tier, unmapped = tiers.classify([])
    assert tier == "tier_1"
    assert unmapped == []
