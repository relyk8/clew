"""Derivation-status classification tests.

`classify()` rolls up per-rule actionability into a sample-level label:
  fully_derivable    — all rules actionable
  partially_derivable — mix of actionable and not
  not_derivable      — no rules actionable (all unmapped, or all outside-target)
  no_capa_signal     — no rules at all

A rule is actionable iff it's mapped in CAPA_RULE_TO_APIS AND every
implied API is in PFUZZER_68_APIS.
"""

from __future__ import annotations

from clew import tiers


def test_classify_fully_derivable():
    # "check for debugger via API" maps to APIs all in Pfuzzer 68.
    status, unmapped = tiers.classify(["check for debugger via API"])
    assert status == "fully_derivable"
    assert unmapped == []


def test_classify_partially_derivable_mixed_mapped_unmapped():
    # A mapped rule + an unmapped rule = mix; should be partially_derivable.
    # (Earlier short-circuit would have demoted to tier_3; pre-rollup model
    # incorrectly promoted to fully_derivable. Correct answer is partial.)
    status, unmapped = tiers.classify(
        [
            "check for debugger via API",
            "totally invented rule name",
        ]
    )
    assert status == "partially_derivable"
    assert unmapped == ["totally invented rule name"]


def test_classify_partially_derivable_outside_target(monkeypatch):
    # Construct one fully-actionable rule + one mapped-but-outside-target
    # rule. Sample should be partially_derivable.
    outside_rule = "fake outside-target rule"
    new_map = dict(tiers.CAPA_RULE_TO_APIS)
    new_map[outside_rule] = frozenset({"NotInPfuzzer68_xyz"})
    monkeypatch.setattr(tiers, "CAPA_RULE_TO_APIS", new_map)

    status, unmapped = tiers.classify(
        [
            "check for debugger via API",
            outside_rule,
        ]
    )
    assert status == "partially_derivable"
    assert unmapped == []  # outside_rule is mapped, so not unmapped


def test_classify_not_derivable_all_unmapped():
    # Rules fired but none are mapped — actionable derivation work.
    status, unmapped = tiers.classify(["totally invented rule name"])
    assert status == "not_derivable"
    assert unmapped == ["totally invented rule name"]


def test_classify_not_derivable_all_outside_target(monkeypatch):
    # All rules mapped, but every implied API is outside the target list.
    outside_rule = "fake outside-only rule"
    new_map = dict(tiers.CAPA_RULE_TO_APIS)
    new_map[outside_rule] = frozenset({"NotInPfuzzer68_xyz"})
    monkeypatch.setattr(tiers, "CAPA_RULE_TO_APIS", new_map)

    status, unmapped = tiers.classify([outside_rule])
    assert status == "not_derivable"
    assert unmapped == []


def test_classify_no_capa_signal():
    # Empty input — no rules at all. Other-channel territory.
    status, unmapped = tiers.classify([])
    assert status == "no_capa_signal"
    assert unmapped == []


def test_classify_unmapped_list_is_sorted():
    status, unmapped = tiers.classify(["zzz rule", "aaa rule", "mmm rule"])
    assert status == "not_derivable"
    assert unmapped == ["aaa rule", "mmm rule", "zzz rule"]
