"""Offline tests for clew.eval.novelty (pure IoC extraction + novelty scoring).

The module is a reusable public helper but previously had zero coverage; these
lock in the core behavior and the asymmetric-dict fix (scout #16).
"""

from clew.eval.novelty import (
    IOC_CATEGORIES,
    extract_iocs,
    noise_filtered_novelty,
    novel_items,
    novelty_score,
)


def test_novelty_score_and_items_count_new():
    base = {"apis": {"a"}, "files_written": set()}
    mut = {"apis": {"a", "b"}, "files_written": {"x"}}
    assert novelty_score(base, mut) == {"apis": 1, "files_written": 1}
    assert novel_items(base, mut) == {"apis": {"b"}, "files_written": {"x"}}


def test_asymmetric_dicts_do_not_keyerror():
    # A category present in one dict but missing from the other must be treated
    # as empty, not raise KeyError (scout #16).
    base = {"apis": {"a"}, "files_written": {"y"}}
    assert novelty_score(base, {"apis": {"a", "b"}}) == {"apis": 1, "files_written": 0}
    assert novel_items(base, {}) == {"apis": set(), "files_written": set()}


def test_noise_filtered_novelty_asymmetric():
    persistent = {"apis": {"a"}}
    assert noise_filtered_novelty(persistent, {}, {}) == {"apis": 0}
    assert noise_filtered_novelty(persistent, {}, {"apis": {"a", "b"}}) == {"apis": 1}


def test_extract_iocs_tolerates_empty_and_none():
    out = extract_iocs({})
    assert set(out) == set(IOC_CATEGORIES)
    assert all(v == set() for v in out.values())
    assert extract_iocs({"behavior": None})["apis"] == set()
