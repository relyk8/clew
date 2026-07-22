"""
novelty.py — CAPE IoC extraction and novelty scoring.

    extract_iocs(report)  -> dict[str, set[str]]
        Collapses a CAPE JSON report into a fixed set of IoC categories.

    novelty_score(baseline, mutated) -> dict[str, int]
        For each category, counts items present in `mutated` but NOT in `baseline`.

Reusable for validating that Clew-extracted candidates actually unlock hidden
behavior when fed back to a fuzzer. Both functions are pure (no I/O).

Migrated from ariadneX.
"""

import re
from typing import Any

# The canonical category order. Keep this list in sync anywhere we enumerate
# IoC types (env observation shape, reward shaping, logging).
IOC_CATEGORIES = (
    "apis",
    "files_written",
    "keys_written",
    "commands",
    "mutexes",
    "services",
)


# Windows embeds session:PID:TID in SM0-style mutex names. These drift across
# every run, so we normalize them out. Pattern matches "SM0:4352:120:..." and
# leaves the stable suffix (WilError_03, WilStaging_02, etc) behind.
_MUTEX_SESSION_PID_TID = re.compile(r"SM\d+:\d+:\d+:")


def _normalize_mutex(name: str) -> str:
    return _MUTEX_SESSION_PID_TID.sub("SM*:*:*:", name)


def extract_iocs(report: dict[str, Any]) -> dict[str, set[str]]:
    """Reduce a CAPE report to comparable IoC sets.

    All lookups use `.get(..., default) or default` so that a missing key
    and a key explicitly set to `None` are both treated as empty — CAPE
    does both depending on analysis outcome.
    """
    behavior = report.get("behavior") or {}
    summary = behavior.get("summary") or {}
    processes = behavior.get("processes") or []

    apis: set[str] = set()
    for proc in processes:
        for call in proc.get("calls") or []:
            name = call.get("api")
            if name:
                apis.add(name)

    return {
        "apis": apis,
        "files_written": set(summary.get("write_files") or []),
        "keys_written": set(summary.get("write_keys") or []),
        "commands": set(summary.get("executed_commands") or []),
        "mutexes": {_normalize_mutex(m) for m in (summary.get("mutexes") or [])},
        "services": set(summary.get("created_services") or []),
    }


def novelty_score(baseline: dict[str, set[str]], mutated: dict[str, set[str]]) -> dict[str, int]:
    """Count new items per category: |mutated - baseline|.

    Symmetric difference is deliberately NOT used — we only care about
    behaviors the mutated run *surfaced* that the baseline did not.
    Behaviors the baseline had but mutation suppressed aren't novelty,
    they're regression, and they get a different signal later.
    """
    return {k: len(mutated[k] - baseline[k]) for k in baseline}


def novel_items(baseline: dict[str, set[str]], mutated: dict[str, set[str]]) -> dict[str, set[str]]:
    """Same as novelty_score but returns the actual novel elements.
    Useful for debugging / inspecting *what* is new, not just how many."""
    return {k: mutated[k] - baseline[k] for k in baseline}


def load_stable_baseline(path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Load a .stable.json produced by build_stable_baseline.py.

    Returns (persistent, volatile) as dicts of sets.
    """
    import json
    from pathlib import Path

    data = json.loads(Path(path).read_text())
    persistent = {k: set(v) for k, v in data["persistent"].items()}
    volatile = {k: set(v) for k, v in data["volatile"].items()}
    # Ensure all IOC_CATEGORIES keys exist even if empty
    for cat in IOC_CATEGORIES:
        persistent.setdefault(cat, set())
        volatile.setdefault(cat, set())
    return persistent, volatile


def noise_filtered_novelty(
    persistent: dict[str, set[str]], volatile: dict[str, set[str]], mutated: dict[str, set[str]]
) -> dict[str, int]:
    """Count items novel vs persistent baseline AND not already seen as volatile.

    persistent: items reliably present across baseline runs
    volatile:   items that appear in some baseline runs but not all (noise)
    mutated:    items from the mutated run under test

    An item counts as novel only if it was in neither set — genuinely new
    behavior surfaced by the mutation, not ambient Windows drift.
    """
    out = {}
    for k in persistent:
        known = persistent[k] | volatile[k]
        out[k] = len(mutated[k] - known)
    return out
