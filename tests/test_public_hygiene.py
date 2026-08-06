"""Guard: no private-audience content in the tracked tree.

This repository is public. Twice now, material written for an audience of one has
reached it -- internal review identifiers, a division of labour between a person
and an assistant, machine-specific paths, and status notes that had become false.
Both times it was found by an ad-hoc sweep long after the fact, and the second
time it arrived on a branch that had been cut *before* the first cleanup, so
nothing conflicted and nothing complained.

A one-time cleanup cannot prevent that. This test encodes the rules instead, so a
branch carrying any of it fails before it merges rather than after.

Every pattern below is here because it was actually found in this repository, not
because it might be. If a check fires on legitimate content, fix the wording or
narrow the pattern -- do not delete the rule.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

# This file necessarily contains every pattern it bans, so it excludes itself.
SELF = "tests/test_public_hygiene.py"


def tracked_files() -> list[str]:
    """Files git knows about. Build output and untracked scratch are irrelevant."""
    out = subprocess.run(
        ["git", "-C", str(REPO), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    return [f for f in out.stdout.splitlines() if f and f != SELF]


# (name, regex, why it is banned). The regexes are assembled from fragments so
# this file does not trip its own patterns when it is itself scanned by a grep.
BANNED = [
    (
        "agent/user workflow tags",
        r"\[" + "USER" + r"\]|\[" + "AGENT" + r"\]",
        "a division of labour between a person and an assistant means nothing to a reader",
    ),
    (
        "internal review identifiers",
        r"\b" + "scout" + r" #\d+",
        "finding IDs from a private audit document that no reader can consult",
    ),
    (
        "internal work-breakdown vocabulary",
        r"\b" + "Unit" + r" [0-9]\b",
        "the public docs define Channels 0-3; Units were never defined anywhere public",
    ),
    (
        "role placeholders",
        r"\b" + "Person" + r"\s+[AB]\b",
        "private project staffing",
    ),
    (
        "home directory paths",
        r"/home/[a-z][a-z0-9_-]*/",
        "machine-specific, and as a default it is a path only its author can use",
    ),
    (
        "private network addresses",
        r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\." + r"\d",
        "internal infrastructure",
    ),
    (
        "VM snapshot names",
        r"clean_" + r"drio|win10_" + r"dev|ch3-" + r"staging",
        "names that exist only on one analysis box",
    ),
    (
        "stale draft-status claims",
        r"COMPILE-" + "UNVERIFIED|" + r"FIRST " + "DRAFT",
        "these outlive the state they describe and end up asserting the opposite of the truth",
    ),
    (
        "references to private rule files",
        r"clew-" + r"(?:conventions|overview|status|run|channel-[0-9])",
        "notes kept outside the repository; a reader has nothing to open",
    ),
]


@pytest.mark.parametrize(("name", "pattern", "why"), BANNED, ids=[b[0] for b in BANNED])
def test_no_private_audience_content(name: str, pattern: str, why: str) -> None:
    rx = re.compile(pattern)
    offenders: list[str] = []
    for rel in tracked_files():
        path = REPO / rel
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if rx.search(line):
                offenders.append(f"  {rel}:{lineno}: {line.strip()[:100]}")

    assert not offenders, (
        f"\n\n{name} found in tracked files.\nWhy this is banned: {why}\n\n"
        + "\n".join(offenders[:25])
        + (f"\n  ... and {len(offenders) - 25} more" if len(offenders) > 25 else "")
        + "\n\nThis repository is public. Reword the content rather than silencing the check.\n"
    )
