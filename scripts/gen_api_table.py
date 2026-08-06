#!/usr/bin/env python3
"""Generate the drtrace client's wrapped-API table from TARGET_ENV_APIS.

The Channel 3 DynamoRIO client wraps the same Windows APIs the pipeline treats
as environment-sensitive. That set lives in `clew/tiers.py` as Python; the client
is C and cannot read it. Rather than maintain the list twice and let the two
drift, this emits the C table from the Python set.

Run from the repo root; rerun after editing TARGET_ENV_APIS:

    python scripts/gen_api_table.py

`--check` exits non-zero if the committed header is stale, for CI or a
pre-commit hook.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HEADER_PATH = REPO_ROOT / "cape_packages" / "drtrace" / "api_table.h"

# Relative path shown in the generated banner, so a reader of the header knows
# what to rerun without guessing the layout.
GENERATOR = "scripts/gen_api_table.py"


def render(api_names: list[str]) -> str:
    """Render the C header for `api_names` (rendered in sorted order)."""
    lines = [
        "/* GENERATED FILE -- DO NOT EDIT BY HAND.",
        " *",
        f" * Regenerate with:  python {GENERATOR}",
        " * Source of truth:  clew/tiers.py TARGET_ENV_APIS",
        " *",
        " * The APIs drtrace wraps are exactly the APIs the pipeline treats as",
        " * environment-sensitive. Generating this table from the Python set keeps",
        " * the client and the pipeline from drifting apart.",
        " */",
        "",
        "#ifndef DRTRACE_API_TABLE_H",
        "#define DRTRACE_API_TABLE_H",
        "",
        f"#define DRTRACE_API_COUNT {len(api_names)}",
        "",
        "/* Sorted, so the table is stable across regenerations and a diff of this",
        " * file shows only genuine additions and removals. */",
        f"static const char *const drtrace_api_names[DRTRACE_API_COUNT] = {{",
    ]
    lines.extend(f'    "{name}",' for name in api_names)
    lines.extend(["};", "", "#endif /* DRTRACE_API_TABLE_H */", ""])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the committed header does not match the current set",
    )
    args = parser.parse_args()

    # Imported here rather than at module top: this is a dev script, and the
    # import only needs to work when it actually runs.
    sys.path.insert(0, str(REPO_ROOT))
    from clew.tiers import TARGET_ENV_APIS

    rendered = render(sorted(TARGET_ENV_APIS))

    if args.check:
        current = HEADER_PATH.read_text() if HEADER_PATH.exists() else ""
        if current != rendered:
            print(
                f"{HEADER_PATH.relative_to(REPO_ROOT)} is stale; "
                f"rerun `python {GENERATOR}`",
                file=sys.stderr,
            )
            return 1
        print(f"{HEADER_PATH.relative_to(REPO_ROOT)} is up to date")
        return 0

    HEADER_PATH.parent.mkdir(parents=True, exist_ok=True)
    HEADER_PATH.write_text(rendered)
    print(f"wrote {HEADER_PATH.relative_to(REPO_ROOT)} ({len(TARGET_ENV_APIS)} APIs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
