"""CAPE task-status vocabulary, shared by the client and the CLI.

Dependency-free on purpose: `cli.py` imports this at module top, so it must not
drag in `requests` the way `client` does (see clew-conventions.md).

The values mirror CAPE's own definitions in `lib/cuckoo/core/data/task.py`; the
failure grouping mirrors `lib/cuckoo/common/web_utils.py`.
"""

from __future__ import annotations

# CAPE's three failure states. 'failed_reporting' belongs here even though a
# report never lands: the analysis itself ran, so its cmplog logs are on disk.
TERMINAL_FAILURE_STATUSES = frozenset(
    {"failed_analysis", "failed_processing", "failed_reporting"}
)

# A task is done -- it will not change status again -- in any of these.
# 'completed' is deliberately absent: it is mid-flight, still headed for
# processing and reporting.
TERMINAL_STATUSES = frozenset({"reported", *TERMINAL_FAILURE_STATUSES})
