"""Channel 2 — Ghidra (open-source backend).

The Ghidra counterpart to `clew.channels.binaryninja`: call-site enumeration
(`callsites`) and the high-P-Code dataflow bridge (`dataflow`). Both produce the
*same* intermediate artifacts as the Binary Ninja backend (`CallSite` /
`BNCallSites` / `BridgedCallSite` / `BNDataflow`), so the downstream pipeline,
schema mapping and record format are unchanged by which backend ran.

Why a second backend: Binary Ninja is commercial and its Enterprise license
gates every static run. Ghidra is public-domain (NSA), so this backend is what
lets clew run for anyone. Ghidra reaches the API in-process via PyGhidra
(the officially supported CPython path since Ghidra 12.0, which replaced
Jython), NOT via the `analyzeHeadless` subprocess — in-process keeps the
one-analysis-shared-by-both-stages orchestration the BN backend already uses.

Imports are pure: the heavy `pyghidra` import happens lazily inside the
functions, never at module load, so importing this package pulls no JVM.

The shared artifact types are currently imported from the Binary Ninja package,
which is where they were first defined. They are backend-neutral in content
(nothing in `CallSite` or `BridgedCallSite` is BN-specific); hoisting them to a
backend-agnostic module is the next refactor and is a prerequisite for removing
the Binary Ninja backend entirely.
"""

from __future__ import annotations

from clew.channels.ghidra.callsites import (
    GHIDRA_PINS,
    GhidraAnalysisError,
    GhidraError,
    GhidraNotAvailableError,
    enumerate_with_program,
    run_ghidra_callsites,
)
from clew.channels.ghidra.dataflow import (
    bridge_with_program,
    run_ghidra_dataflow,
)

__all__ = [
    "GHIDRA_PINS",
    "GhidraAnalysisError",
    "GhidraError",
    "GhidraNotAvailableError",
    "enumerate_with_program",
    "run_ghidra_callsites",
    "bridge_with_program",
    "run_ghidra_dataflow",
]
