"""Channel 2 — Binary Ninja.

Unit 3 (call-site enumeration, `callsites`) and Unit 4 (MLIL-SSA dataflow
bridge, `dataflow`) form one channel and live together here. Both re-exported so
callers can `from clew.channels.binaryninja import enumerate_with_view,
bridge_with_view`. Imports are pure (heavy `binaryninja` is imported lazily
inside the functions, never at module load), so importing this package pulls no
heavy dependency.
"""

from __future__ import annotations

from clew.channels.binaryninja.callsites import (
    BN_PINS,
    BNAnalysisError,
    BNCallSites,
    BNError,
    BNNotAvailableError,
    CallSite,
    enumerate_with_view,
    load_bn_results,
    run_bn_callsites,
)
from clew.channels.binaryninja.dataflow import (
    BNDataflow,
    BridgedCallSite,
    DataflowError,
    FlossIndex,
    bridge_with_view,
    load_dataflow_results,
    run_bn_dataflow,
)

__all__ = [
    "BN_PINS",
    "BNAnalysisError",
    "BNCallSites",
    "BNError",
    "BNNotAvailableError",
    "CallSite",
    "enumerate_with_view",
    "load_bn_results",
    "run_bn_callsites",
    "BNDataflow",
    "BridgedCallSite",
    "DataflowError",
    "FlossIndex",
    "bridge_with_view",
    "load_dataflow_results",
    "run_bn_dataflow",
]
