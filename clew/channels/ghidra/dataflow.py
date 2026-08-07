"""Channel 2: the Ghidra high-P-Code dataflow bridge.

The Ghidra counterpart to `clew.channels.binaryninja.dataflow`, emitting the
same `BridgedCallSite` / `BNDataflow` artifact. Scope, confidence heuristics and
the FLOSS association rules are shared with that module rather than restated
here -- only the IL traversal differs.

Why high P-Code and not raw P-Code: raw P-Code is the direct lifting of machine
instructions, where a CALL has exactly one input (the target) and *no*
arguments -- the stack pushes are separate STORE ops. Only the decompiler's
refined "high" P-Code lifts arguments onto the call, and it is in SSA form
(Ghidra's `heritage` action performs the SSA construction). So high P-Code is
the structural equivalent of Binary Ninja's MLIL-SSA.

Two differences from the MLIL-SSA backend drive the shape of this module:

  * The def edge lives on the varnode. `varnode.getDef()` replaces the BN
    backend's `get_ssa_var_definition(var)` lookup and the version-compatibility
    helper around it.
  * High P-Code is *lower level* than MLIL, which hides register/stack detail
    behind variables. Ghidra retains COPY / CAST / SUBPIECE / INDIRECT /
    PTRSUB / PTRADD chains, so `_resolve` handles more opcodes than its MLIL
    counterpart to reach the same constants.

There is also one capability lost. Binary Ninja exposes its own constant-folded
value for an expression (`expr.value`), which the MLIL backend uses as a fast
path to catch pointers spilled to a stack slot and reloaded. Ghidra has no
equivalent; its decompiler propagates many of those constants directly onto the
call, and the rest are reached by the LOAD/COPY handling below.

Parameter-index caution: `op.getInput(i + 1)` is the *decompiler-recovered*
i-th argument, which aligns with the real API parameter index only when Ghidra
knows the callee's prototype. It does for anything in Ghidra's bundled Windows
type archives (validated: CreateFileW recovers 7 arguments, RegOpenKeyExW 5,
GetModuleHandleW 1). It does not for APIs absent from those archives, nor for
GetProcAddress-resolved indirect calls, which typically recover no arguments at
all. Those call sites yield an unresolved record -- the Channel 3 work list --
rather than a value read from a misaligned index.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from clew.channels.binaryninja.callsites import BNCallSites, CallSite
from clew.channels.binaryninja.dataflow import (
    CHANNEL_BN,
    CONF_OBFUSCATED_ASSOC,
    CONF_UNRESOLVED,
    MAX_ARRAY_ELEMENTS,
    MAX_TRACE_DEPTH,
    SOURCE_STATIC,
    BNDataflow,
    BridgedCallSite,
    FlossIndex,
    _Finding,
    _match_obfuscated,
    _score_static,
)
from clew.channels.ghidra import _api

__all__ = [
    "bridge_with_program",
    "run_ghidra_dataflow",
    "resolve_constants",
]


def run_ghidra_dataflow(
    call_sites: BNCallSites,
    sample: str | Path,
    *,
    floss_index: Optional[FlossIndex] = None,
) -> BNDataflow:
    """Open `sample` with Ghidra and bridge `call_sites` (standalone path)."""
    from clew.channels.ghidra.callsites import open_program

    sample = Path(sample)
    with open_program(sample) as program:
        with _api.Decompiler(program) as decompiler:
            bridged = bridge_with_program(
                program, call_sites, floss_index, decompiler=decompiler
            )
    return BNDataflow(
        sample_path=str(sample),
        sample_sha256=call_sites.sample_sha256,
        bn_core_version=f"ghidra {_api.ghidra_version()}",
        bridged=bridged,
    )


def bridge_with_program(
    program,
    call_sites: BNCallSites,
    floss_index: Optional[FlossIndex] = None,
    *,
    decompiler: Optional[_api.Decompiler] = None,
) -> list[BridgedCallSite]:
    """Bridge against an already-open, already-analysed Program.

    The orchestrator entry point, mirroring
    `binaryninja.dataflow.bridge_with_view`. Pass the same `decompiler` used
    for enumeration so its HighFunction cache is shared: a caller function
    usually holds several call sites, and re-decompiling per site is the
    dominant cost on this backend.
    """
    floss = floss_index or FlossIndex.empty()
    owned = decompiler is None
    decompiler = decompiler or _api.Decompiler(program)
    try:
        bridged: list[BridgedCallSite] = []
        for call_site in call_sites.schema_emittable():
            try:
                bridged.extend(_bridge_call_site(program, call_site, floss, decompiler))
            except Exception as exc:  # noqa: BLE001 - one bad site must not sink the run
                bridged.append(_unresolved(call_site, parameter_index=-1))
                _warn(
                    f"bridge failed at {call_site.api_name}"
                    f"@0x{call_site.call_site_va:08x}: {exc}"
                )
        return bridged
    finally:
        if owned:
            decompiler.close()


def _bridge_call_site(program, cs: CallSite, floss: FlossIndex, decompiler):
    function = program.getFunctionManager().getFunctionAt(
        _api.to_address(program, cs.function_va)
    )
    if function is None:
        return [_unresolved(cs, parameter_index=-1)]

    high = decompiler.high_function(function)
    if high is None:
        # Decompilation failed or timed out; the call site is still real.
        return [_unresolved(cs, parameter_index=-1)]

    call_address = _api.to_address(program, cs.call_site_va)
    op = _api.find_call_op(high, call_address)
    if op is None:
        return [_unresolved(cs, parameter_index=-1)]

    count = _api.argument_count(op)
    if count == 0:
        # No prototype for the callee: indices would be guesses. Channel 3's job.
        return [_unresolved(cs, parameter_index=-1)]

    results: list[BridgedCallSite] = []
    for index in range(count):
        argument = _api.call_argument(op, index)
        traced = _trace_argument(program, argument, floss, cs.function_va)
        if not traced:
            continue
        path, findings = traced
        path_vas = tuple(sorted(set(path) | {cs.call_site_va}))
        for finding in findings:
            results.append(
                BridgedCallSite(
                    api_name=cs.api_name,
                    call_site_va=cs.call_site_va,
                    function_va=cs.function_va,
                    api_resolution=cs.api_resolution,
                    parameter_index=index,
                    value=finding.value,
                    string_source=finding.string_source,
                    string_va=finding.string_va,
                    string_function_va=finding.string_function_va,
                    dataflow_path=path_vas,
                    source_channels=finding.channels,
                    confidence=finding.confidence,
                    resolved=True,
                )
            )

    if not results:
        return [_unresolved(cs, parameter_index=-1)]
    return results


def _unresolved(cs: CallSite, *, parameter_index: int) -> BridgedCallSite:
    return BridgedCallSite(
        api_name=cs.api_name,
        call_site_va=cs.call_site_va,
        function_va=cs.function_va,
        api_resolution=cs.api_resolution,
        parameter_index=parameter_index,
        value=None,
        string_source=None,
        string_va=None,
        string_function_va=None,
        dataflow_path=(cs.call_site_va,),
        source_channels=(CHANNEL_BN,),
        confidence=CONF_UNRESOLVED,
        resolved=False,
    )


# --- the backward walk -------------------------------------------------------


def _trace_argument(program, varnode, floss: FlossIndex, function_va: int):
    """Walk one argument back to its source(s).

    Returns None when nothing is statically recoverable, else
    (path:list[int], findings:list[_Finding]).
    """
    if varnode is None:
        return None
    path: list[int] = []
    findings = _resolve(program, varnode, floss, function_va, 0, path, set())
    if not findings:
        return None
    return (path, findings)


def _resolve(program, varnode, floss, function_va, depth, path, visited) -> list[_Finding]:
    """_Finding list for `varnode` (empty when unresolved)."""
    from ghidra.program.model.pcode import PcodeOp

    if varnode is None or depth > MAX_TRACE_DEPTH:
        return []

    # A constant operand: the pointer value itself. This is where the great
    # majority of static string arguments land, because Ghidra's decompiler
    # propagates the constant onto the call.
    if varnode.isConstant():
        return _findings_for_pointer(program, varnode.getOffset(), floss)

    # A global variable location. Reading a string *at* that address covers the
    # case where the string is stored inline in the global rather than behind a
    # pointer; a non-string global simply yields nothing.
    if varnode.isAddress():
        return _findings_for_pointer(program, varnode.getAddress().getOffset(), floss)

    key = _varnode_key(varnode)
    if key in visited:
        return []
    visited.add(key)

    definition = varnode.getDef()
    if definition is None:
        # No definition in this function: a caller parameter or register
        # live-in. Inter-procedural tracing is out of v1 scope, so if the
        # varnode is a stack location fall back to FLOSS association, else
        # report unresolved for Channel 3.
        if _is_stack_varnode(varnode):
            return _floss_association(function_va, floss)
        return []

    path.append(definition.getSeqnum().getTarget().getOffset())
    opcode = definition.getOpcode()

    # Pass-through ops. MLIL hides these behind variables; P-Code does not, so
    # following input 0 is what keeps the two backends reaching the same source.
    # INDIRECT models a call's side effect on a location and is followed the
    # same way.
    if opcode in (
        PcodeOp.COPY,
        PcodeOp.CAST,
        PcodeOp.INT_ZEXT,
        PcodeOp.INT_SEXT,
        PcodeOp.SUBPIECE,
        PcodeOp.INDIRECT,
    ):
        return _resolve(
            program, definition.getInput(0), floss, function_va, depth + 1, path, visited
        )

    # MULTIEQUAL is P-Code's phi. Try each incoming version on its own copy of
    # the path and commit the first that yields anything, matching the MLIL
    # backend's phi policy (and sharing its v1 limitation: one branch wins).
    if opcode == PcodeOp.MULTIEQUAL:
        for index in range(definition.getNumInputs()):
            branch = list(path)
            found = _resolve(
                program, definition.getInput(index), floss, function_va, depth + 1, branch, visited
            )
            if found:
                path[:] = branch
                return found
        return []

    # PTRSUB(base, offset) is Ghidra's "address of": a global when both sides
    # are constant, a stack buffer when the base is the frame pointer. A stack
    # buffer is obfuscated-string territory -- hand it to FLOSS.
    if opcode == PcodeOp.PTRSUB:
        base, offset = definition.getInput(0), definition.getInput(1)
        if base is not None and offset is not None:
            if base.isConstant() and offset.isConstant():
                return _findings_for_pointer(
                    program, base.getOffset() + offset.getOffset(), floss
                )
            if _is_stack_varnode(base):
                return _floss_association(function_va, floss)
        return []

    # PTRADD(base, index, element_size) is array indexing -- the
    # GetModuleHandleW(names[i]) indicator-array idiom.
    if opcode == PcodeOp.PTRADD:
        return _resolve_array(program, definition, floss, function_va, depth, path, visited)

    if opcode == PcodeOp.INT_ADD:
        left, right = definition.getInput(0), definition.getInput(1)
        if left is not None and right is not None:
            if left.isConstant() and right.isConstant():
                return _findings_for_pointer(
                    program, left.getOffset() + right.getOffset(), floss
                )
        return []

    # A load: resolve the address being loaded from. Input 0 is the address
    # space id, input 1 the address.
    if opcode == PcodeOp.LOAD:
        return _resolve(
            program, definition.getInput(1), floss, function_va, depth + 1, path, visited
        )

    # A call return value or opaque arithmetic. Not a failure -- this is
    # precisely the evidence that the call site needs Channel 3.
    return []


def _resolve_array(program, definition, floss, function_va, depth, path, visited) -> list[_Finding]:
    """Enumerate a statically-initialised pointer array indexed at a call site.

    A constant index selects one element; a loop variable index cannot be
    pinned to one element, so the whole run is emitted -- one _Finding per
    element, which collapses downstream into a single candidate carrying every
    value the loop could supply.
    """
    base, index = definition.getInput(0), definition.getInput(1)
    element_size = definition.getInput(2)

    base_values = _resolve(program, base, floss, function_va, depth + 1, path, visited)
    # Reuse the resolver only for the *address*; if the base itself read as a
    # string the array interpretation does not apply.
    if base_values:
        return base_values

    base_address = _constant_of(base)
    if base_address is None:
        return []
    stride = _constant_of(element_size) or _api.pointer_size(program)
    constant_index = _constant_of(index)

    if constant_index is not None:
        pointer = _read_pointer(program, base_address + constant_index * stride)
        if pointer is None:
            return []
        return _findings_for_pointer(program, pointer, floss)

    findings: list[_Finding] = []
    for slot in range(MAX_ARRAY_ELEMENTS):
        pointer = _read_pointer(program, base_address + slot * stride)
        if not pointer:
            break  # a null or unreadable slot ends the run
        found = _findings_for_pointer(program, pointer, floss)
        if not found:
            break
        findings.extend(found)
    return findings


def _findings_for_pointer(program, offset: int, floss: FlossIndex) -> list[_Finding]:
    """A static-string _Finding for a recovered pointer, if it reads as one.

    A constant that is not a string yields nothing: numeric comparison operands
    are Channel 3 territory, not a value this bridge should invent.
    """
    if not offset:
        return []
    found = _api.read_string_at(program, offset)
    if not found:
        return []
    value = found[0]
    channels, confidence = _score_static(value, floss)
    return [
        _Finding(
            value=value,
            string_source=SOURCE_STATIC,
            string_va=offset,
            string_function_va=None,
            channels=channels,
            confidence=confidence,
        )
    ]


def _floss_association(function_va: int, floss: FlossIndex) -> list[_Finding]:
    """Associate a stack buffer with FLOSS's obfuscated output for this function."""
    matched = _match_obfuscated(function_va, floss)
    if matched is None:
        return []
    value, source = matched
    return [
        _Finding(
            value=value,
            string_source=source,
            string_va=None,
            string_function_va=function_va,
            channels=(CHANNEL_BN, "floss"),
            confidence=CONF_OBFUSCATED_ASSOC,
        )
    ]


# --- small helpers -----------------------------------------------------------


def resolve_constants(program, varnode) -> list[int]:
    """Backward-walk `varnode` to the constant integers that reach it.

    The value-free half of `_resolve`, used by enumeration to read a
    GetProcAddress name argument without needing a FLOSS index.
    """
    path: list[int] = []
    findings = _resolve(program, varnode, FlossIndex.empty(), 0, 0, path, set())
    return [f.string_va for f in findings if f.string_va is not None]


def _constant_of(varnode) -> Optional[int]:
    try:
        if varnode is not None and varnode.isConstant():
            return int(varnode.getOffset())
    except Exception:  # noqa: BLE001
        pass
    return None


def _read_pointer(program, offset: int) -> Optional[int]:
    """Read one pointer-sized little-endian word at `offset`."""
    address = _api.to_address(program, offset)
    if address is None:
        return None
    size = _api.pointer_size(program)
    try:
        memory = program.getMemory()
        value = 0
        for i in range(size):
            byte = memory.getByte(address.add(i)) & 0xFF
            value |= byte << (8 * i)
        return value
    except Exception:  # noqa: BLE001 - unmapped slot ends the array run
        return None


def _varnode_key(varnode):
    """A hashable identity for cycle detection over the SSA graph."""
    try:
        return (str(varnode.getAddress()), int(varnode.getSize()), int(varnode.getUniqueId()))
    except Exception:  # noqa: BLE001
        return id(varnode)


def _is_stack_varnode(varnode) -> bool:
    try:
        if varnode is None:
            return False
        address = varnode.getAddress()
        return bool(address is not None and address.isStackAddress())
    except Exception:  # noqa: BLE001
        return False


def _warn(message: str) -> None:
    import logging

    logging.getLogger("clew.channels.ghidra.dataflow").warning("%s", message)
