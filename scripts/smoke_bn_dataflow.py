#!/usr/bin/env python
"""Live Binary Ninja smoke test for Channel 2 / Unit 4 (the dataflow bridge).

This is the one piece the offline suite cannot cover: the MLIL-SSA walk needs
a real, analysed BinaryView. Point it at a fixture that contains a known
environment check -- the Day-7 al-khaser sample works, since al-khaser's
Sandboxie check is GetModuleHandle(_T("SbieDll.dll")).

    source bn_env.sh                       # so the Enterprise license checks out
    python scripts/smoke_bn_dataflow.py FIXTURE [TARGET_API] [EXPECT_SUBSTR] [--floss FLOSS_JSON]

    e.g.  python scripts/smoke_bn_dataflow.py fixtures/al-khaser.exe \\
              GetModuleHandleW SbieDll --floss tests/fixtures/al-khaser_x86.floss.json

What it validates, layer by layer (each printed so a failure localises):
    1. BN loads + analyses the fixture, core version == BN_PINS.
    2. Unit 3 enumerates the target call site(s)      -> input to the bridge.
    3. Unit 4 locates the SSA call, walks the argument -> value + dataflow_path.
    4. The recovered value matches the expected string.

This uses the standalone entry points (each opens its own view) for
simplicity. The production path is the single-view orchestrator call:
    bv = binaryninja.load(sample); bv.update_analysis_and_wait()
    cs = <enumerate on bv>; bridged = dataflow.bridge_with_view(bv, cs, floss)
"""

from __future__ import annotations

import sys

from clew.analysis import dataflow
from clew.channels import bn_callsites
from clew.channels.bn_callsites import BN_PINS


def _hexpath(vas) -> str:
    return "[" + ", ".join(hex(v) for v in vas) + "]"


def main() -> int:
    argv = sys.argv[1:]
    floss_path = None
    if "--floss" in argv:
        i = argv.index("--floss")
        floss_path = argv[i + 1] if i + 1 < len(argv) else None
        del argv[i : i + 2]
    if not argv:
        print(__doc__)
        return 2
    sample = argv[0]
    target_api = argv[1] if len(argv) > 1 else "GetModuleHandleW"
    expect = argv[2] if len(argv) > 2 else None

    # 1) Unit 3 against the fixture (opens + analyses its own view + checks out).
    print(f"[*] Unit 3: enumerating call sites in {sample} ...")
    cs = bn_callsites.run_bn_callsites(sample, run_license_checkout=True)
    core = cs.bn_core_version
    pin = BN_PINS.get("core_version")
    tag = "== pinned" if core.split()[0] == pin else f"!= pinned {pin} (re-validate BN_PINS)"
    print(f"[+] BN core {core} {tag}")
    print(
        f"[+] {len(cs.call_sites)} total call sites; {len(cs.schema_emittable())} schema-emittable"
    )

    targets = cs.for_api(target_api)
    if not targets:
        print(
            f"[FAIL] Unit 3 found no call sites to {target_api}. "
            f"Nothing for the bridge to work on. APIs present include: "
            f"{sorted(list(cs.api_names()))[:15]} ..."
        )
        return 1
    for s in targets:
        print(
            f"      {target_api}  call_site=0x{s.call_site_va:08x}  "
            f"func=0x{s.function_va:08x}  res={s.api_resolution}"
        )

    # 2) Unit 4 bridge (standalone entry point; re-opens the view).
    floss_index = None
    if floss_path:
        floss_index = dataflow.FlossIndex.from_floss_json(floss_path)
        print(
            f"[*] Unit 4: bridging WITH FLOSS index from {floss_path} "
            f"({len(floss_index.static_values)} static values, "
            f"{len(floss_index.obfuscated_by_function)} obfuscated functions) ..."
        )
    else:
        print("[*] Unit 4: bridging (no FLOSS index -> BN-only static strings) ...")
    df = dataflow.run_bn_dataflow(cs, sample, floss_index=floss_index, run_license_checkout=True)
    print(
        f"[+] {len(df.bridged)} bridged records: "
        f"{len(df.resolved())} resolved, {len(df.unresolved())} unresolved"
    )

    hits = df.for_api(target_api)
    if not hits:
        print(
            f"[FAIL] bridge produced no record for {target_api}. "
            f"The call site was found (step 1) but bridging dropped it -- "
            f"check _find_ssa_call op-name matching for this call."
        )
        return 1

    for b in hits:
        print(
            f"    - p{b.parameter_index:>2}  value={b.value!r:<24} "
            f"src={b.string_source}  string_va="
            f"{b.string_va and hex(b.string_va)}  "
            f"path={_hexpath(b.dataflow_path)}  "
            f"chans={list(b.source_channels)}  conf={b.confidence}  "
            f"resolved={b.resolved}"
        )

    # 3) Verdict.
    resolved_strings = [b for b in hits if b.resolved and isinstance(b.value, str)]
    if expect is not None:
        ok = any(expect.lower() in (b.value or "").lower() for b in resolved_strings)
        print(
            f"[{'PASS' if ok else 'FAIL'}] expected substring {expect!r} "
            f"in a resolved {target_api} argument"
        )
        return 0 if ok else 1
    if resolved_strings:
        print(f"[PASS] bridge resolved a string argument to {target_api}")
        return 0
    print(
        f"[WARN] {target_api} call located but no argument resolved to a "
        f"string. Triage with the per-record line above:"
    )
    print(
        "       value=None, path=[call_va only]  -> arg was a live-in/return "
        "(inter-procedural, expected out-of-scope) OR a var-def lookup returned "
        "None (check _ssa_def / get_ssa_var_definition on this BN build)."
    )
    print(
        "       no record at all                  -> _find_ssa_call op names "
        "(MLIL_*_SSA) don't match this build."
    )
    print(
        "       value=None but path has hops      -> reached a CONST that isn't "
        "a string, or _read_string_at needs the wide-string branch."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
