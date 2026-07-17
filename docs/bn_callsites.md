# Channel 2 / Unit 3: Binary Ninja Call-Site Enumeration

Implementation record for `clew/channels/bn_callsites.py` and
`tests/test_bn_callsites.py`. Companion to `floss.md` (Channel 1).

## What Unit 3 produces

Channel 2 is the **call-site** channel. It answers "where, and how, is each
Windows API called in this binary?" — and nothing else. It does not recover
string values (Channel 1 / FLOSS) and does not trace dataflow from a value to
a comparison (Unit 4). Its output is an intermediate JSON artifact, one record
per call site:

    (api_name, call_site_va, function_va, api_resolution, calling_convention)

This is the `evidence.channels == ["bn_xref"]` half of a clew schema record.
`to_partial_candidates()` emits these as candidate *stubs* (value, dataflow,
and comparison fields left null) so Unit 4 can attach FLOSS values and
dataflow paths to a ready-made skeleton.

## Resolution scope (v1)

Maps onto the schema `api_resolution` enum:

- `import` — statically imported via the IAT (the bulk of call sites)
- `ordinal` — imported by ordinal rather than name
- `getprocaddress` — resolved at runtime via GetProcAddress, name recovered
  from the constant string argument
- `hashed` — **reserved but never produced in v1.** API-name hashing
  (FormBook / Carbanak style) is a v2 item. A call we can see but cannot name
  is simply not emitted, rather than guessed at.

## Key design decision: enumerate imports, don't classify MLIL targets

The first implementation walked every function's MLIL, found every
`MLIL_CALL`/`MLIL_TAILCALL`, and tried to classify each call *target* by the
symbol at its address. This was wrong, and the al-khaser fixture proved it in
three distinct ways. The rewrite inverts the strategy: **enumerate the import
symbols, then follow `get_code_refs()` from each to its call sites.**

This is the approach Vector 35's own docs recommend for imports, and the
diagnostics confirmed why it is correct:

1. **Imports are reached through the IAT slot, not a named constant.** Probing
   `OutputDebugStringW` showed its `ImportedFunctionSymbol` had 1 code ref but
   its `ImportAddressSymbol` (the IAT slot) had 30. The MLIL-target approach
   keyed off names at call targets and missed the IAT-routed calls entirely —
   `OutputDebugStringW` was absent from the output. Following refs from the
   `ImportAddressSymbol` catches them.

2. **Internal functions carry no symbol.** Probing two `j_sub_*` call targets
   returned `symbol == None`, `is_function == True`. The old fallback ("if
   there's any named symbol at the target, call it an import") mislabeled
   internal calls like `j_sub_475250` as imported APIs. Keying off symbol
   *type* (`ImportAddressSymbol` / `ImportedFunctionSymbol`) instead of name
   excludes internal code cleanly.

3. **BN sometimes emits two MLIL call expressions at one address.** A probe of
   the function at `0x42cd20` found address `0x42cd3c` visited twice within
   BN's own block structure (`__builtin_memset` appeared as a duplicate row).
   Deduping on `(call_site_va, api_name)` absorbs this.

## The import-thunk problem (and its fix)

32-bit PEs materialize each imported API as a tiny forwarder "function" — a
single `jmp [IAT_slot]` stub. These cause degenerate rows where
`call_site_va == function_va` (the call sits at the stub's own start), and
they are import plumbing, not real call sites where an environment value is
consumed. They must not become candidates.

Two filtering attempts, in order:

- **First attempt — symbol/flag detection.** `_is_import_thunk()` checks for
  an import symbol at `func.start` or `func.is_thunk == True`. This caught the
  obvious thunks but **missed 296 rows**, because in this binary the thunk
  functions live in a separate region (`0x429xxx`) whose import symbol sits at
  the IAT address (`0x474xxx`), not at the thunk's start — and `is_thunk` was
  `False` for them.

- **Final fix — structural guard.** A genuine call site is never at the exact
  start of its containing function (a real call follows at least a prologue).
  A ref where `ref.address == ref_func.start` AND the function is a tiny
  single-block forwarder (`_is_forwarder_thunk()`: one basic block, ≤2
  instructions) is the thunk's own outgoing jump. Requiring *both* conditions
  means a legitimate call that merely happens to be a function's first
  instruction (hand-written asm, tail calls) is never discarded. This caught
  all 296.

The `_is_forwarder_thunk` size check uses `basic_block.instruction_count`
where available, falling back to a byte-span heuristic (≤8 bytes; one
`jmp [mem]` is ~6).

## GetProcAddress recovery (shallow, v1)

A separate pass finds GetProcAddress call sites (located by GetProcAddress's
IAT address, **not** by name match — same lesson as #1), reads the constant
string from the 2nd argument, and pairs each indirect call in the same
function with the most recent preceding GetProcAddress name.

This is intentionally shallow: same-function association by instruction order,
not real SSA tracing of the resolved pointer to its exact use. Deep tracing is
Unit 4's job; here we only need enough to *name* the call. **This is the
least-tested path** — al-khaser exercises few dynamic-resolution call sites —
and the shallow pairing can mis-associate when a function resolves several
APIs and calls them out of order. Revisit when a GetProcAddress-heavy sample
is available.

## Module structure (mirrors floss.py)

- `BNError` hierarchy: `BNNotAvailableError` (import/license failure),
  `BNAnalysisError` (load/analysis failure).
- Typed results: `CallSite` (frozen dataclass), `BNCallSites` (collection with
  `api_names()`, `for_api()`, `by_resolution()`, `schema_emittable()`).
- `run_bn_callsites()` / `load_bn_results()` pair — one runs headless BN (lazy
  `binaryninja` import so the module loads without BN present; wraps analysis
  in `LicenseCheckout` unless the caller already holds one), the other loads a
  saved fixture for offline tests.
- `BN_PINS` records the validated core version (4.2.6455 Ultimate). Bump on
  re-validation.
- VAs serialize as `0x`-prefixed lowercase hex, matching the schema's
  `call_site_va` / `function_va` convention.

## Test structure (mirrors test_floss.py)

Offline unit tests (no BN, no license) run against the saved fixture
`tests/fixtures/al-khaser_x86.bn_callsites.json`. Integration tests run the
real headless analysis, gated behind `BN_INTEGRATION` (the run is ~4 min and
needs a checked-out Enterprise license).

Ground truth comes from the hand-built record
`tests/fixtures/1fe91674eb8d_01.expected.json`: `IsDebuggerPresent` at call
site `0x00434d4a` inside function `0x00434d20`, resolved as an import. The
sharpest integration assertion (`test_run_enumerates_isdebuggerpresent`) and
the offline `test_isdebuggerpresent_call_site_present` both pin this exact
triple.

Regression guards added during debugging, each locking in one fixed bug:

- `test_no_import_thunk_rows` — zero `call_site_va == function_va` rows.
- `test_isdebuggerpresent_real_sites_only` — every IDP row is a real call site.
- `test_no_duplicate_rows` — no repeated `(call_site_va, api_name)` pairs.
- `test_no_internal_function_names` — no `sub_*` / `j_sub_*` names emitted.
- `test_no_hashed_resolution_in_v1` — `hashed` never produced.
- `test_all_resolutions_are_valid` — intermediate JSON may carry `unknown`,
  but `schema_emittable()` yields only v1 enum values.

Final state: **14 passed** (11 offline + 3 integration).

## Regenerating the fixture

Whenever the enumerator changes, regenerate the offline fixture from a real
run before trusting the offline tests (a stale fixture will pass against old
behavior):

    BN_INTEGRATION=1 python -c "from clew.channels.bn_callsites import \
        run_bn_callsites; run_bn_callsites('tests/fixtures/al-khaser_x86.exe')\
        .write_json('tests/fixtures/al-khaser_x86.bn_callsites.json')"

(During this unit's debugging, checking the offline fixture *before*
regenerating produced a confusing "the fix didn't work" result — the code was
fixed but the fixture on disk was from the prior run. Regenerate first.)

## Known limitations carried to Unit 4 / v2

- **Hashed API resolution** — not detected (v2).
- **GetProcAddress pairing is shallow** — same-function, order-based; can
  mis-associate with out-of-order resolution. Needs a stress fixture.
- **No dataflow** — call sites have no associated values or comparison
  operators yet; that is the entire point of Unit 4's bridge.
- **calling_convention** is whatever BN reports for the containing function,
  which is the caller's convention, not necessarily the callee API's. Adequate
  for grouping; revisit if a consumer needs the callee ABI.
