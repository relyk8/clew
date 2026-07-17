# Channel 2 / Unit 4: MLIL-SSA Dataflow Bridge

Implementation record for `clew/analysis/dataflow.py` and
`tests/test_bn_dataflow.py`. Companion to `bn_callsites.md` (Unit 3)
and `floss.md` (Channel 1). Like those, this captures not just what the
code does but the design decisions and the debugging path that produced it,
because that reasoning is the part worth having on record before Channel 4 and
the derivation stage build on top of it.

Unit 4 is now integrated into the static pipeline that runs it alongside capa,
FLOSS, and Unit 3 -- see `static_pipeline.md` for the orchestrator (the
single-view architecture, FLOSS caching, the CLI, and the operational runbook).
This document is the bridge's internal record; that one is how the channels are
wired together and how to run them.

## What Unit 4 produces

Unit 4 is the *bridge*. clew already had the two halves it joins:

- **Unit 2 (Channel 1 / FLOSS)** recovers string *values*, but not where in
  the binary they are used.
- **Unit 3 (Channel 2 / `bn_xref`)** enumerates API *call sites* — where and
  how each Windows API is called — but never the values that flow into them.

Unit 3 emits call-site *stubs* (`to_partial_candidates()`) with the value,
dataflow, and comparison fields left null. Unit 4 fills the dataflow half: for
each call site, it traces the call's arguments backward through Binary Ninja's
Medium-Level IL in SSA form to whatever flows into them. When an argument
resolves to a string, the bridge attaches the value, the instruction path it
travelled, and the string's provenance — turning `evidence.channels ==
["bn_xref"]` into a candidate with a value on it, and (when FLOSS corroborates)
`["bn_xref", "floss"]`.

Concretely it produces a typed intermediate artifact — `BNDataflow`, a list of
`BridgedCallSite` records — and a `to_partial_candidates()` view that groups
those into schema-shaped candidate dicts. This mirrors Unit 3's shape exactly:
an independently testable JSON artifact, not finished clew records.

## The Person A / derivation boundary

The bridge is deliberately scoped to Person A's static job. It does **not**:

- **Comparison semantics** (`comparison_operator`, `cmp_operand_a/_b`). Whether
  a recovered value is compared with `==`, `!=`, `contains`, etc. is what the
  dynamic channel observes at runtime. The bridge leaves `comparison_operator`
  as `"unknown"` and the operands null. **→ Channel 4 (DynamoRIO cmp-logging).**
- **Semantic classification** (`represents`, `retarget_to`, `evasion_tier`) and
  the sample-level `derivation_status`. Deciding that `"SbieDll.dll"` means
  `sandbox_detected` with `retarget_to: null`, and assigning a defeatability
  tier, is the final derivation pass. The bridge emits `represents:
  "unknown"`, `retarget_to: null`, and no `evasion_tier`. **→ derivation stage
  (Person B).**
- **`hashed` API-name resolution.** A v2 item, same as Unit 3. The bridge only
  ever consumes the schema-emittable call sites Unit 3 produced
  (`import` / `getprocaddress` / `ordinal`).

The result is a candidate dict that is *one derivation pass short* of a schema
`Candidate`. Validated against `schema/clew_record.schema.json`, a bridge
candidate is missing exactly three required fields — `evasion_tier`,
`iteration_number`, `coordination_constraint` — and validates the instant
derivation adds them. That is the clean interface contract between the static
bridge and the derivation stage.

## The core: an MLIL-SSA def-use walk

For each call site, `bridge_with_view` (or the standalone `run_bn_dataflow`)
locates the MLIL-SSA call at `call_site_va`, takes its parameter expressions,
and walks each one backward. `_resolve` is a recursive walk over MLIL-SSA
expressions with a visited-set (to break SSA cycles through phi nodes), a depth
cap (`MAX_TRACE_DEPTH`), and a path accumulator that records every instruction
VA it passes through — this becomes `evidence.dataflow_path`.

The walk dispatches on the expression's operation, in this order:

0. **Value fast path.** If BN's own dataflow already constant-folded the
   expression to a pointer that reads as a string (`expr.value` is a
   `ConstantPointerValue`), use it. This catches pointers spilled to a stack
   slot and reloaded, without hand-threading memory versions.
1. **Constant pointer** (`MLIL_CONST_PTR` / `MLIL_CONST` / `MLIL_IMPORT`) →
   read the string at that address directly from the `BinaryView`.
2. **Memory load** (`MLIL_LOAD_SSA`) → possibly an indicator array; hand off to
   `_resolve_array_load` (see below).
3. **Address-of** (`MLIL_ADDRESS_OF`) → a stack buffer passed by address;
   obfuscated-string territory, resolved by association with FLOSS output for
   the function.
4. **SSA variable** (`MLIL_VAR_SSA`) → follow its definition
   (`get_ssa_var_definition`) and recurse on the definition's source. If the
   variable has no definition in this function, fall back to the FLOSS
   obfuscated association *only if it is a stack variable* (a live-in buffer);
   otherwise it is a caller parameter — inter-procedural, out of v1 scope.
5. **Phi node** (`MLIL_VAR_PHI`) → resolve each incoming version; the first that
   yields values wins (multi-value phis across control flow are a v2
   refinement).
6. Anything else (a call return, arithmetic on non-constants) → unresolved.

Every BN attribute access in the walk is defensive (`getattr`, op names compared
by `.name` string rather than by enum identity), so a minor BN API drift
degrades a call site to unresolved rather than throwing.

## Resolution cases

### Static string constants

The common case: `GetModuleHandleW(L"kernel32.dll")` where the argument is a
constant pointer, directly or one variable-copy removed. The walk reaches the
`MLIL_CONST_PTR`, reads the string, and records `string_source: "static"`,
`string_va`, and a two- or three-hop `dataflow_path`.

### Indicator arrays (the al-khaser idiom)

The interesting case, and the one that motivated most of Unit 4's code.
al-khaser's Sandboxie/AV checks are not single-string calls — they build a
*local array of module-name pointers* and iterate it:

```
GetModuleHandle(_T("SbieDll.dll"))  // conceptually
// compiles to, in one function:
var_48 = &"avghookx.dll"; var_44 = &"avghooka.dll"; ...
var_3c = &"sbiedll.dll"; ...  var_1c = &"cmdvrt32.dll";
for (i = 0; i < N; i++) GetModuleHandleW( (&var_48)[i] );
```

The argument is `array[runtime_index]`, so no single-value trace can say which
element flows in — BN reports `.value` as undetermined precisely because the
index is a loop variable. `_resolve_array_load` handles this: from a load of
`&stack_base + index`, it identifies the base stack variable, then
`_enumerate_pointer_array` collects the contiguous, stride-spaced run of
const-pointer-to-string stack assignments anchored at that base, reads each
string, and returns one finding per element. A constant index picks a single
slot; a variable (loop) index enumerates the whole run.

The schema's multi-value `candidate_values` was designed for exactly this: one
candidate at the call site carrying all N indicator strings. `sub_459500`'s
loop becomes one candidate with 12 values (`avghookx.dll` … `cmdvrt32.dll`,
`sbiedll.dll` among them), each with its own source string address in the typed
artifact.

This is a structural pattern, not a hard-coded sample. Any binary using a local
pointer-array indexed in a loop resolves the same way; nothing in the module
references an al-khaser address or string (those live only in the tests, as
fixtures).

### Obfuscated strings via FLOSS

When an argument is a literal `&stack_buffer` (or a stack variable with no SSA
definition), BN sees no literal string — the value was constructed at runtime.
Here the bridge consults FLOSS. `FlossIndex` exposes the function-keyed
stack/tight/decoded strings FLOSS recovered; if FLOSS reported exactly one
obfuscated string in the function, the bridge associates it (shallow, single
match — ambiguity is left unresolved rather than guessed, the same conservatism
as Unit 3's GetProcAddress pairing). `string_source` is the FLOSS category
(`stackstring` / `tightstring` / `decoded`), `source_channels` is
`["bn_xref", "floss"]`.

FLOSS is an *optional enrichment*, not a hard dependency. The bridge recovers
static strings from BN alone and runs fine with `FlossIndex.empty()`; FLOSS adds
corroboration for static values and supplies values for the obfuscated cases.
There are two ways to build the index: `FlossIndex.from_floss_result()` (from a
`FlossResult` object — the `floss.py` reconcile point) and
`FlossIndex.from_floss_json()` (from FLOSS 3.x `--json` output on disk). The
json path reads the real per-category fields — `static_strings[].string`,
`stack_strings`/`tight_strings` keyed by integer `function`, and
`decoded_strings` keyed by `decoding_routine` (decoded entries have no
`function`) — and was validated against the actual `al-khaser_x86.floss.json`.

### Unresolved → Channel 4 work list

Arguments that don't statically reduce to a value — computed indices,
inter-procedural flow, runtime-decoded names, `GetModuleHandleW(NULL)` — are
recorded as *unresolved* `BridgedCallSite`s (`resolved=False`, value null). This
is not loss: `BNDataflow.unresolved()` is precisely the list of call sites the
dynamic channel should instrument. Reporting them explicitly, rather than
dropping or guessing them, is what makes the static/dynamic hand-off clean.

## Confidence

Heuristic scores, comparable within a single run only (per `docs/schema.md`),
centralised as constants so tuning is one edit:

- `0.9` — static string confirmed by both BN dataflow and FLOSS.
- `0.7` — static string BN read but FLOSS did not report.
- `0.6` — obfuscated string associated via FLOSS (shallow, single-match).
- `0.0` — located but unresolved.

**Indicator-array elements are scored identically to any static string** — 0.9
when FLOSS corroborates the element, 0.7 BN-only — with no array-specific
discount. An earlier version capped array elements at 0.7 regardless of
corroboration, on the reasoning that a variable-index loop proves only that a
string is *in the checked set*, not that it flows in on a given iteration. That
was dropped for two reasons. First, it made the `source_channels` and
`confidence` fields disagree: a FLOSS-corroborated array element carried
`["bn_xref","floss"]` (corroborated) but `0.7` (BN-only), which is
self-contradictory. Second, the set-vs-single distinction is real but belongs
elsewhere: `confidence` answers "is this value real and correctly
characterized," and a BN+FLOSS-agreed module name is exactly that however the
argument was shaped. The "these N checks form one OR over a set" property is a
*coordination* fact — it maps onto `coordination_constraint` and the comparison
semantics, which are the derivation stage's and Channel 4's concern, not a
haircut on the static confidence score.

With FLOSS wired in, BN-only static values (including array elements) that FLOSS
also recovered upgrade from `0.7`/`["bn_xref"]` to `0.9`/`["bn_xref","floss"]`
automatically through the corroboration path — no bridge change needed. On the
al-khaser fixture this is visible directly: with `--floss` supplied,
`kernel32.dll` / `ntdll.dll` and the 12-element module-name array all report
`["bn_xref","floss"]`, and the corroborated values reach `0.9`.

## Output shape and grouping

`to_partial_candidates()` groups `BridgedCallSite` records by
`(call_site_va, parameter_index)` into one candidate per group, with one
`candidate_values` entry per distinct value. A plain single-string argument is
the degenerate group of one. For a multi-value (array) candidate,
`evidence.string_va` is null — the per-element addresses have no home in the
schema and remain only in the typed artifact — while the loop-load
`dataflow_path` is preserved. `evidence.channels` is the union across the group.

## The fixture run: two bugs worth recording

The offline suite passed while the live walk was still broken, because the
offline tests validated the grouping/emission logic given findings — they did
not exercise the BN walk that produces them. The al-khaser fixture run surfaced
two bugs in sequence, both instructive.

### Bug 1 — stack variables invisible (`_is_stack_var` enum name)

Symptom: on the real sample, every `GetModuleHandleW(array[i])` call reported
unresolved, and a diagnostic showed `is_stack=False` for genuine stack
variables whose storage was clearly a negative stack offset (`-72`, `-60`, …).

Cause: `_is_stack_var` tested `"Stack" in str(source_type)`. BN's `str()` of the
`VariableSourceType` enum renders as an int-ish value, *not* the member name —
so the check failed for real stack variables. With `_is_stack_var` wrong,
`_split_base_index` rejected `&var_48`, the array base was never identified, and
`_resolve_array_load` bailed before enumerating anything.

Fix: check the enum by `.name` (`"StackVariableSourceType"`), with a
negative-storage fallback so the helper stays correct even if `source_type` is
unavailable on some build. Two unit tests (`test_is_stack_var_*`) reproduce the
exact condition — an enum whose `str()` lacks "Stack" but whose `.name` has it —
so it cannot regress.

Lesson: comparing BN enums by their stringification is fragile; use `.name` or
the enum member. This applies anywhere in the codebase that inspects
`source_type`, `operation`, etc.

### Bug 2 — the 254 → 11 collapse (SSA-walk branch ordering)

Symptom: after fixing Bug 1, resolved records dropped from ~254 to 11 — even the
simple `kernel32.dll` calls that had always worked stopped resolving.

Cause: fixing the stack detection also (correctly) made the obfuscated-string
branch's `_is_stack_ref` guard return `True` for stack variables. But that
branch was ordered *before* the branch that follows a variable's SSA definition.
Since almost every argument is a stack `MLIL_VAR_SSA`, nearly all of them were
now shunted into the FLOSS-obfuscated path, which returned empty (no FLOSS index
in the smoke run) → unresolved. The obfuscated branch was swallowing arguments
that should have been traced.

The blurred distinction: a bare `MLIL_VAR_SSA` of a stack variable *holds a
value to trace* (follow its definition); only a literal `&buffer`
(`MLIL_ADDRESS_OF`) is the "FLOSS decoded a string into this stack buffer" case.

Fix: restrict the obfuscated branch to literal `MLIL_ADDRESS_OF`, and move the
stack-buffer FLOSS association into the `MLIL_VAR_SSA` *no-definition* fallback —
so a traceable variable is always followed, and only a genuinely undefined stack
buffer falls back to FLOSS. `_is_stack_ref` was removed (it existed only for the
bad guard). `test_resolve_follows_stack_var_to_const_string` reproduces the
collapse with fakes and fails if a stack `VAR_SSA` is ever intercepted again.

Lesson: in an SSA def-use walk, branch order encodes priority. Definition-
following must precede speculative/heuristic associations, or the heuristic
shadows the real trace. The offline fakes now pin both paths.

## Static envelope (v1 scope)

Resolves statically:

- Direct string-constant arguments.
- Pointers spilled to a stack slot and reloaded (via BN's constant-folded
  value).
- Local pointer-arrays indexed in a loop (indicator arrays), element-by-element
  initialised.

Falls to Channel 4 (reported unresolved, by design):

- Arrays block-copied from a global pointer table (a partial, currently
  untested global-array fallback exists).
- Runtime-decoded or encrypted names.
- Computed / data-dependent indices that don't reduce to a fixed slot.
- True inter-procedural flow (the value is a parameter of the containing
  function, e.g. a helper like `IsModuleLoaded(name)`).
- Non-string constant arguments and `GetModuleHandleW(NULL)`.

Different malware families lean on different idioms, so the resolved/unresolved
split shifts per sample — but nothing is tuned to al-khaser, and the unresolved
set is the dynamic channel's work list rather than silent loss.

## Validation

Offline suite (`tests/test_bn_dataflow.py`, 32 tests, no BN or license):
serialization round-trips for `BridgedCallSite` / `BNDataflow` / `FlossIndex`;
the FLOSS adapters (`from_floss_result` and `from_floss_json`, the latter against
the real FLOSS 3.x field shapes) and category normalisation; the pure scoring
and channel-union helpers; the candidate grouping (including array collapse and
dedup); an end-to-end `_resolve_array_load` on fakes mirroring `sub_459500`
(including a stray non-contiguous format string that must be excluded, and a
corroborated-elements case proving 0.9 scoring); and the `_resolve` regression
tests for both walk bugs above.

Schema check: a grouped multi-value indicator-array candidate validates against
`schema/clew_record.schema.json` once the derivation fields are added,
confirming the boundary is exactly three fields wide.

Live fixture (`scripts/smoke_bn_dataflow.py` on `al-khaser_x86.exe`, BN core
`4.2.6455 Ultimate`): 884 call sites → 1085 bridged records (array call sites
fan out to one record per element), 389 resolved, 696 unresolved. `sub_459500`'s
`0x4595fc` resolves to all 12 indicator strings — `sbiedll.dll` among them —
each with its `string_va` and the shared loop-load `dataflow_path`
`[0x4595f7, 0x4595fb, 0x4595fc]`; the direct `kernel32.dll` / `ntdll.dll` calls
resolve as static. Re-run with `--floss tests/fixtures/al-khaser_x86.floss.json`,
the same call sites report `["bn_xref","floss"]` and the corroborated values move
to `0.9`, confirming the FLOSS-json adapter against real output.

### Oracle grading against hand-built ground truth

The strongest check is not self-consistency but agreement with an independently
written oracle. `tests/fixtures/1fe91674eb8d_0{1,2}.expected.json` are hand-built
*full* schema records for two al-khaser candidates — `_01` an `IsDebuggerPresent`
return-value check, `_02` the 12-DLL indicator loop. `clew/analysis/oracle_grade.py`
grades the bridge's `to_partial_candidates(include_unresolved=True)` output against
them, and `tests/test_oracle_grade.py` runs it (BN-gated live; the grading logic
itself is covered by eight offline tests).

Grading is deliberately *scoped*. An oracle is a full record; the bridge produces
only the bridge-owned fields. So the grader compares only what the bridge owns —
`call_site_va`, `function_va`, `api_name`, `api_resolution`, `parameter_index`,
the set of `candidate_values[].value`, and `evidence.string_source` /
`dataflow_path` — and treats the derivation/Channel-4 fields (`represents`,
`retarget_to`, `evasion_tier`, `comparison_operator`, `coordination_constraint`)
as report-only context, never as failures. Value comparison is
case-insensitive (oracle source casing vs binary casing). For a return-value
check (`parameter_index == -1`) only structural identification is bridge-owned;
the "value" is a return, not an argument, so it is report-only.

Both oracles pass on every bridge-owned field (1/1 each):

- **`_02`** — all 12 module-name values match the oracle set, with correct
  `parameter_index`, `string_source: static`, and a `dataflow_path` reaching the
  call site. The report also makes the architecture boundary concrete: the oracle
  assigns *different* `represents` per element — `vmcheck.dll` → `vm_detected`,
  `sbiedll.dll` / `pstorec.dll` / `cmdvrt64.dll` / `cmdvrt32.dll` →
  `sandbox_detected`, the rest → `analysis_tool_detected`. The bridge correctly
  recovers the value *set*; the per-value semantic classification genuinely is a
  separate judgment. This is direct evidence that the Person A / Person B split is
  load-bearing, not merely tidy — the bridge cannot and should not make that call.
- **`_01`** — the bridge nails the structural identification (`call_site_va`,
  `function_va`, `api_name`, `api_resolution`, `parameter_index: -1`) and produces
  *no* value. The oracle's `True` / `debugger_detected` / `retarget_to: false` are
  all return-value semantics owned by Channel 4 and derivation. This is the
  cleanest evidence that the bridge respects the limit of static argument
  dataflow: it locates the check and stops, rather than inventing a return value
  it cannot statically know.

One honest detail the report surfaces (reported, not graded): for `_01` the oracle
`dataflow_path` is `[0x434d20, 0x434d4a]` (function entry → call) while the
bridge's stub carries only `[0x434d4a]` (the call site). This is by design — a
no-argument call has nothing to trace, so there is no def-use path to record;
unresolved and return-value stubs carry the call-site VA alone as a locator.

## Reproducibility and determinism

The bridge and its enumeration are deterministic; the remaining run-to-run
variance is confined to one enrichment source (FLOSS, now pinned by caching) and
to Binary Ninja's analysis of deliberately anti-analytic code, where it is
small, bounded, and outside the validated cases. Concretely, on the al-khaser
fixture:

- **The bridge is deterministic given a fixed view.** Running `bridge_with_view`
  twice on the *same* analysed `BinaryView` produces byte-identical
  `to_partial_candidates()` output. Call-site enumeration (Unit 3) is likewise
  stable (884 sites across independent analyses), as is BN's MLIL-SSA for a given
  discovered function and BN's function discovery itself (3740 functions across
  fresh loads). No nondeterminism originates in `dataflow.py` or
  `bn_callsites.py`; this was confirmed with `PYTHONHASHSEED` pinned, ruling out
  Python hash-order effects in the grouping/dedup path.
- **FLOSS was the first variance source and is now pinned.** FLOSS's string
  emulation is nondeterministic on adversarial code (its stack/tight/decoded
  categories varied a few strings run-to-run; static strings, ~3947 here, are
  deterministic). The pipeline caches FLOSS output as native `floss -j` JSON
  keyed on sample + FLOSS version + min-length + signature identity + flags
  (`.floss_cache/`), so a sample is emulated once and reused verbatim thereafter;
  a key mismatch errors rather than silently using stale strings.
- **A residual <1% BN variance remains on adversarial samples, in two layers.**
  With FLOSS cached, full-pipeline candidate counts varied within a narrow band
  (≈960–967 of ~967 total candidates; ≈269–271 of the resolved subset — under
  1%). The affected call sites cluster in al-khaser's heavily-obfuscated
  `0x0047xxxx` region, where BN's emulator reports the most anti-disassembly
  (junk-byte opcodes, incomplete control flow). Isolating the cause showed it is
  *not* in clew's code (the bridge is deterministic on a fixed view) nor in
  Python hash order (`PYTHONHASHSEED` pinned changed nothing) nor in function
  discovery (3740 functions, and all affected sites contained in a function, on
  every fresh load). It has two contributing layers in BN's analysis itself:
  pinning `analysis.limits.workerThreadCount` to 1 (default 32) **stabilises
  candidate membership** — the set of call sites becomes reproducible at 967 on
  every run, so BN's worker parallelism accounted for the count swing — but a
  smaller, *field-level* drift persists even single-threaded and hash-pinned:
  the output digest still differs run-to-run, meaning a few evidence fields on
  candidates in the obfuscated region are not bit-reproducible. This deeper layer
  was not chased further: it lives inside BN's analysis of anti-analytic code and
  is not controllable from the channel. Crucially, neither layer touches any
  validated case — the twelve-module indicator loop resolves 12/12, the
  `IsDebuggerPresent` return-value check is located, and both hand-built oracles
  pass on every run. The residual variance is therefore documented as a known,
  bounded limitation of static analysis over deliberately anti-analytic binaries,
  expected for the class of input, and not affecting the evasion-check cases the
  channel exists to recover.

For thesis reproducibility the intended workflow is to generate the FLOSS cache
once and archive it alongside results, making re-runs fast, silent, and — modulo
the residual BN variance above — reproducible. Where a reproducible *set* of
findings matters (e.g. a headline candidate count), setting
`analysis.limits.workerThreadCount` to 1 stabilises candidate membership at the
cost of roughly doubled BN analysis time; it does not remove the smaller
field-level drift, so it is offered as a knob rather than a default. The
pragmatic stance for v1 is to report results with the measured <1% variance
bound stated, since it falls entirely outside the validated evasion-check cases.

## BN API surface and version pinning

The walk depends on: `func.mlil.ssa_form`; block/instruction iteration with
`.operation`/`.address`; the SSA call ops (`MLIL_CALL_SSA` and variants);
`call.params`; `MLIL_VAR_SSA.src`, `MLIL_VAR_PHI.src`; `MLIL_CONST(_PTR).constant`;
`MLIL_ADDRESS_OF.src`; `ssa.get_ssa_var_definition(var)` (tolerating an
instruction-index return); `Variable.storage` / `.source_type`;
`bv.get_string_at` / `get_ascii_string_at` / `read`; `bv.arch.address_size`.
Validated on BN core `4.2.6455` (Ultimate). Re-validate on BN bumps — companion
to `BN_PINS` in `bn_callsites.py`.

## Open items

- **Real-malware evaluation (deferred to week-5 piloting).** al-khaser confirms
  the walk and both hand-built oracles pass, but al-khaser is the deliberate v1
  fixture (see `tests/fixtures/SOURCES.md`): hand-built oracles are not tractable
  for wrapper-router malware (Delphi RTL, NSIS, dispatch helpers), so real-family
  evaluation moves to Channel 2 piloting, graded qualitatively against published
  RE writeups rather than `expected.json`. The deferred samples
  (`269aff53…` rebhip, `68644c…` Pony) are that test set. The relevant risk to
  watch there is a *wrong-value* resolution (false positive), which a
  different-family sample is where it would surface.
- **Global-array fallback.** The block-copy-from-global path is stubbed but
  untested; a fixture exercising it would close the second static-array idiom.
- **Orchestrator wiring.** `bridge_with_view` is ready; wire Unit 3 + Unit 4
  onto one analysed `BinaryView` in the orchestrator so analysis runs once.

_Closed since first draft: the `!= pinned` cosmetic check (now compares
`core.split()[0]`); FLOSS corroboration on real data (via `--floss` and
`FlossIndex.from_floss_json`); oracle grading against `_01`/`_02`._
