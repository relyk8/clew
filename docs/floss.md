# Channel 1 (FLOSS): string extraction

Implementation record for `clew/channels/floss.py` and `tests/test_floss.py`.
Companion to `bn_callsites.md` (Channel 2 / Unit 3). Channel 1 recovers string
*values* (static, stackstring, tightstring, decoded); mapping those values to
API call sites is Channel 2's job.

**Outcome:** Channel 1 implemented, tested end-to-end, and committed.
`clew/channels/floss.py` + `tests/test_floss.py` pass 3 unit + 3 integration
tests against the al-khaser fixture, extracting all 12 record-#2 DLL
fingerprints, including the 4 capa misses.

## 1. What got built

- **`clew/channels/floss.py`** — Channel 1. Mirrors `capa.py` conventions
  (future-annotations, `FLOSS_PINS`, four-level error hierarchy, frozen
  dataclass result, independently-testable adapter, keyword-only args).
  - `run_floss(sample_path, *, min_length=4, sigs_path=None, enable_*=True, save_workspace=False)`
    — drives FLOSS's extractor functions in-process, in `floss.main.main()`'s
    order, returning a `FlossResult`.
  - `load_floss_results(path)` — loads a saved FLOSS JSON via
    `floss.results.read` for offline unit tests (mirrors capa's saved-JSON
    pattern).
  - `FlossString` dataclass — one string tagged by `source` (schema
    `string_source` enum value) with that category's **native location fields
    preserved, not normalized**.
  - `FlossResult` dataclass — four category lists + `min_length` + `raw` (the
    `ResultDocument`), plus `all_strings()` / `values()` helpers.
  - Error hierarchy: `FlossError`, `FlossImportError`, `FlossRunError`,
    `FlossParseError`.
- **`tests/test_floss.py`** — 3 unit (offline, fixture-driven adapter checks) +
  3 integration (`FLOSS_INTEGRATION`-gated live runs). Integration asserts the
  12 DLLs and, sharply, the exact 4 capa-misses.
- **`tests/fixtures/al-khaser_x86.floss.json`** — saved `floss -j` output,
  committed for offline unit tests (same pattern as the capa fixture).

**Test end-state:** `3 passed, 3 skipped` without `FLOSS_INTEGRATION`;
`6 passed` with it. Integration runtime ~626s for the two full-analysis tests
(fixture generation alone took ~304s).

Installing flare-floss downgrades networkx (3.6.x → 3.1) to satisfy FLOSS's
pin. networkx is shared with capa/vivisect, so this was a flagged risk; it was
cleared by re-running the full suite including the capa integration path (the
real graph-analysis path) afterward — green.

## 2. FLOSS API findings + design decisions

Discovered by inspecting the installed `flare-floss==3.1.1` directly (not the
docs), via throwaway probe scripts and reading `main()`'s source. Recorded so
the module's design choices are traceable — including the alternatives we
weighed and rejected.

### 2.1 The Python API surface
- `floss.api` does **not** exist in 3.1.1. The real surface is `floss.main`
  (run + extractor functions) + `floss.results` (typed output dataclasses).
- `floss.results` exposes: `ResultDocument`, `Strings`, `StaticString`,
  `StackString`, `TightString`, `DecodedString`, `StringEncoding`,
  `AddressType`, plus `read` and `load`.

### 2.2 Design decision: invocation — Python API vs subprocess CLI

**Weighed:**
- *Subprocess CLI* (`floss -j` + parse JSON, like `capa.py`): the JSON output
  is a far more stable contract than FLOSS's internal functions; CLI contracts
  outlast library internals across versions. But FLOSS's console-script
  shebangs proved fragile on a migrated environment, so subprocess invocation
  carries that fragility. The pilot also actually went through JSON (`jq` on
  `floss -j` output), so this was the *validated* path.
- *Python API* (call extractor functions in-process): no subprocess, no
  shebang exposure, structured dataclasses back instead of JSON to parse, and
  richer per-string location data than the JSON exposes cleanly. Downside:
  FLOSS's Python API is **not a documented stable contract** — internal
  functions move between releases (e.g. `floss.api` existed in older versions,
  gone in 3.1.1).

**Chose:** Python API, **pinned exactly to 3.1.1** to neutralize the
instability downside. The shebang fragility was itself the argument against
subprocess, and the in-process path gives Channel 2 the richer location fields
it needs. Exact-pin (not `>=3.1,<4`) is the mitigation for the unstable-surface
risk; reproducibility beats picking up patch releases.

### 2.3 Design decision: location fields — preserve vs normalize

`ResultDocument.strings` (a `Strings`) holds six lists; we use four and drop
two:

| FLOSS list | schema `string_source` | location fields |
|---|---|---|
| `static_strings` | `static` | `offset` (file offset), `encoding` |
| `stack_strings` | `stackstring` | `function`, `program_counter`, `frame_offset` (+more) |
| `tight_strings` | `tightstring` | same shape as stack |
| `decoded_strings` | `decoded` | `address`, `address_type` (STACK/GLOBAL/HEAP), `decoding_routine` |
| `language_strings` | — | dropped (v2 item #16) |
| `language_strings_missed` | — | dropped (v2 item #16) |

The four categories express *location* differently — static has a file
`offset`, stack/tight have `function`+`program_counter`, decoded has a typed
`address`+`address_type`. There is no single "address" field across them.

**Weighed:**
- *Normalize now* — collapse to one `(value, source, address)` shape with a
  single location field. Cleaner downstream interface. But Channel 2 (BN xref),
  which consumes these, **doesn't exist yet** to tell us what location shape it
  wants — so any normalization is a guess, and the address semantics differ too
  much across types to collapse safely (a decoded STACK address ≠ a static file
  offset).
- *Preserve faithfully* — `FlossString` keeps each category's native fields,
  normalizing nothing.

**Chose:** preserve. Premature normalization here discards data Channel 2 can't
recover — the same trap as premature filtering (§2.4). The only thing Channel 1
standardizes is the *category label* (FLOSS's four lists → the `string_source`
enum), which is genuinely Channel 1's call. `FlossString` carries the union of
all location fields, with the inapplicable ones left `None`.

### 2.4 Design decision: filtering — extract everything vs filter

The README lists "raw output is noisy — needs regex filtering" as a FLOSS
concern.

**Weighed:**
- *Filter in Channel 1* — drop junk/short strings, regex to likely-candidate
  values. Cleaner output. But the channel boundary is: FLOSS extracts,
  **Channel 2 maps strings to call sites — that mapping IS the filter**. A
  string only matters if it traces to an API call site, and Channel 1 can't
  know which do. Filtering here risks discarding a string Channel 2 needed
  (e.g. a short DLL-fingerprint string).
- *Extract everything, tag, defer* — preserve all of FLOSS's output.

**Chose:** extract everything, no semantic filtering. The only length floor
applied is FLOSS's own `MIN_STRING_LENGTH` (passed through as `min_length`),
which is FLOSS's filter, not ours. Same information-preservation principle as
§2.3.

### 2.5 The two `load`s — a naming trap
- `floss.results.read(path) -> ResultDocument` — **the JSON-file
  deserializer.** This is what `load_floss_results` uses.
- `floss.results.load(sample, analysis, functions, min_length)` AND
  `floss.main.load(...)` — both **assemble** a ResultDocument from a live
  vivisect workspace. NOT file readers.
- Initial code used `fr.load(path)` and failed with `missing 3 required
  positional arguments`. Fixed to `fr.read(path)`. The module comment warns
  about this explicitly so it isn't repeated.

### 2.6 `main()` has an interactive prompt that silently disables deobfuscation
- Reading `inspect.getsource(floss.main.main)` revealed: when no explicit
  `--only`/`--no` flags are given and a language is identified, `main()` calls
  `input("Do you want to enable string deobfuscation? [y/N]")`. In a **non-TTY**
  context it defaults to `"n"` and **disables** stack/tight/decoded extraction.
- **Consequence:** naively reusing `main()` in tests/automation would yield
  static-strings-only — a silent partial result, not an error. `run_floss()`
  avoids this entirely by constructing the `Analysis` object explicitly and
  calling the extractor functions directly — never touching the prompt. This is
  the single biggest reason the module drives the extractors itself rather than
  shelling out to (or calling) `main()`.

### 2.7 Extraction orchestration (mirrored from `main()`)
Order, fast→slow: static → (build workspace) → stack → tight → decoded.
- Static strings: `get_static_strings(sample, min_length)` — no workspace
  needed.
- Workspace: `load_vw(sample, fmt, sigpaths, save_workspace)`; sigs default to
  `get_default_root()/"sigs"` (FLOSS bundles its own sigs — **separate from
  capa's**; caller need not supply them).
- Functions: `select_functions(vw, None)` then
  `find_decoding_function_features(vw, funcs, ...)`.
- **Stack/tight coupling:** when tight is enabled, stack strings are extracted
  from `get_functions_without_tightloops(features)` (FP avoidance) and tight
  from `get_functions_with_tightloops(features)`.
- Decoded: top-20 by score (`get_top_functions(features, 20)`) + tight fvas,
  deduped via `append_unique`, then `decode_strings(vw, fvas, min_length)`.

### 2.8 Pin
- `flare-floss==3.1.1` (exact) — see the §2.2 rationale. FLOSS ships its own
  signatures inside the package, so there is no separate rules/sigs repo to pin
  (unlike capa's three-artifact pin).

## 3. Notes carried forward

- **`run_floss()`'s one fragile spot:** `select_functions(vw, None)` worked, but
  if a future FLOSS version errors on function selection, try
  `select_functions(vw, [])` (main() passes `args.functions`, an empty list).
- **Workspace caching:** `save_workspace=True` (or env `FLOSS_SAVE_WORKSPACE`)
  caches the vivisect workspace, which would cut the ~100s+ repeat-run cost. Not
  enabled by default.
- **Channel boundary → Channel 2:** FLOSS is a *value* channel — it produces
  strings + their locations. Mapping values to API call sites is **Channel 2
  (Binary Ninja xref)**. The input contract for Channel 2 is `FlossResult`:
  static strings carry a file `offset`, decoded strings carry an
  `address`+`address_type` — those are the join keys BN works from.
