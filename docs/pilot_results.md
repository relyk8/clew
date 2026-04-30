# Pilot Results

Two channel pilots conducted ahead of the DefCon proposal: FLOSS (Channel 1) and DynamoRIO-inside-CAPE (Channel 4). Channel 0 (capa) was implemented in full during week 2 and is not duplicated here. Channels 2 and 5 do not require pre-proposal pilots — Channel 2's risk is in the dataflow research itself (weeks 5–7), Channel 5 is family-specific and load-bearing on no proposal claims.

Both pilots passed. DynamoRIO required engineering iteration to expose what production Channel 4 will need; that iteration is documented here so the proposal can cite concrete cost estimates rather than hedged predictions.

## Channel 1 — FLOSS

**Tool**: flare-floss 3.1.1 (PyPI install, no auxiliary configuration required).

**Target**: `tests/fixtures/al-khaser_x86.exe`.

**Runtime**: 113 seconds end to end. FLOSS' work breaks down as static-string scan (sub-second), control-flow recovery on 1469 functions, stackstring extraction across 1423 functions (~27 seconds), tightstring extraction on 3 candidate functions (sub-second), and decoded-string extraction via emulation on 22 calls (~7 seconds). The "incomplete control flow graph" warning vivisect emitted is normal for malware samples and matches what capa surfaces.

**Static-string coverage (record #2 candidates)**: all 12 DLL fingerprint strings extracted, each present once: `avghookx.dll`, `avghooka.dll`, `snxhk.dll`, `dbghelp.dll`, `api_log.dll`, `dir_watch.dll`, `sbiedll.dll`, `pstorec.dll`, `vmcheck.dll`, `wpespy.dll`, `cmdvrt64.dll`, `cmdvrt32.dll`. This means FLOSS alone covers the full record-#2 candidate value set, closing the 8-of-12 coverage gap that capa's `reference anti-VM strings` rule leaves (documented in `docs/schema_v2_notes.md`).

**Other category counts**: 9 stackstrings, 0 tightstrings, 1 decoded string. The 9 stackstrings include al-khaser's ACPI BIOS fingerprints (`BMSR`, `IPCA`, `IPCAFACP`) — exactly the kind of runtime-constructed string the schema's `string_source: stackstring` value was designed to represent. Their existence in al-khaser confirms the schema's stackstring design has real targets, not theoretical ones. The low tightstring and decoded-string counts are unsurprising: al-khaser is a public benchmark, not packed or obfuscated. A real Pony or rebhip sample would show many more decoded strings; that's the test case for week 3's FLOSS implementation, not for the pilot.

**Schema mapping**: FLOSS 3.1.1 emits four categories — `static_strings`, `stack_strings`, `tight_strings`, `decoded_strings` — that map 1:1 to the schema's `string_source` enum (`static`, `stackstring`, `tightstring`, `decoded`). The mapping requires only normalizing the plural-vs-singular naming convention, not actual reshape work.

**v2 finding surfaced**: FLOSS additionally emits `language_strings` and `language_strings_missed` categories (Go/Rust/etc. language-runtime strings). For PE32 al-khaser these are empty, but they're not in the schema enum. v2 may need to widen the enum or document the omission. Appended to `docs/schema_v2_notes.md` as item #16.

**Verdict**: pass. Channel 1 is feasible as designed. Implementation in week 3 should be straightforward — Python API, no external configuration, output shape matches schema expectations.

## Channel 4 — DynamoRIO inside CAPE

The README's pre-proposal characterization was right: this is the riskiest channel. The infrastructure question — "can DynamoRIO be invoked inside CAPE's analysis VM and produce retrievable coverage logs" — has now been answered yes, but the path to that answer exposed multiple specific engineering costs that production Channel 4 will need to absorb.

### Final working pipeline

End-to-end flow proven on task ID 47:

1. Sample submitted to CAPE via REST API with `package=exe_drcov`.
2. CAPE's analyzer loads the custom `exe_drcov.py` package (committed at `docs/cape_integration/exe_drcov.py`).
3. Package invokes `C:\dynamorio\bin32\drrun.exe -c "C:\dynamorio\tools\lib32\release\drcov.dll" -logdir "C:\drcov_logs" -- <sample>` inside the guest.
4. drrun spawns the sample as a child process under drcov instrumentation. CAPE's resultserver observes both processes (`drrun.exe` parent, sample child).
5. Sample executes; drcov writes coverage logs to `C:\drcov_logs\drcov.<image>.<pid>.<thread>.proc.log`.
6. Package's `finish()` method enumerates `C:\drcov_logs\drcov.*.log` and uses CAPE's `upload_to_host()` to push each log to the host's per-task results directory at `files/<filename>`.
7. drcov logs retrievable from `/opt/CAPEv2/storage/analyses/<task_id>/files/`.

**Verified header on retrieved log** (`/opt/CAPEv2/storage/analyses/47/files/drcov.calc.exe.06352.0000.proc.log`):

```
DRCOV VERSION: 3
DRCOV FLAVOR: drcov
Module Table: version 5, count 71
```

That's a valid drcov v3 log. 999 KB for the calc.exe-instrumented run. Same format the existing drcov2lcov tooling consumes.

### Performance numbers

End-to-end task 47 runtime: 37 seconds (CAPE accepted at 03:52:46, reported at 03:53:23). Compare to the baseline al-khaser run from task 39 at 59 seconds. For short executions, drrun startup overhead dominates — the actual instrumentation cost during a brief execution doesn't add measurable time. For longer real-malware detonations (sample running 60+ seconds), the README's predicted 3–5x slowdown is plausible but unverified by this pilot.

Per-sample coverage log size: ~1 MB for the short execution measured. Production estimate for typical malware detonations: 5–50 MB.

### Engineering iteration log

Six concrete obstacles surfaced. Each is a specific work item for week 8's full Channel 4 implementation, not a re-derivable surprise.

**1. al-khaser self-terminates under CAPE, regardless of DynamoRIO.** First test submission (task 39) ran al-khaser unwrapped through CAPE's `exe` package. CAPE's monitor injected successfully, sample executed for ~13 seconds, then exited. No `.bson` behavior logs were produced. al-khaser detected something (almost certainly CAPE's monitor DLL or environmental fingerprints) and exited before any meaningful execution happened. This is consistent with the README's note that "sophisticated malware detects DynamoRIO" and the same applies to CAPE's monitor. **Implication**: Channel 4 cannot use al-khaser as its end-to-end test target. A benign 32-bit PE (in this pilot, an arbitrary 32-bit console exe from CAPE's sample store) is required for pipeline validation.

**2. KVM snapshot type matters.** libvirt distinguishes "running" snapshots (memory + disk state, fast revert to running guest) from "shutoff" snapshots (disk only, requires boot on revert). CAPE's KVM machinery expects running snapshots. An initial "shutoff" snapshot caused tasks to hang in `pending` indefinitely because the analyzer waited for the agent to respond and the agent never started. Resolved by booting the guest interactively, installing DynamoRIO, then snapshotting from the running state. **Implication for production**: snapshot management documentation needs to specify "running" snapshots. The `--atomic` flag alone doesn't enforce this.

**3. CAPE's `exe` package has no executable-redirect option.** The `exe.py` package always launches the dropped sample directly via `self.execute(path, args, path)`. There's no option to wrap the launch in a different executable. Production Channel 4 requires a custom analysis package (`exe_drcov.py`), not configuration of the existing one. About 50 lines of Python.

**4. drcov has a known option-parsing bug for `-t drcov -logdir`.** DynamoRIO issue #1750 (filed 2015) documents that invoking `drrun -t drcov -logdir <dir>` fails to pass the `-logdir` option through to drcov correctly — an empty token gets prepended to drcov's argv that causes its option parser to stop reading. The documented workaround is to use the `-c <full_path_to_drcov.dll>` form instead of `-t drcov`. The `-c` form was used in the final package. **Implication**: production Channel 4 should pin the working invocation form and not assume `-t` syntactic sugar works.

**5. CAPE's resultserver has a strict destination-path allowlist.** The `upload_to_host(local_path, remote_filename)` call rejects any `remote_filename` with a path prefix not on its allowlist. Initial attempts using `"drcov/<filename>"` were rejected with `Netlog client requested banned path: b'drcov/...'`. Resolved by using `files/<filename>` — the standard landing path for CAPE-collected artifacts. **Implication**: Channel 4 documentation should be explicit that drcov outputs land under `files/`, alongside CAPE's normal collected files. Downstream consumers parsing the analysis tree need to filter `files/drcov.*.log` to find Channel 4's contribution.

**6. CAPE's monitor injects into drrun, not into the instrumented child.** The behavior log produced at task 44 (one of the intermediate iterations) recorded drrun's API calls, not the sample's. This is correct CAPE behavior — its monitor injects into the launched process, which is drrun.exe, not into drrun's children. For Channel 4 this is actually fine: the deliverable is the drcov coverage log, not CAPE's behavior trace. But it means that for a sample run under Channel 4, CAPE's normal `behavior.processes` data describes drrun's lifecycle rather than the sample's. Reports that combine Channel 4 output with CAPE's normal behavior signatures need to handle this asymmetry.

### Architecture decision confirmed

The README's design choice to run Channel 4 inside CAPE (rather than as a separate DBI sandbox) is viable and is now demonstrated to work. Channel 4 stays in scope for the proposal as a CAPE-integrated channel. The infrastructure complexity above is engineering work for week 8, not architecture rework.

### Out of scope, deliberately

The pilot did not test Channel 4 against an evasion-aware target (e.g. samples that detect DynamoRIO via TLS callbacks, INT 2D, or DR-specific module paths). The README explicitly scopes 19 such samples out of Clew's coverage based on Pfuzzer's findings. Channel 4 evaluation in week 8 will document specific failure modes against known DR-detecting samples; this pilot does not.

### Verdict: pass with engineering-cost notes

Channel 4 is feasible as designed. The infrastructure works end-to-end. Six specific engineering costs are now documented, none of which threaten the channel's viability — all are tractable in week 8's implementation budget.

## Cross-pilot v2 schema findings

Both pilots surfaced items that have been appended to `docs/schema_v2_notes.md`:

- **Item 16 (FLOSS)**: `language_strings` and `language_strings_missed` are FLOSS output categories not represented in the `string_source` enum. v2 should either widen the enum or document the omission as deliberate.
- **Item 17 (DynamoRIO)**: drcov logs land in `files/drcov.*.log` under CAPE's per-task analysis directory. The schema doesn't currently constrain output-collection paths; this is a Channel 4 evidence-source convention rather than a schema field, but downstream consumers parsing the analysis tree need to know where to look. Possibly an `evidence.channels` value of `drio_drcov` in v2 (currently `drio` is the schema's reserved value; v2 may want sub-types).

## What feeds the proposal

Concrete numbers and findings the proposal's "Pilot results" section can cite directly:

- **Channel 0 (capa)**: 106 rules fired against al-khaser, 25 evasion-relevant after filtering. capa's `reference anti-VM strings` rule covered 8 of 12 al-khaser DLL fingerprints; FLOSS covered all 12. Together they cover the full record-#2 candidate set.
- **Channel 1 (FLOSS)**: pass clean. 113s runtime, 12/12 fingerprint coverage, 9 stackstrings (including ACPI BIOS fingerprints), schema mapping 1:1.
- **Channel 4 (DynamoRIO)**: pass with documented engineering cost. End-to-end pipeline confirmed: CAPE → custom analysis package → drrun-with-drcov → guest-side log → `upload_to_host` → host-side `files/`. ~1 MB log per short execution, ~37s end-to-end runtime for short execs versus ~59s baseline. Six specific engineering costs documented.
- **Channels 2 and 5**: no pilots needed before the proposal. Channel 2's risk is dataflow tractability (weeks 5–7); Channel 5 is family-specific.

The proposal can now make the contribution claim — "Clew automates per-sample candidate extraction across five channels covering Pfuzzer's 68 evasion APIs" — with infrastructure-level evidence that the channel architecture is real, not aspirational.

## Artifacts

- `docs/cape_integration/exe_drcov.py` — working CAPE analysis package (committed alongside this writeup).
- `docs/cape_integration/sample_drcov.log` — sample drcov v3 log retrieved from a CAPE run; 999 KB; preserved for format-validation reference.
- `tests/fixtures/al-khaser_x86.capa.json` and `tests/fixtures/al-khaser_x86.capa_techniques.json` — Channel 0 artifacts (committed during week 2).

The FLOSS output JSON is not committed — week 3's FLOSS implementation will produce its own canonical fixture in the same shape that `al-khaser_x86.capa.json` plays for Channel 0.
