# cmplog — Clew Channel 3 comparison-operand logger

A DynamoRIO client that logs the **runtime comparison operands** of a sample —
the concrete values an evasion check compares against (e.g. the "2 GB" behind
*if RAM < 2 GB, hide*). It is the real Channel 3 deliverable; the earlier
`exe_drcov` package only logged coverage and existed to prove the CAPE +
DynamoRIO mechanism.

## What it does

For every executed `OP_cmp` / `OP_test` application instruction, the client
inserts a clean call that re-decodes the instruction at its app PC and records
each source operand's **live** value:

- **register** → `reg_get_value` from the thread mcontext
- **immediate** → `opnd_get_immed_int`
- **memory** → `opnd_compute_address` + `dr_safe_read` of the bytes

One text line per comparison (thread id, app PC, opcode name, per-operand
kind+hex value) to a per-thread file `cmplog.<pid>.<tid>.log` under
`C:\cmp_logs` (overridable via `-logdir`).

`OP_sub`, the `cmov*` / `set*` families, `cmpxchg`, and string compares are
documented candidate future additions; the draft deliberately starts narrow
(`cmp`/`test`) for signal-to-noise.

## Status

**First draft — COMPILE-UNVERIFIED.** There is no MSVC toolchain on the Linux
dev host (DynamoRIO's CMake refuses any non-MSVC compiler), so this has not been
built or run. Correctness was established by verifying every DR API call against
the DR 11.91.20651 headers and modeling on the shipped samples. Build it in a
Windows dev snapshot per `BUILD_RECIPE.md`, then deploy per `exe_cmplog.py`.

Target: **32-bit / x86**, DynamoRIO **11.91.20651** (the Clew guest is PE32).

## Files

- `cmplog.c` — the DR client.
- `CMakeLists.txt` — MSVC/32-bit build (`find_package(DynamoRIO 11.91)`,
  `configure_DynamoRIO_client`, `use_DynamoRIO_extension(cmplog drmgr)`).
- `BUILD_RECIPE.md` — copy-paste guest build + deploy steps.
- `../exe_cmplog.py` — the CAPE `Package` that runs `drrun -c cmplog.dll -logdir
  ... -- <sample>` and uploads `cmplog.*.log`. Cloned from `exe_drcov.py`.

## Flush caveat (why per-record flushing is mandatory)

CAPE kills the target at the analysis timeout — most malware never self-exits.
`drcov` only wrote its log on **clean** process exit, so under CAPE it produced
0-byte logs (`upload_to_host` then silently skips them). `cmplog` therefore
**flushes after every logged comparison** (`dr_flush_file`), so a timeout-kill
still leaves every comparison observed up to that point on disk.

## Fit in the pipeline

Channel 3 is **dynamic and not yet integrated** into the static `clew/`
pipeline; the intermediate record currently emits the comparison operands as
placeholders (`comparison_operator="unknown"`, `cmp_operand_a`/`_b=null`). This
client produces the raw runtime data those fields will eventually be filled
from. See the rule notes `clew-channel-34-dynamic` (design) and
`clew-channel-3-cape-drio` (CAPE/DynamoRIO ops).
