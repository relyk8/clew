# `drtrace` — Clew Channel 3 DynamoRIO client

Successor to `cmplog`. Where `cmplog` logged only comparison operands, `drtrace`
also traces the Windows API calls that produce the values being compared, so
Channel 3 becomes a **candidate producer** — a peer of Channel 2 — rather than a
downstream annotator of Channel 2's call sites.

Three things it captures that static analysis structurally cannot:

1. **Values that are not in the binary.** `GetComputerNameA` → the machine name,
   `GetVolumeInformationW` → the volume serial, `RegQueryValueExA` → the value
   read back. An evasion check compares the sample's expected value (usually in
   the binary, so FLOSS-recoverable) against the environment's actual answer
   (never in the binary). Static gets one side; this gets the other.
2. **Site and value together.** FLOSS produces a bag of strings with no location.
   It knows `"SbieDll.dll"` exists; it cannot know it is argument 0 to
   `GetModuleHandleW` at `0x412a3f`. That binding is what fills the unresolved
   stubs the dataflow bridge leaves behind.
3. **Calls static enumeration never found** — hash-resolved imports, ordinal
   `GetProcAddress`, packed or runtime-unpacked code, indirect vtable/COM
   dispatch. Wrapping the callee means how the call site was reached stops
   mattering.

It does **not** solve anti-DR samples (al-khaser still yields no logs) or path
coverage (you see only what executed that run). This is a recall gain, not a
completeness guarantee.

## Log format (v1)

One file per thread, `drtrace.<pid>.<tid>.log`, in the client's `-logdir`.
Every record is flushed immediately: CAPE kills the target at the analysis
timeout, so anything not already on disk is lost.

Four record types. Every record carries a **global monotonic `seq`**, shared
across all threads and all record types — that ordering is what lets the host
join a comparison to the API return that produced its operand, instead of
guessing by PC proximity.

```
# drtrace v1 pid=5148 tid=2224
M seq=1     base=0x00400000 end=0x0049a000 name=<hex>
C seq=10432 T2224 api=GetModuleHandleW site=0x0041a2f0 a0=0x0019fb14 s0=W:53006200… a1=0x0
R seq=10433 T2224 api=GetModuleHandleW site=0x0041a2f0 rv=0x00000000 o0=A:4445534b…
T2224 pc=0x0041a2f5 cmp seq=10434 jcc=jz src0=reg:eax=0x0 src1=imm=0x0
```

| Type | Meaning |
|------|---------|
| `M` | Module load. `base`/`end` give the runtime extent, so the host rebases PCs into static VA space without being told the load address. Retires the ASLR-off assumption and the manual `--module-base`. |
| `C` | Wrapped API call, pre-callback. `site=` is `drwrap_get_retaddr()` — the **call site** in the caller. `aN=` is argument N's raw value; `sN=` is that value dereferenced, when it read as text. |
| `R` | The matching return, post-callback. `rv=` is the return value. `oN=` is argument N re-read *after* the call — this is what captures out-parameters, where the value is written into a caller-supplied buffer rather than returned. |
| `T` | A comparison. The `cmplog` line, plus `seq=` and `jcc=`. |

### Arguments

A fixed number of argument slots is read per call (default 8), because the client
carries no per-API knowledge of arity. Reads past a function's real argument
count return whatever is on the stack; the host filters that. Eight covers the
widest target in the set — `GetVolumeInformationW`, whose volume serial is
argument 3 and filesystem name argument 6.

The raw value is **always** logged alongside any dereferenced string. `sN`/`oN`
are an observation ("these bytes read as text"), not a claim about the argument's
type, and the analyst can see what it was derived from.

### Strings are hex-encoded

`A:` for ASCII, `W:` for UTF-16LE, followed by the raw bytes in hex, capped at
128 bytes.

This is not cosmetic. The bytes come from memory the sample controls. Logged as
literal text, a sample could embed a newline and a well-formed record in a string
argument and inject fabricated comparisons into our log — the host parser reads
these files as trusted input. Hex encoding removes that, and sidesteps quoting
and encoding questions at the same time.

Module names are hex-encoded for the same reason. API names are not: they come
from the client's own table, not from the sample.

### Comparisons

`cmp` sets flags but does not say what the comparison meant — the following
conditional jump does. `jcc=` records it, so the host can resolve a `cmp` to a
concrete operator (`equality`, `less_than`, …) instead of `unknown`. `test` is
unambiguous on its own and maps to `bitwise_and`.

### Hit caps

Each (API, call site) pair logs at most a fixed number of calls (default 64), so
a `GetTickCount` timing loop cannot fill the disk. When a pair is capped the
client emits a `# capped api=… site=…` marker: truncation is reported, never
silent.

### Compatibility with `cmplog` logs

`M`, `C` and `R` records do not match the legacy parser's line pattern (anchored
on `^T<tid>`), and the added `seq=`/`jcc=` tokens fall in the tail it already
ignores. So `cmplog_parse.py` reads a v1 `drtrace` log as if it were a `cmplog`
log, and existing `cmplog` logs keep parsing unchanged.

## Build

MSVC only — DynamoRIO's CMake config hard-fails on any other compiler, so this
cannot be built on Linux. See `BUILD_RECIPE.md`.

The wrapped API set is generated from `clew/tiers.py`'s `TARGET_ENV_APIS` by
`scripts/gen_api_table.py` into `api_table.h`, so the client and the pipeline
cannot drift apart.
