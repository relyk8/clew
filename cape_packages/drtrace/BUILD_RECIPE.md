# drtrace build recipe (Windows guest)

Copy-paste steps to build `drtrace.dll` inside the `win10_dev` snapshot. **This
cannot be built on the Linux host** — DynamoRIO's CMake config `FATAL_ERROR`s on
any non-MSVC compiler (`DynamoRIOConfig.cmake` L563), and its headers need
`windows.h`. Target build: **32-bit / x86**, DR **11.91.20651**.

This is the `cmplog` recipe with the deltas for `drtrace`. That build succeeded
on 2026-07-21 and the toolchain is banked in `win10_dev`, so this should be a
rebuild rather than a fresh provision.

Legend: **[USER]** needs capeadmin / VM-state control (revert a snapshot, take a
snapshot, `qemu-img`, sudo). **[AGENT]** is drivable over the CAPE agent
`/execute` + `/extract` from the host (`192.168.122.1`) once the guest is up.

---

## What changed from the cmplog build

- **Two extensions now**, not one: `drmgr` **and `drwrap`**. Both ship in the
  dev kit's `ext/lib32/release/`, which the lean kit already includes — no new
  files to push, but a link error naming `drwrap` means the kit is incomplete.
- **A generated header.** `api_table.h` sits next to `drtrace.c` and must be
  regenerated on the host (`python scripts/gen_api_table.py`) **before** zipping
  the source, whenever `TARGET_ENV_APIS` changes. `gen_api_table.py --check`
  fails if it is stale. `CMakeLists.txt` puts the source dir on the include path
  so an out-of-tree build still finds it.
- **New target name:** `--target drtrace`, output `drtrace.dll`.
- **New deploy path in the guest:**
  `C:\dynamorio\tools\lib32\release\drtrace.dll` (alongside `cmplog.dll`, which
  stays — `exe_cmplog` keeps working through the transition).

---

## Pre-flight: syntax-check on the Linux host  [AGENT]

Do this before booting the guest. It will not produce a `.dll` — DR's CMake is
MSVC-only — but MinGW supplies `windows.h` and targets 32-bit Windows, so the DR
headers parse and the client gets a real syntax and type check. That is the
difference between finding a typo here and burning a VM session on it.

```bash
sudo apt install gcc-mingw-w64-i686        # one time
SDK=/home/relyk8/dr-sdk/DynamoRIO-Windows-11.91.20651
cd cape_packages/drtrace
python ../../scripts/gen_api_table.py       # api_table.h must be current
i686-w64-mingw32-gcc -fsyntax-only -DWINDOWS -DX86_32 -Wall -Wextra \
  -Wno-unused-parameter -I. -I$SDK/include -I$SDK/ext/include drtrace.c
```

`-DX86_32` is the one that matters: DR derives `X86` from it, and passing `-DX86`
directly leaves the architecture undefined and buries you in errors from
`dr_defines.h`.

Expect exactly one warning, from DR's own headers ignoring an MSVC
`#pragma warning`. Anything else is yours. `cape_packages/cmplog/cmplog.c`
— which really did build under MSVC — produces the same single warning, so it is
a useful control if you suspect the check itself.

**What this does not catch:** linking (so a missing
`use_DynamoRIO_extension` shows up only on the guest), MSVC-specific
diagnostics, and anything about DR's runtime behaviour.

---

## 0. Prereqs / state  [USER]

Revert to a **running/agent-up** snapshot so the CAPE agent comes up:

```
virsh snapshot-revert win10 win10_dev --running
```

Do **not** cold-boot — the agent does not auto-start, and there is no other
headless control channel into the guest.

`win10_dev` already banks the DR SDK, VS Build Tools, cmake and ninja.

## 1. Push the source  [AGENT]

Zip `cape_packages/drtrace/` (`drtrace.c`, `CMakeLists.txt`, **`api_table.h`**)
on the host and push it via the agent's `/extract` with `dirpath=C:\clew\drtrace`.

The agent parses commands with POSIX `shlex.split`, so backslashes get stripped:
wrap Windows commands in **single quotes + `cmd /c`**. Nested `"` get mangled —
push a `.bat` and run it rather than fighting inline quoting. This bit the
cmplog build repeatedly.

## 2. Configure + build 32-bit  [AGENT]

```
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86 && cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake -S C:\clew\drtrace -B C:\clew\drtrace\build && cmake --build C:\clew\drtrace\build --target drtrace'
```

Output: `C:\clew\drtrace\build\drtrace.dll`.

Adapt `/home/relyk8/ch3-staging/build.bat` rather than retyping this — it is the
form that actually worked.

## 3. Smoke it standalone  [AGENT]

```
cmd /c 'C:\dynamorio\bin32\drrun.exe -c C:\clew\drtrace\build\drtrace.dll -logdir C:\drtrace_logs -- C:\Windows\SysWOW64\hostname.exe'
```

**The smoke target must be 32-bit** — the guest is 64-bit Windows, so
`System32\hostname.exe` is 64-bit and 32-bit `drrun` cannot instrument it. Use
`SysWOW64`. drrun prints cosmetic *"not a valid DynamoRIO root"* and missing
lib64/debug warnings against the lean install; harmless.

What to check in `C:\drtrace_logs\`, beyond "a log exists":

- `drtrace.<pid>.modules.log` holds `M` records with plausible bases, and the
  name field is hex (`6b65726e656c33322e646c6c` = `kernel32.dll`).
- At least one `C`/`R` pair. `hostname.exe` is a thin target, so if nothing is
  wrapped, check the DR log for `drtrace: module ... -> wrapped N APIs` with
  N > 0 on kernel32 — N == 0 everywhere means `dr_get_proc_address` is failing
  and nothing downstream will work.
- `seq=` increases monotonically across all records and both files.
- Comparison lines carry `jcc=` at least sometimes.

Instrumentation is slow (a clean call per comparison, now plus wrapping), so
`hostname.exe` can take minutes to self-exit. That is expected.

## 4. Pull `drtrace.dll` back to the host  [AGENT]

Retrieve it to `/home/relyk8/ch3-staging/drtrace.dll` (next to the banked
`cmplog.dll`).

## 5. Deploy for CAPE runs  [USER for snapshot steps]

- **[AGENT]** push `drtrace.dll` into the **analysis** snapshot's guest at
  `C:\dynamorio\tools\lib32\release\drtrace.dll` (the path hardcoded in
  `exe_drtrace.py`).
- **[USER]** re-take the running analysis snapshot so CAPE reverts to a state
  that already has `drtrace.dll` in place, and repoint `kvm.conf` `snapshot=` at
  it. Keep `clean_drio_cmplog` as the fallback.
- **[USER]** deploy `exe_drtrace.py` to
  `/opt/CAPEv2/analyzer/windows/modules/packages/exe_drtrace.py` (cape-owned;
  sudo). No CAPE restart needed — the analyzer payload is assembled per task.

Then submit with `package=exe_drtrace` **and `options=free=yes`**:

```
curl -F file=@S.exe -F package=exe_drtrace -F timeout=120 -F enforce_timeout=1 \
     -F options=free=yes http://127.0.0.1:8000/apiv2/tasks/create/file/
```

`free` is a *package* option read via `self.options.get(OPT_FREE)`; a top-level
`-F "free=1"` is ignored. Logs land in
`/opt/CAPEv2/storage/analyses/<task_id>/files/drtrace.*.log`.

## Client options

All optional; the defaults are what `exe_drtrace.py` runs with.

| Option | Default | Meaning |
|--------|---------|---------|
| `-logdir <dir>` | `C:\drtrace_logs` | where logs are written |
| `-nargs <n>` | 8 | argument slots read per call (max 16) |
| `-maxhits <n>` | 64 | calls logged per (API, call site); `0` disables the cap |
| `-minstr <n>` | 4 | characters before a readable run counts as a string |

Raising `-nargs` costs log volume and junk strings; lowering `-minstr` below 4
raises the false-positive rate on non-pointer arguments sharply.
