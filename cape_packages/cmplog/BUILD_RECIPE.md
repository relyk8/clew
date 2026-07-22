# cmplog build recipe (Windows guest)

Copy-paste steps to build `cmplog.dll` (Clew Channel 3 comparison-operand
logger) inside a Windows dev snapshot. **This cannot be built on the Linux host**
— DynamoRIO's CMake config `FATAL_ERROR`s on any non-MSVC compiler
(`DynamoRIOConfig.cmake` L563: *"DynamoRIO's CMake configuration only supports
the Microsoft compiler on Windows"*). Target build: **32-bit / x86**, DR
**11.91.20651**.

Legend: **[USER]** needs capeadmin / VM-state control (revert a snapshot, take a
snapshot, `qemu-img`, sudo). **[AGENT]** is drivable over the CAPE agent
`/execute` + `/extract` from the host (`192.168.122.1`) once the guest is up.

---

## ✅ PROVEN RECIPE (2026-07-21) — this build actually succeeded

The client built to a valid 32-bit `cmplog.dll` (89,088 bytes, PE32) and, under
`drrun`, logged real `cmp`/`test` operands (reg/imm/mem live values). Snapshot
**`win10_dev`** now banks the toolchain (DR SDK + VS BuildTools + source). Gotchas
that actually bit, so the next rebuild is smooth:

1. **Dev-session boot:** revert to a running/agent-up snapshot
   (`virsh snapshot-revert win10 clean_drio_mlcluster --running`) so the CAPE agent
   comes up — do **not** cold-boot (agent won't auto-start). Drive everything else
   over the agent (`/store`, `/extract`, `/execute`) from host `192.168.122.1:8000`.
2. **Agent quoting:** it `shlex.split`s (POSIX) → **single-quote-wrap** every command
   so backslashes survive: `cmd /c 'C:\path\x.bat'`. Nested `"` inside get mangled —
   **push a `.bat` and run it** instead of inline double-quotes. (Bit us repeatedly.)
3. **VS install:** guest HAS internet (libvirt NAT + CAPE `route=none`), so the online
   bootstrapper works: `vs_BuildTools.exe --quiet --wait --norestart --nocache --add
   Microsoft.VisualStudio.Workload.VCTools --includeRecommended`. Exit **3010 = success +
   reboot-required**; **do NOT reboot** (cold boot kills the agent). `cl.exe` works
   without the reboot. `--includeRecommended` brings VS-bundled cmake+ninja (under
   `...\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\{CMake\bin,Ninja}`).
4. **Dev kit must include `tools/lib32/release/`.** `find_package(DynamoRIO)` loads the
   whole `DynamoRIOTarget32.cmake` and FATAL_ERRORs if any imported target's `.lib`/`.dll`
   is missing — even `drmemtrace_*` we never link. The build-needed set (lean, ~90 MB
   zipped): `cmake include ext/include lib32 ext/lib32 bin32 ext/bin32 tools/lib32/release`.
   Only `Target32` loads for a 32-bit build (`_DR_bits`=32), so **no lib64 needed**.
5. **Build (from an x86 Native Tools env):** `call vcvarsall.bat x86` then
   `cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake
   -S <src> -B <src>\build` then `cmake --build <src>\build --target cmplog`. See the
   canonical `build.bat` in `/home/relyk8/ch3-staging/`.
6. **Smoke target must be 32-bit:** guest is 64-bit Windows, so `System32\hostname.exe`
   is 64-bit and 32-bit `drrun` can't instrument it — use **`SysWOW64\hostname.exe`**.
   drrun prints cosmetic `"not a valid DynamoRIO root"` / missing lib64+debug warnings
   (lean install) — harmless; the client still logs. Instrumentation is slow (clean-call
   per comparison), so `hostname.exe` can take >2 min to self-exit — that's expected.

Built DLL saved to host: `/home/relyk8/ch3-staging/cmplog.dll`. Staging dir also holds
`vs_BuildTools.exe`, `dr-devkit-lean.zip`, `dr-tools-lib32.zip`, `cmplog-src.zip`,
`build.bat`, `smoke.bat`, `diag.bat`.

---

---

## 0. Prereqs / state  [USER]

- The current CAPE snapshot `clean_drio_mlcluster` is **runtime-only** (lean
  bin32/lib32, no compiler, no dev headers). Building needs a **separate win10
  dev snapshot** with VS Build Tools — do **not** pollute the analysis snapshot.
- Bring up a Windows guest with the CAPE agent reachable (revert an agent-up
  snapshot, or interactive logon on cold boot — see clew-channel-3-cape-drio
  notes on why cold boot leaves the agent down).
- The agent parses commands with POSIX `shlex.split`, so backslashes get
  stripped: wrap Windows commands in **single quotes + `cmd /c`**, e.g.
  `cmd /c 'cd C:\build && cmake ...'`.

## 1. Install VS Build Tools (headless)  [AGENT] (once, then [USER] snapshots it)

Push `vs_BuildTools.exe` into the guest, then:

```
vs_BuildTools.exe --quiet --wait --norestart ^
  --add Microsoft.VisualStudio.Workload.VCTools ^
  --includeRecommended
```

Also ensure **CMake** and **Ninja** are on PATH (VS Build Tools ships a CMake
under `...\Common7\IDE\CommonExtensions\Microsoft\CMake\`, or install
standalone). After it succeeds, **[USER]** takes a `win10_dev` snapshot so this
is a one-time cost.

## 2. Push the DR dev kit + cmplog source into the guest  [AGENT]

The runtime `C:\dynamorio` is NOT enough to build — you need the **dev kit**
(headers + `cmake/`). Durable host copy:
`/home/relyk8/dr-sdk/DynamoRIO-Windows-11.91.20651/` (and the `.zip`).

- Push the kit via the CAPE agent `/extract` (as was done for the lean runtime
  zip), landing it at e.g. `C:\dynamorio-sdk\` (so `C:\dynamorio-sdk\cmake\` and
  `C:\dynamorio-sdk\include\` exist).
- Push `cmplog.c` and `CMakeLists.txt` (this directory) to e.g. `C:\clew\cmplog\`.

`/extract` takes a zip + `dirpath=<dest>`; zip the two dirs on the host first.

## 3. Configure + build 32-bit  [AGENT]

From a **32-bit** toolchain environment. Easiest is the x86 Native Tools env; a
one-liner that sets it up and builds with Ninja:

```
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86 && cmake -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake -S C:\clew\cmplog -B C:\clew\cmplog\build && cmake --build C:\clew\cmplog\build --target cmplog'
```

Alternative (VS generator instead of Ninja): `cmake -G "Visual Studio 17 2022"
-A Win32 -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake -S ... -B ...` then
`cmake --build ... --config RelWithDebInfo --target cmplog`.

Output: `C:\clew\cmplog\build\cmplog.dll` (Ninja) or under a config subdir (VS).

Sanity-check it standalone before pulling it back:

```
cmd /c 'C:\dynamorio\bin32\drrun.exe -c C:\clew\cmplog\build\cmplog.dll -logdir C:\cmp_logs -- C:\Windows\System32\hostname.exe && type C:\cmp_logs\cmplog.*.log'
```

(Use a **self-exiting** target like `hostname.exe`; a target CAPE would have to
kill leaves data only because we flush per-record, but for a manual smoke a
clean exit is simplest.)

## 4. Pull cmplog.dll back to the host  [AGENT]

Use `upload_to_host` / the agent file-fetch path (same mechanism the packages
use) to retrieve `cmplog.dll` to the host, e.g. into this directory or a
`build/` sibling.

## 5. Deploy for CAPE runs  [USER for snapshot steps]

- **[AGENT]** push `cmplog.dll` into the **analysis** snapshot's guest at
  `C:\dynamorio\tools\lib32\release\cmplog.dll` (the path hardcoded in
  `exe_cmplog.py`).
- **[USER]** re-take the running analysis snapshot so CAPE reverts to a state
  that already has `cmplog.dll` in place (mirrors how DR itself was baked into
  `clean_drio_mlcluster`).
- **[USER]** deploy `exe_cmplog.py` to
  `/opt/CAPEv2/analyzer/windows/modules/packages/exe_cmplog.py` (cape-owned;
  sudo). No CAPE restart needed — the analyzer payload is assembled per task.

Then submit a sample with `package=exe_cmplog`; logs land at
`/opt/CAPEv2/storage/analyses/<task_id>/files/cmplog.*.log`.
