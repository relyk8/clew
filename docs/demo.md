# Clew demo

The commands are the same whichever static backend is configured — Ghidra
(default, no licence) or Binary Ninja. Only the setup differs, and one log line
tells you which one ran.

| | |
|---|---|
| static candidate extraction | `clew static` |
| dynamic detonation | `clew detonate` |
| monitor the sandbox | `clew tasks` |
| correlate runtime → static | `clew correlate` |
| read the values back | `clew show` |
| the whole pipeline in one command | `clew run` |

## Setup (once)

```bash
cd ~/clew
source .venv/bin/activate
```

Backend settings live in `~/.config/clew/config.env`, so nothing needs
exporting per shell:

```
CLEW_STATIC_BACKEND=ghidra
GHIDRA_INSTALL_DIR=/home/shared/ghidra_12.1.2_PUBLIC
JAVA_HOME=/home/shared/jdk-21.0.12+8
```

See [ghidra_headless_setup.md](ghidra_headless_setup.md) if any of that is
missing. Warm the FLOSS cache for the demo sample beforehand — it is the
slowest stage and it is cached per sample, so paying it once off-stage turns a
seven-minute wait into a two-second cache hit:

```bash
clew static /opt/CAPEv2/analyzer/windows/bin/autoit3.exe -o /dev/null
```

## Demo

### 0. The tool

```bash
clew doctor
clew --help
```

`doctor` names the active backend and reports the other one as
`backend not in use` rather than as a failure — an install with no Binary Ninja
is a complete install.

### 1. Static

```bash
clew static /opt/CAPEv2/analyzer/windows/bin/autoit3.exe -o results/autoit3.static.clew.json
```

The `Ghidra: ...` progress line is where to point: no licence was checked out.

### 2. Detonate

Run this ahead of time — the guest takes a couple of minutes.

```bash
clew detonate /opt/CAPEv2/analyzer/windows/bin/autoit3.exe
```

### 3. Watch the sandbox

```bash
clew tasks
```

`clew tasks --watch` refreshes in place if you want it live on screen.

### 4. Correlate

```bash
clew correlate --record results/autoit3.static.clew.json --task <ID> -o results/autoit3.clew.json
```

### 5. The payoff — values seen at runtime that are nowhere in the binary

```bash
clew show results/autoit3.clew.json --runtime
```

```
API                  ARG   VALUE                                           CONF  CHANNELS
GetModuleHandleW     arg0  'kernel32.dll'                                  0.95  drio
GetModuleFileNameW   arg1  'C:\Users\cape\AppData\Local\Temp\autoit3.exe'  0.95  drio
GetNativeSystemInfo  -     327681                                          0.95  drio

3 runtime-resolved value(s) in results/autoit3.clew.json
```

The sample's own path under `\AppData\Local\Temp\` is the point: no static pass
could have produced it, because it does not exist until the sample runs.

Drop `--runtime` to see everything the static pass recovered, and `--api` to
narrow to one API:

```bash
clew show results/autoit3.clew.json
clew show results/autoit3.clew.json --api loadlibrary
```

### 6. All of it in one command

```bash
clew run /opt/CAPEv2/analyzer/windows/bin/autoit3.exe --force
```

## Optional: the backend comparison

Both backends write the same record format, so the same sample can be run
through each and the results compared directly. Measured on this machine:

| | Binary Ninja 4.2.6455 | Ghidra 12.1.2 |
|---|---|---|
| autoit3.exe candidates | 2334 | 2512 |
| autoit3.exe **with values** | **2** | **105** |
| Channel 2 wall clock | 139s | 228s |
| Licence | Enterprise seat | none |

```bash
clew static /opt/CAPEv2/analyzer/windows/bin/autoit3.exe --backend binaryninja -o results/autoit3.bn.clew.json
clew static /opt/CAPEv2/analyzer/windows/bin/autoit3.exe --backend ghidra      -o results/autoit3.ghidra.clew.json
clew show results/autoit3.bn.clew.json
clew show results/autoit3.ghidra.clew.json --limit 15
```

Ghidra is slower but recovers far more here, because Ghidra's bundled Windows
type archives give the decompiler real prototypes for the imported APIs, so
arguments are recovered at the correct index across many more call sites.

A good closing line for al-khaser, which is the more evasive sample:

```bash
clew show results/al-khaser.ghidra.clew.json --api findwindow
```

```
API          ARG   VALUE                   CONF  CHANNELS
FindWindowW  arg0  'VBoxTrayToolWndClass'  0.90  bn_xref,floss
FindWindowW  arg1  'VBoxTrayToolWnd'       0.90  bn_xref,floss
```

That is the sample checking whether it is inside VirtualBox, with the exact
window class it looks for — recovered statically, with no licence, and keyed to
the call site that consumes it.

## If something goes wrong on stage

* **Backend not configured** — fails in under a second with the fix named, and
  `clew doctor` shows the same thing. It never gets as far as FLOSS.
* **Fall back to the other backend** — `--backend binaryninja` on any `static`
  or `run` command.
* **A record already holds runtime data** — `clew static` refuses to overwrite
  it. Add `--force`, or write elsewhere with `-o`.
* **`clew tasks` cannot reach CAPE** — check `CAPE_BASE_URL`; `clew doctor`
  probes it.
