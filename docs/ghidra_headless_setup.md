# Ghidra headless setup

clew's Channel 2 (call-site enumeration + the dataflow bridge) runs on either
Ghidra or Binary Ninja. Ghidra is the default and needs no licence, so this is
the path to set up if you just want clew to work.

Nothing here needs root.

## What you need

| Component | Version | Why |
|---|---|---|
| Ghidra | 12.0 or newer | PyGhidra became the default Python engine in 12.0; Jython stopped shipping in 12.1 |
| JDK | 21 or newer | **A JRE is not enough** -- see the note below |
| `pyghidra` | 3.x | The in-process CPython bridge; 3.x requires Ghidra 12.0+ |

> **A JRE will not work.** Ghidra's launcher shells out to its own
> `LaunchSupport` to locate a JDK, and when it finds only a JRE it exits with a
> bare non-zero status -- no message naming the cause. The symptom is
> `An error occurred launching Ghidra: ... returned non-zero exit status 1`.
> If you see that, check for `javac`, not `java`:
> `ls "$JAVA_HOME/bin/javac"`. `clew doctor` checks this for you.

## Install

```bash
# 1. Ghidra
curl -LO https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip
unzip -q ghidra_12.1.2_PUBLIC_20260605.zip -d /opt      # any directory works

# 2. A JDK, if `javac -version` does not already print 21+
curl -L -o jdk21.tar.gz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse"
tar xzf jdk21.tar.gz -C /opt

# 3. The Python bridge, into the same venv as clew
pip install pyghidra
```

## Configure

clew reads `~/.config/clew/config.env` at startup, so these do not have to be
exported in every shell (anything already in the environment wins):

```bash
mkdir -p ~/.config/clew
cat >> ~/.config/clew/config.env <<'EOF'
CLEW_STATIC_BACKEND=ghidra
GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.2_PUBLIC
JAVA_HOME=/opt/jdk-21.0.12+8
EOF
```

Then confirm:

```bash
clew doctor
```

The `ghidra` row should read `<install dir>, JDK at <jdk dir>`. Every failure
mode above is reported there with the line that fixes it.

## Choosing a backend per run

```bash
clew static sample.exe                          # the configured default
clew static sample.exe --backend ghidra
clew static sample.exe --backend binaryninja    # needs a licence
```

`--backend` beats `CLEW_STATIC_BACKEND`, which beats the built-in default
(`ghidra`). Both backends emit the same record format, so a record does not
depend on which one produced it. The backend is checked before capa and FLOSS
run, so a misconfiguration fails in under a second rather than several minutes
in.

## Tuning

`GHIDRA_HEADLESS_MAXMEM` controls the JVM heap; Ghidra's own default of 2G is
tuned for many parallel instances, not for one deep analysis. For obfuscated
malware, raise it:

```bash
export GHIDRA_HEADLESS_MAXMEM=8G
```

Decompiler out-of-memory shows up as functions that silently yield no call
sites, not as an error.

## How it works, and why not `analyzeHeadless`

clew drives Ghidra **in-process** through PyGhidra rather than shelling out to
`support/analyzeHeadless`. Two reasons:

* `analyzeHeadless` pays JVM and module-scan startup on every invocation, and
  gives no return channel -- results have to be written to a file by a
  `-postScript` and read back.
* clew opens and analyses the sample **once**, then shares that one analysis
  between call-site enumeration and the dataflow bridge, along with a single
  decompiler and its `HighFunction` cache. A subprocess boundary would force
  that to be split or repeated.

Analysis of a mid-size PE32 takes roughly a minute; the decompiler then runs
lazily, per function, only for functions that actually contain call sites of
interest.

## Known differences from the Binary Ninja backend

Both backends emit the same artifacts, but they do not agree on everything:

* **Ordinal imports.** Binary Ninja maps a well-known ordinal to its export
  name (WS2_32 `Ordinal_115` -> `WSAStartup`) from a built-in table. Ghidra
  ships no such table, so clew records `api_resolution: "ordinal"` with the
  ordinal number and keeps the `Ordinal_<n>` label. This is what the schema's
  `ordinal` value is for.
* **APIs with no prototype.** Ghidra's bundled Windows type archives give exact
  parameter indices for documented APIs. For an API absent from them, and for
  `GetProcAddress`-resolved indirect calls, the decompiler recovers no
  arguments -- clew emits an unresolved record (the Channel 3 work list) rather
  than reading a possibly-misaligned index.
* **Coverage.** On al-khaser, Ghidra finds 823 of the 884 call sites Binary
  Ninja does at identical addresses, plus several hundred more that Binary
  Ninja's import-symbol walk misses (including `CreateToolhelp32Snapshot`,
  `Thread32Next` and `GetAdaptersInfo`).
