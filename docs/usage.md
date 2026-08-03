# Clew — usage

The command reference and the end-to-end workflow. For the problem Clew solves and
its approach, see [theory.md](theory.md). For the record it produces, see
[schema.md](schema.md).

## Setup

Install Clew into an environment of its own, so there is nothing to activate
before a run:

```bash
pipx install git+https://github.com/relyk8/clew
```

`uv tool install git+https://github.com/relyk8/clew` is equivalent. To work on
Clew itself, clone it and install editable with `pip install -e '.[dev,analysis]'`.

### Configuration

Clew reads its machine-specific settings from the environment, and will load them
from a file so they do not have to be exported before every run. Sources, in
decreasing precedence:

1. the process environment, so a one-off override still works
2. `./.env` in the working directory, the per-checkout convention
3. `~/.config/clew/config.env`, or `$XDG_CONFIG_HOME/clew/config.env`

Nothing already set is ever overwritten. The file format is the `KEY=value`
subset of shell, including an optional `export` prefix, so a file written to be
`source`d can be used as-is.

```bash
mkdir -p ~/.config/clew
cp .env.example ~/.config/clew/config.env
chmod 600 ~/.config/clew/config.env    # it holds a Binary Ninja password
```

The settings, by channel:

| Variable | Purpose |
|---|---|
| `CLEW_BN_API` | directory containing the `binaryninja` package (Channel 2) |
| `BN_ENTERPRISE_SERVER` / `_USERNAME` / `_PASSWORD` | Binary Ninja Enterprise license checkout |
| `CLEW_CAPA_RULES` / `CLEW_CAPA_SIGS` | capa rules checkout and its signatures (Channel 0) |
| `CAPE_BASE_URL` | CAPE instance, used only by the dynamic commands (Channel 3) |

`CLEW_BN_API` matters when Clew is installed in an isolated environment. Binary
Ninja's `install_api.py` writes a `binaryninja.pth` into one specific
`site-packages`, which a pipx or uv install does not share, so pointing this at
the API directory is what makes `import binaryninja` resolve. Leave it unset if
Binary Ninja already imports in Clew's environment.

The static pipeline needs a Binary Ninja 4.2.6455 Ultimate Enterprise license
checked out for the process; the credentials above are what the in-process
checkout uses.

## The pipeline end to end

Clew has a static half that runs locally and a dynamic half that runs a sample in
a sandbox. The two are separate commands joined by the record on disk.

`static` runs capa (Channel 0), FLOSS (Channel 1), and Binary Ninja (Channel 2)
over the sample and writes an intermediate record: candidate values tied to API
call sites, each with provenance and a confidence score. The Channel 3 comparison
operands are left as placeholders at this stage.

`detonate` submits the sample to CAPE under the cmplog DynamoRIO package, which
logs the runtime `cmp`/`test` operands the sample compares against as it executes.
Submission returns a task id immediately. The detonation runs in the sandbox on
its own schedule, so you can submit and come back to it.

`correlate` reads those cmplog logs, matches each runtime comparison to the static
call site it sits after, and fills the record's `comparison_candidates`. It reads
logs either from a CAPE task id or from a local directory, so you can re-correlate
a record without detonating again.

`run` chains all three for one sample.

```bash
clew static suspicious.exe          # local, static record
clew detonate suspicious.exe        # -> {"task_id": 42}
clew correlate --record results/<sha256>.clew.json --task 42
clew run suspicious.exe             # all three at once
```

## Output

`static`, `correlate`, and `run` write the record to `results/<sha256>.clew.json`
by default and log the path to stderr. Pass `-o <path>` to choose a file, or
`-o -` to write the record to stdout for piping. `detonate` prints a small
`{"task_id": N}` object, and `tasks` prints a table. Progress and errors always go
to stderr, so stdout stays clean.

Records are keyed by sample SHA-256, so re-running a sample overwrites its record.
The `results/` directory is gitignored.

## Commands

`clew <sample>` is a shorthand for `clew static <sample>`. Every command accepts
`-v` (debug logging), `-q` (warnings only), and `-h`.

### static — run the static pipeline (Channels 0-2)

```bash
clew static SAMPLE [-o OUTPUT]
```

| Option | Meaning |
|---|---|
| `--capa-rules DIR` | capa rules dir (default `$CLEW_CAPA_RULES`) |
| `--capa-sigs DIR` | capa signatures dir (default `$CLEW_CAPA_SIGS`) |
| `--floss-sigs PATH` | FLOSS signature file (default: FLOSS built-in) |
| `--capa-bin BIN` | capa executable to invoke (default `capa` on PATH) |
| `--no-license-checkout` | assume a Binary Ninja license is already checked out |
| `--exclude-unresolved` | omit located-but-unresolved call sites (the Channel 3 work list) |
| `--verbose-floss` | don't suppress vivisect/FLOSS emulator logging |
| `--floss-cache DIR` | FLOSS result cache dir (default `.floss_cache/`) |
| `--no-cache` | disable the FLOSS cache |
| `--refresh-floss-cache` | force a FLOSS re-run and overwrite the cache |
| `-o, --output PATH` | default `results/<sha256>.clew.json`, `-` for stdout |

### detonate — submit to CAPE for comparison logging (Channel 3)

```bash
clew detonate SAMPLE [--wait]
```

| Option | Meaning |
|---|---|
| `--package PKG` | CAPE analysis package (default `exe_cmplog`) |
| `--timeout SECS` | guest analysis timeout (default 120) |
| `--wait` | block until the task reaches a terminal state, then report status |
| `--enforce-timeout` / `--no-enforce-timeout` | kill the guest at the timeout vs wait for self-exit (default on) |
| `--cape-url URL` | CAPE base URL (default `$CAPE_BASE_URL` or `http://127.0.0.1:8000`) |
| `-o, --output PATH` | write the task-id JSON to a file (omit or `-` for stdout) |

### correlate — join runtime operands onto a record (Channel 3)

```bash
clew correlate --record RECORD (--cmplog-dir DIR | --task N)
```

| Option | Meaning |
|---|---|
| `--record PATH` | the static record to enrich (required) |
| `--cmplog-dir DIR` | a local dir of `cmplog.*.log` files (offline, no CAPE) |
| `--task N` | a CAPE task id; reads the logs from CAPE storage |
| `--module-base ADDR` | runtime load base to rebase PCs into the record's address space (`0x...`) |
| `--storage-root DIR` | CAPE analyses storage root (with `--task`) |
| `--max-cmp-records N` | cap comparison records loaded from the logs (`0` = unlimited; default 5,000,000) — guards host memory/CPU on an oversized log |
| `-o, --output PATH` | default `results/<sha256>.clew.json`, `-` for stdout |

`--cmplog-dir` and `--task` are mutually exclusive, and one is required.

### tasks — the CAPE detonation dashboard (Channel 3)

```bash
clew tasks [--watch] [--json]
```

| Option | Meaning |
|---|---|
| `--status STATUS` | only tasks with this status (e.g. `reported`) |
| `--limit N` | show at most N tasks (newest first) |
| `--json` | emit rows as JSON instead of a table |
| `--watch` | refresh continuously until Ctrl-C |
| `--interval SECS` | refresh interval with `--watch` (default 2.0) |
| `--cape-url URL` | CAPE base URL |
| `--storage-root DIR` | CAPE analyses storage root (read for the RECORDS column) |

The RECORDS column shows how many comparison records each terminal task produced,
so a sample that defeats instrumentation reads 0 at a glance.

### run — static, detonate, and correlate end to end

```bash
clew run SAMPLE
```

Takes the `static` options plus `--package`, `--timeout`, `--enforce-timeout`,
`--cape-url`, `--module-base`, `--storage-root`, `--max-cmp-records`, and `-o`. It runs the static pipeline,
detonates and waits for the terminal status, then correlates the logs onto the
record.

### doctor — check the prerequisites

```bash
clew doctor [--license]
```

| Option | Meaning |
|---|---|
| `--license` | also load Binary Ninja and take a license seat |
| `--cape-url URL` | CAPE base URL to probe |
| `--storage-root DIR` | CAPE analyses storage root to check for readability |
| `--timeout SECS` | seconds to wait on the CAPE probe (default 5) |

Reports each prerequisite, and for anything missing, the line that fixes it. The
severity follows the pipeline's degradation policy: only Binary Ninja, the core
channel, is a blocking failure, while capa, FLOSS, and CAPE are warnings because
Clew degrades past them rather than failing. So the exit code answers exactly one
question, which is whether static analysis will run.

By default nothing is executed and no license seat is consumed: the Binary Ninja
check locates the package without importing it. `--license` opts into the real
import, a core-version comparison against the pinned version, and a checkout
round trip, which is the check worth running before a long batch.

## Channel 3 requirements

The dynamic commands (`detonate`, `run`, and `correlate --task`) need a CAPE
instance with the cmplog DynamoRIO analysis package deployed, reachable at
`CAPE_BASE_URL`. The package runs the sample under DynamoRIO and records its
runtime comparison operands, which CAPE stores per task under
`storage/analyses/<id>/files/`.

`correlate --cmplog-dir` needs none of this. Given a directory of `cmplog.*.log`
files, it runs fully offline, which is the path the correlation tests exercise.

A sample whose anti-instrumentation checks defeat DynamoRIO produces no logs, so
correlation yields an empty `comparison_candidates` for it. That is expected and
visible as a 0 in the `tasks` RECORDS column.
