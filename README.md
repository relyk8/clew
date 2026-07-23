# Clew

Clew reads a single PE32 malware sample once and emits a per-sample seed corpus
that an environmental fuzzer uses to reach the code paths a sample hides behind
its environment checks. It derives, statically, the concrete values those checks
are keyed on and ties each candidate to the API call site that consumes it. Clew
does not defeat evasion itself. It produces the per-sample seed data that lets a
fuzzer do so, and it matters most for run-on-match checks, where a sample proceeds
only on a specific value that no generic default can supply.

## Why

Environment-sensitive malware gates its payload behind checks against the machine
it runs on, and one survey of over 180,000 samples found 68% of families contain
at least one evasive sample. Some of those checks hide on a match, like sandbox or
debugger detection, and a generic default that never matches already defeats them.
Others run only on a match. A binary that reads a username with `GetUserNameA` and
compares it against `"JohnDoe"` exits on every other name, so the only way to
unlock that path is the exact value the sample expects. That value lives in the
binary, and recovering it is what Clew does. See [docs/theory.md](docs/theory.md)
for the full argument.

## What it recovers

Clew recovers the values these checks compare against, among them DLL and device
names, registry paths, mutexes, usernames, and the numeric constants the checks
test. Each candidate is an API call site plus the value(s) that flow into it, a
provenance record, and a confidence score the downstream fuzzer uses to rank what
to try first.

Running Clew over a sample and reading one candidate from the record:

```bash
clew suspicious.exe          # writes results/<sha256>.clew.json
```

```json
{
  "call_site_va": "0x0046e2b9",
  "api_name": "LookupPrivilegeValueW",
  "parameter_index": 1,
  "candidate_values": [
    { "value": "SeDebugPrivilege", "confidence": 0.9,
      "source_channels": ["bn_xref", "floss"] }
  ],
  "evidence": { "string_source": "static" }
}
```

The sample looks up `SeDebugPrivilege` at `0x46e2b9`, recovered from a static
string that Binary Ninja and FLOSS both confirm (confidence 0.9). A fuzzer that
reaches this call site now knows the exact argument to supply. Fields are abridged
here. The full contract is in [docs/schema.md](docs/schema.md).

## Quickstart

Install:

```bash
pip install -e '.[dev,analysis]'
```

Run the static pipeline over a sample. A Binary Ninja license and capa rules/sigs
are required:

```bash
export CLEW_CAPA_RULES=/path/to/capa-rules
export CLEW_CAPA_SIGS=/path/to/capa-src/sigs
clew suspicious.exe
```

The record is written to `results/<sha256>.clew.json` by default. Pass `-o <path>`
to choose a location, or `-o -` to write to stdout. To add the dynamic comparison
operands, Clew detonates the sample under DynamoRIO in CAPE and correlates the
runtime comparisons back onto the record:

```bash
clew run suspicious.exe      # static, then detonate, then correlate
```

`clew --help` lists the commands. See [docs/usage.md](docs/usage.md) for the full
command reference and the end-to-end workflow.

## Prerequisites

- Binary Ninja 4.2.6455 Ultimate with an Enterprise license, for the core static
  analysis.
- capa rules and signatures, via `CLEW_CAPA_RULES` and `CLEW_CAPA_SIGS` (copy
  `.env.example` to `.env` and load it with `set -a; source .env; set +a`).
- A CAPE instance with the cmplog DynamoRIO package, for the dynamic step
  (`detonate`, `run`). The static pipeline runs without it.

Without a Binary Ninja license, the offline test suite still runs clean on a bare
checkout (see Tests).

## Documentation

- [docs/theory.md](docs/theory.md) — the problem and Clew's approach (read first).
- [docs/usage.md](docs/usage.md) — the command reference and end-to-end workflow.
- [docs/schema.md](docs/schema.md) — the record contract. The machine-checkable
  version is `schema/clew_record.schema.json`.
- [docs/binary_ninja_headless_setup.md](docs/binary_ninja_headless_setup.md) —
  headless Binary Ninja setup notes.

## Tests

```bash
pytest        # offline, fixture-driven; no BN license or capa rules needed
```

Expensive and licensed tests are opt-in via environment variables. `BN_INTEGRATION=1`
enables the licensed Binary Ninja analysis tests (needs a BN Enterprise license and
the fixture `.exe`), and `CAPA_RULES_PATH` with `CAPA_SIGS_PATH` enables the capa
integration tests. Tests skip when a required fixture is absent, so a clean checkout
runs a reduced but green suite.
