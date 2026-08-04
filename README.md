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

## Installation

```bash
pipx install git+https://github.com/relyk8/clew
```

Clew needs a licensed Binary Ninja, a capa rules checkout, and, for the dynamic
step, a CAPE instance. Configure them once and check the result with `clew
doctor`. See [docs/installation.md](docs/installation.md) for every installation
and configuration method.

## Usage

```bash
clew suspicious.exe          # writes results/<sha256>.clew.json
clew run suspicious.exe      # static, then detonate, then correlate
```

`clew --help` lists the commands. See [docs/usage.md](docs/usage.md) for the full
command reference and the end-to-end workflow.

## Documentation

- [docs/theory.md](docs/theory.md) — the problem and Clew's approach (read first).
- [docs/installation.md](docs/installation.md) — installing, configuring, and
  verifying a setup, plus running the tests.
- [docs/usage.md](docs/usage.md) — the command reference and end-to-end workflow.
- [docs/schema.md](docs/schema.md) — the record contract. The machine-checkable
  version is `schema/clew_record.schema.json`.
- [docs/binary_ninja_headless_setup.md](docs/binary_ninja_headless_setup.md) —
  headless Binary Ninja setup notes.
