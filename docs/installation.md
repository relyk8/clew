# Clew — installation

How to install Clew and point it at the tools it needs. For the commands
themselves, see [usage.md](usage.md). For the problem Clew solves, see
[theory.md](theory.md).

## Install

Install Clew into an environment of its own, so there is nothing to activate
before a run:

```bash
pipx install git+https://github.com/relyk8/clew
```

`uv tool install git+https://github.com/relyk8/clew` is equivalent. To work on
Clew itself, clone it and install editable with `pip install -e '.[dev,analysis]'`.

## What Clew cannot install for you

Three of Clew's dependencies are outside pip's reach, and all of the
configuration below exists to locate them:

- **Binary Ninja 4.2.6455 Ultimate**, with an Enterprise license. This is the
  core channel: without it the static pipeline cannot run at all. See
  [binary_ninja_headless_setup.md](binary_ninja_headless_setup.md) for the
  headless setup.
- **capa rules and signatures**, as a checkout. capa 9.4.0 ships its signatures
  in its source tree rather than the installed package, so the two paths differ.
- **A CAPE instance** with the cmplog DynamoRIO package, for the dynamic
  commands only. The static pipeline runs without it.

capa and CAPE are enrichment: if they are missing or misconfigured, Clew degrades
rather than failing. Binary Ninja is not.

## Configuration

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

Installed with pipx and have no checkout to copy from? Fetch the template
directly:

```bash
curl -o ~/.config/clew/config.env \
  https://raw.githubusercontent.com/relyk8/clew/main/.env.example
```

The settings, by channel:

| Variable | Purpose |
|---|---|
| `CLEW_BN_API` | directory containing the `binaryninja` package (Channel 2) |
| `BN_ENTERPRISE_SERVER` / `_USERNAME` / `_PASSWORD` | Binary Ninja Enterprise license checkout |
| `CLEW_CAPA_RULES` / `CLEW_CAPA_SIGS` | capa rules checkout and its signatures (Channel 0) |
| `CAPE_BASE_URL` | CAPE instance, used only by the dynamic commands (Channel 3) |

### Why `CLEW_BN_API` exists

Binary Ninja's `install_api.py` writes a `binaryninja.pth` into one specific
`site-packages`. An isolated install does not share that one, so `import
binaryninja` fails there with nothing to indicate why. Setting `CLEW_BN_API` to
the directory *containing* the `binaryninja` package is what makes it resolve.

Leave it unset if Binary Ninja already imports in Clew's environment, which is
the case for a virtualenv you built and ran `install_api.py` against yourself.

## Verify

```bash
clew doctor
```

`doctor` reports every prerequisite above and, for anything missing, the line
that fixes it. Its exit code answers one question, which is whether static
analysis will run: only Binary Ninja is a blocking failure, and capa, FLOSS, and
CAPE are warnings because Clew degrades past them.

Nothing is executed and no license seat is taken by default. Add `--license` to
additionally load Binary Ninja, compare its core version against the pinned one,
and confirm a checkout succeeds, which is the check worth running before a long
batch.

A configured install looks like this:

```
  +  python            3.12.3
  +  config            ~/.config/clew/config.env (6 key(s))
  +  binary ninja api  /path/to/binaryninja/python
  +  bn credentials    server https://binaryninja.example, username set, password set
  +  capa rules        /path/to/capa-rules
  +  capa binary       /path/to/venv/bin/capa (installed alongside clew)
  +  floss             importable
  +  cape              http://127.0.0.1:8000 reachable (1 task(s) visible)

All checks passed.
```

## Tests

```bash
pytest        # offline, fixture-driven; no BN license or capa rules needed
```

Expensive and licensed tests are opt-in through environment variables:
`BN_INTEGRATION=1` enables the licensed Binary Ninja tests, `FLOSS_INTEGRATION=1`
the slow real-FLOSS ones, and `CAPA_RULES_PATH` with `CAPA_SIGS_PATH` the capa
integration tests. Tests skip when a required fixture is absent, so a clean
checkout runs a reduced but green suite.
