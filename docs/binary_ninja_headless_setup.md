# Binary Ninja Headless Setup (clew / Channel 2)

This document covers running Binary Ninja in **headless mode** on `ml-cluster-01`
for clew's Channel 2 work (call-site enumeration and the dataflow bridge).

The Binary Ninja application, the clew virtual environment, and a shared
credentials file are **already set up**. Per-researcher setup is just **two
`source` commands**.

---

## What's already set up (shared, do not repeat)

- **Application:** Binary Ninja 4.2.6455 Ultimate, extracted to
  `/home/shared/binaryninja/` (group-readable).
- **Python API wiring:** `install_api.py` has already been run against the shared
  clew venv, so `import binaryninja` resolves there. You do **not** need to run it
  again.
- **Shared venv:** `/home/shared/clew-env/clew/.venv`
- **Shared environment file:** `/home/shared/clew-env/bn_env.sh` — sets the
  Enterprise server URL and the shared account credentials.

> Note: this is a non-standard install location (convention is `/opt/binaryninja`).
> It lives under `/home/shared` because that's the large data partition (11 TB)
> and where the rest of the shared researcher files live. Anything that assumes
> the default path needs to be pointed at `/home/shared/binaryninja` explicitly.

---

## Setup (every session)

Two commands — activate the shared venv, then source the shared environment file:

```bash
source /home/shared/clew-env/clew/.venv/bin/activate
source /home/shared/clew-env/bn_env.sh
```

That's the whole setup. The env file provides the Enterprise server URL and the
shared school account credentials, so the license checkout works with no further
configuration.

> The `bn_env.sh` file contains the shared school account credentials. This is a
> default account issued to the whole group, so the password is shared by design —
> there's nothing private to protect here. Keep the file inside `/home/shared`;
> don't copy credentials into the repo or anywhere public.

---

## Running headless

### Verify your setup

Confirm the API resolves:

```bash
python -c "import binaryninja; print(binaryninja.core_version())"
# expected: 4.2.6455 Ultimate
```

Confirm a floating-license checkout works:

```bash
python -c "
from binaryninja.enterprise import LicenseCheckout
import binaryninja
with LicenseCheckout():
    print('BN version:', binaryninja.core_version())
    print('Headless license acquired successfully')
"
```

If you see `Headless license acquired successfully`, you're ready to work.

### Use the checkout in your own scripts

Always wrap analysis in the `LicenseCheckout` context manager. It connects to the
server, authenticates with the env-var credentials, checks out a floating seat,
and **releases it automatically** when the block exits — so you don't hold a seat
longer than needed.

```python
from binaryninja.enterprise import LicenseCheckout
import binaryninja

with LicenseCheckout():
    bv = binaryninja.load("/path/to/sample.exe")
    bv.update_analysis_and_wait()
    for func in bv.functions:
        ...  # Channel 2 analysis: enumerate call sites, walk MLIL, etc.
# license released here
```

---

## Troubleshooting

**`Unknown Enterprise Server URL` (RuntimeError on checkout)**
You didn't source `bn_env.sh` in this shell (env vars don't survive across separate
SSH sessions). Re-run `source /home/shared/clew-env/bn_env.sh`.

**`Could not checkout a license: Not authenticated`**
Same cause — the credentials env vars aren't set in the current shell. Re-source
`bn_env.sh`. If it still fails, the shared account password may have changed (ask
the group) or the server may have switched to SSO, which username/password auth
can't satisfy.

**TLS / certificate errors**
The server (`*.cdn.local`) uses an internal certificate. If the client rejects it,
the host's CA may need to be added to the system trust store. (A successful
checkout confirms the cert is trusted; if checkout works, this isn't your problem.)

**`database is locked` (Error while saving database snapshot)**
Binary Ninja uses SQLite for `.bndb` databases — only one process can open a given
database at a time. Don't have the GUI open on the same database a headless script
is touching. Close all instances and retry.

**Wrong/old version picked up**
Confirm `import binaryninja` reports `4.2.6455 Ultimate`. If it reports something
else, another Binary Ninja install may be shadowing the shared one in your
environment.
