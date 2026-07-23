# Binary Ninja Headless Setup (clew / Channel 2)

This document covers running Binary Ninja in **headless mode** for clew's
Channel 2 work (call-site enumeration and the dataflow bridge). It assumes a
Binary Ninja Enterprise (floating-license) deployment. Adapt the license step if
you have a standalone license.

Clew pins **Binary Ninja core `4.2.6455 Ultimate`** (`BN_PINS` in
`clew/channels/binaryninja/callsites.py`). Bump on re-validation.

---

## One-time setup

1. **Install Binary Ninja** wherever you keep it (the convention is
   `/opt/binaryninja`, but any path works as long as the Python API is pointed at
   it). Note the install directory, which we call `$BN_INSTALL`.

2. **Wire the Python API into your environment.** Run Binary Ninja's bundled
   `install_api.py` against the Python interpreter/venv you'll use for clew, so
   that `import binaryninja` resolves:

   ```bash
   python "$BN_INSTALL/scripts/install_api.py"
   ```

3. **Create a local environment file** (e.g. `bn_env.sh`) that exports your
   Enterprise server URL and license credentials as environment variables. Keep
   this file **out of the repository**, since it holds credentials. A `.gitignore`
   entry for it is a good idea.

---

## Setup (every session)

Activate the venv that has the API wired in, then source your environment file:

```bash
source /path/to/venv/bin/activate
source bn_env.sh
```

The env file supplies the Enterprise server URL and credentials, so the license
checkout works with no further configuration. Environment variables don't
survive across separate shells or SSH sessions, so re-source `bn_env.sh` in each
new shell.

> Never copy license credentials into the repository or anywhere public. Keep
> them in the local, gitignored env file.

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
and **releases it automatically** when the block exits, so you don't hold a seat
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
You didn't source your env file in this shell (env vars don't survive across
separate SSH sessions). Re-source `bn_env.sh`.

**`Could not checkout a license: Not authenticated`**
Same cause. The credentials env vars aren't set in the current shell. Re-source
your env file. If it still fails, the account password may have changed, or the
server may have switched to SSO, which username/password auth can't satisfy.

**TLS / certificate errors**
If the Enterprise server uses an internal or self-signed certificate and the
client rejects it, the host's CA may need to be added to the system trust store.
(A successful checkout confirms the cert is trusted. If checkout works, this
isn't your problem.)

**`database is locked` (Error while saving database snapshot)**
Binary Ninja uses SQLite for `.bndb` databases, so only one process can open a
given database at a time. Don't have the GUI open on the same database a headless
script is touching. Close all instances and retry.

**Wrong/old version picked up**
Confirm `import binaryninja` reports `4.2.6455 Ultimate`. If it reports something
else, another Binary Ninja install may be shadowing the intended one in your
environment.
