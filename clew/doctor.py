"""Preflight checks for a clew installation.

clew depends on things pip cannot install: a licensed Binary Ninja, a capa rules
checkout, a CAPE instance with the cmplog DynamoRIO package. When one of them is
missing or misconfigured the failure surfaces deep inside a run -- often minutes
in, after a Binary Ninja seat has already been checked out -- as an error that
names the symptom and not the cause.

`clew doctor` answers "will this actually run, and if not, what do I fix" before
any of that is spent. Every check reports what it found and, when it found a
problem, the specific line that fixes it.

Checks are ordered from the pipeline's core outward: the interpreter, then the
configuration, then Channel 2 (Binary Ninja, the core channel), then the
enrichment channels, then Channel 3's dynamic infrastructure. Only a failure
that stops the core pipeline is a hard failure; a missing enrichment channel is
a warning, because the pipeline is designed to degrade past it.

Nothing here executes a sample, consumes a license seat, or loads the Binary
Ninja core unless --license is passed, so it is safe and fast to run anywhere.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from clew.config import config_sources, default_capa_bin, loaded_files, user_config_path

OK = "ok"
WARN = "warn"
FAIL = "fail"
SKIP = "skip"

_SYMBOLS = {OK: "+", WARN: "!", FAIL: "x", SKIP: "-"}

# Minimum interpreter, mirroring requires-python in pyproject.toml.
_MIN_PYTHON = (3, 10)


def _short(path: Path | str) -> str:
    """Render a path with the home directory contracted to ~.

    Fix lines name the config file repeatedly; spelled in full they dominate the
    report and push the actual advice off the edge of a terminal.
    """
    text = str(path)
    home = str(Path.home())
    if text == home:
        return "~"
    if text.startswith(home + os.sep):
        return "~" + text[len(home) :]
    return text


@dataclass(frozen=True)
class Check:
    """One preflight result.

    `fix` is the command or edit that resolves a WARN/FAIL. It is printed
    verbatim under the row, so it should be something the user can act on
    without further translation.
    """

    name: str
    status: str
    detail: str
    fix: str | None = None


def check_python() -> Check:
    v = sys.version_info
    detail = f"{v.major}.{v.minor}.{v.micro}"
    if (v.major, v.minor) < _MIN_PYTHON:
        return Check(
            "python",
            FAIL,
            f"{detail} (clew needs >= {_MIN_PYTHON[0]}.{_MIN_PYTHON[1]})",
            fix=f"install clew under python {_MIN_PYTHON[0]}.{_MIN_PYTHON[1]} or newer",
        )
    return Check("python", OK, detail)


def check_config() -> Check:
    loaded = loaded_files()
    if not loaded:
        searched = ", ".join(_short(p) for p in config_sources())
        return Check(
            "config",
            SKIP,
            f"no config file found (searched {searched})",
            fix=f"optional: keep settings in {_short(user_config_path())} instead of exporting them",
        )
    parts = [f"{_short(entry.path)} ({len(entry.defined)} key(s))" for entry in loaded]
    return Check("config", OK, "; ".join(parts))


def check_bn_api() -> Check:
    # find_spec, not import: locating the package proves the path wiring without
    # loading the Binary Ninja core or touching a license.
    configured = os.environ.get("CLEW_BN_API")
    try:
        spec = importlib.util.find_spec("binaryninja")
    except (ImportError, ValueError):
        spec = None
    if spec is not None and spec.origin:
        # Report the directory *containing* the package, which is what
        # CLEW_BN_API names, so the row and the setting can be compared directly.
        api_dir = _short(Path(spec.origin).parent.parent)
        detail = api_dir if configured else f"{api_dir} (already on sys.path)"
        return Check("binary ninja api", OK, detail)
    if configured:
        return Check(
            "binary ninja api",
            FAIL,
            f"not importable, and CLEW_BN_API={configured} did not provide it",
            fix="point CLEW_BN_API at the directory containing the 'binaryninja' package",
        )
    return Check(
        "binary ninja api",
        FAIL,
        "not importable (Channel 2 is the core channel; static analysis cannot run)",
        fix=f"set CLEW_BN_API=/path/to/binaryninja/python in {_short(user_config_path())}",
    )


def check_bn_credentials() -> Check:
    keys = ("BN_ENTERPRISE_SERVER", "BN_ENTERPRISE_USERNAME", "BN_ENTERPRISE_PASSWORD")
    missing = [k for k in keys if not os.environ.get(k)]
    if not missing:
        server = os.environ.get("BN_ENTERPRISE_SERVER", "")
        return Check("bn credentials", OK, f"server {server}, username set, password set")
    if len(missing) == len(keys):
        return Check(
            "bn credentials",
            WARN,
            "unset; the license checkout in `clew static` will fail unless a seat "
            "is already held or --no-license-checkout is passed",
            fix=f"add BN_ENTERPRISE_SERVER/USERNAME/PASSWORD to {_short(user_config_path())}",
        )
    return Check(
        "bn credentials",
        WARN,
        f"incomplete, missing: {', '.join(missing)}",
        fix=f"add the missing key(s) to {_short(user_config_path())}",
    )


def check_bn_license() -> Check:
    """Import Binary Ninja for real and take a license seat. Opt-in (--license)."""
    try:
        import binaryninja
    except ImportError as e:
        return Check("bn license", FAIL, f"cannot import binaryninja: {e}")
    try:
        from clew.channels.binaryninja.callsites import BN_PINS

        pinned = BN_PINS.get("core_version")
    except ImportError:  # pragma: no cover - defensive
        pinned = None
    try:
        core = binaryninja.core_version()
    except Exception as e:  # noqa: BLE001 - native BN core; doctor must never crash
        return Check("bn license", FAIL, f"binaryninja imported but core_version() failed: {e}")
    # The pinned version is what the channel's behaviour was validated against;
    # a mismatch is not fatal but does mean analysis output may shift.
    version_note = ""
    if pinned and pinned not in str(core):
        version_note = f" (validated against {pinned})"
    try:
        from binaryninja.enterprise import LicenseCheckout

        with LicenseCheckout():
            return Check("bn license", OK, f"checkout succeeded, core {core}{version_note}")
    except ImportError:
        return Check("bn license", WARN, f"core {core}{version_note}, not an Enterprise build")
    except Exception as e:  # noqa: BLE001 - license server errors are not a fixed type
        return Check(
            "bn license",
            FAIL,
            f"core {core}{version_note}, checkout failed: {e}",
            fix="verify BN_ENTERPRISE_SERVER/USERNAME/PASSWORD and that a seat is free",
        )


def _check_dir(name: str, env_var: str, what: str) -> Check:
    raw = os.environ.get(env_var)
    if not raw:
        return Check(
            name,
            WARN,
            f"{env_var} not set; only needed when you pass --capa, which is off "
            "by default",
            fix=f"set {env_var} to your {what} in {_short(user_config_path())}",
        )
    path = Path(raw).expanduser()
    if not path.is_dir():
        return Check(name, WARN, f"{path} does not exist", fix=f"correct {env_var}")
    if not any(path.iterdir()):
        return Check(name, WARN, f"{path} is empty", fix=f"correct {env_var}")
    return Check(name, OK, str(path))


def check_capa_rules() -> Check:
    return _check_dir("capa rules", "CLEW_CAPA_RULES", "capa-rules checkout")


def check_capa_sigs() -> Check:
    return _check_dir("capa sigs", "CLEW_CAPA_SIGS", "capa signatures directory")


def check_capa_bin() -> Check:
    # capa is the one channel invoked as a subprocess. Resolve it exactly the way
    # the pipeline will, so the report cannot disagree with what a run does.
    resolved = default_capa_bin()
    if os.path.isabs(resolved):
        return Check("capa binary", OK, f"{_short(resolved)} (installed alongside clew)")
    found = shutil.which(resolved)
    if found:
        return Check("capa binary", OK, f"{found} (on PATH)")
    return Check(
        "capa binary",
        WARN,
        "capa not found; only needed when you pass --capa, which is off by default",
        fix="pip install 'flare-capa>=9.4.0,<10' into the same environment as clew",
    )


def check_floss() -> Check:
    if importlib.util.find_spec("floss") is not None:
        return Check("floss", OK, "importable")
    return Check(
        "floss",
        WARN,
        "flare-floss not importable; Channel 1 degrades to BN-only static strings",
        fix="pip install 'flare-floss==3.1.1' into the same environment as clew",
    )


def check_cape(base_url: str, *, timeout: int) -> Check:
    if importlib.util.find_spec("requests") is None:
        return Check("cape", WARN, "requests not installed; Channel 3 unavailable")
    from clew.channels.cape.client import CapeClient, CapeError

    try:
        client = CapeClient(base_url, http_timeout=timeout)
        tasks = client.list_tasks(limit=1)
    except CapeError as e:
        return Check(
            "cape",
            WARN,
            f"{base_url} unreachable ({e}); Channel 3 unavailable, static is unaffected",
            fix=f"start CAPE, or set CAPE_BASE_URL in {_short(user_config_path())}",
        )
    except Exception as e:  # noqa: BLE001 - requests raises a wide family; report, never crash
        return Check("cape", WARN, f"{base_url} unreachable ({type(e).__name__}: {e})")
    return Check("cape", OK, f"{base_url} reachable ({len(tasks)} task(s) visible)")


def check_cape_storage(storage_root: str) -> Check:
    path = Path(storage_root)
    if not path.is_dir():
        return Check(
            "cape storage",
            SKIP,
            f"{path} not present; `correlate --task` needs CAPE storage on this host",
            fix="use `correlate --cmplog-dir` when running off the CAPE host",
        )
    if not os.access(path, os.R_OK):
        return Check("cape storage", WARN, f"{path} not readable", fix=f"check permissions on {path}")
    return Check("cape storage", OK, str(path))


def run_checks(*, cape_url: str, storage_root: str, timeout: int, license_check: bool) -> list[Check]:
    checks = [
        check_python(),
        check_config(),
        check_bn_api(),
        check_bn_credentials(),
    ]
    if license_check:
        checks.append(check_bn_license())
    checks += [
        check_capa_rules(),
        check_capa_sigs(),
        check_capa_bin(),
        check_floss(),
        check_cape(cape_url, timeout=timeout),
        check_cape_storage(storage_root),
    ]
    return checks


def format_report(checks: list[Check], *, version: str, location: str) -> str:
    width = max(len(c.name) for c in checks)
    lines = [f"clew {version}  ({location})", ""]
    for c in checks:
        lines.append(f"  {_SYMBOLS[c.status]}  {c.name.ljust(width)}  {c.detail}")
        if c.fix and c.status in (WARN, FAIL, SKIP):
            lines.append(f"     {' ' * width}  fix: {c.fix}")
    failed = [c for c in checks if c.status == FAIL]
    warned = [c for c in checks if c.status == WARN]
    lines.append("")
    if failed:
        lines.append(f"{len(failed)} blocking problem(s), {len(warned)} warning(s).")
    elif warned:
        lines.append(f"No blocking problems, {len(warned)} warning(s) -- static analysis will run.")
    else:
        lines.append("All checks passed.")
    return "\n".join(lines)


def has_failures(checks: list[Check]) -> bool:
    return any(c.status == FAIL for c in checks)
