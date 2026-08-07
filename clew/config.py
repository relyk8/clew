"""Layered configuration for the clew CLI.

clew reads its machine-specific settings (capa rules and signatures, the CAPE
base URL, the Binary Ninja API location and Enterprise credentials) from the
process environment. That works, but it forces every invocation to be preceded
by shell setup -- sourcing a virtualenv and an environment script -- which makes
the tool feel like a checkout rather than something installed.

This module lets those settings live in a file instead, without changing how any
of them are consumed: everything still arrives as an environment variable, and
the process environment always wins. Sources, in decreasing precedence:

1. the process environment (anything already exported, or set inline for one run)
2. ``./.env`` in the working directory (the existing per-checkout convention)
3. ``~/.config/clew/config.env`` (or ``$XDG_CONFIG_HOME/clew/config.env``)

The precedence rule is enforced by applying sources in that order and never
overwriting a key that is already set: the first source to define a key wins,
and a variable already present in the environment always survives. That makes
loading purely additive -- every command that worked before this module existed
behaves identically after it.

The file format is the ``KEY=value`` subset of shell that an environment script
already uses, including an optional ``export`` prefix, so an existing file
written for ``source`` can be pointed at directly with no edits.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path

_log = logging.getLogger("clew.config")

# The settings clew consumes. Loading is not restricted to these -- a config file
# may define anything, matching `set -a; source .env` semantics -- but these are
# what the tool itself reads, and what `clew doctor` reports on.
CONFIG_KEYS = (
    "CLEW_CAPA_RULES",
    "CLEW_CAPA_SIGS",
    "CLEW_BN_API",
    "CAPE_BASE_URL",
    "BN_ENTERPRISE_SERVER",
    "BN_ENTERPRISE_USERNAME",
    "BN_ENTERPRISE_PASSWORD",
)

# Keys whose values are secrets. Used to decide whether a world-readable config
# file is worth warning about, and to redact values in diagnostic output.
_SECRET_MARKERS = ("PASSWORD", "TOKEN", "SECRET", "KEY")


@dataclass(frozen=True)
class LoadedFile:
    """One config file that was found and read.

    `defined` is every key the file sets; `applied` is the subset that actually
    took effect, i.e. was not already present in the environment (or set by a
    higher-precedence file). The difference is exactly what a user needs to see
    when a config file appears to be ignored.
    """

    path: Path
    defined: tuple[str, ...]
    applied: tuple[str, ...]


# Populated by load_config() so the CLI can report what happened once logging is
# configured. Loading has to run before argparse builds its parser (several
# defaults read os.environ at construction time), which is before the -v/-q
# flags have been parsed, so the load itself cannot emit debug output.
_loaded: tuple[LoadedFile, ...] = ()


def user_config_path() -> Path:
    """Return the per-user config location, honouring XDG_CONFIG_HOME."""
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "clew" / "config.env"


def is_secret(key: str) -> bool:
    """True if a key's value should be treated as a credential."""
    return any(marker in key.upper() for marker in _SECRET_MARKERS)


def parse_env_file(text: str, *, source: str = "<string>") -> dict[str, str]:
    """Parse the KEY=value subset of shell used by environment scripts.

    Recognises blank lines, ``#`` comments, an optional ``export`` prefix, and
    values wrapped in matching single or double quotes. Inline comments are not
    stripped: an unquoted ``#`` is part of the value, because credentials
    legitimately contain one. Malformed lines are warned about and skipped
    rather than raising, so one bad line cannot make the tool unusable.
    """
    values: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            _log.warning("%s:%d: ignoring line without a KEY=value assignment", source, lineno)
            continue
        if not key.replace("_", "").isalnum():
            _log.warning("%s:%d: ignoring line with a non-identifier key %r", source, lineno, key)
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values


def _warn_if_exposed(path: Path, keys: tuple[str, ...]) -> None:
    # A config file holding the Binary Ninja Enterprise password should not be
    # readable by other users on a shared analysis box. Warn only when the file
    # actually carries a secret, so the ordinary all-paths config stays quiet.
    if not any(is_secret(k) for k in keys):
        return
    try:
        mode = path.stat().st_mode
    except OSError:  # pragma: no cover - stat failing after a successful read
        return
    if mode & 0o077:
        _log.warning(
            "%s is readable by other users (mode %o) and holds credentials; "
            "restrict it with: chmod 600 %s",
            path,
            mode & 0o777,
            path,
        )


def _apply_file(path: Path) -> LoadedFile | None:
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    except OSError as e:
        _log.warning("cannot read config file %s: %s", path, e)
        return None

    values = parse_env_file(text, source=str(path))
    if not values:
        return LoadedFile(path=path, defined=(), applied=())

    applied = []
    for key, value in values.items():
        # This is the precedence rule: anything already in the environment --
        # exported by the user, or set by a higher-precedence file -- stands.
        if key in os.environ:
            continue
        os.environ[key] = value
        applied.append(key)

    loaded = LoadedFile(path=path, defined=tuple(values), applied=tuple(applied))
    _warn_if_exposed(path, loaded.defined)
    return loaded


def config_sources() -> tuple[Path, ...]:
    """The config file locations, in decreasing precedence."""
    return (Path(".env"), user_config_path())


def default_capa_bin() -> str:
    """Resolve the capa executable to invoke.

    capa is the one channel driven as a subprocess, and it has always been
    looked up as a bare ``capa`` on PATH. That breaks precisely where clew is
    otherwise most convenient: an isolated install (pipx, uv tool) puts only
    clew's own entry point on PATH and leaves its dependencies' console scripts
    inside a venv nothing else can see, so Channel 0 would fail on exactly the
    installation the README recommends.

    Prefer the capa sitting next to the interpreter running clew, which is where
    pip puts it when it installs clew's dependencies, and fall back to a PATH
    lookup so an externally-managed capa still wins when there is no bundled one.
    """
    bindir = Path(sys.executable).parent
    for name in ("capa", "capa.exe"):
        candidate = bindir / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return "capa"


def ensure_bn_on_path() -> Path | None:
    """Make the Binary Ninja Python API importable, if CLEW_BN_API points at it.

    Binary Ninja is not a pip dependency -- it is licensed, installed out of
    band, and reaches the interpreter through a ``binaryninja.pth`` that its
    install_api.py drops into a specific site-packages. That works for a
    virtualenv the user built by hand, and not at all for an isolated install
    (pipx, uv tool), whose site-packages nothing ever wrote a .pth into.

    Setting CLEW_BN_API to the directory *containing* the ``binaryninja``
    package closes that gap without asking anyone to hand-edit an isolated
    environment. Every ``import binaryninja`` in the codebase is lazy, inside
    the functions that need it, so amending sys.path at startup is early enough.

    Returns the directory added, or None when the variable is unset or unusable.
    """
    raw = os.environ.get("CLEW_BN_API")
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_dir():
        _log.warning("CLEW_BN_API=%s is not a directory; ignoring it", path)
        return None
    if not (path / "binaryninja").is_dir():
        # Not fatal -- a layout we do not recognise may still import -- but this
        # is far and away the most likely misconfiguration, and the resulting
        # ImportError much later gives no hint that this variable caused it.
        _log.warning(
            "CLEW_BN_API=%s does not contain a 'binaryninja' package directory; "
            "it should point at the API directory of a Binary Ninja install",
            path,
        )
    entry = str(path)
    if entry not in sys.path:
        sys.path.insert(0, entry)
    return path


def load_config() -> tuple[LoadedFile, ...]:
    """Load config files into the environment and return what was read.

    Also makes the Binary Ninja API importable if the loaded configuration asks
    for it, so a single call establishes clew's whole runtime configuration.

    Idempotent in effect: no assignment overwrites an existing variable, so a
    second call cannot change what the first established.
    """
    global _loaded
    loaded = []
    for path in config_sources():
        entry = _apply_file(path)
        if entry is not None:
            loaded.append(entry)
    _loaded = tuple(loaded)
    ensure_bn_on_path()
    return _loaded


def loaded_files() -> tuple[LoadedFile, ...]:
    """What the last load_config() call read. Empty before it runs."""
    return _loaded
