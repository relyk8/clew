"""Guard: the packaged version must match the record/schema version of record.

The pyproject `version` drifted from CLEW_VERSION once already because nothing
enforced the pairing. These tests make the offline suite enforce it.
"""

import pathlib
import re
from importlib.metadata import version

from clew.pipeline import CLEW_VERSION


def test_package_version_matches_clew_version():
    # Compares INSTALLED dist metadata (baked in at `pip install -e` time) to the
    # source constant -- validates the packaging round-trip, but only relative to
    # the last editable install. A version bump without a reinstall can make this
    # fail spuriously; the pyproject-reading test below is the install-independent
    # source-of-truth check.
    assert version("clew") == CLEW_VERSION


def _pyproject_version() -> str:
    text = (pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
    try:
        import tomllib  # stdlib in 3.11+
    except ModuleNotFoundError:  # 3.10: parse the version line directly, no dep
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
        assert m, "could not find project version in pyproject.toml"
        return m.group(1)
    return tomllib.loads(text)["project"]["version"]


def test_pyproject_version_matches_clew_version():
    # Install-independent source-of-truth check: reads the actual pyproject.toml
    # (works on the whole requires-python >=3.10 range, tomllib or regex fallback).
    assert _pyproject_version() == CLEW_VERSION
