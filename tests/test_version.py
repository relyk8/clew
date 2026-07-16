"""Guard: the packaged version must match the record/schema version of record.

The pyproject `version` drifted from CLEW_VERSION once already because nothing
enforced the pairing. These tests make the offline suite enforce it.
"""

import sys
from importlib.metadata import version

import pytest

from clew.pipeline import CLEW_VERSION


def test_package_version_matches_clew_version():
    # Compares INSTALLED dist metadata (baked in at `pip install -e` time) to the
    # source constant -- validates the packaging round-trip, but only relative to
    # the last editable install. A version bump without a reinstall can make this
    # fail spuriously; the pyproject-reading test below is the install-independent
    # source-of-truth check.
    assert version("clew") == CLEW_VERSION


@pytest.mark.skipif(sys.version_info < (3, 11), reason="tomllib is stdlib in 3.11+")
def test_pyproject_version_matches_clew_version():
    import pathlib

    import tomllib

    root = pathlib.Path(__file__).resolve().parents[1]
    with (root / "pyproject.toml").open("rb") as f:
        data = tomllib.load(f)
    assert data["project"]["version"] == CLEW_VERSION
