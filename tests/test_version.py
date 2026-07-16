"""Guard: the packaged version must match the record/schema version of record.

The pyproject `version` drifted from CLEW_VERSION once already because nothing
enforced the pairing. This test makes the offline suite enforce it.
"""

from importlib.metadata import version

from clew.pipeline import CLEW_VERSION


def test_package_version_matches_clew_version():
    assert version("clew") == CLEW_VERSION
