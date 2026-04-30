import os
from pathlib import Path

import pytest


@pytest.fixture
def capa_paths():
    rules = os.environ.get("CAPA_RULES_PATH")
    sigs = os.environ.get("CAPA_SIGS_PATH")
    if not rules or not sigs:
        pytest.skip("Set CAPA_RULES_PATH and CAPA_SIGS_PATH to run capa integration tests")
    return Path(rules), Path(sigs)


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"
