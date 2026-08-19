import os
import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _restore_process_environment():
    """Snapshot and restore os.environ and sys.path around every test.

    clew.config.load_config() writes config-file values straight into
    os.environ, and ensure_bn_on_path() amends sys.path. Neither goes through
    monkeypatch, so those mutations outlive the test that triggered them. The
    first CLI test to call main() therefore leaks the developer's real Binary
    Ninja Enterprise credentials into the whole pytest process, which makes
    `import binaryninja` succeed for every later test. BN-gated cases in
    test_oracle_grade.py then acquire a license seat and run a full al-khaser
    analysis instead of skipping.

    Restoring both globals after each test keeps every test observably
    isolated, the way monkeypatch already does where it is used explicitly.
    """
    env_before = dict(os.environ)
    path_before = list(sys.path)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(env_before)
        sys.path[:] = path_before


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
