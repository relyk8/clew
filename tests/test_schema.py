"""Schema regression tests.

Validates that:
  - The schema itself is a well-formed JSON Schema (draft 2020-12).
  - All inline JSON record examples in docs/schema.md validate against it.
  - All hand-built fixture records under tests/fixtures/ validate against it.

Run with: pytest tests/test_schema.py -v
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "clew_record.schema.json"
DOC_PATH = REPO_ROOT / "docs" / "schema.md"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"

JSON_BLOCK_RE = re.compile(r"```json\n(.*?)\n```", re.DOTALL)


def _load_schema():
    return json.loads(SCHEMA_PATH.read_text())


def _doc_example_records():
    """Pull every full record example out of docs/schema.md."""
    if not DOC_PATH.exists():
        return []
    blocks = JSON_BLOCK_RE.findall(DOC_PATH.read_text())
    return [json.loads(b) for b in blocks if '"sample_sha256"' in b]


def _fixture_paths():
    if not FIXTURES_DIR.exists():
        return []
    return sorted(FIXTURES_DIR.glob("*.expected.json"))


def _format_errors(errors):
    return "\n" + "\n".join(
        f"  at {'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}"
        for e in errors
    )


def test_schema_is_well_formed():
    schema = _load_schema()
    jsonschema.Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize(
    "record",
    _doc_example_records(),
    ids=lambda r: r.get("sample_sha256", "?")[:12],
)
def test_doc_example_validates(record):
    validator = jsonschema.Draft202012Validator(_load_schema())
    errors = list(validator.iter_errors(record))
    assert not errors, _format_errors(errors)


@pytest.mark.parametrize(
    "fixture_path",
    _fixture_paths(),
    ids=lambda p: p.name,
)
def test_fixture_validates(fixture_path):
    validator = jsonschema.Draft202012Validator(_load_schema())
    record = json.loads(fixture_path.read_text())
    errors = list(validator.iter_errors(record))
    assert not errors, _format_errors(errors)