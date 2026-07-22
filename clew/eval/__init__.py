"""Evaluation & research tooling — not part of the analysis pipeline.

`oracle_grade` grades bridge output against hand-built `*.expected.json` oracles;
`novelty` scores CAPE-report IoCs to validate that candidates unlock hidden
behavior. Neither is imported by `clew.pipeline` / `clew.cli`; they are used by
tests and offline research, kept here so they stay importable without cluttering
the channel code.
"""
