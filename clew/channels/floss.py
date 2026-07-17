"""Channel 1: FLOSS string extraction.

Wraps flare-floss (called in-process, not via subprocess) and adapts its
typed result objects into a FlossResult. FLOSS is a value channel: it
contributes candidate *values* (DLL names, registry paths, VM-artifact
strings), never call-site matches. Channel 2 (BN/Ghidra xref) is what
maps these values to their API call sites. See docs/schema_v2_notes.md
(findings #2 and #4) for the architectural note.

FLOSS emits four string categories that map 1:1 to the schema's
`string_source` enum:

    static_strings  -> static
    stack_strings   -> stackstring
    tight_strings   -> tightstring
    decoded_strings -> decoded

FLOSS additionally emits `language_strings` / `language_strings_missed`
(Go/Rust/.NET language-specific extraction); these are outside the
current schema enum and are deliberately dropped here. Tracked in
docs/schema_v2_notes.md as v2 item #16.

This channel does no semantic/regex filtering: it preserves every string
FLOSS returns, tagged by source category and its native location fields,
because Channel 2 needs that location data to perform the call-site join
and cannot recover strings dropped here. FLOSS's own MIN_STRING_LENGTH
floor is the only length filter applied (passed through as min_length).

Orchestration note: run_floss() mirrors the extraction sequence in
floss.main.main() but NOT its CLI machinery. In particular it constructs
the Analysis object explicitly and never reaches main()'s interactive
"enable string deobfuscation? [y/N]" stdin prompt, which in a non-TTY
context silently disables stack/tight/decoded extraction. It also
replicates main()'s stack-vs-tight function exclusion (stack strings are
not extracted from tight-loop functions when tight extraction is on).

Version pinning: FLOSS bundles its own signatures (separate from capa's),
defaulting to floss.get_default_root()/"sigs". FLOSS_PINS records the
currently-validated version; bump when re-validating.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# Validated pin from the Channel 1 pilot (docs/pilot_results.md).
# FLOSS ships its signatures inside the package, so unlike capa there is
# no separate rules/sigs repo to pin — only the flare-floss version.
FLOSS_PINS: dict[str, str] = {
    "flare_floss": "3.1.1",
}


class FlossError(Exception):
    """Base error for Channel 1."""


class FlossImportError(FlossError):
    """flare-floss is not importable / not installed in this environment."""


class FlossRunError(FlossError):
    """FLOSS analysis failed (workspace load or extraction raised)."""


class FlossParseError(FlossError):
    """A saved FLOSS results file could not be loaded/parsed."""


@dataclass(frozen=True)
class FlossString:
    """One extracted string, tagged by source category, with the native
    location fields FLOSS provides for that category preserved verbatim.

    `source` is the schema `string_source` value ("static", "stackstring",
    "tightstring", "decoded"). `value` is the string itself. `encoding` is
    FLOSS's StringEncoding name ("ASCII"/"UTF16LE"/"UTF8").

    Location is category-dependent and intentionally NOT normalized here
    (Channel 2 owns the join logic and decides how to use each kind):

      static     -> offset (file offset)
      stackstring / tightstring -> function, program_counter, frame_offset
      decoded    -> address, address_type ("STACK"/"GLOBAL"/"HEAP"),
                    decoding_routine

    Fields not applicable to a category are None.
    """

    value: str
    source: str
    encoding: str
    # static
    offset: Optional[int] = None
    # stack / tight
    function: Optional[int] = None
    program_counter: Optional[int] = None
    frame_offset: Optional[int] = None
    # decoded
    address: Optional[int] = None
    address_type: Optional[str] = None
    decoding_routine: Optional[int] = None


@dataclass(frozen=True)
class FlossResult:
    static: list[FlossString]
    stackstring: list[FlossString]
    tightstring: list[FlossString]
    decoded: list[FlossString]
    min_length: int
    raw: object  # the underlying floss.results.ResultDocument

    def all_strings(self) -> list[FlossString]:
        """Flat list across all four categories (location preserved)."""
        return [*self.static, *self.stackstring, *self.tightstring, *self.decoded]

    def values(self) -> set[str]:
        """Set of distinct string values across all categories.

        Convenience for value-membership checks (e.g. 'does FLOSS cover
        this DLL fingerprint?'). Discards location — use all_strings() when
        location matters.
        """
        return {s.value for s in self.all_strings()}


# --- category adapters: floss.results.* dataclass -> FlossString --------------
# Kept independently testable (mirrors capa._parse_capa_json's separation),
# so unit tests can adapt a loaded fixture without running FLOSS.


def _adapt_static(s) -> FlossString:
    return FlossString(
        value=s.string,
        source="static",
        encoding=s.encoding.name,
        offset=s.offset,
    )


def _adapt_stack(s, source: str) -> FlossString:
    # StackString and TightString share a shape; `source` distinguishes them.
    return FlossString(
        value=s.string,
        source=source,
        encoding=s.encoding.name,
        function=s.function,
        program_counter=s.program_counter,
        frame_offset=s.frame_offset,
    )


def _adapt_decoded(s) -> FlossString:
    return FlossString(
        value=s.string,
        source="decoded",
        encoding=s.encoding.name,
        address=s.address,
        address_type=s.address_type.name,
        decoding_routine=s.decoding_routine,
    )


def _adapt_result_document(doc, min_length: int) -> FlossResult:
    """Adapt a floss.results.ResultDocument into a FlossResult.

    Drops language_strings / language_strings_missed (v2 item #16).
    """
    strings = doc.strings
    return FlossResult(
        static=[_adapt_static(s) for s in strings.static_strings],
        stackstring=[_adapt_stack(s, "stackstring") for s in strings.stack_strings],
        tightstring=[_adapt_stack(s, "tightstring") for s in strings.tight_strings],
        decoded=[_adapt_decoded(s) for s in strings.decoded_strings],
        min_length=min_length,
        raw=doc,
    )


def load_floss_results(path: Path, min_length: int = 4) -> FlossResult:
    """Load a saved FLOSS JSON results file into a FlossResult.

    Mirrors capa's saved-JSON unit-test pattern: lets tests exercise the
    adapter offline without running the (~100s) analysis. Uses
    floss.results.read, the JSON-file deserializer (read(path) ->
    ResultDocument). NB: do NOT confuse this with floss.results.load or
    floss.main.load — both of those ASSEMBLE a ResultDocument from a live
    vivisect workspace and take (sample, analysis, functions, min_length).
    The file reader is `read`.
    """
    try:
        import floss.results as fr
    except ImportError as e:  # pragma: no cover - environment guard
        raise FlossImportError("flare-floss is not installed") from e

    try:
        doc = fr.read(Path(path))
    except Exception as e:
        raise FlossParseError(f"could not load FLOSS results from {path}: {e}") from e

    md_min = getattr(getattr(doc, "metadata", None), "min_length", None)
    return _adapt_result_document(doc, md_min if isinstance(md_min, int) else min_length)


def run_floss(
    sample_path: Path,
    *,
    min_length: int = 4,
    sigs_path: Optional[Path] = None,
    fmt: str = "auto",
    enable_static: bool = True,
    enable_stack: bool = True,
    enable_tight: bool = True,
    enable_decoded: bool = True,
    save_workspace: bool = False,
) -> FlossResult:
    """Run FLOSS against a PE and return a FlossResult.

    Drives FLOSS's extractor functions directly in floss.main's order,
    constructing the Analysis object explicitly (so we never hit main()'s
    interactive deobfuscation prompt). Defaults to FLOSS's bundled
    signatures unless sigs_path is given.

    Raises FlossImportError if flare-floss is unavailable, FlossRunError if
    workspace load or extraction fails.
    """
    try:
        import floss.main as fm
        from floss.results import Analysis, Metadata, ResultDocument
    except ImportError as e:
        raise FlossImportError("flare-floss is not installed") from e

    sample_path = Path(sample_path)

    analysis = Analysis(
        enable_static_strings=enable_static,
        enable_stack_strings=enable_stack,
        enable_tight_strings=enable_tight,
        enable_decoded_strings=enable_decoded,
    )
    doc = ResultDocument(
        metadata=Metadata(file_path=str(sample_path), min_length=min_length),
        analysis=analysis,
    )

    # 1. static strings — always cheap, also used for language id upstream.
    try:
        static_strings = fm.get_static_strings(sample_path, min_length)
    except Exception as e:
        raise FlossRunError(f"static string extraction failed: {e}") from e

    if analysis.enable_static_strings:
        doc.strings.static_strings = static_strings

    deobf = enable_stack or enable_tight or enable_decoded
    if deobf:
        # 2. build the vivisect workspace (the expensive step).
        sigs = sigs_path if sigs_path is not None else (fm.get_default_root() / "sigs")
        try:
            sigpaths = fm.get_signatures(Path(sigs))
            vw = fm.load_vw(sample_path, fmt, sigpaths, save_workspace)
        except fm.WorkspaceLoadError as e:
            raise FlossRunError(f"workspace load failed: {e}") from e
        except Exception as e:
            raise FlossRunError(f"workspace setup failed: {e}") from e

        doc.metadata.imagebase = fm.get_imagebase(vw)

        try:
            selected_functions = fm.select_functions(vw, None)
        except ValueError as e:
            raise FlossRunError(f"function selection failed: {e}") from e

        decoding_features, _library = fm.find_decoding_function_features(
            vw, selected_functions, disable_progress=True
        )

        # 3. stack strings — exclude tight-loop functions when tight is on,
        #    matching main()'s FP-avoidance logic.
        if enable_stack:
            stack_funcs = selected_functions
            if enable_tight:
                stack_funcs = fm.get_functions_without_tightloops(decoding_features)
            try:
                doc.strings.stack_strings = fm.extract_stackstrings(
                    vw, stack_funcs, min_length, disable_progress=True
                )
            except Exception as e:
                raise FlossRunError(f"stack string extraction failed: {e}") from e

        # 4. tight strings
        if enable_tight:
            tight_funcs = fm.get_functions_with_tightloops(decoding_features)
            try:
                doc.strings.tight_strings = fm.extract_tightstrings(
                    vw, tight_funcs, min_length=min_length, disable_progress=True
                )
            except Exception as e:
                raise FlossRunError(f"tight string extraction failed: {e}") from e

        # 5. decoded strings — top-20 by score + tight fvas, deduped.
        if enable_decoded:
            top = fm.get_top_functions(decoding_features, 20)
            fvas = fm.get_function_fvas(top)
            fvas = fm.append_unique(fvas, fm.get_tight_function_fvas(decoding_features))
            if fvas:
                try:
                    doc.strings.decoded_strings = fm.decode_strings(
                        vw, fvas, min_length, disable_progress=True
                    )
                except Exception as e:
                    raise FlossRunError(f"decoded string extraction failed: {e}") from e

    return _adapt_result_document(doc, min_length)
