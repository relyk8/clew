"""clew analysis channels.

Each channel is an independent evidence source (capa, FLOSS, the static
backends, CAPE/DynamoRIO) that contributes to a clew record. Nothing here is
imported at package load; the modules are pulled in lazily by the pipeline so
importing `clew.channels` never drags in a heavy dependency.
"""

from __future__ import annotations


class BackendUnavailable(RuntimeError):
    """The selected Channel 2 backend is not installed or not configured.

    Raised by a backend before it does any work, so the CLI can report the
    missing prerequisite and its fix instead of a traceback from deep inside a
    JVM launch or a license checkout. Backends raise their own subclass.

    Defined here rather than in `clew.pipeline` so a channel never has to
    import the pipeline that drives it.
    """


__all__ = ["BackendUnavailable"]
