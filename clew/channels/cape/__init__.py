"""Channel 3 — CAPE.

Minimal CAPE apiv2 REST client (`client`) used to submit samples for dynamic
detonation and fetch reports. Not wired into the static pipeline; `CAPE_BASE_URL`
is read only by the client's `__main__` harness. The CAPE analyzer *packages*
that run inside the guest (drcov/cmplog) are deploy payloads and live in the
top-level `cape_packages/` dir, not here (they import CAPE's `lib.common.*` and
are not importable as part of `clew`).
"""

from __future__ import annotations

from typing import Any

__all__ = ["CapeClient", "CapeError"]


def __getattr__(name: str) -> Any:
    # Lazy re-export so importing this package (or its dependency-free
    # cmplog_parse/correlate siblings) does not pull in `client`, which needs
    # `requests`. See clew-conventions.md (heavy deps imported lazily).
    if name in __all__:
        from clew.channels.cape import client

        return getattr(client, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
