"""Channel 3 — CAPE.

Minimal CAPE apiv2 REST client (`client`) used to submit samples for dynamic
detonation and fetch reports. Not wired into the static pipeline; `CAPE_BASE_URL`
is read only by the client's `__main__` harness. The CAPE analyzer *packages*
that run inside the guest (drcov/cmplog) are deploy payloads and live in the
top-level `cape_packages/` dir, not here (they import CAPE's `lib.common.*` and
are not importable as part of `clew`).
"""

from __future__ import annotations

from clew.channels.cape.client import CapeClient, CapeError

__all__ = ["CapeClient", "CapeError"]
