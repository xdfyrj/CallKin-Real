"""Refusal stub. The frozen V0 engine is not part of CallKin-Real.

`v1_candidates.py` is copied here byte-for-byte, and it imports this module at
the top so that its oracle-side entry points -- the ones that load a projected
fixture and run 1-WL over it -- resolve. CallKin-Real never calls those: it
gets the relation partition from `relation.json`, which its own run produced.

Shipping the real `engine.py` would make the oracle path merely unused.
Shipping this makes it impossible, and says so at the point someone tries.
"""

from __future__ import annotations

from typing import Any

CGWLMode = str
CG_WL_MODES: tuple[str, ...] = ()

_MESSAGE = (
    "the frozen V0 engine is not available in CallKin-Real: the relation "
    "partition comes from relation.json, built by callkin_real.py, not from a "
    "projected fixture. Use real_v1_adapter.load_from_run instead."
)


class CGWLResult:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(_MESSAGE)


def run_cg_wl(*args: Any, **kwargs: Any) -> CGWLResult:
    raise NotImplementedError(_MESSAGE)
