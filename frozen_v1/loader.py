"""Refusal stub. Projected fixtures do not exist for a real stripped binary.

`load_case` reads the oracle pipeline's fixture: a graph already projected with
knowledge of which functions were candidates, which were anchors, and what the
build produced. That knowledge is exactly what CallKin-Real does not have.

See `engine.py` beside this file for why the stub is here rather than the real
module.
"""

from __future__ import annotations

from typing import Any

_MESSAGE = (
    "projected fixtures are an oracle artifact and do not exist for a real "
    "stripped binary; CallKin-Real supplies the universe from universe.json "
    "and the relation from relation.json"
)


def load_case(*args: Any, **kwargs: Any) -> Any:
    raise NotImplementedError(_MESSAGE)
