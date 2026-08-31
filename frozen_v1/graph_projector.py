"""Only `function_id`, because that is all the frozen F10 imports from here.

The real `graph_projector.py` builds the projected fixture: it decides which
functions are candidates and which are anchors using knowledge from the build.
That is the oracle CallKin-Real replaces, so it is not carried.

`function_id` is one line of arithmetic and is reproduced verbatim, because F10
uses it to turn a FLIRT match address into a member id and that mapping has to
agree with the one `callkin_real.function_id` used to name the members.
"""

from __future__ import annotations

from typing import Any

_MESSAGE = (
    "graph_projector builds a projected fixture from build knowledge; "
    "CallKin-Real's universe comes from universe.json"
)


def function_id(address: int, *, id_bias: int) -> str:
    return f"FUN_{address + id_bias:08x}"


def project_graph(*args: Any, **kwargs: Any) -> Any:
    raise NotImplementedError(_MESSAGE)
