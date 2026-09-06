import os
from pathlib import Path
from unittest.mock import patch

from callkin_real import (
    default_oxidizer_dir,
    Function,
    Transfer,
    apply_angr_resolutions,
    function_id,
    make_graph,
    wl_clusters,
)


def main() -> None:
    with patch.dict(os.environ, {}, clear=True):
        assert default_oxidizer_dir() == Path(__file__).resolve().parent.parent / "oxidizer"
    with patch.dict(os.environ, {"CALLKIN_OXIDIZER_DIR": "/custom/oxidizer"}, clear=True):
        assert default_oxidizer_dir() == Path("/custom/oxidizer")
    assert function_id(0x1000) == "FUN_00101000"
    functions = {
        0x1000: Function(0x1000, 10, "entry", "test"),
        0x1100: Function(0x1100, 10, "a", "test"),
        0x1200: Function(0x1200, 10, "b", "test"),
    }
    edges = {
        0x1000: {0x1100: 1, 0x1200: 1},
        0x1100: {0x1000: 1},
        0x1200: {0x1000: 1},
    }
    statuses = {0x1000: "anchor", 0x1100: "candidate", 0x1200: "candidate"}
    colors = {0x1000: "root"}
    clusters, rounds, _trace = wl_clusters(functions, edges, statuses, colors, False)
    assert clusters == {"C1": ["FUN_00101100", "FUN_00101200"]}
    assert rounds >= 1

    transfer = Transfer(
        source=0x1100,
        callsite=0x1104,
        kind="tail-call",
        operand_kind="memory",
        instruction="jmp qword ptr [rip + 0x10]",
        status="unmapped",
        target=0x1300,
        resolver="elf-relocation",
        confidence="address-only",
    )
    graph_functions, graph_edges, _ = make_graph(functions, [transfer], None)
    assert graph_functions[0x1300].kind == "opaque"
    assert graph_edges[0x1100][0x1300] == 1

    unresolved = Transfer(
        source=0x1100,
        callsite=0x1108,
        kind="call",
        operand_kind="register",
        instruction="call rax",
        status="unresolved",
        target=None,
        resolver=None,
        confidence="unknown",
    )
    summary = apply_angr_resolutions([unresolved], {}, {(0x1100, 0x1108)})
    assert summary["unresolvable"] == 1
    assert unresolved.angr_status == "unresolvable-target"
    print("CallKin-Real self-test: PASS")


if __name__ == "__main__":
    main()
