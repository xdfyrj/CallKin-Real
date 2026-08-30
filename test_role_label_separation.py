"""R1: analysis status, grouping role and label status are three separate things.

The frozen V1 decided membership partly from a function's owner, and fed FLIRT
names into the relation colouring. On zoxide that removed every FLIRT seed from
the grouping universe, so no label could propagate. These tests pin the rule
that replaces it: a role is decided from how much of a function was recovered,
never from what it is called.
"""

from __future__ import annotations

import collections

from callkin_real import (
    ANALYSIS_ADDRESS_ONLY,
    ANALYSIS_COMPLETE,
    ANALYSIS_EXTERNAL,
    ANALYSIS_INCOMPLETE,
    ROLE_ABSTAIN,
    ROLE_CONTEXT_ONLY,
    ROLE_MEMBER,
    Function,
    analysis_status_for,
    canonical_sha256,
    classify_nodes,
    context_color_for,
    grouping_role_for,
    grouping_core,
)


def _internal(address: int, size: int = 32, name: str | None = None) -> Function:
    return Function(
        address=address,
        size=size,
        name=name or f"fcn.{address:x}",
        boundary_source="radare2",
    )


def _import(address: int, name: str = "sym.imp.malloc") -> Function:
    return Function(address=address, size=0, name=name, boundary_source="import", kind="sym")


def _opaque(address: int) -> Function:
    return Function(
        address=address, size=0, name=f"FUN_{address:08x}",
        boundary_source="opaque-target", kind="opaque",
    )


def _edges(pairs) -> dict[int, collections.Counter]:
    edges: dict[int, collections.Counter] = collections.defaultdict(collections.Counter)
    for source, target in pairs:
        edges[source][target] += 1
    return edges


def test_a_named_standard_library_function_is_still_a_member():
    # The whole point: direct FLIRT knowing this is core::ptr::drop_in_place
    # must not remove it from grouping. The role function never sees the name.
    drop_in_place = _internal(0x2000)
    assert analysis_status_for(drop_in_place) == ANALYSIS_COMPLETE
    assert grouping_role_for(ANALYSIS_COMPLETE, is_root=False) == ROLE_MEMBER


def test_the_same_function_gets_the_same_role_with_and_without_flirt():
    functions = {0x1000: _internal(0x1000), 0x2000: _internal(0x2000)}
    edges = _edges([(0x1000, 0x2000)])

    without = classify_nodes(dict(functions), edges, root=None)

    labelled = {address: _internal(address) for address in functions}
    labelled[0x2000].flirt = {
        "name": "core::ptr::drop_in_place<alloc::string::String>",
        "canonical_origin": "core::ptr::drop_in_place",
        "owner": "core",
    }
    with_flirt = classify_nodes(labelled, edges, root=None)

    roles_without, colors_without, abstentions_without, statuses_without = without
    roles_with, colors_with, abstentions_with, statuses_with = with_flirt
    assert roles_without == roles_with
    assert colors_without == colors_with
    assert abstentions_without == abstentions_with
    assert statuses_without == statuses_with
    assert roles_with[0x2000] == ROLE_MEMBER


def test_root_import_and_address_only_are_context_only():
    functions = {
        0x1000: _internal(0x1000),
        0x2000: _import(0x2000),
        0x3000: _opaque(0x3000),
        0x4000: _internal(0x4000),
    }
    edges = _edges([(0x1000, 0x2000), (0x1000, 0x3000), (0x1000, 0x4000)])

    roles, colors, _, statuses = classify_nodes(functions, edges, root=0x1000)

    assert roles[0x1000] == ROLE_CONTEXT_ONLY and colors[0x1000] == "root"
    assert statuses[0x2000] == ANALYSIS_EXTERNAL
    assert roles[0x2000] == ROLE_CONTEXT_ONLY
    assert colors[0x2000] == "import:sym.imp.malloc"
    assert statuses[0x3000] == ANALYSIS_ADDRESS_ONLY
    assert roles[0x3000] == ROLE_CONTEXT_ONLY
    assert colors[0x3000] == "opaque:3000"
    assert roles[0x4000] == ROLE_MEMBER


def test_an_incomplete_internal_function_abstains():
    functions = {0x1000: _internal(0x1000), 0x2000: _internal(0x2000)}
    edges = _edges([(0x1000, 0x2000)])

    roles, _, abstentions, statuses = classify_nodes(
        functions, edges, root=None, complete_bodies={0x1000}
    )

    assert statuses[0x2000] == ANALYSIS_INCOMPLETE
    assert roles[0x2000] == ROLE_ABSTAIN
    reasons = {item["id"]: item["reason"] for item in abstentions}
    assert reasons["FUN_00102000"] == "incomplete_body"
    assert roles[0x1000] == ROLE_MEMBER


def test_a_complete_isolated_function_stays_a_member_and_is_relation_abstain():
    # V0 had no information about an edgeless function, so it abstained. V1 has
    # its body, so it is a member; only the relation-only baseline cannot judge.
    functions = {0x1000: _internal(0x1000), 0x9000: _internal(0x9000)}
    edges = _edges([(0x1000, 0x1000)])

    roles, _, abstentions, _ = classify_nodes(functions, edges, root=None)

    assert roles[0x9000] == ROLE_MEMBER
    isolated = [item for item in abstentions if item["id"] == "FUN_00109000"]
    assert len(isolated) == 1
    assert isolated[0]["reason"] == "relation_abstain"
    assert isolated[0]["grouping_role"] == ROLE_MEMBER


def test_no_discovered_function_is_silently_dropped():
    functions = {
        0x1000: _internal(0x1000),
        0x2000: _import(0x2000),
        0x3000: _opaque(0x3000),
        0x4000: _internal(0x4000),
    }
    edges = _edges([(0x1000, 0x2000)])

    roles, _, _, statuses = classify_nodes(
        functions, edges, root=0x1000, complete_bodies={0x1000}
    )

    assert set(roles) == set(functions)
    assert set(statuses) == set(functions)
    assert all(
        role in {ROLE_MEMBER, ROLE_CONTEXT_ONLY, ROLE_ABSTAIN}
        for role in roles.values()
    )


def test_a_context_colour_never_carries_a_label():
    labelled = _internal(0x2000)
    labelled.flirt = {
        "name": "core::ptr::drop_in_place<T>",
        "canonical_origin": "core::ptr::drop_in_place",
        "owner": "core",
    }
    # Even if such a function were context-only, its colour comes from the
    # image, never from the label.
    assert context_color_for(_opaque(0x3000), is_root=False) == "opaque:3000"
    assert context_color_for(_import(0x2000), is_root=False) == "import:sym.imp.malloc"
    assert context_color_for(labelled, is_root=True) == "root"


def _function_records(labelled: bool) -> list[dict]:
    records = []
    for address in (0x1000, 0x2000):
        record = {
            "id": f"FUN_{address + 0x100000:08x}",
            "address": hex(address),
            "name": f"fcn.{address:x}",
            "kind": "code",
            "size": 32,
            "analysis_status": ANALYSIS_COMPLETE,
            "grouping_role": ROLE_MEMBER,
            "label_status": "direct" if labelled and address == 0x2000 else "unknown",
            "boundary_source": "radare2",
            "flirt": (
                {"name": "core::ptr::drop_in_place<T>",
                 "canonical_origin": "core::ptr::drop_in_place", "owner": "core"}
                if labelled and address == 0x2000 else None
            ),
        }
        records.append(record)
    return records


def _core(labelled: bool) -> dict:
    return grouping_core(
        binary_sha256="a" * 64,
        root_id="FUN_00101000",
        clusters={"C1": ["FUN_00102000"]},
        rounds=2,
        functions=_function_records(labelled),
        edges=[{"source": "FUN_00101000", "target": "FUN_00102000", "count": 1}],
        abstentions=[],
    )


def test_the_grouping_core_hash_does_not_move_when_a_label_appears():
    # The invariant the frozen V1 could not state: the same binary and config
    # must produce the same grouping bytes whether or not FLIRT ran.
    without, with_flirt = _core(False), _core(True)
    assert canonical_sha256(without) == canonical_sha256(with_flirt)
    assert "flirt" not in json_keys(without)
    assert "label_status" not in json_keys(without)


def json_keys(core: dict) -> set[str]:
    keys = set(core)
    for record in core["functions"]:
        keys |= set(record)
    return keys


def test_the_core_hash_still_moves_when_the_grouping_moves():
    baseline = canonical_sha256(_core(False))
    moved = grouping_core(
        binary_sha256="a" * 64,
        root_id="FUN_00101000",
        clusters={"C1": ["FUN_00101000", "FUN_00102000"]},
        rounds=2,
        functions=_function_records(False),
        edges=[{"source": "FUN_00101000", "target": "FUN_00102000", "count": 1}],
        abstentions=[],
    )
    assert canonical_sha256(moved) != baseline


def test_the_grouping_module_boundary_excludes_labels():
    import inspect

    import callkin_real

    for name in ("classify_nodes", "analysis_status_for", "grouping_role_for",
                 "context_color_for"):
        source = inspect.getsource(getattr(callkin_real, name))
        for forbidden in ("flirt", "canonical_origin", "STANDARD_OWNERS",
                          "owner_from_name"):
            assert forbidden not in source, f"{name} refers to {forbidden}"


def main() -> int:
    test_a_named_standard_library_function_is_still_a_member()
    test_the_same_function_gets_the_same_role_with_and_without_flirt()
    test_root_import_and_address_only_are_context_only()
    test_an_incomplete_internal_function_abstains()
    test_a_complete_isolated_function_stays_a_member_and_is_relation_abstain()
    test_no_discovered_function_is_silently_dropped()
    test_a_context_colour_never_carries_a_label()
    test_the_grouping_core_hash_does_not_move_when_a_label_appears()
    test_the_core_hash_still_moves_when_the_grouping_moves()
    test_the_grouping_module_boundary_excludes_labels()
    print("CallKin-Real role/label separation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
