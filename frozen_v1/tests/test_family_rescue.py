"""F7 rescue: the six acceptance conditions, the fragment graph and the budget."""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import FunctionBody  # noqa: E402
from family_rescue import (  # noqa: E402
    ACCEPTED,
    BASIS_NOT_COMPLETE,
    BUDGET_BLOCKED,
    NO_INTERNAL_SUPPORT,
    NO_RELATION_BRIDGE,
    OVER_BUDGET,
    REJECTED,
    TOO_FEW_INDEPENDENT_AXES,
    TOO_MANY_MEMBERS,
    Component,
    RescueBudget,
    accepted_fragments,
    build_components,
    check_inputs_agree,
    evaluate_component,
    final_partition,
    rescue_families,
    rescued_clusters,
    reserve_cost,
)
from slot_overlay import CALL_TARGET, RESOLVED, SlotObservation  # noqa: E402


def _body(identifier: str, count: int = 4) -> FunctionBody:
    instructions = tuple(
        {
            "offset": offset,
            "mnemonic_class": "CALL" if offset == 0 else "MOV",
            "operands": [],
            "control_flow": "call" if offset == 0 else "none",
        }
        for offset in range(count)
    )
    return FunctionBody(
        id=identifier,
        size=count,
        instructions=instructions,
        edges=(),
        blocks=({"label": "B0", "instruction_offsets": list(range(count))},),
        quality={"complete_decode": True, "opaque_indirect_jumps": 0},
    )


def _slots(*values) -> tuple[SlotObservation, ...]:
    """One CALL_TARGET per offset, so each value defines one axis position."""
    return tuple(
        SlotObservation(
            offset=index, index=0, kind=CALL_TARGET, value=value, state=RESOLVED
        )
        for index, value in enumerate(values)
    )


# A 2 x 3: axis A over two values, axis B over three, split into two fragments
# so that BOTH axes vary inside a fragment.
COMPLETE_FRAGMENTS = {
    "F1": ("M0", "M1", "M2"),
    "F2": ("M3", "M4", "M5"),
}
COMPLETE_OBSERVATIONS = {
    "M0": _slots("a0", "b0"), "M1": _slots("a0", "b1"), "M2": _slots("a0", "b2"),
    "M3": _slots("a1", "b0"), "M4": _slots("a1", "b1"), "M5": _slots("a1", "b2"),
}


def _component(fragments, bridges=(("M0", "M3"),)):
    members = tuple(sorted(m for ms in fragments.values() for m in ms))
    return Component(
        fragments=tuple(sorted(fragments)), members=members,
        bridge_pairs=tuple(bridges),
    )


def _bodies(observations):
    return {name: _body(name) for name in observations}


def test_a_complete_two_by_three_with_internal_support_is_accepted():
    # Axis A separates the fragments, axis B varies inside each. Wait: axis A
    # here separates F1 from F2, so give axis B the internal support and check
    # the rule refuses. The accepting case needs both axes varying inside.
    fragments = {"F1": ("M0", "M3", "M1"), "F2": ("M4", "M2", "M5")}
    component = _component(fragments, bridges=(("M0", "M4"),))
    evaluate_component(
        component, fragments, _bodies(COMPLETE_OBSERVATIONS), COMPLETE_OBSERVATIONS
    )

    assert component.status == ACCEPTED, (component.reason, component.internal_support)
    assert component.report["independent_axis_count"] == 2
    assert all(component.internal_support.values())


def test_an_incomplete_product_is_refused():
    observations = dict(COMPLETE_OBSERVATIONS)
    del observations["M5"]  # five members over a 2 x 3 grid
    fragments = {"F1": ("M0", "M3", "M1"), "F2": ("M4", "M2")}
    component = _component(fragments, bridges=(("M0", "M4"),))

    evaluate_component(component, fragments, _bodies(observations), observations)

    assert component.status == REJECTED
    assert component.reason == BASIS_NOT_COMPLETE


def test_a_single_axis_is_refused():
    observations = {
        "M0": _slots("a0", "x"), "M1": _slots("a1", "x"),
        "M2": _slots("a0", "x"), "M3": _slots("a1", "x"),
    }
    fragments = {"F1": ("M0", "M1"), "F2": ("M2", "M3")}
    component = _component(fragments, bridges=(("M0", "M2"),))

    evaluate_component(component, fragments, _bodies(observations), observations)

    assert component.status == REJECTED
    assert component.reason == TOO_FEW_INDEPENDENT_AXES


def test_an_axis_that_only_separates_the_fragments_is_refused():
    # The axis04 shape: a complete bijective 2 x 2 where one axis never varies
    # inside a fragment.
    observations = {
        "L0": _slots("left", "a0"), "L1": _slots("left", "a1"),
        "R0": _slots("right", "a0"), "R1": _slots("right", "a1"),
    }
    fragments = {"L": ("L0", "L1"), "R": ("R0", "R1")}
    component = _component(fragments, bridges=(("L0", "R0"),))

    evaluate_component(component, fragments, _bodies(observations), observations)

    assert component.status == REJECTED
    assert component.reason == NO_INTERNAL_SUPPORT
    assert sorted(component.internal_support.values()) == [False, True]


def test_a_hypothesis_without_a_relation_bridge_is_refused_before_anything_else():
    fragments = {"F1": ("M0", "M3", "M1"), "F2": ("M4", "M2", "M5")}
    component = _component(fragments, bridges=())

    evaluate_component(
        component, fragments, _bodies(COMPLETE_OBSERVATIONS), COMPLETE_OBSERVATIONS
    )

    assert component.status == REJECTED
    assert component.reason == NO_RELATION_BRIDGE
    # Body-only merging is refused without ever inferring an axis.
    assert component.report is None


def test_components_are_built_over_fragments_not_functions():
    fragments = {"F1": ("A", "B"), "F2": ("C", "D"), "F3": ("E", "F")}
    pairs = [
        {"pair": ["A", "C"], "same_prior_color": True},
        {"pair": ["A", "B"], "same_prior_color": True},   # inside F1, ignored
        {"pair": ["E", "ZZ"], "same_prior_color": True},  # unknown, ignored
    ]

    components = build_components(fragments, pairs)

    assert len(components) == 1
    (component,) = components
    assert component.fragments == ("F1", "F2")
    assert component.members == ("A", "B", "C", "D")
    assert component.bridge_pairs == (("A", "C"),)


def test_only_accepted_clusters_take_part():
    artifact = {"clusters": [
        {"id": "C1", "status": "accepted", "members": ["A", "B"]},
        {"id": "C2", "status": "provisional", "members": ["C"]},
        {"id": "C3", "status": "unresolved", "members": ["D"]},
        {"id": "C4", "status": "abstain", "members": ["E"]},
    ]}
    assert accepted_fragments(artifact) == {"C1": ("A", "B")}


def test_cost_is_reserved_for_the_worst_possible_medoid():
    bodies = {"A": _body("A", 10), "B": _body("B", 20), "C": _body("C", 5)}
    comparisons, cells = reserve_cost(["A", "B", "C"], bodies)

    assert comparisons == 3 + 2          # C(3,2) medoid pairs, then 2 alignments
    pairwise = 10 * 20 + 10 * 5 + 20 * 5
    worst = 20 * 10 + 20 * 5             # B is the most expensive medoid
    assert cells == pairwise + worst


def _artifacts(universe=("A", "B", "C", "D"), **overrides):
    provenance = {
        "stripped_sha256": "a" * 64,
        "body_evidence_sha256": "b" * 64,
        "raw_graph_sha256": "c" * 64,
        "candidate_selection_sha256": "d" * 64,
        "projection_config_sha256": "e" * 64,
        "anchor_policy": "role",
        "edge_policy": ["direct-immediate"],
    }
    base = {
        "case": "demo", "build": "O3S", "profile": "plain", "scope": "rust-nonstd",
        "provenance": provenance,
        "universe": {"target_ids": list(universe)},
    }
    family = {**base, "clusters": [
        {"id": "F1", "status": "accepted", "members": ["A", "B"]},
        {"id": "F2", "status": "accepted", "members": ["C", "D"]},
    ]}
    candidate = {**base, "pairs": [{"pair": ["A", "C"], "same_prior_color": True}]}
    for key, value in overrides.items():
        candidate[key] = value
    return family, candidate


def _expect(callable_, expected: str):
    try:
        callable_()
    except ValueError as exc:
        assert expected in str(exc), str(exc)
    else:
        raise AssertionError(f"expected a refusal mentioning {expected!r}")


def test_mismatched_inputs_are_refused():
    family, candidate = _artifacts()
    check_inputs_agree(family, candidate)

    _, other = _artifacts(profile="min")
    other["profile"] = "min"
    _expect(lambda: check_inputs_agree(family, other), "disagree on profile")

    _, stale = _artifacts()
    stale["provenance"] = {**stale["provenance"], "body_evidence_sha256": "f" * 64}
    _expect(lambda: check_inputs_agree(family, stale), "body_evidence_sha256")

    _, shrunk = _artifacts(universe=("A", "B", "C"))
    shrunk["universe"] = {"target_ids": ["A", "B", "C"]}
    _expect(lambda: check_inputs_agree(family, shrunk), "target universes differ")


def test_a_component_over_budget_runs_nothing_and_keeps_its_fragments():
    family, candidate = _artifacts()
    bodies = {name: _body(name, 100) for name in ("A", "B", "C", "D")}

    components, used = rescue_families(
        family, candidate, bodies, {}, {name: 0 for name in bodies},
        budget=RescueBudget(max_alignment_cells=1),
    )

    (component,) = components
    assert component.status == BUDGET_BLOCKED
    assert component.reason == OVER_BUDGET
    assert component.report is None, "no comparison may run inside a blocked component"
    assert used == {"reserved_comparisons": 0, "reserved_alignment_cells": 0}
    # The strict fragments survive untouched.
    partition = final_partition(family, components)
    assert [item["id"] for item in partition] == ["F1", "F2"]
    assert all(item["origin"] == "strict" for item in partition)


def test_an_oversized_component_is_blocked_before_it_is_priced():
    family, candidate = _artifacts()
    bodies = {name: _body(name) for name in ("A", "B", "C", "D")}

    (component,), _ = rescue_families(
        family, candidate, bodies, {}, {name: 0 for name in bodies},
        budget=RescueBudget(max_component_members=3),
    )

    assert component.status == BUDGET_BLOCKED
    assert component.reason == TOO_MANY_MEMBERS
    assert component.reserved_comparisons == 0


def test_the_final_partition_merges_only_accepted_components():
    family, _ = _artifacts()
    merged = Component(
        fragments=("F1", "F2"), members=("A", "B", "C", "D"), status=ACCEPTED
    )
    partition = final_partition(family, [merged])

    assert len(partition) == 1
    assert partition[0]["id"] == "F1+F2"
    assert partition[0]["members"] == ["A", "B", "C", "D"]
    assert partition[0]["origin"] == "rescued"


FAMILY_SHA = "0" * 64


def _rescue(final=None, **overrides):
    record = {
        "artifact": "v1-family-rescue",
        "case": "demo", "build": "O3S", "profile": "plain", "scope": "rust-nonstd",
        "provenance": {"family_artifact_sha256": FAMILY_SHA},
        "strict_partition": [
            {"id": "F1", "members": ["A", "B"]},
            {"id": "F2", "members": ["C", "D"]},
        ],
        "final_partition": final if final is not None else [
            {"id": "F1+F2", "members": ["A", "B", "C", "D"], "origin": "rescued"},
        ],
    }
    record.update(overrides)
    return record


def test_a_valid_rescue_replaces_the_strict_clusters():
    family, _ = _artifacts()
    clusters = rescued_clusters(
        family, _rescue(), family_artifact_sha256=FAMILY_SHA
    )
    assert clusters == [["A", "B", "C", "D"]]

    unchanged = rescued_clusters(
        family,
        _rescue(final=[
            {"id": "F1", "members": ["A", "B"]},
            {"id": "F2", "members": ["C", "D"]},
        ]),
        family_artifact_sha256=FAMILY_SHA,
    )
    assert unchanged == [["A", "B"], ["C", "D"]]


def test_a_rescue_built_from_another_family_artifact_is_refused():
    family, _ = _artifacts()
    _expect(
        lambda: rescued_clusters(
            family, _rescue(), family_artifact_sha256="9" * 64
        ),
        "was built from family artifact",
    )


def test_a_rescue_whose_strict_partition_drifted_is_refused():
    family, _ = _artifacts()
    drifted = _rescue()
    drifted["strict_partition"] = [{"id": "F1", "members": ["A", "B", "C", "D"]}]
    _expect(
        lambda: rescued_clusters(family, drifted, family_artifact_sha256=FAMILY_SHA),
        "strict partition does not match",
    )


def test_the_rescued_partition_may_not_change_the_membership():
    family, _ = _artifacts()
    for final, expected in (
        ([{"id": "X", "members": ["A", "B", "C"]}], "absent from the rescued"),
        ([{"id": "X", "members": ["A", "B", "C", "D", "E"]}], "were added"),
        ([{"id": "X", "members": ["A", "B", "C", "D"]},
          {"id": "Y", "members": ["A"]}], "more than one rescued family"),
    ):
        _expect(
            lambda final=final: rescued_clusters(
                family, _rescue(final=final), family_artifact_sha256=FAMILY_SHA
            ),
            expected,
        )


def test_a_rescue_for_a_different_case_is_refused():
    family, _ = _artifacts()
    _expect(
        lambda: rescued_clusters(
            family, _rescue(profile="min"), family_artifact_sha256=FAMILY_SHA
        ),
        "disagree on profile",
    )


def main() -> int:
    test_a_complete_two_by_three_with_internal_support_is_accepted()
    test_an_incomplete_product_is_refused()
    test_a_single_axis_is_refused()
    test_an_axis_that_only_separates_the_fragments_is_refused()
    test_a_hypothesis_without_a_relation_bridge_is_refused_before_anything_else()
    test_components_are_built_over_fragments_not_functions()
    test_only_accepted_clusters_take_part()
    test_cost_is_reserved_for_the_worst_possible_medoid()
    test_mismatched_inputs_are_refused()
    test_a_component_over_budget_runs_nothing_and_keeps_its_fragments()
    test_an_oversized_component_is_blocked_before_it_is_priced()
    test_the_final_partition_merges_only_accepted_components()
    test_a_valid_rescue_replaces_the_strict_clusters()
    test_a_rescue_built_from_another_family_artifact_is_refused()
    test_a_rescue_whose_strict_partition_drifted_is_refused()
    test_the_rescued_partition_may_not_change_the_membership()
    test_a_rescue_for_a_different_case_is_refused()
    print("F7 family rescue PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
