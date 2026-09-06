"""TDD coverage for whole-component F5 budget selection."""

from __future__ import annotations

import copy
import dataclasses

from body_similarity import FunctionBody
from real_v1_adapter import RealV1Input
from v1_component_budget import build_budgeted_candidate_artifact
from v1_candidates import MultiViewCandidatePair, PairKey, build_multiview_candidate_artifact
from v1_engine import PairPolicyConfig


SOURCE_SHA = "c" * 64


def _body(function_id: str, instruction_count: int, *, complete: bool = True,
          opaque: int = 0) -> FunctionBody:
    instructions = tuple(
        {
            "offset": index,
            "mnemonic_class": "RET" if index == instruction_count - 1 else "NOP",
            "operands": [],
            "control_flow": "return" if index == instruction_count - 1 else "none",
            "constants": [],
        }
        for index in range(instruction_count)
    )
    blocks = ({"label": "B0", "instruction_offsets": list(range(instruction_count))},)
    return FunctionBody(
        id=function_id,
        size=instruction_count,
        instructions=instructions,
        edges=(),
        blocks=blocks,
        quality={
            "complete_decode": complete,
            "opaque_indirect_jumps": opaque,
        },
    )


def _pair(first: str, second: str) -> MultiViewCandidatePair:
    return MultiViewCandidatePair(
        pair=PairKey.make(first, second),
        views={
            "cfg": {"score": 1.0, "rank": 1},
            "relation": {"score": 1.0, "rank": 1},
            "token": {"score": 1.0, "rank": 1},
        },
        reasons={"cfg_top_k", "relation_top_k", "token_top_k"},
    )


def _fixture() -> tuple[dict, RealV1Input, PairPolicyConfig]:
    # A and B are connected components. I, O and X are isolated vertices;
    # O is opaque and X is incomplete, so neither contributes to cost.
    lengths = {
        "a1": 2,
        "a2": 3,
        "a3": 4,
        "b1": 5,
        "b2": 6,
        "i1": 7,
        "o1": 8,
        "x1": 9,
    }
    bodies = {
        member: _body(member, length, opaque=1 if member == "o1" else 0,
                       complete=member != "x1")
        for member, length in lengths.items()
    }
    members = tuple(sorted(bodies))
    artifact = build_multiview_candidate_artifact(
        case="synthetic",
        build="UNKNOWN",
        profile="plain",
        scope="subject",
        bodies=bodies,
        pairs=[_pair("a1", "a2"), _pair("a2", "a3"), _pair("b1", "b2")],
        top_k=1,
        views=("token", "cfg", "relation"),
        provenance={"source": "synthetic"},
    )
    source = RealV1Input(
        binary_sha256="b" * 64,
        stage_sha256={"body": "d" * 64},
        members=members,
        comparable=tuple(member for member in members if member != "x1"),
        bodies=bodies,
        relation={},
    )
    config = PairPolicyConfig(
        structure_match_threshold=0.95,
        slot_match_threshold=1.0,
        max_comparison_count=4,
        max_alignment_cell_budget=50,
    )
    return artifact, source, config


def test_components_are_atomic_and_budget_order_is_cost_then_members():
    artifact, source, config = _fixture()
    derived, report = build_budgeted_candidate_artifact(
        artifact, source, config, SOURCE_SHA
    )

    # A costs 3 comparisons and 26 cells; B costs 1 and 30. A fits first,
    # while adding B would exceed cells, so no edge from B may survive.
    assert report["selected_component_count"] == 4
    assert report["deferred_component_count"] == 1
    assert report["selected_member_count"] == 6
    assert report["deferred_member_count"] == 2
    assert report["selected_upper_bound_comparisons"] == 3
    assert report["selected_upper_bound_alignment_cells"] == 26
    assert {tuple(item["pair"]) for item in derived["pairs"]} == {
        ("a1", "a2"), ("a2", "a3")
    }
    deferred = report["deferred_components"]
    assert len(deferred) == 1
    assert deferred[0]["members"] == ["b1", "b2"]
    assert deferred[0]["comparisons"] == 1
    assert deferred[0]["alignment_cells"] == 30


def test_upper_bound_formula_and_zero_cost_members_match_hand_calculation():
    artifact, source, config = _fixture()
    _, report = build_budgeted_candidate_artifact(
        artifact, source, dataclasses.replace(config, max_comparison_count=None,
                                              max_alignment_cell_budget=None),
        SOURCE_SHA,
    )
    by_members = {tuple(item["members"]): item for item in report["components"]}
    assert by_members[("a1", "a2", "a3")]["comparisons"] == 3
    assert by_members[("a1", "a2", "a3")]["alignment_cells"] == 26
    assert by_members[("b1", "b2")]["comparisons"] == 1
    assert by_members[("b1", "b2")]["alignment_cells"] == 30
    assert by_members[("o1",)]["comparisons"] == 0
    assert by_members[("o1",)]["alignment_cells"] == 0
    assert by_members[("x1",)]["comparisons"] == 0
    assert by_members[("x1",)]["alignment_cells"] == 0


def test_pair_records_and_universe_are_copied_without_mutation():
    artifact, source, config = _fixture()
    original_pairs = copy.deepcopy(artifact["pairs"])
    original_universe = copy.deepcopy(artifact["universe"])
    derived, _ = build_budgeted_candidate_artifact(
        artifact, source, config, SOURCE_SHA
    )
    kept = [pair for pair in original_pairs if tuple(pair["pair"]) in {
        ("a1", "a2"), ("a2", "a3")
    }]
    assert derived["pairs"] == kept
    assert derived["universe"] == original_universe
    assert artifact["pairs"] == original_pairs
    assert artifact["universe"] == original_universe


def test_provenance_records_hash_policy_and_selected_deferred_costs():
    artifact, source, config = _fixture()
    derived, _ = build_budgeted_candidate_artifact(
        artifact, source, config, SOURCE_SHA
    )
    derivation = derived["provenance"]["component_budget_derivation"]
    assert derivation["source_candidate_sha256"] == SOURCE_SHA
    assert derivation["policy"] == config.to_dict()
    assert derivation["selected_component_count"] == 4
    assert derivation["deferred_component_count"] == 1


def test_malformed_source_hash_fails_closed():
    artifact, source, config = _fixture()
    try:
        build_budgeted_candidate_artifact(artifact, source, config, "bad")
    except ValueError as exc:
        assert "SHA-256" in str(exc)
    else:
        raise AssertionError("malformed source SHA-256 was accepted")


def test_selected_components_fit_both_formal_limits():
    artifact, source, config = _fixture()
    _, report = build_budgeted_candidate_artifact(
        artifact, source, config, SOURCE_SHA
    )
    assert report["selected_upper_bound_comparisons"] <= config.max_comparison_count
    assert report["selected_upper_bound_alignment_cells"] <= config.max_alignment_cell_budget


def test_component_order_does_not_use_labels_or_oracle_data():
    artifact, source, config = _fixture()
    artifact["provenance"]["opaque_label_payload"] = {
        "label": "must-not-be-read",
        "canonical_origin": "must-not-be-read",
    }
    derived, report = build_budgeted_candidate_artifact(
        artifact, source, config, SOURCE_SHA
    )
    assert report["components"][0]["members"] == ["i1"]
    assert [item["members"] for item in report["components"]] == [
        ["i1"], ["o1"], ["x1"], ["a1", "a2", "a3"], ["b1", "b2"],
    ]
    assert {tuple(item["pair"]) for item in derived["pairs"]} == {
        ("a1", "a2"), ("a2", "a3")
    }


if __name__ == "__main__":
    for _test in (
        test_components_are_atomic_and_budget_order_is_cost_then_members,
        test_upper_bound_formula_and_zero_cost_members_match_hand_calculation,
        test_pair_records_and_universe_are_copied_without_mutation,
        test_provenance_records_hash_policy_and_selected_deferred_costs,
        test_malformed_source_hash_fails_closed,
        test_selected_components_fit_both_formal_limits,
        test_component_order_does_not_use_labels_or_oracle_data,
    ):
        _test()
    print("CallKin-Real component budget: PASS")
