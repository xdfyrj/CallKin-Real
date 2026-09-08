"""Focused regression coverage for the opt-in F6 lazy non-match path."""

from __future__ import annotations

import dataclasses
from unittest.mock import patch

import v1_grouping
from body_similarity import FunctionBody
from real_v1_adapter import RealV1Input
from v1_candidates import MultiViewCandidatePair, PairKey, build_multiview_candidate_artifact
from v1_engine import PairEvidenceCache, PairFeatures, PairPolicyConfig


def _body(function_id: str, classes: list[str], *, raw: list[str] | None = None,
          complete: bool = True, opaque: int = 0) -> FunctionBody:
    raw = raw or classes
    instructions = tuple(
        {
            "offset": index,
            "mnemonic": raw[index],
            "mnemonic_class": mnemonic_class,
            "operands": [],
            "control_flow": "none",
            "constants": [7] if index == 0 else [],
            "slots": [],
        }
        for index, mnemonic_class in enumerate(classes)
    )
    return FunctionBody(
        id=function_id,
        size=len(classes),
        instructions=instructions,
        edges=(),
        blocks=({"label": "B0", "instruction_offsets": list(range(len(classes)))},),
        quality={"complete_decode": complete, "opaque_indirect_jumps": opaque},
    )


def _candidate_pair(first: str, second: str) -> MultiViewCandidatePair:
    return MultiViewCandidatePair(
        pair=PairKey.make(first, second),
        views={
            "cfg": {"score": 1.0, "rank": 1},
            "relation": {"score": 1.0, "rank": 1},
            "token": {"score": 1.0, "rank": 1},
        },
        reasons={"cfg_top_k", "relation_top_k", "token_top_k"},
    )


def _config(**overrides: object) -> PairPolicyConfig:
    return dataclasses.replace(
        PairPolicyConfig(
            structure_match_threshold=0.95,
            slot_match_threshold=1.0,
            structure_reject_threshold=None,
            require_informative_slot=True,
            abstain_on_opaque_indirect=True,
            max_comparison_count=None,
            max_alignment_cell_budget=None,
        ),
        **overrides,
    )


def test_lazy_nonmatch_is_exact_before_f4_and_preserves_partition():
    # Adjacent bodies match in normalized classes, while A and D have the same
    # raw mnemonic but different normalized mnemonic_class values.  The latter
    # is the cheap non-match reached during complete-link validation.
    bodies = {
        "A": _body("A", ["X"] * 100, raw=["mov"] * 100),
        "B": _body("B", ["X"] * 99 + ["Y"], raw=["mov"] * 100),
        "C": _body("C", ["X"] * 98 + ["Y", "Z"], raw=["mov"] * 100),
        "D": _body("D", ["X"] * 97 + ["Y", "Z", "W"], raw=["mov"] * 100),
    }
    pairs = [
        _candidate_pair("A", "B"),
        _candidate_pair("B", "C"),
        _candidate_pair("C", "D"),
    ]
    candidate = build_multiview_candidate_artifact(
        case="lazy",
        build="UNKNOWN",
        profile="plain",
        scope="subject",
        bodies=bodies,
        pairs=pairs,
        top_k=1,
        views=("cfg", "relation", "token"),
        provenance={"body_evidence_sha256": "d" * 64},
    )
    pair_records = candidate["pairs"]
    source = RealV1Input(
        binary_sha256="b" * 64,
        stage_sha256={"body": "d" * 64},
        members=tuple(sorted(bodies)),
        comparable=tuple(sorted(bodies)),
        bodies=bodies,
        relation={},
    )

    # The A/D proof must not enter block alignment/LCS, and must use the
    # normalized mnemonic_class counter rather than the raw mnemonic field.
    def fail_f4(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("F4 called for a certified non-match")

    with patch("v1_engine.compare_bodies", fail_f4):
        try:
            cache = PairEvidenceCache(
                bodies, pair_records, _config(), lazy_nonmatch=True
            )
            nonmatch = cache.get_evaluation("A", "D")
        except (TypeError, AssertionError):
            nonmatch = None
    assert nonmatch is not None
    assert nonmatch.decision == "unknown"
    assert nonmatch.features.mnemonic_multiset_jaccard == 97 / 103
    serialized = nonmatch.to_dict()["features"]
    assert serialized["structure_score"] is None
    assert serialized["aligned_instruction_ratio"] is None
    assert serialized["sequence_ratio"] is None
    assert serialized["proof"]["kind"] == "cheap_nonmatch"

    # Equality at the match boundary cannot certify: F4 remains necessary.
    boundary = {
        "left": _body("left", ["X"] * 19),
        "right": _body("right", ["X"] * 20),
    }
    f4_called = False

    def boundary_f4(*_args: object, **_kwargs: object) -> object:
        nonlocal f4_called
        f4_called = True
        raise AssertionError("boundary requires F4")

    with patch("v1_engine.compare_bodies", boundary_f4):
        try:
            PairEvidenceCache(
                boundary, [], _config(), lazy_nonmatch=True
            ).get_evaluation("left", "right")
        except AssertionError:
            pass
    assert f4_called is True

    # Equality at an explicit reject boundary is an exact cheap REJECT.
    reject = _config(structure_reject_threshold=0.95)
    with patch("v1_engine.compare_bodies", fail_f4):
        rejected = PairEvidenceCache(
            boundary, [], reject, lazy_nonmatch=True
        ).get_evaluation("left", "right")
    assert rejected.decision == "reject"

    # With an explicit reject threshold, a cheap score between reject and
    # match is unsupported: the exact structure score must decide it.
    middle = {
        "left": _body("left", ["X"] * 10),
        "right": _body("right", ["X"] * 9),
    }
    middle_called = False

    def middle_f4(*_args: object, **_kwargs: object) -> object:
        nonlocal middle_called
        middle_called = True
        raise AssertionError("middle policy requires F4")

    with patch("v1_engine.compare_bodies", middle_f4):
        try:
            PairEvidenceCache(
                middle, [], _config(structure_reject_threshold=0.8),
                lazy_nonmatch=True,
            ).get_evaluation("left", "right")
        except AssertionError:
            pass
    assert middle_called is True

    # Incomplete and opaque precedence remains ABSTAIN and does not inspect
    # mnemonic evidence.  A supplied feature provider also disables the lazy
    # certificate so custom evaluators retain authority.
    special = {
        "incomplete": _body("incomplete", ["X"], complete=False),
        "opaque": _body("opaque", ["X"], opaque=1),
    }
    with patch("v1_engine.compare_bodies", fail_f4):
        cache = PairEvidenceCache(special, [], _config(), lazy_nonmatch=True)
        assert cache.get_evaluation("incomplete", "opaque").decision == "abstain"

    def provider(pair: PairKey) -> PairFeatures:
        return PairFeatures(
            pair=pair,
            structure_score=1.0,
            aligned_instruction_ratio=1.0,
            sequence_ratio=1.0,
            mnemonic_multiset_jaccard=1.0,
            constant_similarity=1.0,
            call_shape_similarity=None,
            data_reference_similarity=None,
            same_final_color=None,
            same_prior_color=None,
            same_out_signature=None,
            same_in_signature=None,
            both_complete=True,
            opaque_indirect_jumps=0,
        )

    assert PairEvidenceCache(
        {"A": bodies["A"], "D": bodies["D"]},
        [],
        _config(),
        feature_provider=provider,
        lazy_nonmatch=True,
    ).get_evaluation("A", "D").decision == "match"

    # Preflight and complete-link on-demand pricing charge only the two F4
    # matches; A/C is one cheap check.  Eager and lazy runs retain the same
    # accepted/provisional partition on these small bodies.
    lazy_config = _config(max_comparison_count=5, max_alignment_cell_budget=50000)
    priced = v1_grouping.price(candidate, source, lazy_config, lazy_nonmatch=True)
    assert priced["required_comparisons"] == 3
    assert priced["required_alignment_cells"] == 30000
    status_lazy, families_lazy, accounting_lazy = v1_grouping.build_strict_families(
        candidate,
        source,
        config=lazy_config,
        candidate_sha256="c" * 64,
        lazy_nonmatch=True,
    )
    status_eager, families_eager, _ = v1_grouping.build_strict_families(
        candidate,
        source,
        config=_config(),
        candidate_sha256="c" * 64,
    )
    assert status_lazy == status_eager == v1_grouping.COMPLETED
    assert families_lazy is not None and families_eager is not None
    assert families_lazy["status_members"] == families_eager["status_members"]
    assert families_lazy["metrics"]["total_detailed_comparisons"] == 5
    assert families_lazy["metrics"]["cheap_nonmatch_count"] == 1
    assert "cheap_nonmatch_count" not in families_eager["metrics"]
    lazy_decisions = {
        tuple(item["pair"]): item for item in families_lazy["pair_decisions"]
    }
    eager_decisions = {
        tuple(item["pair"]): item for item in families_eager["pair_decisions"]
    }
    for pair in (("A", "B"), ("B", "C"), ("C", "D")):
        assert lazy_decisions[pair]["features"] == eager_decisions[pair]["features"]
    assert eager_decisions[("A", "D")]["features"]["structure_score"] is not None

    import analyze

    assert v1_grouping.build_arg_parser().parse_args(
        ["candidate", "--lazy-nonmatch"]
    ).lazy_nonmatch is True
    assert analyze.build_arg_parser().parse_args(
        ["binary", "--output-dir", "out", "--lazy-nonmatch"]
    ).lazy_nonmatch is True


if __name__ == "__main__":
    test_lazy_nonmatch_is_exact_before_f4_and_preserves_partition()
    print("CallKin-Real lazy non-match: PASS")
