"""A relaxed V1 may attach uncertain singletons without changing strict F6.

The production break each test catches is stated in its name.  Expectations
are literal: the test never asks the relaxed implementation to compute its
own expected result.
"""

from __future__ import annotations

import copy

from body_similarity import FunctionBody


A, B, C, D, E = (f"FUN_0010{value:04x}" for value in range(1, 6))


def _module():
    try:
        import v1_relaxed
    except ModuleNotFoundError as exc:
        raise AssertionError("v1_relaxed.py has not been implemented") from exc
    return v1_relaxed


def _evaluation(left, right, decision, source):
    return {
        "pair": sorted([left, right]),
        "decision": decision,
        "source": source,
        "features": {},
    }


def _families(
    *evaluations,
    second_core=False,
    provisional=(C,),
    unresolved=(),
    abstain=(),
):
    accepted = [A, B] + ([D, E] if second_core else [])
    clusters = [
        {"id": "F1", "status": "accepted", "members": [A, B]},
    ]
    if second_core:
        clusters.append(
            {"id": "F2", "status": "accepted", "members": [D, E]}
        )
    clusters.extend(
        {"id": f"P{index}", "status": "provisional", "members": [member]}
        for index, member in enumerate(provisional, 1)
    )
    clusters.extend(
        {"id": f"U{index}", "status": "unresolved", "members": [member]}
        for index, member in enumerate(unresolved, 1)
    )
    targets = accepted + list(provisional) + list(unresolved) + list(abstain)
    return {
        "schema_version": 1,
        "artifact": "v1-family-grouping",
        "case": "test",
        "build": "UNKNOWN",
        "profile": "plain",
        "scope": "subject",
        "config": {},
        "provenance": {
            "stripped_sha256": "a" * 64,
            "body_evidence_sha256": "b" * 64,
            "candidate_artifact_sha256": "c" * 64,
            "candidate_derivation": {
                "kind": "minimum-view-consensus",
                "minimum_view_count": 3,
            },
        },
        "universe": {
            "target_count": len(targets),
            "target_ids": sorted(targets),
            "complete_body_count": len(targets) - len(abstain),
            "incomplete_ids": sorted(abstain),
        },
        "clusters": clusters,
        "status_members": {
            "accepted": sorted(accepted),
            "provisional": sorted(provisional),
            "unresolved": sorted(unresolved),
            "abstain": sorted(abstain),
        },
        "abstain_reasons": {},
        "pair_decisions": list(evaluations),
        "blocked_merges": [],
        "metrics": {},
    }


def _candidate(left, right):
    left, right = sorted((left, right))
    return {
        "pair": [left, right],
        "first": left,
        "second": right,
        "reasons": ["cfg_top_k", "relation_top_k"],
        "views": {
            "cfg": {"rank": 1, "score": 1.0},
            "relation": {"rank": 1, "score": 1.0},
            "token": None,
        },
        "last_shared_round": 0,
        "same_out_signature": True,
        "same_in_signature": True,
        "same_final_color": False,
        "same_prior_color": True,
    }


def _consensus2(*pairs, targets=(A, B, C)):
    return {
        "schema_version": 2,
        "artifact": "v1-multiview-candidate-pairs",
        "case": "test",
        "build": "UNKNOWN",
        "profile": "plain",
        "scope": "subject",
        "config": {
            "top_k": 16,
            "view_top_k": {"cfg": 16, "relation": 16, "token": 16},
            "views": ["token", "cfg", "relation"],
            "view_profiles": {
                "cfg": "cfg-v2-digested-topology",
                "relation": "relation-v3-anchor-class-context",
                "token": "token-v2-no-sequence",
            },
        },
        "provenance": {
            "stripped_sha256": "a" * 64,
            "body_evidence_sha256": "b" * 64,
            "candidate_derivation": {
                "kind": "minimum-view-consensus",
                "minimum_view_count": 2,
            },
        },
        "universe": {
            "target_count": len(targets),
            "complete_body_count": len(targets),
            "incomplete_ids": [],
            "target_ids": sorted(targets),
        },
        "pairs": sorted(pairs, key=lambda item: item["pair"]),
    }


def _body(function_id):
    return FunctionBody(
        id=function_id,
        size=1,
        instructions=({"mnemonic": "ret", "constants": [1], "slots": []},),
        edges=(),
        blocks=({"label": "B0", "instruction_indices": [0]},),
        quality={"complete_decode": True, "opaque_indirect_jumps": 0},
    )


def _match_features(pair):
    from v1_engine import PairFeatures

    return PairFeatures(
        pair=pair,
        structure_score=1.0,
        aligned_instruction_ratio=1.0,
        sequence_ratio=1.0,
        mnemonic_multiset_jaccard=1.0,
        constant_similarity=1.0,
        call_shape_similarity=None,
        data_reference_similarity=None,
        same_final_color=False,
        same_prior_color=True,
        same_out_signature=True,
        same_in_signature=True,
        both_complete=True,
        opaque_indirect_jumps=0,
    )


def _formal_config(**overrides):
    import dataclasses
    from v1_engine import PairPolicyConfig

    config = PairPolicyConfig.from_file("frozen_v1/configs/v1.formal.json")
    return dataclasses.replace(config, **overrides)


def test_evaluate_relaxed_pairs_returns_shared_decisions_and_accounting():
    families = _families(provisional=(), unresolved=(C,))
    evaluations, accounting = _module().evaluate_relaxed_pairs(
        families,
        _consensus2(_candidate(A, C)),
        {member: _body(member) for member in (A, B, C)},
        _formal_config(),
        {"strict-core": {"F1": (A, B)}},
        feature_provider=_match_features,
    )
    decisions = {
        tuple(item.pair.to_list()): (item.decision, item.source)
        for item in evaluations
    }
    assert decisions == {
        tuple(sorted((A, C))): ("match", "candidate"),
        tuple(sorted((B, C))): ("match", "on-demand"),
    }
    assert accounting["required_comparisons"] == 2
    assert accounting["required_alignment_cells"] == 2
    assert accounting["total_detailed_comparisons"] == 2


def test_unresolved_member_uses_a_consensus2_candidate_match():
    families = _families(provisional=(), unresolved=(C,))
    strict, after_f7 = _module().build_relaxed_artifacts(
        families,
        _consensus2(_candidate(A, C)),
        {member: _body(member) for member in (A, B, C)},
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        feature_provider=_match_features,
    )
    assert [item["member"] for item in strict["attachments"]] == [C]
    assert strict["summary"]["candidate_member_count"] == 1
    assert after_f7 is None


def test_abstain_member_is_not_a_relaxed_candidate():
    calls = []

    def features(pair):
        calls.append(pair)
        return _match_features(pair)

    strict, _ = _module().build_relaxed_artifacts(
        _families(provisional=(), abstain=(C,)),
        _consensus2(_candidate(A, C)),
        {member: _body(member) for member in (A, B)},
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        feature_provider=features,
    )
    assert strict["summary"]["candidate_member_count"] == 0
    assert strict["attachments"] == []
    assert calls == []


def test_on_demand_match_without_candidate_match_does_not_attach():
    import dataclasses

    candidate_pair = tuple(sorted((A, C)))

    def features(pair):
        matched = _match_features(pair)
        if (pair.left, pair.right) == candidate_pair:
            return dataclasses.replace(matched, structure_score=0.90)
        return matched

    strict, _ = _module().build_relaxed_artifacts(
        _families(provisional=(), unresolved=(C,)),
        _consensus2(_candidate(A, C)),
        {member: _body(member) for member in (A, B, C)},
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        feature_provider=features,
    )
    decisions = {
        tuple(item["pair"]): (item["decision"], item["source"])
        for item in strict["pair_decisions"]
    }
    assert decisions[tuple(sorted((A, C)))] == ("unknown", "candidate")
    assert decisions[tuple(sorted((B, C)))] == ("match", "on-demand")
    assert strict["attachments"] == []
    assert strict["unassigned_members"] == [C]


def test_relaxed_budget_is_checked_before_any_comparison_runs():
    calls = []

    def features(pair):
        calls.append(pair)
        return _match_features(pair)

    families = _families(provisional=(), unresolved=(C,))
    before = copy.deepcopy(families)
    try:
        _module().build_relaxed_artifacts(
            families,
            _consensus2(_candidate(A, C)),
            {member: _body(member) for member in (A, B, C)},
            _formal_config(max_comparison_count=1),
            family_artifact_sha256="d" * 64,
            candidate_artifact_sha256="e" * 64,
            feature_provider=features,
        )
    except ValueError as exc:
        assert "exceeds the formal comparison budget" in str(exc)
    else:
        raise AssertionError("relaxed comparisons started beyond the frozen budget")
    assert calls == []
    assert families == before


def test_relaxed_policy_rejects_threshold_changes_before_comparison_runs():
    import dataclasses

    calls = []

    def features(pair):
        calls.append(pair)
        return _match_features(pair)

    try:
        _module().evaluate_relaxed_pairs(
            _families(provisional=(), unresolved=(C,)),
            _consensus2(_candidate(A, C)),
            {member: _body(member) for member in (A, B, C)},
            dataclasses.replace(_formal_config(), structure_match_threshold=0.90),
            {"strict-core": {"F1": (A, B)}},
            feature_provider=features,
        )
    except ValueError as exc:
        assert "frozen" in str(exc)
    else:
        raise AssertionError("relaxed evaluation accepted a changed threshold")
    assert calls == []


def test_relaxed_policy_rejects_raised_or_unbounded_budgets_before_comparison_runs():
    import dataclasses

    families = _families(provisional=(), unresolved=(C,))
    candidates = _consensus2(_candidate(A, C))
    bodies = {member: _body(member) for member in (A, B, C)}
    partition = {"strict-core": {"F1": (A, B)}}
    for overrides in (
        {"max_comparison_count": 10001},
        {"max_alignment_cell_budget": 500000001},
        {"max_comparison_count": None},
        {"max_alignment_cell_budget": None},
    ):
        calls = []

        def features(pair, _calls=calls):
            _calls.append(pair)
            return _match_features(pair)

        try:
            _module().evaluate_relaxed_pairs(
                families,
                candidates,
                bodies,
                dataclasses.replace(_formal_config(), **overrides),
                partition,
                feature_provider=features,
            )
        except ValueError as exc:
            assert "budget" in str(exc)
        else:
            raise AssertionError(f"relaxed evaluation accepted budget {overrides}")
        assert calls == []


def test_built_relaxed_artifact_scores_and_rejects_tampering():
    import copy

    families = _families(provisional=(), unresolved=(C,))
    artifact, _ = _module().build_relaxed_artifacts(
        families,
        _consensus2(_candidate(A, C)),
        {member: _body(member) for member in (A, B, C)},
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        feature_provider=_match_features,
    )
    groups = _module().groups_for_scoring(
        artifact, families, family_artifact_sha256="d" * 64
    )
    assert sorted(groups) == sorted([[A, B], [A, B, C]])

    tampered_attachment = copy.deepcopy(artifact)
    tampered_attachment["attachments"][0]["support_pairs"] = []
    try:
        _module().groups_for_scoring(
            tampered_attachment, families, family_artifact_sha256="d" * 64
        )
    except ValueError as exc:
        assert "deterministic" in str(exc)
    else:
        raise AssertionError("tampered attachment was accepted")

    tampered_decision = copy.deepcopy(artifact)
    tampered_decision["pair_decisions"][0]["source"] = "on-demand"
    try:
        _module().groups_for_scoring(
            tampered_decision, families, family_artifact_sha256="d" * 64
        )
    except ValueError as exc:
        assert "deterministic" in str(exc)
    else:
        raise AssertionError("tampered pair decision was accepted")

    tampered_hash = copy.deepcopy(artifact)
    tampered_hash["provenance"]["family_artifact_sha256"] = "e" * 64
    try:
        _module().groups_for_scoring(
            tampered_hash, families, family_artifact_sha256="d" * 64
        )
    except ValueError as exc:
        assert "different family artifact" in str(exc)
    else:
        raise AssertionError("relaxed artifact from another strict run was accepted")


def test_unsupported_rescue_input_is_rejected_before_comparison_runs():
    calls = []

    def features(pair):
        calls.append(pair)
        return _match_features(pair)

    try:
        _module().build_relaxed_artifacts(
            _families(provisional=(), unresolved=(C,)),
            _consensus2(_candidate(A, C)),
            {member: _body(member) for member in (A, B, C)},
            _formal_config(),
            family_artifact_sha256="d" * 64,
            candidate_artifact_sha256="e" * 64,
            rescue_artifact_sha256="f" * 64,
            feature_provider=features,
        )
    except NotImplementedError as exc:
        assert "F7" in str(exc)
    else:
        raise AssertionError("unsupported rescue input was evaluated")
    assert calls == []


def test_unknown_does_not_veto_one_strong_core_attachment():
    relaxed = _module().build_provisional_artifact(
        _families(
            _evaluation(A, C, "match", "candidate"),
            _evaluation(B, C, "unknown", "on-demand"),
        ),
        family_artifact_sha256="d" * 64,
    )
    assert relaxed["attachments"] == [{
        "member": C,
        "family_id": "F1",
        "support_pairs": [[A, C]],
        "unknown_pairs": [[B, C]],
        "abstain_pairs": [],
        "missing_pairs": [],
    }]
    assert relaxed["summary"]["attached_member_count"] == 1


def test_a_hard_reject_vetoes_the_attachment():
    relaxed = _module().build_provisional_artifact(
        _families(
            _evaluation(A, C, "match", "candidate"),
            _evaluation(B, C, "reject", "on-demand"),
        ),
        family_artifact_sha256="d" * 64,
    )
    assert relaxed["attachments"] == []
    assert relaxed["unassigned_members"] == [C]


def test_an_on_demand_match_is_not_independent_retrieval_support():
    relaxed = _module().build_provisional_artifact(
        _families(
            _evaluation(A, C, "match", "on-demand"),
            _evaluation(B, C, "unknown", "on-demand"),
        ),
        family_artifact_sha256="d" * 64,
    )
    assert relaxed["attachments"] == []
    assert relaxed["unassigned_members"] == [C]


def test_a_member_compatible_with_two_cores_stays_ambiguous():
    relaxed = _module().build_provisional_artifact(
        _families(
            _evaluation(A, C, "match", "candidate"),
            _evaluation(B, C, "unknown", "on-demand"),
            _evaluation(C, D, "match", "candidate"),
            _evaluation(C, E, "unknown", "on-demand"),
            second_core=True,
        ),
        family_artifact_sha256="d" * 64,
    )
    assert relaxed["attachments"] == []
    assert relaxed["ambiguous_members"] == [{
        "member": C,
        "candidate_family_ids": ["F1", "F2"],
    }]


def test_two_attachments_do_not_infer_a_pair_between_provisional_members():
    relaxed = _module().build_provisional_artifact(
        _families(
            _evaluation(A, C, "match", "candidate"),
            _evaluation(B, C, "unknown", "on-demand"),
            _evaluation(A, D, "match", "candidate"),
            _evaluation(B, D, "unknown", "on-demand"),
            provisional=(C, D),
        ),
        family_artifact_sha256="d" * 64,
    )
    groups = _module().groups_for_scoring(
        relaxed,
        _families(
            _evaluation(A, C, "match", "candidate"),
            _evaluation(B, C, "unknown", "on-demand"),
            _evaluation(A, D, "match", "candidate"),
            _evaluation(B, D, "unknown", "on-demand"),
            provisional=(C, D),
        ),
        family_artifact_sha256="d" * 64,
    )
    assert sorted(groups) == sorted([[A, B], [A, B, C], [A, B, D]])
    assert [A, B, C, D] not in groups


def test_building_relaxed_output_does_not_mutate_strict_f6():
    families = _families(
        _evaluation(A, C, "match", "candidate"),
        _evaluation(B, C, "unknown", "on-demand"),
    )
    before = copy.deepcopy(families)
    relaxed = _module().build_provisional_artifact(
        families, family_artifact_sha256="d" * 64,
    )
    assert families == before
    assert relaxed["provenance"]["family_artifact_sha256"] == "d" * 64
    assert relaxed["ground_truth"] == {"used_for": "not used"}


def test_scoring_refuses_a_relaxed_artifact_from_another_strict_run():
    families = _families(
        _evaluation(A, C, "match", "candidate"),
        _evaluation(B, C, "unknown", "on-demand"),
    )
    relaxed = _module().build_provisional_artifact(
        families, family_artifact_sha256="d" * 64,
    )
    try:
        _module().groups_for_scoring(
            relaxed, families, family_artifact_sha256="e" * 64,
        )
    except ValueError as exc:
        assert "family artifact" in str(exc)
    else:
        raise AssertionError("relaxed output was scored against another strict run")


def test_a_non_consensus3_strict_queue_is_refused():
    families = _families(
        _evaluation(A, C, "match", "candidate"),
        _evaluation(B, C, "unknown", "on-demand"),
    )
    families["provenance"]["candidate_derivation"]["minimum_view_count"] = 2
    try:
        _module().build_provisional_artifact(
            families, family_artifact_sha256="d" * 64,
        )
    except ValueError as exc:
        assert "consensus3" in str(exc)
    else:
        raise AssertionError("a two-view candidate was treated as strict support")


def test_missing_or_invalid_strict_provenance_is_refused():
    families = _families(
        _evaluation(A, C, "match", "candidate"),
        _evaluation(B, C, "unknown", "on-demand"),
    )
    families["provenance"]["body_evidence_sha256"] = "not-a-hash"
    try:
        _module().build_provisional_artifact(
            families, family_artifact_sha256="d" * 64,
        )
    except ValueError as exc:
        assert "body_evidence_sha256" in str(exc)
    else:
        raise AssertionError("invalid strict provenance reached relaxed output")


def test_evaluator_reports_relaxed_precision_and_recall_separately():
    import evaluate

    families = _families(
        _evaluation(A, C, "match", "candidate"),
        _evaluation(B, C, "unknown", "on-demand"),
    )
    relaxed = _module().build_provisional_artifact(
        families, family_artifact_sha256="d" * 64,
    )
    ground_truth = {
        "symbols": {},
        "origins": [{"origin": "same", "members": [A, B, C]}],
    }
    universe = {"functions": [
        {"id": member, "grouping_role": "member"} for member in (A, B, C)
    ]}
    relation = {"predicted_clusters": {}}
    report = evaluate.score_grouping(
        ground_truth,
        universe,
        relation,
        families,
        None,
        {},
        relaxed=relaxed,
        family_artifact_sha256="d" * 64,
    )
    strict = report["methods"]["v1_strict"]
    provisional = report["methods"]["v1_relaxed_provisional"]
    assert strict["true_positive"] == 1 and strict["recall"] == 0.3333
    assert provisional["true_positive"] == 3
    assert provisional["precision"] == 1.0
    assert provisional["recall"] == 1.0
    assert provisional["attachment_count"] == 1


def test_relaxed_artifact_is_refused_as_a_flirt_propagation_partition():
    from flirt_labels import build_label_artifact
    from label_propagation import build_propagation

    families = _families(
        _evaluation(A, C, "match", "candidate"),
        _evaluation(B, C, "unknown", "on-demand"),
    )
    relaxed = _module().build_provisional_artifact(
        families, family_artifact_sha256="d" * 64,
    )
    labels = build_label_artifact(
        {"matches": []}, binary_sha256="a" * 64, discovery_addresses=set()
    )
    try:
        build_propagation(
            relaxed,
            labels,
            None,
            family_artifact_sha256="d" * 64,
            label_artifact_sha256="e" * 64,
            rescue_artifact_sha256=None,
        )
    except ValueError as exc:
        assert "strict" in str(exc) or "family" in str(exc)
    else:
        raise AssertionError("provisional attachments were used for FLIRT propagation")


def main() -> int:
    test_evaluate_relaxed_pairs_returns_shared_decisions_and_accounting()
    test_unresolved_member_uses_a_consensus2_candidate_match()
    test_abstain_member_is_not_a_relaxed_candidate()
    test_on_demand_match_without_candidate_match_does_not_attach()
    test_relaxed_budget_is_checked_before_any_comparison_runs()
    test_relaxed_policy_rejects_threshold_changes_before_comparison_runs()
    test_relaxed_policy_rejects_raised_or_unbounded_budgets_before_comparison_runs()
    test_built_relaxed_artifact_scores_and_rejects_tampering()
    test_unsupported_rescue_input_is_rejected_before_comparison_runs()
    test_unknown_does_not_veto_one_strong_core_attachment()
    test_a_hard_reject_vetoes_the_attachment()
    test_an_on_demand_match_is_not_independent_retrieval_support()
    test_a_member_compatible_with_two_cores_stays_ambiguous()
    test_two_attachments_do_not_infer_a_pair_between_provisional_members()
    test_building_relaxed_output_does_not_mutate_strict_f6()
    test_scoring_refuses_a_relaxed_artifact_from_another_strict_run()
    test_a_non_consensus3_strict_queue_is_refused()
    test_missing_or_invalid_strict_provenance_is_refused()
    test_evaluator_reports_relaxed_precision_and_recall_separately()
    test_relaxed_artifact_is_refused_as_a_flirt_propagation_partition()
    print("CallKin-Real relaxed V1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
