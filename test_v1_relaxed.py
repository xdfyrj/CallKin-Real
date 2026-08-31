"""A relaxed V1 may attach uncertain singletons without changing strict F6.

The production break each test catches is stated in its name.  Expectations
are literal: the test never asks the relaxed implementation to compute its
own expected result.
"""

from __future__ import annotations

import copy


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


def _families(*evaluations, second_core=False, provisional=(C,)):
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
    targets = accepted + list(provisional)
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
            "complete_body_count": len(targets),
            "incomplete_ids": [],
        },
        "clusters": clusters,
        "status_members": {
            "accepted": sorted(accepted),
            "provisional": sorted(provisional),
            "unresolved": [],
            "abstain": [],
        },
        "abstain_reasons": {},
        "pair_decisions": list(evaluations),
        "blocked_merges": [],
        "metrics": {},
    }


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
