"""A relaxed V1 may attach uncertain singletons without changing strict F6.

The production break each test catches is stated in its name.  Expectations
are literal: the test never asks the relaxed implementation to compute its
own expected result.
"""

from __future__ import annotations

import copy
import hashlib
import json

from body_similarity import FunctionBody


A, B, C, D, E = (f"FUN_0010{value:04x}" for value in range(1, 6))


def _module():
    try:
        import v1_relaxed
    except ModuleNotFoundError as exc:
        raise AssertionError("v1_relaxed.py has not been implemented") from exc
    return v1_relaxed


def _rescue_sha(rescue):
    encoded = (
        json.dumps(rescue, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
            "raw_graph_sha256": "1" * 64,
            "candidate_selection_sha256": "2" * 64,
            "projection_config_sha256": "3" * 64,
            "anchor_policy": "fixed",
            "edge_policy": ["direct"],
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
            "raw_graph_sha256": "1" * 64,
            "candidate_selection_sha256": "2" * 64,
            "projection_config_sha256": "3" * 64,
            "anchor_policy": "fixed",
            "edge_policy": ["direct"],
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


def _bodies(*members):
    return {member: _body(member) for member in members}


def _two_core_families(singleton=C):
    return _families(second_core=True, provisional=(), unresolved=(singleton,))


def _rescue_that_merges_the_two_cores(families):
    return {
        "artifact": "v1-family-rescue",
        "schema_version": 1,
        "rescue_rule_version": "f7-rescue-v1",
        "case": families["case"],
        "build": families["build"],
        "profile": families["profile"],
        "scope": families["scope"],
        "ground_truth": {"used_for": "not used"},
        "provenance": {
            "family_artifact_sha256": "d" * 64,
            "candidate_artifact_sha256": "e" * 64,
            "body_evidence_sha256": families["provenance"]["body_evidence_sha256"],
            "raw_graph_sha256": families["provenance"]["raw_graph_sha256"],
        },
        "verified_provenance": {
            "stripped_sha256": families["provenance"]["stripped_sha256"],
            "body_evidence_sha256": families["provenance"]["body_evidence_sha256"],
            "raw_graph_sha256": families["provenance"]["raw_graph_sha256"],
            "candidate_selection_sha256": families["provenance"][
                "candidate_selection_sha256"
            ],
            "projection_config_sha256": families["provenance"][
                "projection_config_sha256"
            ],
            "anchor_policy": families["provenance"]["anchor_policy"],
            "edge_policy": families["provenance"]["edge_policy"],
            "target_count": len(families["universe"]["target_ids"]),
        },
        "budget": {
            "max_component_members": 64,
            "max_comparisons": 4096,
            "max_alignment_cells": 500000000,
        },
        "summary": {},
        "components": [],
        "strict_partition": [
            {"id": "F1", "members": [A, B]},
            {"id": "F2", "members": [D, E]},
        ],
        "final_partition": [
            {"id": "F1+F2", "members": [A, B, D, E], "origin": "rescued"},
        ],
    }


def _build_two_core_variants(rescue, *, rescue_sha=None, feature_provider=None):
    families = _two_core_families(C)
    return _module().build_relaxed_artifacts(
        families,
        _consensus2(
            _candidate(A, C),
            _candidate(D, C),
            targets=(A, B, C, D, E),
        ),
        _bodies(A, B, C, D),
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        rescue_artifact=rescue,
        rescue_artifact_sha256=(
            _rescue_sha(rescue) if rescue_sha is None else rescue_sha
        ),
        feature_provider=feature_provider or _match_features,
    )


def _expect_rescue_rejected(rescue, message):
    families = _two_core_families(C)
    calls = []

    def features(pair):
        calls.append(pair)
        return _match_features(pair)

    try:
        _module().build_relaxed_artifacts(
            families,
            _consensus2(
                _candidate(A, C),
                _candidate(D, C),
                targets=(A, B, C, D, E),
            ),
            _bodies(A, B, C, D),
            _formal_config(),
            family_artifact_sha256="d" * 64,
            candidate_artifact_sha256="e" * 64,
            rescue_artifact=rescue,
            rescue_artifact_sha256=_rescue_sha(rescue),
            feature_provider=features,
        )
    except ValueError as exc:
        assert message in str(exc), str(exc)
    else:
        raise AssertionError("malformed rescue artifact was accepted")
    assert calls == []


def _unchanged_rescue(families):
    return {
        "artifact": "v1-family-rescue",
        "schema_version": 1,
        "rescue_rule_version": "f7-rescue-v1",
        "case": families["case"],
        "build": families["build"],
        "profile": families["profile"],
        "scope": families["scope"],
        "ground_truth": {"used_for": "not used"},
        "provenance": {
            "family_artifact_sha256": "d" * 64,
            "candidate_artifact_sha256": "e" * 64,
            "body_evidence_sha256": families["provenance"]["body_evidence_sha256"],
            "raw_graph_sha256": families["provenance"]["raw_graph_sha256"],
        },
        "verified_provenance": {
            "stripped_sha256": families["provenance"]["stripped_sha256"],
            "body_evidence_sha256": families["provenance"]["body_evidence_sha256"],
            "raw_graph_sha256": families["provenance"]["raw_graph_sha256"],
            "candidate_selection_sha256": families["provenance"][
                "candidate_selection_sha256"
            ],
            "projection_config_sha256": families["provenance"][
                "projection_config_sha256"
            ],
            "anchor_policy": families["provenance"]["anchor_policy"],
            "edge_policy": families["provenance"]["edge_policy"],
            "target_count": len(families["universe"]["target_ids"]),
        },
        "budget": {
            "max_component_members": 64,
            "max_comparisons": 4096,
            "max_alignment_cells": 500000000,
        },
        "summary": {},
        "components": [],
        "strict_partition": [{"id": "F1", "members": [A, B]}],
        "final_partition": [
            {"id": "F1", "members": [A, B], "origin": "strict"},
        ],
    }


def _build_two_attachment_variants():
    families = _families(provisional=(), unresolved=(C, D))
    rescue = _unchanged_rescue(families)
    return _module().build_relaxed_artifacts(
        families,
        _consensus2(
            _candidate(A, C),
            _candidate(A, D),
            targets=(A, B, C, D),
        ),
        _bodies(A, B, C, D),
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        rescue_artifact=rescue,
        rescue_artifact_sha256=_rescue_sha(rescue),
        feature_provider=_match_features,
    )


def _body(function_id):
    return FunctionBody(
        id=function_id,
        size=1,
        instructions=({
            "offset": 0,
            "mnemonic": "ret",
            "mnemonic_class": "ret",
            "operands": [],
            "constants": [1],
            "slots": [],
        },),
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


def test_f7_merge_can_turn_two_strict_cores_into_one_attachment_target():
    families = _two_core_families(C)
    rescue = _rescue_that_merges_the_two_cores(families)
    strict, after_f7 = _module().build_relaxed_artifacts(
        families,
        _consensus2(
            _candidate(A, C),
            _candidate(D, C),
            targets=(A, B, C, D, E),
        ),
        _bodies(A, B, C, D),
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        rescue_artifact=rescue,
        rescue_artifact_sha256=_rescue_sha(rescue),
        feature_provider=_match_features,
    )
    assert "rescue_artifact_sha256" not in strict["provenance"]
    assert strict["summary"]["ambiguous_member_count"] == 1
    assert after_f7["summary"]["attached_member_count"] == 1


def test_rescue_wrong_or_missing_rule_is_refused_before_comparison_runs():
    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["rescue_rule_version"] = "not-f7-rescue-v1"
    _expect_rescue_rejected(rescue, "rescue rule version")

    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    del rescue["rescue_rule_version"]
    _expect_rescue_rejected(rescue, "schema")


def test_rescue_verified_provenance_drift_or_missing_is_refused_before_comparison_runs():
    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["verified_provenance"]["raw_graph_sha256"] = "0" * 64
    _expect_rescue_rejected(rescue, "provenance mismatch")

    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    del rescue["verified_provenance"]
    _expect_rescue_rejected(rescue, "schema")

    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["verified_provenance"]["unexpected"] = True
    _expect_rescue_rejected(rescue, "verified_provenance")


def test_rescue_ground_truth_policy_drift_is_refused_before_comparison_runs():
    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["ground_truth"] = {"used_for": "evaluation"}
    _expect_rescue_rejected(rescue, "ground_truth policy")


def test_rescue_provenance_mismatches_are_refused_before_comparison_runs():
    for field, message in (
        ("family_artifact_sha256", "another strict"),
        ("candidate_artifact_sha256", "another candidate"),
        ("body_evidence_sha256", "provenance mismatch"),
        ("raw_graph_sha256", "provenance mismatch"),
    ):
        rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
        rescue["provenance"][field] = "0" * 64
        _expect_rescue_rejected(rescue, message)


def test_rescue_schema_missing_or_extra_fields_is_refused_before_comparison_runs():
    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    del rescue["components"]
    _expect_rescue_rejected(rescue, "schema")

    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["unexpected"] = True
    _expect_rescue_rejected(rescue, "schema")

    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    del rescue["provenance"]["raw_graph_sha256"]
    _expect_rescue_rejected(rescue, "provenance")

    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["provenance"]["unexpected"] = "x"
    _expect_rescue_rejected(rescue, "provenance")


def test_f7_scoring_requires_the_validated_rescue_and_actual_hash():
    families = _two_core_families(C)
    rescue = _rescue_that_merges_the_two_cores(families)
    strict, after_f7 = _build_two_core_variants(rescue)
    assert after_f7 is not None

    try:
        _module().groups_for_scoring(
            after_f7, families, family_artifact_sha256="d" * 64
        )
    except ValueError as exc:
        assert "rescue" in str(exc)
    else:
        raise AssertionError("F7 artifact was scored without its rescue artifact")

    try:
        _module().groups_for_scoring(
            after_f7,
            families,
            family_artifact_sha256="d" * 64,
            rescue_artifact=rescue,
            rescue_artifact_sha256="0" * 64,
        )
    except ValueError as exc:
        assert "rescue artifact" in str(exc)
    else:
        raise AssertionError("F7 artifact was scored with the wrong rescue hash")

    wrong_rescue = copy.deepcopy(rescue)
    wrong_rescue["final_partition"][0]["members"] = [A, B]
    try:
        _module().groups_for_scoring(
            after_f7,
            families,
            family_artifact_sha256="d" * 64,
            rescue_artifact=wrong_rescue,
            rescue_artifact_sha256=_rescue_sha(wrong_rescue),
        )
    except ValueError as exc:
        assert "rescue artifact" in str(exc)
    else:
        raise AssertionError("F7 artifact was scored with a wrong rescue object")

    groups = _module().groups_for_scoring(
        after_f7,
        families,
        family_artifact_sha256="d" * 64,
        rescue_artifact=rescue,
        rescue_artifact_sha256=_rescue_sha(rescue),
    )
    assert sorted(groups) == sorted([[A, B, D, E], [A, B, C, D, E]])

    tampered_core = copy.deepcopy(after_f7)
    tampered_core["core_partition"][0]["members"] = [A, B]
    try:
        _module().groups_for_scoring(
            tampered_core,
            families,
            family_artifact_sha256="d" * 64,
            rescue_artifact=rescue,
            rescue_artifact_sha256=_rescue_sha(rescue),
        )
    except ValueError as exc:
        assert "core_partition" in str(exc)
    else:
        raise AssertionError("F7 artifact with a drifted core partition was accepted")


def test_build_rejects_stale_rescue_digest_before_comparison_runs():
    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    stale_sha = _rescue_sha(rescue)
    rescue["summary"]["tampered"] = True
    calls = []

    def features(pair):
        calls.append(pair)
        return _match_features(pair)

    try:
        _build_two_core_variants(
            rescue, rescue_sha=stale_sha, feature_provider=features
        )
    except ValueError as exc:
        assert "SHA-256" in str(exc)
    else:
        raise AssertionError("stale rescue digest was accepted during build")
    assert calls == []


def test_scoring_rejects_stale_rescue_digest():
    families = _two_core_families(C)
    rescue = _rescue_that_merges_the_two_cores(families)
    _, after_f7 = _build_two_core_variants(rescue)
    stale_sha = _rescue_sha(rescue)
    rescue["summary"]["tampered"] = True
    try:
        _module().groups_for_scoring(
            after_f7,
            families,
            family_artifact_sha256="d" * 64,
            rescue_artifact=rescue,
            rescue_artifact_sha256=stale_sha,
        )
    except ValueError as exc:
        assert "SHA-256" in str(exc)
    else:
        raise AssertionError("stale rescue digest was accepted during scoring")


def test_rescue_digest_matches_repository_writer_encoding():
    import v1_rescue

    class MemoryParent:
        def mkdir(self, *, parents, exist_ok):
            assert parents and exist_ok

    class MemoryPath:
        parent = MemoryParent()

        def write_bytes(self, data):
            self.data = data
            return len(data)

    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    path = MemoryPath()
    assert v1_rescue.write_json(path, rescue) == _rescue_sha(rescue)
    assert path.data == (
        json.dumps(rescue, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def test_rescue_from_another_strict_hash_is_refused():
    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["provenance"]["family_artifact_sha256"] = "0" * 64
    try:
        _build_two_core_variants(rescue)
    except ValueError as exc:
        assert "another strict" in str(exc)
    else:
        raise AssertionError("a rescue from another strict run was accepted")


def test_rescue_strict_partition_drift_is_refused():
    rescue = _rescue_that_merges_the_two_cores(_two_core_families(C))
    rescue["strict_partition"][0]["members"] = [A]
    try:
        _build_two_core_variants(rescue)
    except ValueError as exc:
        assert "strict_partition" in str(exc)
    else:
        raise AssertionError("a drifted strict partition was accepted")


def test_two_attachments_never_create_a_pair_between_singletons():
    families = _families(provisional=(), unresolved=(C, D))
    strict, after_f7 = _build_two_attachment_variants()
    rescue = _unchanged_rescue(families)
    for artifact in (strict, after_f7):
        rescue_kwargs = {}
        if artifact["partition"] == "f7-core":
            rescue_kwargs = {
                "rescue_artifact": rescue,
                "rescue_artifact_sha256": _rescue_sha(rescue),
            }
        groups = _module().groups_for_scoring(
            artifact,
            families,
            family_artifact_sha256="d" * 64,
            **rescue_kwargs,
        )
        assert [A, B, C, D] not in groups


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
    except ValueError as exc:
        assert "rescue artifact" in str(exc)
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


def test_evaluator_reports_both_relaxed_variants_separately():
    import evaluate

    families = _two_core_families(C)
    rescue = _rescue_that_merges_the_two_cores(families)
    rescue["summary"] = {
        "final_family_count": 1,
        "rescued_family_count": 1,
        "reserved_comparisons": 0,
        "reserved_alignment_cells": 0,
    }
    strict_relaxed, rescue_relaxed = _build_two_core_variants(rescue)
    assert rescue_relaxed is not None
    ground_truth = {
        "symbols": {},
        "origins": [{"origin": "same", "members": [A, B, C, D, E]}],
    }
    universe = {"functions": [
        {"id": member, "grouping_role": "member"}
        for member in (A, B, C, D, E)
    ]}
    relation = {"predicted_clusters": {}}
    methods = evaluate.score_grouping(
        ground_truth,
        universe,
        relation,
        families,
        rescue,
        {},
        relaxed=strict_relaxed,
        rescue_relaxed=rescue_relaxed,
        family_artifact_sha256="d" * 64,
        rescue_artifact_sha256=_rescue_sha(rescue),
    )["methods"]
    assert "v1_relaxed_provisional" in methods
    assert "v1_strict_rescue_relaxed_provisional" in methods
    assert methods["v1_relaxed_provisional"]["partition"] == "strict-core"
    assert methods["v1_strict_rescue_relaxed_provisional"]["partition"] == "f7-core"


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

    f7_families = _two_core_families(C)
    f7_rescue = _rescue_that_merges_the_two_cores(f7_families)
    _, f7_relaxed = _build_two_core_variants(f7_rescue)
    assert f7_relaxed is not None
    strict_relaxed, _ = _module().build_relaxed_artifacts(
        _families(provisional=(), unresolved=(C,)),
        _consensus2(_candidate(A, C)),
        _bodies(A, B, C),
        _formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        feature_provider=_match_features,
    )
    for artifact in (strict_relaxed, f7_relaxed):
        try:
            build_propagation(
                artifact,
                labels,
                None,
                family_artifact_sha256="d" * 64,
                label_artifact_sha256="e" * 64,
                rescue_artifact_sha256=None,
            )
        except ValueError as exc:
            assert "strict" in str(exc) or "family" in str(exc)
        else:
            raise AssertionError("a relaxed output was used for FLIRT propagation")


class _MemoryPath:
    files = {}
    writes = {}

    def __init__(self, value):
        self.value = str(value)

    @property
    def parent(self):
        return _MemoryPath(self.value.rsplit("/", 1)[0] if "/" in self.value else "")

    @property
    def stem(self):
        return self.value.rsplit("/", 1)[-1].rsplit(".", 1)[0]

    def __truediv__(self, other):
        return _MemoryPath(
            f"{self.value}/{other}" if self.value else str(other)
        )

    def read_bytes(self):
        return self.files[self.value]

    def read_text(self, encoding=None):
        return self.read_bytes().decode(encoding or "utf-8")

    def is_file(self):
        return self.value in self.files

    def mkdir(self, *, parents=False, exist_ok=False):
        return None

    def write_bytes(self, data):
        self.writes[self.value] = data
        return len(data)

    def __str__(self):
        return self.value


def _json_bytes(value):
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _run_relaxed_cli(files, source):
    import contextlib
    import io
    from unittest.mock import patch

    import v1_relaxed

    _MemoryPath.files = files
    _MemoryPath.writes = {}
    output = io.StringIO()
    errors = io.StringIO()
    config = _formal_config()
    with patch.object(v1_relaxed, "Path", _MemoryPath), \
            patch.object(v1_relaxed, "load_from_run", return_value=source), \
            patch.object(
                v1_relaxed.PairPolicyConfig,
                "from_file",
                return_value=config,
            ), \
            contextlib.redirect_stdout(output), \
            contextlib.redirect_stderr(errors):
        code = v1_relaxed.main(["run.json", "--config", "formal.json"])
    report = json.loads(output.getvalue()) if output.getvalue() else None
    return code, report, dict(_MemoryPath.writes), errors.getvalue()


def test_relaxed_cli_writes_paired_outputs_and_preserves_input_provenance():
    families = _two_core_families(C)
    candidates = _consensus2(
        _candidate(A, C),
        _candidate(D, C),
        targets=(A, B, C, D, E),
    )
    rescue = _rescue_that_merges_the_two_cores(families)
    family_raw = _json_bytes(families)
    candidate_raw = _json_bytes(candidates)
    rescue["provenance"]["family_artifact_sha256"] = hashlib.sha256(
        family_raw
    ).hexdigest()
    rescue["provenance"]["candidate_artifact_sha256"] = hashlib.sha256(
        candidate_raw
    ).hexdigest()
    rescue_raw = _json_bytes(rescue)
    files = {
        "run.json": _json_bytes({"binary": {"sha256": "a" * 64}}),
        "formal.json": b"formal-config",
        "run.v1.families.strict.json": family_raw,
        "run.v1.consensus2.k16.candidates.json": candidate_raw,
        "run.v1.families.rescue.json": rescue_raw,
    }
    source = type("Source", (), {
        "binary_sha256": "a" * 64,
        "bodies": _bodies(A, B, C, D, E),
    })()
    code, report, writes, errors = _run_relaxed_cli(files, source)
    assert code == 0, errors
    assert sorted(writes) == [
        "run.v1.families.relaxed.json",
        "run.v1.families.rescue-relaxed.json",
    ]
    strict = json.loads(writes["run.v1.families.relaxed.json"])
    f7 = json.loads(writes["run.v1.families.rescue-relaxed.json"])
    assert strict["partition"] == "strict-core"
    assert f7["partition"] == "f7-core"
    assert strict["provenance"]["family_artifact_sha256"] == hashlib.sha256(
        family_raw
    ).hexdigest()
    assert f7["provenance"]["rescue_artifact_sha256"] == hashlib.sha256(
        rescue_raw
    ).hexdigest()
    assert report["queue"]["kind"] == "consensus2"
    assert report["artifacts"]["f7"]["partition"] == "f7-core"


def test_relaxed_cli_omits_f7_output_when_rescue_is_absent():
    families = _families(provisional=(), unresolved=(C,))
    candidates = _consensus2(_candidate(A, C), targets=(A, B, C))
    family_raw = _json_bytes(families)
    candidate_raw = _json_bytes(candidates)
    files = {
        "run.json": _json_bytes({"binary": {"sha256": "a" * 64}}),
        "formal.json": b"formal-config",
        "run.v1.families.strict.json": family_raw,
        "run.v1.consensus2.k16.candidates.json": candidate_raw,
    }
    source = type("Source", (), {
        "binary_sha256": "a" * 64,
        "bodies": _bodies(A, B, C),
    })()
    code, report, writes, errors = _run_relaxed_cli(files, source)
    assert code == 0, errors
    assert sorted(writes) == ["run.v1.families.relaxed.json"]
    assert report["rescue"] is None
    assert report["artifacts"]["f7"] is None


def test_relaxed_cli_rejects_rescue_built_from_another_strict_artifact():
    families = _two_core_families(C)
    candidates = _consensus2(
        _candidate(A, C),
        _candidate(D, C),
        targets=(A, B, C, D, E),
    )
    rescue = _rescue_that_merges_the_two_cores(families)
    files = {
        "run.json": _json_bytes({"binary": {"sha256": "a" * 64}}),
        "formal.json": b"formal-config",
        "run.v1.families.strict.json": _json_bytes(families),
        "run.v1.consensus2.k16.candidates.json": _json_bytes(candidates),
        "run.v1.families.rescue.json": _json_bytes(rescue),
    }
    source = type("Source", (), {
        "binary_sha256": "a" * 64,
        "bodies": _bodies(A, B, C, D, E),
    })()
    code, report, writes, errors = _run_relaxed_cli(files, source)
    assert code == 1
    assert report is None
    assert writes == {}
    assert "another strict" in errors


def main() -> int:
    test_f7_merge_can_turn_two_strict_cores_into_one_attachment_target()
    test_rescue_from_another_strict_hash_is_refused()
    test_rescue_strict_partition_drift_is_refused()
    test_two_attachments_never_create_a_pair_between_singletons()
    test_rescue_wrong_or_missing_rule_is_refused_before_comparison_runs()
    test_rescue_verified_provenance_drift_or_missing_is_refused_before_comparison_runs()
    test_rescue_ground_truth_policy_drift_is_refused_before_comparison_runs()
    test_rescue_provenance_mismatches_are_refused_before_comparison_runs()
    test_rescue_schema_missing_or_extra_fields_is_refused_before_comparison_runs()
    test_f7_scoring_requires_the_validated_rescue_and_actual_hash()
    test_build_rejects_stale_rescue_digest_before_comparison_runs()
    test_scoring_rejects_stale_rescue_digest()
    test_rescue_digest_matches_repository_writer_encoding()
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
    test_evaluator_reports_both_relaxed_variants_separately()
    test_relaxed_artifact_is_refused_as_a_flirt_propagation_partition()
    test_relaxed_cli_writes_paired_outputs_and_preserves_input_provenance()
    test_relaxed_cli_omits_f7_output_when_rescue_is_absent()
    test_relaxed_cli_rejects_rescue_built_from_another_strict_artifact()
    print("CallKin-Real relaxed V1: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
