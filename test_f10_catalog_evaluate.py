"""Synthetic tests for the evaluation-only exact F10 catalog scorer."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from pathlib import Path

import callkin_real
from flirt_labels import DIRECT_FLIRT, build_label_artifact, direct_seeds
from label_propagation import build_propagation

import f10_catalog_evaluate as scorer


STRIPPED = "a" * 64
FAMILY_SHA = "b" * 64
LABEL_SHA = "c" * 64
RESCUE_SHA = "d" * 64
A, B, D = 0x1000, 0x2000, 0x9000
PRED_BIAS = callkin_real.ID_BIAS
CATALOG_BIAS = 0


def _id(address: int, bias: int = PRED_BIAS) -> str:
    return f"FUN_{address + bias:08x}"


def _family() -> dict:
    members = [_id(A), _id(B)]
    return {
        "schema_version": 1,
        "artifact": "v1-family-grouping",
        "case": "synthetic",
        "build": "different-build",
        "profile": "synthetic-profile",
        "scope": "subject",
        "config": {},
        "provenance": {
            "stripped_sha256": STRIPPED,
            "id_bias": PRED_BIAS,
            "body_evidence_sha256": "2" * 64,
            "raw_graph_sha256": "3" * 64,
            "candidate_selection_sha256": "4" * 64,
            "projection_config_sha256": "5" * 64,
            "anchor_policy": "synthetic",
            "edge_policy": "synthetic",
        },
        "universe": {
            "target_count": len(members),
            "target_ids": members,
            "complete_body_count": len(members),
            "incomplete_ids": [],
        },
        "clusters": [{"id": "F1", "status": "accepted", "members": members}],
        "status_members": {
            "accepted": members,
            "provisional": [],
            "unresolved": [],
            "abstain": [],
        },
        "abstain_reasons": {},
        "pair_decisions": [],
        "blocked_merges": [],
        "metrics": {},
    }


def _labels() -> dict:
    return build_label_artifact(
        {
            "matches": [
                {
                    "address": callkin_real.hex_address(A),
                    "mapped_address": "0x9001",
                    "name": "crate::origin_a",
                    "evidence": DIRECT_FLIRT,
                },
                {
                    "address": callkin_real.hex_address(D),
                    "mapped_address": "0x9009",
                    "name": "crate::outside",
                    "evidence": DIRECT_FLIRT,
                },
            ]
        },
        binary_sha256=STRIPPED,
        discovery_addresses={A},
    )


def _catalog(*, owner: str = "crate") -> dict:
    members = [f"FUN_{A:08x}", f"FUN_{B:08x}"]
    return {
        "schema_version": 1,
        "case": "other-case",
        "build": "other-build",
        "profile": "other-profile",
        "scope": "all-rust",
        "root_namespace": "synthetic",
        "id_bias": CATALOG_BIAS,
        "provenance": {
            "build_id": "synthetic",
            "source_sha256": "e" * 64,
            "non_stripped_sha256": "f" * 64,
            "stripped_sha256": STRIPPED,
        },
        "source": "synthetic-catalog",
        "origins": [{"origin": "crate::origin_a", "members": members}],
        "symbols": {member: [f"synthetic::{member}"] for member in members},
        "owners": {member: owner for member in members},
        "cross_origin_aliases": [],
    }


def _alias_catalog() -> dict:
    catalog = _catalog()
    first, second = catalog["origins"][0]["members"]
    catalog["origins"] = [
        {"origin": f"shared-address@{first}", "members": [first]},
        {"origin": "crate::origin_a", "members": [second]},
    ]
    catalog["symbols"] = {
        first: [f"synthetic::{first}"],
        second: [f"synthetic::{second}"],
    }
    catalog["owners"] = {first: "shared-address", second: "crate"}
    catalog["cross_origin_aliases"] = [{
        "member": first,
        "origins": ["crate::origin_a", "crate::origin_b"],
    }]
    return catalog


def _rescue(family: dict) -> dict:
    family_sha = hashlib.sha256(
        json.dumps(family, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    members = family["clusters"][0]["members"]
    return {
        "artifact": "v1-family-rescue",
        "schema_version": 1,
        "rescue_rule_version": "f7-rescue-v1",
        "case": family["case"],
        "build": family["build"],
        "profile": family["profile"],
        "scope": family["scope"],
        "ground_truth": {"used_for": "not used"},
        "provenance": {
            "family_artifact_sha256": family_sha,
            "candidate_artifact_sha256": "1" * 64,
            "body_evidence_sha256": "2" * 64,
            "raw_graph_sha256": "3" * 64,
        },
        "verified_provenance": {
            "stripped_sha256": STRIPPED,
            "body_evidence_sha256": "2" * 64,
            "raw_graph_sha256": "3" * 64,
            "candidate_selection_sha256": "4" * 64,
            "projection_config_sha256": "5" * 64,
            "anchor_policy": "synthetic",
            "edge_policy": "synthetic",
            "target_count": len(members),
        },
        "budget": {
            "max_component_members": 128,
            "max_comparisons": 10000,
            "max_alignment_cells": 50000000,
        },
        "summary": {
            "strict_accepted_fragment_count": 1,
            "strict_accepted_member_count": len(members),
            "component_count": 0,
            "accepted_component_count": 0,
            "rejected_component_count": 0,
            "budget_blocked_component_count": 0,
            "rejection_reasons": {},
            "reserved_comparisons": 0,
            "reserved_alignment_cells": 0,
            "final_family_count": 1,
            "rescued_family_count": 0,
        },
        "strict_partition": [{"id": "F1", "members": members}],
        "final_partition": [{"id": "F1", "members": members, "origin": "strict"}],
        "components": [],
    }


def _prediction(
    rescue: dict | None = None,
    *,
    labels: dict | None = None,
    labels_sha256: str | None = None,
) -> dict:
    labels = labels or _labels()
    return build_propagation(
        _family(),
        labels,
        rescue,
        family_artifact_sha256=(
            rescue["provenance"]["family_artifact_sha256"] if rescue else FAMILY_SHA
        ),
        label_artifact_sha256=labels_sha256 or _raw_sha(labels),
        rescue_artifact_sha256=RESCUE_SHA if rescue else None,
    )


def _write_json(path: Path, value: dict) -> str:
    raw = json.dumps(value, indent=2, sort_keys=True).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _raw_sha(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, indent=2, sort_keys=True).encode()).hexdigest()


def _canonical_sha(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _score(room: Path, catalog: dict, labels: dict, prediction: dict) -> dict:
    catalog_path, labels_path, prediction_path = (
        room / "catalog.json", room / "labels.json", room / "prediction.json"
    )
    _write_json(catalog_path, catalog)
    _write_json(labels_path, labels)
    _write_json(prediction_path, prediction)
    return scorer.score_catalog_propagation(catalog_path, labels_path, prediction_path)


def test_strict_scores_exact_origin_owner_and_all_direct_seeds():
    labels = _labels()
    prediction = _prediction(labels=labels)
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        report = _score(Path(directory), _catalog(), labels, prediction)
    assert report["provenance"]["method"] == "strict"
    assert report["direct"]["predicted_member_count"] == len(direct_seeds(labels))
    assert report["metrics"]["direct_correct_count"] == 1
    assert report["metrics"]["direct_unknown_count"] == 1
    assert report["metrics"]["propagated_correct_count"] == 1
    assert report["metrics"]["newly_correct_member_count"] == 1
    assert report["metrics"]["combined_catalog_coverage"] == 1.0


def test_rescue_is_scored_and_case_build_names_are_not_identity():
    family, labels = _family(), _labels()
    rescue = _rescue(family)
    prediction = _prediction(rescue, labels=labels)
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        report = _score(Path(directory), _catalog(), labels, prediction)
    assert report["provenance"]["method"] == "rescue"
    assert report["metrics"]["combined_catalog_coverage"] == 1.0


def test_owner_only_error_is_wrong_propagation_and_wrong_family():
    labels = _labels()
    labels["matches"][0]["owner"] = "wrong-owner"
    prediction = _prediction(labels=labels)
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        report = _score(Path(directory), _catalog(), labels, prediction)
    assert report["metrics"]["propagated_incorrect_count"] == 1
    assert report["metrics"]["wrongly_propagated_family_count"] == 1


def test_unknown_propagated_address_fails_closed():
    labels, prediction = _labels(), _prediction()
    prediction["propagated_labels"][0]["member"] = _id(0x9999)
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        room = Path(directory)
        try:
            _score(room, _catalog(), labels, prediction)
        except ValueError as exc:
            assert "propagated" in str(exc)
        else:
            raise AssertionError("unknown propagated address was accepted")


def test_hash_and_direct_baseline_mismatches_fail_without_mutation():
    labels, prediction = _labels(), _prediction()
    before = copy.deepcopy(prediction)
    prediction["direct_labels"][0]["mapped_address"] = "0xdead"
    family_row = next(row for row in prediction["families"] if row["id"] == "F1")
    family_row["seed_labels"][0]["mapped_address"] = "0xdead"
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        room = Path(directory)
        try:
            _score(room, _catalog(), labels, prediction)
        except ValueError as exc:
            assert "direct" in str(exc)
        else:
            raise AssertionError("tampered direct baseline was accepted")
    assert prediction != before


def test_stripped_hash_mismatch_is_rejected():
    labels, prediction = _labels(), _prediction()
    catalog = _catalog()
    catalog["provenance"]["stripped_sha256"] = "9" * 64
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        try:
            _score(Path(directory), catalog, labels, prediction)
        except ValueError as exc:
            assert "stripped" in str(exc)
        else:
            raise AssertionError("stripped hash mismatch was accepted")


def test_scoring_does_not_modify_input_files():
    labels, prediction, catalog = _labels(), _prediction(), _catalog()
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        room = Path(directory)
        paths = {
            "catalog": room / "catalog.json",
            "labels": room / "labels.json",
            "prediction": room / "prediction.json",
        }
        for name, value in (("catalog", catalog), ("labels", labels), ("prediction", prediction)):
            _write_json(paths[name], value)
        before = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
        scorer.score_catalog_propagation(paths["catalog"], paths["labels"], paths["prediction"])
        after = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
    assert after == before


def test_raw_label_hash_binds_prediction_to_the_file_being_scored():
    labels, prediction = _labels(), _prediction()
    labels["matches"][0]["mapped_address"] = "0xbeef"
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        try:
            _score(Path(directory), _catalog(), labels, prediction)
        except ValueError as exc:
            assert "labels" in str(exc)
        else:
            raise AssertionError("prediction was not bound to raw labels hash")


def test_catalog_alias_is_ambiguous_neutral_for_direct_and_evaluable_metrics():
    labels, prediction = _labels(), _prediction()
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        report = _score(Path(directory), _alias_catalog(), labels, prediction)
    metrics = report["metrics"]
    assert metrics["catalog_raw_member_count"] == 2
    assert metrics["catalog_evaluable_member_count"] == 1
    assert metrics["catalog_ambiguous_member_count"] == 1
    assert metrics["direct_ambiguous_count"] == 1
    assert metrics["propagated_ambiguous_count"] == 0
    assert metrics["direct_correct_count"] == 0
    assert metrics["propagated_correct_count"] == 1
    assert metrics["propagated_incorrect_count"] == 0
    assert report["direct"]["ambiguous_count"] == 1
    assert report["combined"]["catalog_coverage"] == 1.0


def test_catalog_alias_is_ambiguous_neutral_for_propagated_member():
    labels = build_label_artifact(
        {"matches": [{
            "address": callkin_real.hex_address(B),
            "name": "crate::origin_a",
            "evidence": DIRECT_FLIRT,
        }]},
        binary_sha256=STRIPPED,
        discovery_addresses={B},
    )
    prediction = _prediction(labels=labels)
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        report = _score(Path(directory), _alias_catalog(), labels, prediction)
    metrics = report["metrics"]
    assert metrics["direct_ambiguous_count"] == 0
    assert metrics["propagated_ambiguous_count"] == 1
    assert metrics["propagated_incorrect_count"] == 0
    assert metrics["wrongly_propagated_member_count"] == 0


def test_malformed_catalog_alias_is_rejected():
    labels, prediction = _labels(), _prediction()
    malformed = _alias_catalog()
    malformed["origins"][0]["origin"] = "crate::origin_a"
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        try:
            _score(Path(directory), malformed, labels, prediction)
        except ValueError as exc:
            assert "alias" in str(exc) or "catalog" in str(exc)
        else:
            raise AssertionError("malformed catalog alias was accepted")


def test_malformed_catalog_alias_values_fail_closed_as_value_error():
    labels, prediction = _labels(), _prediction()
    malformed = _alias_catalog()
    malformed["cross_origin_aliases"][0]["origins"] = ["crate::origin_a", {"bad": []}]
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        try:
            _score(Path(directory), malformed, labels, prediction)
        except ValueError as exc:
            assert "alias" in str(exc) or "catalog" in str(exc)
        else:
            raise AssertionError("unhashable malformed alias was accepted")


def test_direct_member_spelling_is_bound_to_label_artifact():
    labels, prediction = _labels(), _prediction()
    original = prediction["direct_labels"][0]["member"]
    alternate = "FUN_0" + original[4:]
    prediction["direct_labels"][0]["member"] = alternate
    family = prediction["families"][0]
    family["members"] = sorted(
        alternate if member == original else member for member in family["members"]
    )
    family["direct_seed_members"] = [
        alternate if member == original else member
        for member in family["direct_seed_members"]
    ]
    family["seed_labels"] = [
        {**seed, "member": alternate if seed["member"] == original else seed["member"]}
        for seed in family["seed_labels"]
    ]
    for item in prediction["propagated_labels"]:
        item["seed_members"] = [
            alternate if member == original else member
            for member in item["seed_members"]
        ]
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        try:
            _score(Path(directory), _catalog(), labels, prediction)
        except ValueError as exc:
            assert "member" in str(exc) or "direct" in str(exc)
        else:
            raise AssertionError("alternate direct member spelling was accepted")


def test_decoded_direct_and_propagated_address_overlap_fails_closed():
    labels, prediction = _labels(), _prediction()
    direct_member = prediction["direct_labels"][0]["member"]
    alternate = "FUN_0" + direct_member[4:]
    prediction["propagated_labels"][0]["member"] = alternate
    family = prediction["families"][0]
    family["members"] = sorted(
        alternate if member == _id(B) else member for member in family["members"]
    )
    family["propagated_members"] = [alternate]
    with tempfile.TemporaryDirectory(prefix="f10-score-") as directory:
        try:
            _score(Path(directory), _catalog(), labels, prediction)
        except ValueError as exc:
            assert "share decoded address" in str(exc)
        else:
            raise AssertionError("decoded direct/propagated overlap was accepted")


def test_mapping_inputs_bind_canonical_content_and_reject_tampering():
    catalog, labels = _catalog(), _labels()
    catalog_sha = _canonical_sha(catalog)
    labels_sha = _canonical_sha(labels)
    prediction = _prediction(labels=labels, labels_sha256=labels_sha)
    prediction_sha = _canonical_sha(prediction)
    report = scorer.score_callkin_f10_catalog(
        catalog,
        labels,
        prediction,
        catalog_sha256=catalog_sha,
        labels_sha256=labels_sha,
        prediction_sha256=prediction_sha,
    )
    assert report["provenance"]["all_rust_catalog_sha256"] == catalog_sha
    assert report["provenance"]["oxidizer_labels_sha256"] == labels_sha
    assert report["provenance"]["family_label_propagation_sha256"] == prediction_sha

    tampered_catalog = copy.deepcopy(catalog)
    tampered_catalog["case"] = "tampered"
    try:
        scorer.score_callkin_f10_catalog(
            tampered_catalog,
            labels,
            prediction,
            catalog_sha256=catalog_sha,
            labels_sha256=labels_sha,
            prediction_sha256=prediction_sha,
        )
    except ValueError as exc:
        assert "canonical" in str(exc) or "catalog" in str(exc)
    else:
        raise AssertionError("tampered mapping was accepted with its old digest")


def _main() -> int:
    test_strict_scores_exact_origin_owner_and_all_direct_seeds()
    test_rescue_is_scored_and_case_build_names_are_not_identity()
    test_owner_only_error_is_wrong_propagation_and_wrong_family()
    test_unknown_propagated_address_fails_closed()
    test_hash_and_direct_baseline_mismatches_fail_without_mutation()
    test_stripped_hash_mismatch_is_rejected()
    test_scoring_does_not_modify_input_files()
    test_raw_label_hash_binds_prediction_to_the_file_being_scored()
    test_catalog_alias_is_ambiguous_neutral_for_direct_and_evaluable_metrics()
    test_catalog_alias_is_ambiguous_neutral_for_propagated_member()
    test_malformed_catalog_alias_is_rejected()
    test_malformed_catalog_alias_values_fail_closed_as_value_error()
    test_direct_member_spelling_is_bound_to_label_artifact()
    test_decoded_direct_and_propagated_address_overlap_fails_closed()
    test_mapping_inputs_bind_canonical_content_and_reject_tampering()
    print("CallKin-Real F10 catalog scoring: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
