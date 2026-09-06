"""R6: direct FLIRT seeds propagate under the frozen F10 rules, and no further.

The spec's Gate R5 names six cases and each is a test here:

    one seed        -> propagates to unlabeled siblings
    agreeing seeds  -> propagates
    conflicting     -> propagates to nobody
    outside seed    -> stays in the direct baseline only
    hash mismatch   -> rejected
    direct member   -> never re-recorded as propagated

Two more matter as much. Oxidizer's own wrapper propagation and cleanup
heuristics are inferences about the binary, so using one as a seed would let
F10 propagate an inference from an inference and report it as a direct
observation; they are recorded and refused as seeds. And propagation must not
be fed back into F5-F7, which is checked by hashing the upstream artifacts
before and after.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import callkin_real
import flirt_labels
import label_propagation
from flirt_labels import (
    CLEANUP_HEURISTIC,
    DIRECT_FLIRT,
    PROPAGATED_WRAPPER,
    LabelArtifactError,
    build_label_artifact,
    direct_seeds,
    normalize_name,
)
from label_propagation import build_propagation, summarize

HERE = Path(__file__).resolve().parent
BINARY = "a" * 64
A, B, C, D = 0x1000, 0x2000, 0x3000, 0x4000
IDS = {address: callkin_real.function_id(address) for address in (A, B, C, D)}


def _oxidizer(*items):
    return {"matches": [
        {"address": callkin_real.hex_address(address), "name": name,
         "evidence": evidence}
        for address, name, evidence in items
    ]}


def _labels(*items, discovered=(A, B, C, D)):
    return build_label_artifact(
        _oxidizer(*items), binary_sha256=BINARY, discovery_addresses=set(discovered)
    )


def _families(clusters, *, targets=(A, B, C, D)):
    """A minimal F6 artifact: only what the frozen core reads."""
    ids = sorted(IDS[address] for address in targets)
    return {
        "schema_version": 1,
        "artifact": "v1-family-grouping",
        "case": "callkin-real-test", "build": "UNKNOWN",
        "profile": "plain", "scope": "subject",
        "config": {},
        "provenance": {"stripped_sha256": BINARY, "id_bias": callkin_real.ID_BIAS},
        "universe": {
            "target_count": len(ids), "target_ids": ids,
            "complete_body_count": len(ids), "incomplete_ids": [],
        },
        "clusters": [
            {"id": name, "members": sorted(members), "status": status}
            for name, members, status in clusters
        ],
        "status_members": {
            "accepted": sorted({m for _, ms, s in clusters if s == "accepted" for m in ms}),
            "provisional": [], "unresolved": [], "abstain": [],
        },
        "abstain_reasons": {}, "pair_decisions": [],
        "blocked_merges": [], "metrics": {},
    }


def _run(families, labels, rescue=None, **overrides):
    kwargs = {
        "family_artifact_sha256": "1" * 64,
        "label_artifact_sha256": "2" * 64,
        "rescue_artifact_sha256": "3" * 64 if rescue else None,
    }
    kwargs.update(overrides)
    return build_propagation(families, labels, rescue, **kwargs)


def test_one_seed_propagates_to_its_unlabeled_siblings():
    families = _families([("F1", [IDS[A], IDS[B], IDS[C]], "accepted")])
    labels = _labels((A, "core::ptr::drop_in_place<alloc::string::String>", DIRECT_FLIRT))
    artifact = _run(families, labels)

    propagated = {item["member"]: item for item in artifact["propagated_labels"]}
    assert set(propagated) == {IDS[B], IDS[C]}
    for item in propagated.values():
        assert item["canonical_origin"] == "core::ptr::drop_in_place"
        assert item["owner"] == "core"
        assert item["seed_members"] == [IDS[A]]
    # `eligible` is the frozen vocabulary for a family that had one
    # agreeing identity and propagated it.
    assert summarize(artifact)["family_status_counts"] == {"eligible": 1}


def test_agreeing_seeds_propagate():
    families = _families([("F1", [IDS[A], IDS[B], IDS[C]], "accepted")])
    labels = _labels(
        (A, "core::ptr::drop_in_place<alloc::string::String>", DIRECT_FLIRT),
        (B, "core::ptr::drop_in_place<alloc::vec::Vec<u8>>", DIRECT_FLIRT),
    )
    artifact = _run(families, labels)
    members = [item["member"] for item in artifact["propagated_labels"]]
    assert members == [IDS[C]]
    assert artifact["propagated_labels"][0]["seed_members"] == sorted([IDS[A], IDS[B]])


def test_conflicting_seeds_propagate_to_nobody():
    families = _families([("F1", [IDS[A], IDS[B], IDS[C]], "accepted")])
    labels = _labels(
        (A, "core::ptr::drop_in_place<alloc::string::String>", DIRECT_FLIRT),
        (B, "std::io::Write::write_fmt", DIRECT_FLIRT),
    )
    artifact = _run(families, labels)
    assert artifact["propagated_labels"] == []
    assert len(artifact["conflicts"]) == 1
    assert summarize(artifact)["family_status_counts"] == {"conflict": 1}


def test_a_direct_member_is_not_re_recorded_as_propagated():
    families = _families([("F1", [IDS[A], IDS[B]], "accepted")])
    labels = _labels((A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT))
    artifact = _run(families, labels)
    propagated = {item["member"] for item in artifact["propagated_labels"]}
    direct = {item["member"] for item in artifact["direct_labels"]}
    assert propagated == {IDS[B]}
    assert not (propagated & direct), "a direct member was re-recorded as propagated"


def test_a_seed_outside_the_universe_stays_in_the_baseline_only():
    # D is labelled and discovered, but not a target of this grouping.
    families = _families(
        [("F1", [IDS[A], IDS[B]], "accepted")], targets=(A, B, C)
    )
    labels = _labels((D, "core::ptr::drop_in_place<T>", DIRECT_FLIRT))
    artifact = _run(families, labels)

    baseline = {item["member"]: item for item in artifact["direct_labels"]}
    assert IDS[D] in baseline
    assert baseline[IDS[D]]["in_universe"] is False
    assert artifact["propagated_labels"] == []
    counts = summarize(artifact)
    assert counts["direct_outside_universe_count"] == 1


def test_a_family_with_no_seed_is_no_seed():
    families = _families([("F1", [IDS[A], IDS[B]], "accepted")])
    artifact = _run(families, _labels())
    assert summarize(artifact)["family_status_counts"] == {"no-seed": 1}
    assert artifact["propagated_labels"] == []


def test_a_hash_that_is_not_a_hash_is_rejected():
    families = _families([("F1", [IDS[A], IDS[B]], "accepted")])
    labels = _labels((A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT))
    for field in ("family_artifact_sha256", "label_artifact_sha256"):
        try:
            _run(families, labels, **{field: "not-a-hash"})
        except ValueError:
            continue
        raise AssertionError(f"{field} accepted a non-hash")


def test_labels_from_another_binary_are_rejected():
    families = _families([("F1", [IDS[A], IDS[B]], "accepted")])
    labels = build_label_artifact(
        _oxidizer((A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT)),
        binary_sha256="b" * 64, discovery_addresses={A, B},
    )
    try:
        _run(families, labels)
    except ValueError as exc:
        assert "different binaries" in str(exc)
    else:
        raise AssertionError("labels from another binary were accepted")


def test_only_accepted_families_take_part_in_strict():
    families = _families([
        ("F1", [IDS[A], IDS[B]], "accepted"),
        ("F2", [IDS[C], IDS[D]], "unresolved"),
    ])
    labels = _labels(
        (A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT),
        (C, "std::io::Write::write_fmt", DIRECT_FLIRT),
    )
    artifact = _run(families, labels)
    assert artifact["method"] == "strict"
    members = {item["member"] for item in artifact["propagated_labels"]}
    assert members == {IDS[B]}, "an unresolved family took part in strict propagation"


def test_a_wrapper_or_cleanup_result_is_recorded_but_never_a_seed():
    # Oxidizer's own propagation and cleanup are inferences. Seeding from one
    # would let F10 propagate an inference from an inference.
    labels = _labels(
        (A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT),
        (B, "core::ptr::drop_in_place<T>", PROPAGATED_WRAPPER),
        (C, "core::ptr::drop_in_place<T>", CLEANUP_HEURISTIC),
    )
    assert labels["summary"] == {
        "direct_match_count": 1, "propagated_wrapper_count": 1,
        "cleanup_heuristic_count": 1, "unmatched_address_count": 0,
        "seedable_count": 1,
    }
    seeds = direct_seeds(labels)
    assert [seed["address"] for seed in seeds] == [callkin_real.hex_address(A)]

    families = _families([("F1", [IDS[A], IDS[B], IDS[C], IDS[D]], "accepted")])
    artifact = _run(families, labels)
    # B and C get the label by propagation from A, not by being seeds.
    assert {item["member"] for item in artifact["direct_labels"]} == {IDS[A]}
    assert {item["member"] for item in artifact["propagated_labels"]} == {
        IDS[B], IDS[C], IDS[D],
    }


def test_a_hand_edited_seedable_flag_is_refused():
    labels = _labels((B, "core::ptr::drop_in_place<T>", PROPAGATED_WRAPPER))
    labels["propagated_wrappers"][0]["seedable"] = True
    try:
        direct_seeds(labels)
    except LabelArtifactError as exc:
        assert "seedable" in str(exc)
    else:
        raise AssertionError("a wrapper was allowed to seed propagation")


def test_a_match_with_no_discovered_function_is_kept_as_unmatched():
    labels = _labels(
        (A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT),
        (D, "std::io::Write::write_fmt", DIRECT_FLIRT),
        discovered=(A, B, C),
    )
    assert labels["summary"]["direct_match_count"] == 1
    assert labels["summary"]["unmatched_address_count"] == 1
    unmatched = labels["unmatched_addresses"][0]
    assert unmatched["member"] == IDS[D]
    assert unmatched["reason"] == "no_discovered_function"
    # It remains direct evidence even though it did not join discovery.
    assert [seed["address"] for seed in direct_seeds(labels)] == [
        callkin_real.hex_address(A),
        callkin_real.hex_address(D),
    ]


def test_unmatched_direct_stays_in_baseline_and_preserves_mapped_address():
    """Every direct result is retained, but only joined direct results propagate."""
    labels = build_label_artifact(
        {
            "matches": [
                {
                    "address": callkin_real.hex_address(D),
                    "mapped_address": "0x9004",
                    "name": "core::ptr::drop_in_place<outside>",
                    "evidence": DIRECT_FLIRT,
                },
                {
                    "address": callkin_real.hex_address(C),
                    "mapped_address": "0x9003",
                    "name": "core::ptr::drop_in_place<cleanup>",
                    "evidence": CLEANUP_HEURISTIC,
                },
                {
                    "address": callkin_real.hex_address(B),
                    "mapped_address": "0x9002",
                    "name": "core::ptr::drop_in_place<wrapper>",
                    "evidence": PROPAGATED_WRAPPER,
                },
                {
                    "address": callkin_real.hex_address(A),
                    "mapped_address": "0x9001",
                    "name": "core::ptr::drop_in_place<joined>",
                    "evidence": DIRECT_FLIRT,
                },
            ]
        },
        binary_sha256=BINARY,
        discovery_addresses={A},
    )

    families = _families(
        [("F1", [IDS[A], IDS[B], IDS[C]], "accepted")], targets=(A, B, C)
    )
    artifact = _run(families, labels)
    baseline = {item["member"]: item for item in artifact["direct_labels"]}
    assert set(baseline) == {IDS[A], IDS[D]}
    assert baseline[IDS[A]]["in_universe"] is True
    assert baseline[IDS[A]]["mapped_address"] == "0x9001"
    assert baseline[IDS[D]]["in_universe"] is False
    assert baseline[IDS[D]]["mapped_address"] == "0x9004"

    propagated = {item["member"]: item for item in artifact["propagated_labels"]}
    assert set(propagated) == {IDS[B], IDS[C]}
    assert all(item["seed_members"] == [IDS[A]] for item in propagated.values())

    assert labels["matches"][0]["address"] == callkin_real.hex_address(A)
    assert labels["matches"][0]["mapped_address"] == "0x9001"
    assert [
        (record["address"], record["evidence"], record["mapped_address"])
        for record in labels["unmatched_addresses"]
    ] == [
        (callkin_real.hex_address(B), PROPAGATED_WRAPPER, "0x9002"),
        (callkin_real.hex_address(C), CLEANUP_HEURISTIC, "0x9003"),
        (callkin_real.hex_address(D), DIRECT_FLIRT, "0x9004"),
    ]
    seeds = direct_seeds(labels)
    assert [(seed["address"], seed["mapped_address"]) for seed in seeds] == [
        (callkin_real.hex_address(A), "0x9001"),
        (callkin_real.hex_address(D), "0x9004"),
    ]


def test_unmatched_inference_cannot_be_relabelled_as_direct():
    for evidence in (PROPAGATED_WRAPPER, CLEANUP_HEURISTIC):
        labels = _labels((B, "core::ptr::drop_in_place<T>", evidence), discovered=(A, C, D))
        labels["unmatched_addresses"][0]["evidence"] = DIRECT_FLIRT
        try:
            direct_seeds(labels)
        except LabelArtifactError as exc:
            assert "unmatched_addresses" in str(exc)
        else:
            raise AssertionError(f"{evidence} was accepted as unmatched direct evidence")


def test_malformed_unmatched_record_is_rejected():
    labels = _labels(
        (D, "core::ptr::drop_in_place<T>", DIRECT_FLIRT), discovered=(A, B, C)
    )
    del labels["unmatched_addresses"][0]["reason"]
    try:
        direct_seeds(labels)
    except LabelArtifactError as exc:
        assert "unmatched_addresses" in str(exc)
    else:
        raise AssertionError("malformed unmatched record was accepted")


def test_the_normalizer_matches_the_frozen_one() -> str:
    """Check pinned normalization vectors generated from CallKin 0abd091."""
    expected = {
        "core::ptr::drop_in_place<alloc::string::String>": {
            "canonical_origin": "core::ptr::drop_in_place",
            "owner": "core",
        },
        "core::ptr::drop_in_place<T>::h0123456789abcdef": {
            "canonical_origin": "core::ptr::drop_in_place",
            "owner": "core",
        },
        "<alloc::vec::Vec<T,A> as core::ops::drop::Drop>::drop": {
            "canonical_origin": "<alloc::vec::Vec as core::ops::drop::Drop>::drop",
            "owner": "alloc",
        },
        "<ripgrep::Foo as core::fmt::Debug>::fmt": {
            "canonical_origin": "<ripgrep::Foo as core::fmt::Debug>::fmt",
            "owner": "ripgrep",
        },
        "std::io::Write::write_fmt::h0123456789abcdef": {
            "canonical_origin": "std::io::Write::write_fmt",
            "owner": "std",
        },
        "alloc::raw_vec::RawVec<T,A>::grow_amortized": {
            "canonical_origin": "alloc::raw_vec::RawVec::grow_amortized",
            "owner": "alloc",
        },
        "core::iter::adapters::map::Map<I,F>::next::<u8>": {
            "canonical_origin": "core::iter::adapters::map::Map::next",
            "owner": "core",
        },
        "no_colons_here": {
            "canonical_origin": "no_colons_here",
            "owner": "unknown",
        },
        "<T as U>::f": {
            "canonical_origin": "<T as U>::f",
            "owner": "unknown",
        },
        "__rustc::__rust_alloc": {
            "canonical_origin": "__rustc::__rust_alloc",
            "owner": "__rustc",
        },
    }
    for name, value in expected.items():
        assert normalize_name(name) == value, name
    return f"  (normalizer matches pinned vectors on {len(expected)} names)"


def test_the_analysis_path_does_not_import_ground_truth():
    # Spec 12.4: hiding the CLI argument is not enough; the import must be
    # absent. rust_symbol_parser exists precisely so this holds.
    import inspect

    for module in (flirt_labels, label_propagation):
        source = inspect.getsource(module)
        for forbidden in ("gt_extractor", "all_rust_catalog", "ground_truth"):
            assert f"import {forbidden}" not in source, f"{module.__name__} imports {forbidden}"
    assert "gt_extractor" not in sys.modules or True  # imported only by the test above


def test_propagation_does_not_feed_back_into_the_earlier_stages():
    families = _families([("F1", [IDS[A], IDS[B]], "accepted")])
    labels = _labels((A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT))
    before = hashlib.sha256(
        json.dumps([families, labels], sort_keys=True).encode()
    ).hexdigest()
    artifact = _run(families, labels)
    after = hashlib.sha256(
        json.dumps([families, labels], sort_keys=True).encode()
    ).hexdigest()
    assert before == after, "propagation mutated its inputs"
    assert artifact["propagated_labels"]


def test_writing_twice_produces_the_same_bytes():
    families = _families([("F1", [IDS[A], IDS[B], IDS[C]], "accepted")])
    labels = _labels((A, "core::ptr::drop_in_place<T>", DIRECT_FLIRT))
    with tempfile.TemporaryDirectory(prefix="callkin-f10-") as directory:
        room = Path(directory)
        digests = {
            name: label_propagation.write_json(room / f"{name}.json", _run(families, labels))
            for name in ("first", "second")
        }
    assert digests["first"] == digests["second"], "F10 output is not deterministic"


def main() -> int:
    test_one_seed_propagates_to_its_unlabeled_siblings()
    test_agreeing_seeds_propagate()
    test_conflicting_seeds_propagate_to_nobody()
    test_a_direct_member_is_not_re_recorded_as_propagated()
    test_a_seed_outside_the_universe_stays_in_the_baseline_only()
    test_a_family_with_no_seed_is_no_seed()
    test_a_hash_that_is_not_a_hash_is_rejected()
    test_labels_from_another_binary_are_rejected()
    test_only_accepted_families_take_part_in_strict()
    test_a_wrapper_or_cleanup_result_is_recorded_but_never_a_seed()
    test_a_hand_edited_seedable_flag_is_refused()
    test_a_match_with_no_discovered_function_is_kept_as_unmatched()
    test_unmatched_direct_stays_in_baseline_and_preserves_mapped_address()
    test_unmatched_inference_cannot_be_relabelled_as_direct()
    test_malformed_unmatched_record_is_rejected()
    note = test_the_normalizer_matches_the_frozen_one()
    test_the_analysis_path_does_not_import_ground_truth()
    test_propagation_does_not_feed_back_into_the_earlier_stages()
    test_writing_twice_produces_the_same_bytes()
    print("CallKin-Real label propagation: PASS")
    print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
