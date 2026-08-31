"""R4: the frozen F6 runs on the F5 consensus3 queue, or refuses it whole.

The refusal path matters as much as the success path. F6 prices the queue
before it compares anything and rejects the artifact outright when it does not
fit, because candidates are stored in function-id order and spending the budget
while walking them would analyse an arbitrary prefix of the binary and present
the result as an answer about the binary. A test that only ever ran inside the
budget would not notice if that gate were removed.

The real-binary part runs when CALLKIN_REAL_TEST_BINARY is set.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import tempfile
from pathlib import Path

import callkin_real
import v1_grouping
from real_v1_adapter import load_from_run, load_real_v1_input
from v1_grouping import (
    BUDGET_REFUSED,
    COMPLETED,
    FORMAL_CONFIG,
    STRICT_QUEUE,
    build_strict_families,
    price,
    summarize,
)
from v1_retrieval import DEFAULT_TOP_K, build_candidate_artifacts

HERE = Path(__file__).resolve().parent
FROZEN_V1 = HERE.parent / "v0-engine-py-f10"
COPIED = ("v1_engine.py", "configs/v1.formal.json")

# Spec 10.5. Written out so a silent edit to the config file fails here rather
# than changing what "formal" means three stages downstream.
FORMAL_POLICY = {
    "structure_match_threshold": 0.95,
    "slot_match_threshold": 1.0,
    "structure_reject_threshold": None,
    "require_informative_slot": True,
    "abstain_on_opaque_indirect": True,
    "max_comparison_count": 10000,
    "max_alignment_cell_budget": 500000000,
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_copied_f6_is_byte_identical_to_the_frozen_one() -> str:
    if not FROZEN_V1.is_dir():
        return "  (frozen V1 checkout absent; byte comparison skipped)"
    for name in COPIED:
        here, there = HERE / "frozen_v1" / name, FROZEN_V1 / name
        assert _sha256(here) == _sha256(there), f"{name} diverged from the frozen V1"
    return f"  ({len(COPIED)} F6 files byte-identical to the frozen V1)"


def test_the_formal_policy_is_the_one_the_spec_names():
    from v1_engine import PairPolicyConfig

    config = PairPolicyConfig.from_file(FORMAL_CONFIG)
    for name, expected in FORMAL_POLICY.items():
        assert getattr(config, name) == expected, name
    assert STRICT_QUEUE == "consensus3"


def _stub_source(directory: Path):
    """Four bodies over a two-round relation, small enough to price exactly."""
    clean = bytes([0x31, 0xC0, 0xC3])
    longer = bytes([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])

    class _Image:
        def read(self, address, size):
            return {0x1000: clean, 0x2000: clean,
                    0x3000: longer, 0x4000: longer}[address][:size]

    from body_builder import build_bodies

    ids = ["FUN_00101000", "FUN_00102000", "FUN_00103000", "FUN_00104000"]
    body = build_bodies(_Image(), {
        0x1000: (ids[0], len(clean)), 0x2000: (ids[1], len(clean)),
        0x3000: (ids[2], len(longer)), 0x4000: (ids[3], len(longer)),
    })
    universe = {
        "functions": [
            {"id": i, "analysis_status": "complete", "grouping_role": "member",
             "quality": {"complete_decode": True}} for i in ids
        ],
        "abstentions": [],
    }
    relation = {
        "rounds": 1,
        "predicted_clusters": {"C1": ids[:2], "C2": ids[2:]},
        "round_history": [
            {"round": 0, "clusters": {f"C{n + 1}": [i] for n, i in enumerate(ids)}},
            {"round": 1, "changed": True, "clusters": {"C1": ids[:2], "C2": ids[2:]}},
        ],
        "anchor_classes": {},
        "edges": [{"source": ids[0], "target": ids[2], "count": 1},
                  {"source": ids[1], "target": ids[3], "count": 1}],
        "functions": [{"id": i, "relation_status": "relation-member"} for i in ids],
    }

    body_path = directory / "body.json"
    callkin_real.write_json(body_path, callkin_real.artifact_envelope(
        stage="body", binary_sha256="a" * 64,
        inputs={"discovery": "d" * 64}, payload=body))
    universe_path = directory / "universe.json"
    callkin_real.write_json(universe_path, callkin_real.artifact_envelope(
        stage="universe", binary_sha256="a" * 64,
        inputs={"discovery": "d" * 64, "body": _sha256(body_path)},
        payload=universe))
    relation_path = directory / "relation.json"
    callkin_real.write_json(relation_path, callkin_real.artifact_envelope(
        stage="relation", binary_sha256="a" * 64,
        inputs={"universe": _sha256(universe_path)}, payload=relation))
    return load_real_v1_input(body_path, universe_path, relation_path)


def _queue(source):
    artifacts = build_candidate_artifacts(source, top_k=DEFAULT_TOP_K)
    return artifacts[STRICT_QUEUE]


def _config(**overrides):
    from v1_engine import PairPolicyConfig

    return dataclasses.replace(
        PairPolicyConfig.from_file(FORMAL_CONFIG), **overrides
    )


def test_f6_completes_inside_the_budget_and_the_artifact_validates():
    from v1_engine import _validate_family_statuses

    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        queue = _queue(source)
        status, families, accounting = build_strict_families(
            queue, source, config=_config(), candidate_sha256="c" * 64,
        )

    assert status == COMPLETED
    assert families is not None
    assert accounting["within_budget"] is True
    _validate_family_statuses(families)
    assert families["artifact"] == "v1-family-grouping"
    assert families["universe"]["target_ids"] == sorted(source.comparable)
    assert families["metrics"]["budget_limited"] is False
    # Every target lands in exactly one status bucket, whatever that status is.
    buckets = families["status_members"]
    placed = sum(len(buckets[name]) for name in
                 ("accepted", "provisional", "unresolved", "abstain"))
    assert placed == len(families["universe"]["target_ids"])


def test_a_queue_that_does_not_fit_is_refused_whole():
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        queue = _queue(source)
        exact = price(queue, source, _config())
        # One cell short of what the queue needs.
        status, families, accounting = build_strict_families(
            queue, source,
            config=_config(
                max_alignment_cell_budget=exact["required_alignment_cells"] - 1
            ),
            candidate_sha256="c" * 64,
        )

    assert status == BUDGET_REFUSED
    # No artifact at all, rather than an artifact about part of the binary.
    assert families is None
    assert accounting["within_budget"] is False
    assert accounting["required_alignment_cells"] == exact["required_alignment_cells"]
    assert accounting["pair_count"] == len(queue["pairs"])


def test_the_comparison_ceiling_refuses_the_same_way():
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        queue = _queue(source)
        status, families, accounting = build_strict_families(
            queue, source,
            config=_config(max_comparison_count=0), candidate_sha256="c" * 64,
        )
    assert status == BUDGET_REFUSED and families is None
    assert accounting["max_comparison_count"] == 0


def test_one_more_cell_than_needed_is_enough():
    # The gate is on the real demand, not on a margin: exactly the required
    # number of cells must pass.
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        queue = _queue(source)
        required = price(queue, source, _config())["required_alignment_cells"]
        status, families, _ = build_strict_families(
            queue, source,
            config=_config(max_alignment_cell_budget=required),
            candidate_sha256="c" * 64,
        )
    assert status == COMPLETED and families is not None


def test_the_accounting_reports_the_shape_of_the_cost_not_only_its_total():
    # A refusal caused by one enormous pair is a different problem from one
    # caused by a long tail, and the fix differs, so the split is recorded.
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        accounting = price(_queue(source), source, _config())
    for key in ("alignment_cells_median", "alignment_cells_max",
                "alignment_cells_top10_share", "alignment_cells_top50_share"):
        assert key in accounting
    assert accounting["alignment_cells_max"] >= accounting["alignment_cells_median"]
    assert 0.0 <= accounting["alignment_cells_top10_share"] <= 1.0


def test_the_families_artifact_names_the_body_and_the_queue_it_used():
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        _, families, _ = build_strict_families(
            _queue(source), source, config=_config(), candidate_sha256="c" * 64,
        )
    provenance = families["provenance"]
    assert provenance["body_evidence_sha256"] == source.stage_sha256["body"]
    assert provenance["candidate_artifact_sha256"] == "c" * 64
    assert provenance["subject_metadata_observed"] is False


def test_a_body_hash_that_disagrees_with_the_queue_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        queue = _queue(source)
        wrong = dataclasses.replace(source, stage_sha256={
            **source.stage_sha256, "body": "f" * 64,
        })
        try:
            build_strict_families(
                queue, wrong, config=_config(), candidate_sha256="c" * 64,
            )
        except ValueError as exc:
            assert "SHA-256 mismatch" in str(exc)
        else:
            raise AssertionError("F6 scored a queue against the wrong bodies")


def test_no_label_reaches_the_families_artifact():
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        source = _stub_source(Path(directory))
        _, families, _ = build_strict_families(
            _queue(source), source, config=_config(), candidate_sha256="c" * 64,
        )
    text = json.dumps(families)
    for leaked in ("flirt", "canonical_origin", "label_status", "drop_in_place"):
        assert leaked not in text, f"the families artifact carries {leaked}"


def test_running_f6_twice_produces_the_same_bytes():
    with tempfile.TemporaryDirectory(prefix="callkin-f6-") as directory:
        room = Path(directory)
        source = _stub_source(room)
        queue = _queue(source)
        digests = []
        for run in ("first", "second"):
            _, families, _ = build_strict_families(
                queue, source, config=_config(), candidate_sha256="c" * 64,
            )
            digests.append(v1_grouping.write_json(room / f"{run}.json", families))
        assert digests[0] == digests[1], "F6 output is not deterministic"


def test_a_real_binary_runs_f6_or_says_why_it_could_not() -> str:
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the real-binary check)"

    from v1_engine import _validate_family_statuses

    with tempfile.TemporaryDirectory(prefix="callkin-f6-real-") as directory:
        room = Path(directory)
        output = room / "run.json"
        assert callkin_real.main([target, "--no-flirt", "--output", str(output)]) == 0
        source = load_from_run(output)
        queue = build_candidate_artifacts(source, top_k=DEFAULT_TOP_K)[STRICT_QUEUE]
        status, families, accounting = build_strict_families(
            queue, source, config=_config(), candidate_sha256="c" * 64,
        )

        if status == BUDGET_REFUSED:
            assert families is None
            assert accounting["required_alignment_cells"] > (
                accounting["max_alignment_cell_budget"]
            ) or accounting["required_comparisons"] > (
                accounting["max_comparison_count"]
            )
            return (
                f"  (budget-refused: {accounting['pair_count']} pairs need "
                f"{accounting['required_alignment_cells']:,} cells, ceiling is "
                f"{accounting['max_alignment_cell_budget']:,})"
            )

        _validate_family_statuses(families)
        assert families["universe"]["target_ids"] == sorted(source.comparable)
        counts = summarize(families)
        return (
            f"  (completed: {accounting['pair_count']} pairs, "
            f"{counts['accepted_family_count']} accepted families, "
            f"{counts['accepted_member_count']} accepted members)"
        )


def main() -> int:
    notes = [test_the_copied_f6_is_byte_identical_to_the_frozen_one()]
    test_the_formal_policy_is_the_one_the_spec_names()
    test_f6_completes_inside_the_budget_and_the_artifact_validates()
    test_a_queue_that_does_not_fit_is_refused_whole()
    test_the_comparison_ceiling_refuses_the_same_way()
    test_one_more_cell_than_needed_is_enough()
    test_the_accounting_reports_the_shape_of_the_cost_not_only_its_total()
    test_the_families_artifact_names_the_body_and_the_queue_it_used()
    test_a_body_hash_that_disagrees_with_the_queue_is_refused()
    test_no_label_reaches_the_families_artifact()
    test_running_f6_twice_produces_the_same_bytes()
    notes.append(test_a_real_binary_runs_f6_or_says_why_it_could_not())
    print("CallKin-Real F6 strict grouping: PASS")
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
