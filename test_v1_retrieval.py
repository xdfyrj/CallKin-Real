"""R3b: the frozen F5 runs on CallKin-Real artifacts and stays frozen.

Three things are worth failing on. The F5 code must be the frozen bytes, or the
formal V1 results say nothing about what this produces. The oracle-side modules
it imports must refuse rather than run, or the fixture path is merely unused
instead of unavailable. And the three artifacts must satisfy the schema F6
validates, since an artifact that only nearly validates fails later and further
from the cause.

The real-binary part runs when CALLKIN_REAL_TEST_BINARY is set.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import callkin_real
import v1_retrieval
from real_v1_adapter import load_from_run
from v1_retrieval import (
    CANDIDATE_SCOPE,
    DEFAULT_TOP_K,
    build_candidate_artifacts,
    write_candidate_artifacts,
)

HERE = Path(__file__).resolve().parent
FROZEN_V1 = HERE.parent / "v0-engine-py-f10"
COPIED = {
    "v1_candidates.py": "v1_candidates.py",
    "v1_retrieval_views.py": "v1_retrieval_views.py",
    "paths.py": "paths.py",
    "analysis/v1_consensus_candidates.py": "analysis/v1_consensus_candidates.py",
}
STUBS = ("engine.py", "loader.py", "build_manifest.py")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_copied_f5_is_byte_identical_to_the_frozen_one() -> str:
    if not FROZEN_V1.is_dir():
        return "  (frozen V1 checkout absent; byte comparison skipped)"
    for local, frozen in COPIED.items():
        here, there = HERE / "frozen_v1" / local, FROZEN_V1 / frozen
        assert _sha256(here) == _sha256(there), f"{local} diverged from the frozen V1"
    return f"  ({len(COPIED)} F5 modules byte-identical to the frozen V1)"


def test_the_oracle_side_modules_refuse_instead_of_running():
    # If these ever became real, a fixture-based run would silently become
    # possible again, and its universe would come from an oracle.
    sys.path.insert(0, str(HERE / "frozen_v1"))
    try:
        import engine
        import loader
    finally:
        sys.path.remove(str(HERE / "frozen_v1"))

    for call in (lambda: loader.load_case("anything"),
                 lambda: engine.run_cg_wl(None),
                 lambda: engine.CGWLResult()):
        try:
            call()
        except NotImplementedError:
            continue
        raise AssertionError("an oracle-side entry point ran")
    # v1_candidates imports both at module scope, so importing it must still
    # work; only calling through them may not.
    assert v1_retrieval.generate_multiview_candidate_pairs is not None


def _stub_input():
    """Four bodies, two of them identical, over a two-round relation."""
    clean = bytes([0x31, 0xC0, 0xC3])
    longer = bytes([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])

    class _Image:
        def read(self, address, size):
            return {0x1000: clean, 0x2000: clean,
                    0x3000: longer, 0x4000: longer}[address][:size]

    from body_builder import build_bodies

    body = build_bodies(_Image(), {
        0x1000: ("FUN_00101000", len(clean)),
        0x2000: ("FUN_00102000", len(clean)),
        0x3000: ("FUN_00103000", len(longer)),
        0x4000: ("FUN_00104000", len(longer)),
    })
    ids = ["FUN_00101000", "FUN_00102000", "FUN_00103000", "FUN_00104000"]
    universe = {
        "functions": [
            {"id": function_id, "analysis_status": "complete",
             "grouping_role": "member", "quality": {"complete_decode": True}}
            for function_id in ids
        ],
        "abstentions": [],
    }
    relation = {
        "rounds": 1,
        "predicted_clusters": {"C1": ids[:2], "C2": ids[2:]},
        "round_history": [
            {"round": 0, "clusters": {f"C{i + 1}": [f] for i, f in enumerate(ids)}},
            {"round": 1, "changed": True,
             "clusters": {"C1": ids[:2], "C2": ids[2:]}},
        ],
        "anchor_classes": {},
        "edges": [
            {"source": ids[0], "target": ids[2], "count": 1},
            {"source": ids[1], "target": ids[3], "count": 1},
        ],
        "functions": [
            {"id": function_id, "relation_status": "relation-member"}
            for function_id in ids
        ],
    }
    return body, universe, relation


def _load_stub(directory: Path):
    body, universe, relation = _stub_input()
    body_path = directory / "body.json"
    callkin_real.write_json(body_path, callkin_real.artifact_envelope(
        stage="body", binary_sha256="a" * 64,
        inputs={"discovery": "d" * 64}, payload=body,
    ))
    universe_path = directory / "universe.json"
    callkin_real.write_json(universe_path, callkin_real.artifact_envelope(
        stage="universe", binary_sha256="a" * 64,
        inputs={"discovery": "d" * 64, "body": _sha256(body_path)},
        payload=universe,
    ))
    relation_path = directory / "relation.json"
    callkin_real.write_json(relation_path, callkin_real.artifact_envelope(
        stage="relation", binary_sha256="a" * 64,
        inputs={"universe": _sha256(universe_path)}, payload=relation,
    ))
    from real_v1_adapter import load_real_v1_input

    return load_real_v1_input(body_path, universe_path, relation_path)


def test_the_three_artifacts_are_built_and_validate():
    from v1_candidates import validate_candidate_artifact

    with tempfile.TemporaryDirectory(prefix="callkin-f5-") as directory:
        artifacts = build_candidate_artifacts(_load_stub(Path(directory)))

    assert set(artifacts) == {"multi", "consensus3", "consensus2"}
    for name, artifact in artifacts.items():
        validate_candidate_artifact(artifact)
        assert artifact["artifact"] == "v1-multiview-candidate-pairs", name
        assert artifact["config"]["top_k"] == DEFAULT_TOP_K
        assert artifact["config"]["views"] == ["token", "cfg", "relation"]
        assert artifact["scope"] == CANDIDATE_SCOPE


def test_consensus_is_a_subset_and_three_is_a_subset_of_two():
    with tempfile.TemporaryDirectory(prefix="callkin-f5-") as directory:
        artifacts = build_candidate_artifacts(_load_stub(Path(directory)))

    def keys(name):
        return {tuple(pair["pair"]) for pair in artifacts[name]["pairs"]}

    assert keys("consensus3") <= keys("consensus2") <= keys("multi")
    for name, required in (("consensus3", 3), ("consensus2", 2)):
        derivation = artifacts[name]["provenance"]["candidate_derivation"]
        assert derivation["minimum_view_count"] == required
        assert derivation["derived_pair_count"] == len(artifacts[name]["pairs"])
        for pair in artifacts[name]["pairs"]:
            chosen = [r for r in pair["reasons"] if r.endswith("_top_k")]
            assert len(chosen) >= required, pair["pair"]


def test_no_label_reaches_the_candidate_artifacts():
    with tempfile.TemporaryDirectory(prefix="callkin-f5-") as directory:
        artifacts = build_candidate_artifacts(_load_stub(Path(directory)))
    text = json.dumps(artifacts)
    for leaked in ("flirt", "canonical_origin", "label_status", "drop_in_place"):
        assert leaked not in text, f"the candidate artifacts carry {leaked}"


def test_the_provenance_says_the_subject_metadata_was_not_observed():
    # case/build/profile/scope are a closed schema describing a controlled
    # compilation. A binary found in the wild has none of it, and the field
    # itself cannot say so, so the provenance has to.
    with tempfile.TemporaryDirectory(prefix="callkin-f5-") as directory:
        artifacts = build_candidate_artifacts(_load_stub(Path(directory)))
    provenance = artifacts["multi"]["provenance"]
    assert provenance["subject_metadata_observed"] is False
    assert provenance["binary_sha256"] == "a" * 64
    for stage in ("body", "universe", "relation"):
        assert len(provenance[f"{stage}_sha256" if stage != "body"
                               else "body_evidence_sha256"]) == 64


def test_writing_twice_produces_the_same_bytes():
    with tempfile.TemporaryDirectory(prefix="callkin-f5-") as directory:
        room = Path(directory)
        source = _load_stub(room)
        digests = []
        for run in ("first", "second"):
            target = room / run
            written = write_candidate_artifacts(
                build_candidate_artifacts(source), target, "case",
                top_k=DEFAULT_TOP_K,
            )
            digests.append({name: item["sha256"] for name, item in written.items()})
        assert digests[0] == digests[1], "F5 output is not deterministic"


def test_the_consensus_derivation_names_the_multi_view_file_on_disk():
    with tempfile.TemporaryDirectory(prefix="callkin-f5-") as directory:
        room = Path(directory)
        written = write_candidate_artifacts(
            build_candidate_artifacts(_load_stub(room)), room / "out", "case",
            top_k=DEFAULT_TOP_K,
        )
        for name in ("consensus3", "consensus2"):
            artifact = json.loads(Path(written[name]["path"]).read_text(encoding="utf-8"))
            recorded = artifact["provenance"]["candidate_derivation"][
                "source_candidate_sha256"
            ]
            assert recorded == written["multi"]["sha256"], name
            assert recorded == _sha256(Path(written["multi"]["path"]))


def test_a_real_binary_produces_the_three_queues() -> str:
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the real-binary check)"

    from v1_candidates import validate_candidate_artifact

    with tempfile.TemporaryDirectory(prefix="callkin-f5-real-") as directory:
        room = Path(directory)
        output = room / "run.json"
        assert callkin_real.main([target, "--no-flirt", "--output", str(output)]) == 0
        source = load_from_run(output)
        artifacts = build_candidate_artifacts(source)
        written = write_candidate_artifacts(artifacts, room, "run", top_k=DEFAULT_TOP_K)

        counts = {}
        for name, artifact in artifacts.items():
            validate_candidate_artifact(artifact)
            counts[name] = len(artifact["pairs"])
            ids = set(artifact["universe"]["target_ids"])
            assert ids == set(source.comparable), name
            for pair in artifact["pairs"]:
                assert pair["first"] in ids and pair["second"] in ids, name

        assert counts["consensus3"] <= counts["consensus2"] <= counts["multi"]
        assert counts["multi"] > 0, "F5 retrieved nothing"
        for name, item in written.items():
            assert _sha256(Path(item["path"])) == item["sha256"], name

    return (
        f"  ({len(source.comparable)} targets -> multi {counts['multi']}, "
        f"consensus2 {counts['consensus2']}, consensus3 {counts['consensus3']})"
    )


def main() -> int:
    notes = [test_the_copied_f5_is_byte_identical_to_the_frozen_one()]
    test_the_oracle_side_modules_refuse_instead_of_running()
    test_the_three_artifacts_are_built_and_validate()
    test_consensus_is_a_subset_and_three_is_a_subset_of_two()
    test_no_label_reaches_the_candidate_artifacts()
    test_the_provenance_says_the_subject_metadata_was_not_observed()
    test_writing_twice_produces_the_same_bytes()
    test_the_consensus_derivation_names_the_multi_view_file_on_disk()
    notes.append(test_a_real_binary_produces_the_three_queues())
    print("CallKin-Real F5 retrieval: PASS")
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
