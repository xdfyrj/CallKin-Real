"""R4: the adapter hands over the universe, the bodies and the relation, only.

Two kinds of failure matter here and they fail differently. Handing the frozen
V1 a label is a correctness failure that would produce a good-looking number,
so it is checked by content. Handing it a stale artifact is the same kind of
failure, so the chain is checked by hash rather than by filename.

The real-binary part runs when CALLKIN_REAL_TEST_BINARY is set. The last test
runs only when the frozen V1 checkout is beside this one, because what it
proves is that the reshaped relation is the shape that module actually takes.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
from pathlib import Path

import callkin_real
from real_v1_adapter import (
    ArtifactChainError,
    assert_label_free,
    load_from_run,
    load_real_v1_input,
    relation_context,
)

FROZEN_V1 = Path(__file__).resolve().parent.parent / "v0-engine-py-f10"


def _write(directory: Path, stage: str, payload, inputs, binary="a" * 64) -> Path:
    path = directory / f"{stage}.json"
    callkin_real.write_json(path, callkin_real.artifact_envelope(
        stage=stage, binary_sha256=binary, inputs=inputs, payload=payload,
    ))
    return path


def _body_payload():
    clean = bytes([0x31, 0xC0, 0xC3])
    gapped = bytes([0x31, 0xC0, 0x06, 0xC3])

    class _Image:
        def read(self, address, size):
            return {0x1000: clean, 0x2000: clean, 0x3000: gapped}[address][:size]

    from body_builder import build_bodies

    return build_bodies(_Image(), {
        0x1000: ("FUN_00101000", len(clean)),
        0x2000: ("FUN_00102000", len(clean)),
        0x3000: ("FUN_00103000", len(gapped)),
    })


def _universe_payload():
    return {
        "functions": [
            {"id": "FUN_00101000", "analysis_status": "complete",
             "grouping_role": "member", "quality": {"complete_decode": True}},
            {"id": "FUN_00102000", "analysis_status": "complete",
             "grouping_role": "member", "quality": {"complete_decode": True}},
            {"id": "FUN_00103000", "analysis_status": "incomplete",
             "grouping_role": "abstain", "quality": {"complete_decode": False}},
            {"id": "FUN_00109000", "analysis_status": "external",
             "grouping_role": "context-only", "quality": None},
        ],
        "abstentions": [{"id": "FUN_00103000", "reason": "incomplete_body"}],
    }


def _relation_payload():
    return {
        "rounds": 2,
        "predicted_clusters": {"C1": ["FUN_00101000", "FUN_00102000"]},
        "round_history": [
            {"round": 0, "clusters": {"C1": ["FUN_00101000"],
                                      "C2": ["FUN_00102000"]}},
            {"round": 1, "changed": True,
             "clusters": {"C1": ["FUN_00101000", "FUN_00102000"]}},
        ],
        "anchor_classes": {"FUN_00109000": "import:sym.imp.malloc"},
        "edges": [
            {"source": "FUN_00101000", "target": "FUN_00109000", "count": 2},
            {"source": "FUN_00102000", "target": "FUN_00109000", "count": 2},
        ],
        "functions": [
            {"id": "FUN_00101000", "relation_status": "relation-member"},
            {"id": "FUN_00102000", "relation_status": "relation-member"},
            {"id": "FUN_00109000", "relation_status": "relation-context"},
        ],
    }


def _chain(directory: Path, *, body=None, universe=None, relation=None,
           body_binary="a" * 64):
    body_path = _write(directory, "body", body or _body_payload(),
                       {"discovery": "d" * 64}, binary=body_binary)
    body_hash = callkin_real.sha256_file(body_path)
    universe_path = _write(directory, "universe", universe or _universe_payload(),
                           {"discovery": "d" * 64, "body": body_hash})
    universe_hash = callkin_real.sha256_file(universe_path)
    relation_path = _write(directory, "relation", relation or _relation_payload(),
                           {"universe": universe_hash})
    return body_path, universe_path, relation_path


def test_the_universe_is_the_members_and_the_bodies_are_the_complete_ones():
    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        loaded = load_real_v1_input(*_chain(Path(directory)))

    # abstain and context-only are not members; the abstaining member's body
    # is not offered to F4 but the function is still known to be a member.
    assert loaded.members == ("FUN_00101000", "FUN_00102000")
    assert loaded.comparable == ("FUN_00101000", "FUN_00102000")
    assert set(loaded.bodies) == set(loaded.comparable)


def test_an_incomplete_member_is_a_member_but_not_comparable():
    universe = _universe_payload()
    # Same function, now a member with an incomplete body: the case where the
    # universe and the decode result disagree about what may be scored.
    universe["functions"][2]["grouping_role"] = "member"
    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        loaded = load_real_v1_input(*_chain(Path(directory), universe=universe))

    assert "FUN_00103000" in loaded.members
    assert "FUN_00103000" not in loaded.comparable
    assert loaded.excluded_incomplete == ("FUN_00103000",)


def test_a_stale_body_beside_a_fresh_universe_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        room = Path(directory)
        body_path, universe_path, relation_path = _chain(room)
        # Rewrite the body so its hash no longer matches what the universe
        # recorded. Nothing about the file looks wrong on its own.
        stale = _body_payload()
        stale["functions"] = stale["functions"][:2]
        _write(room, "body", stale, {"discovery": "d" * 64})
        try:
            load_real_v1_input(body_path, universe_path, relation_path)
        except ArtifactChainError as exc:
            assert "built from body" in str(exc)
        else:
            raise AssertionError("a stale body was accepted")


def test_artifacts_from_two_binaries_are_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        paths = _chain(Path(directory), body_binary="b" * 64)
        try:
            load_real_v1_input(*paths)
        except ArtifactChainError as exc:
            assert "different binaries" in str(exc)
        else:
            raise AssertionError("artifacts from two binaries were accepted")


def test_the_wrong_artifact_in_the_wrong_slot_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        body_path, universe_path, relation_path = _chain(Path(directory))
        try:
            load_real_v1_input(universe_path, universe_path, relation_path)
        except ArtifactChainError as exc:
            assert "callkin-real-body" in str(exc)
        else:
            raise AssertionError("a universe artifact was accepted as a body")


def test_a_member_with_no_body_record_is_refused():
    universe = _universe_payload()
    universe["functions"].append({
        "id": "FUN_00107000", "analysis_status": "complete",
        "grouping_role": "member", "quality": {"complete_decode": True},
    })
    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        try:
            load_real_v1_input(*_chain(Path(directory), universe=universe))
        except ArtifactChainError as exc:
            assert "no body record" in str(exc)
        else:
            raise AssertionError("a member with no body was accepted")


def test_opaque_count_is_aliased_and_frozen_cache_abstains():
    body = _body_payload()
    body["functions"][0]["quality"]["opaque_indirect_jump_count"] = 1

    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        loaded = load_real_v1_input(*_chain(Path(directory), body=body))

    opaque = loaded.bodies["FUN_00101000"]
    assert opaque.quality["opaque_indirect_jumps"] == 1

    sys.path.insert(0, str(Path(__file__).resolve().parent / "frozen_v1"))
    try:
        from v1_candidates import PairKey
        from v1_engine import PairEvidenceCache, PairPolicyConfig
    finally:
        sys.path.remove(str(Path(__file__).resolve().parent / "frozen_v1"))

    config = PairPolicyConfig.from_dict({
        "policy": {
            "structure_match_threshold": 0.95,
            "slot_match_threshold": 1.0,
            "abstain_on_opaque_indirect": True,
        },
    })
    cache = PairEvidenceCache(loaded.bodies, [], config)
    pair = PairKey.make("FUN_00101000", "FUN_00102000")
    assert not cache.would_compare(pair)
    assert cache.get_evaluation(pair).decision == "abstain"
    assert cache.total_comparisons == 0
    assert cache.total_alignment_cells == 0


def test_conflicting_opaque_quality_keys_are_refused():
    body = _body_payload()
    body["functions"][0]["quality"].update({
        "opaque_indirect_jump_count": 1,
        "opaque_indirect_jumps": 2,
    })

    with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
        try:
            load_real_v1_input(*_chain(Path(directory), body=body))
        except ArtifactChainError as exc:
            assert "opaque_indirect" in str(exc)
        else:
            raise AssertionError("conflicting opaque quality keys were accepted")


def test_a_label_anywhere_in_the_universe_is_refused():
    for field, value in (
        ("flirt", {"name": "core::ptr::drop_in_place<T>"}),
        ("name", "core::ptr::drop_in_place"),
        ("label_status", "direct"),
        ("origin", "core::ptr::drop_in_place"),
    ):
        universe = _universe_payload()
        universe["functions"][0][field] = value
        with tempfile.TemporaryDirectory(prefix="callkin-adapter-") as directory:
            try:
                load_real_v1_input(*_chain(Path(directory), universe=universe))
            except ValueError as exc:
                assert field in str(exc) or "name" in str(exc)
            else:
                raise AssertionError(f"a {field} field reached the frozen V1")


def test_assert_label_free_looks_at_keys_not_at_values():
    # An import's own name is an image fact and a legitimate anchor colour.
    assert_label_free({"FUN_00109000": "import:sym.imp.malloc"}, "anchors")


def test_the_relation_reshape_keeps_only_what_1_wl_saw():
    relation = relation_context(_relation_payload())

    assert relation["final_groups"] == [["FUN_00101000", "FUN_00102000"]]
    assert relation["prior_round_groups"] == [
        (0, [["FUN_00101000"], ["FUN_00102000"]])
    ]
    assert relation["final_round"] == 1
    assert relation["out_signatures"]["FUN_00101000"] == (("FUN_00109000", 2),)
    assert relation["in_signatures"]["FUN_00109000"] == (
        ("FUN_00101000", 2), ("FUN_00102000", 2),
    )
    # A relation-member with no edge gets an empty signature, not a missing key.
    assert relation["out_signatures"]["FUN_00109000"] == ()
    assert relation["anchor_classes"] == {"FUN_00109000": "import:sym.imp.malloc"}


def test_the_reshaped_relation_is_the_shape_the_frozen_view_takes() -> str:
    if not (FROZEN_V1 / "v1_retrieval_views.py").is_file():
        return "  (frozen V1 checkout absent; relation view shape unchecked)"
    sys.path.insert(0, str(FROZEN_V1))
    try:
        from v1_retrieval_views import build_relation_profiles
    finally:
        sys.path.remove(str(FROZEN_V1))

    relation = relation_context(_relation_payload())
    profiles = build_relation_profiles(
        ["FUN_00101000", "FUN_00102000"],
        final_groups=relation["final_groups"],
        prior_round_groups=relation["prior_round_groups"],
        final_round=relation["final_round"],
        out_signatures=relation["out_signatures"],
        in_signatures=relation["in_signatures"],
        anchor_classes=relation["anchor_classes"],
    )
    assert set(profiles) == {"FUN_00101000", "FUN_00102000"}
    for profile in profiles.values():
        assert profile.has_evidence, "the reshape produced an empty profile"
    # They merged at round 1 and were apart at round 0, so the histories differ
    # while the final group agrees. That is the signal the relation view scores.
    first, second = profiles["FUN_00101000"], profiles["FUN_00102000"]
    assert first.final_group == second.final_group
    assert first.history != second.history
    return "  (frozen relation view accepted the reshape)"


def test_a_real_run_loads_end_to_end() -> str:
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the real-binary check)"

    with tempfile.TemporaryDirectory(prefix="callkin-adapter-real-") as directory:
        output = Path(directory) / "run.json"
        assert callkin_real.main([target, "--no-flirt", "--output", str(output)]) == 0
        run = json.loads(output.read_text(encoding="utf-8"))
        loaded = load_from_run(output)

        assert len(loaded.members) == run["summary"]["grouping_role"]["member"]
        assert len(loaded.comparable) == len(loaded.bodies)
        assert set(loaded.comparable) <= set(loaded.members)
        assert loaded.binary_sha256 == run["binary"]["sha256"]
        assert loaded.stage_sha256["body"] == run["stage_sha256"]["body"]

        relation = loaded.relation
        assert relation["final_round"] == run["summary"]["rounds"]
        assert len(relation["prior_round_groups"]) == run["summary"]["rounds"]
        covered = sum(len(group) for group in relation["final_groups"])
        assert covered <= len(loaded.members)

        # A run manifest pointing at an artifact that has since changed must
        # not load, even though every file is individually well formed.
        body_path = callkin_real.stage_artifact_path(output, "body")
        payload = json.loads(body_path.read_text(encoding="utf-8"))
        edited = copy.deepcopy(payload)
        edited["payload"]["functions"] = edited["payload"]["functions"][:-1]
        callkin_real.write_json(body_path, edited)
        try:
            load_from_run(output)
        except ArtifactChainError:
            pass
        else:
            raise AssertionError("a run manifest accepted a changed artifact")

    return (
        f"  ({len(loaded.members)} members, {len(loaded.comparable)} comparable, "
        f"{len(loaded.excluded_incomplete)} incomplete excluded, "
        f"{len(relation['final_groups'])} relation groups)"
    )


def main() -> int:
    test_the_universe_is_the_members_and_the_bodies_are_the_complete_ones()
    test_an_incomplete_member_is_a_member_but_not_comparable()
    test_a_stale_body_beside_a_fresh_universe_is_refused()
    test_artifacts_from_two_binaries_are_refused()
    test_the_wrong_artifact_in_the_wrong_slot_is_refused()
    test_a_member_with_no_body_record_is_refused()
    test_opaque_count_is_aliased_and_frozen_cache_abstains()
    test_conflicting_opaque_quality_keys_are_refused()
    test_a_label_anywhere_in_the_universe_is_refused()
    test_assert_label_free_looks_at_keys_not_at_values()
    test_the_relation_reshape_keeps_only_what_1_wl_saw()
    notes = [
        test_the_reshaped_relation_is_the_shape_the_frozen_view_takes(),
        test_a_real_run_loads_end_to_end(),
    ]
    print("CallKin-Real V1 adapter: PASS")
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
