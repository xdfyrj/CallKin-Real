"""Tests for the frozen relaxed replay evaluator."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import replay_relaxed as replay
from replay_relaxed import micro_aggregate, score_replay


A, B, C = "A", "B", "C"


def test_wsl_frozen_paths_translate_only_for_windows_runtime():
    wsl = Path("/mnt/c/users/sumyr/playground/REV/v0-engine-py-f1")
    assert str(replay.native_path(wsl, os_name="nt")).replace("\\", "/") == (
        "C:/users/sumyr/playground/REV/v0-engine-py-f1"
    )
    assert replay.native_path(wsl, os_name="posix") == wsl
    ordinary = Path("relative/results")
    assert replay.native_path(ordinary, os_name="nt") == ordinary


def test_oracle_metadata_may_omit_scope_but_not_conflict():
    strict = {"case": "c", "build": "O3S", "profile": "plain", "scope": "rust-nonstd"}
    oracle = {"case": "c", "build": "O3S", "profile": "plain"}
    replay._metadata_match(strict, oracle, allow_missing={"scope"})
    conflicting = dict(oracle, build="O2")
    try:
        replay._metadata_match(strict, conflicting, allow_missing={"scope"})
    except ValueError as exc:
        assert "build" in str(exc)
    else:
        raise AssertionError("conflicting oracle build metadata was accepted")


def test_replay_scores_prediction_only_after_it_is_built():
    report = score_replay(
        strict_groups=[[A, B]], rescue_groups=[[A, B]],
        strict_relaxed_groups=[[A, B], [A, B, C]],
        rescue_relaxed_groups=[[A, B], [A, B, C]],
        ground_truth={"symbols": {}, "origins": [{"origin": "O", "members": [A, B, C]}]},
        universe={A, B, C}, neutral={},
    )
    assert report["strict"]["true_positive"] == 1
    assert report["strict_relaxed"]["true_positive"] == 3


def test_micro_aggregate_sums_pair_counts_before_rounding():
    one = score_replay(
        strict_groups=[[A, B]], rescue_groups=[[A, B]],
        strict_relaxed_groups=[[A, B]], rescue_relaxed_groups=[[A, B]],
        ground_truth={"symbols": {}, "origins": [{"origin": "O", "members": [A, B]}]},
        universe={A, B}, neutral={}, v0_groups=[],
    )
    two = score_replay(
        strict_groups=[], rescue_groups=[],
        strict_relaxed_groups=[], rescue_relaxed_groups=[],
        ground_truth={"symbols": {}, "origins": [{"origin": "O", "members": [A, B]}]},
        universe={A, B}, neutral={}, v0_groups=[],
    )
    micro = micro_aggregate([one, two])
    assert micro["strict"]["true_positive"] == 1
    assert micro["strict"]["false_negative"] == 1


def test_crlf_rescue_uses_canonical_digest_for_f7_validation():
    """A Windows rescue file's raw SHA must not be passed as its artifact SHA."""
    import test_v1_relaxed as fixtures

    families = fixtures._families(provisional=(), unresolved=(fixtures.C,))
    candidates = fixtures._consensus2(fixtures._candidate(fixtures.A, fixtures.C))
    rescue = fixtures._unchanged_rescue(families)
    raw = (json.dumps(rescue, indent=2, sort_keys=True, ensure_ascii=False) + "\r\n").encode()
    raw_sha = hashlib.sha256(raw).hexdigest()
    canonical_sha = replay.canonical_artifact_sha(rescue)
    assert raw_sha != canonical_sha

    _strict, f7 = replay.build_relaxed_artifacts(
        families,
        candidates,
        fixtures._bodies(fixtures.A, fixtures.B, fixtures.C),
        fixtures._formal_config(),
        family_artifact_sha256="d" * 64,
        candidate_artifact_sha256="e" * 64,
        rescue_artifact=rescue,
        rescue_artifact_sha256=canonical_sha,
        feature_provider=fixtures._match_features,
    )
    assert f7 is not None
    groups = replay.groups_for_scoring(
        f7,
        families,
        family_artifact_sha256="d" * 64,
        rescue_artifact=rescue,
        rescue_artifact_sha256=canonical_sha,
    )
    # F7 retains the strict core and records the provisional attachment as a
    # second partition group.  Most importantly, validation succeeds with the
    # canonical artifact digest even though the source bytes were CRLF.
    assert sorted(groups) == sorted([
        [fixtures.A, fixtures.B],
        [fixtures.A, fixtures.B, fixtures.C],
    ])


def test_frozen_input_pins_match_and_drift_is_rejected():
    for subject in replay.SUBJECTS.values():
        pins = replay.FROZEN_PINS[subject.name]
        for name in ("body", "candidates", "strict", "rescue", "ground_truth", "linkage_audit", "v0"):
            digest = replay.sha256_file(getattr(subject, name))
            assert digest == pins[name], (subject.name, name, digest, pins[name])
        assert replay.sha256_file(replay.FORMAL_CONFIG_PATH) == pins["config"]
        assert replay.canonical_artifact_sha(replay.read_json(subject.rescue)[0]) == replay.FROZEN_CANONICAL_RESCUE_PINS[subject.name]

    subject = replay.SUBJECTS["fd"]
    try:
        replay._assert_pinned_digest(subject, "v0", subject.v0, "0" * 64)
    except ValueError as exc:
        assert "pinned" in str(exc)
    else:
        raise AssertionError("a replaced V0 input was accepted by its pin")


def test_budget_refusal_is_reported_before_prediction_execution():
    import test_v1_relaxed as fixtures

    families = fixtures._families(provisional=(), unresolved=(fixtures.C,))
    candidates = fixtures._consensus2(fixtures._candidate(fixtures.A, fixtures.C))
    rescue = fixtures._unchanged_rescue(families)
    original_cache = replay.PairEvidenceCache

    class ExpensiveCache:
        def __init__(self, *args, **kwargs):
            pass

        def demand(self, pairs):
            return replay.MAX_COMPARISONS + 1, 0

    replay.PairEvidenceCache = ExpensiveCache
    try:
        result = replay.dry_price(
            families,
            candidates,
            fixtures._bodies(fixtures.A, fixtures.B, fixtures.C),
            fixtures._formal_config(),
            rescue,
            "d" * 64,
            "e" * 64,
        )
    finally:
        replay.PairEvidenceCache = original_cache
    assert result["status"] == "budget-refused"
    assert result["within_budget"] is False


def test_direct_predict_subject_checks_formal_runtime_before_feature_work():
    subject = replay.Subject(
        "missing", Path("."), *(Path("/does/not/exist") for _ in range(7))
    )
    original_guard = replay._require_formal_runtime
    original_inputs = replay._subject_inputs
    calls = []

    def injected_guard():
        calls.append("runtime")
        raise RuntimeError("nonformal test runtime refusal")

    def forbidden_inputs(_subject):
        calls.append("inputs")
        raise AssertionError("feature/input work started before runtime guard")

    replay._require_formal_runtime = injected_guard
    replay._subject_inputs = forbidden_inputs
    try:
        try:
            replay.predict_subject(subject, Path("/dev/shm/replay-test"))
        except RuntimeError as exc:
            assert "nonformal test" in str(exc)
        else:
            raise AssertionError("predict_subject bypassed the formal runtime guard")
    finally:
        replay._require_formal_runtime = original_guard
        replay._subject_inputs = original_inputs
    assert calls == ["runtime"]


def test_stale_prediction_manifest_hash_is_rejected_before_scoring():
    subject = replay.Subject(
        "fake", Path("."), *(Path("/does/not/exist") for _ in range(7))
    )
    paths = (
        Path("/tmp/fake-strict-relaxed.json"),
        Path("/tmp/fake-f7-relaxed.json"),
        Path("/tmp/fake-prediction-manifest.json"),
    )
    original_paths = replay._prediction_paths
    original_loader = replay.read_json
    reads = []

    def fake_paths(_subject, _output_root):
        return paths

    def fake_read_json(path):
        reads.append(path)
        if path == paths[2]:
            return {
                "status": "predictions-built",
                "predictions": {
                    "strict_relaxed": {"path": str(paths[0]), "sha256": "0" * 64},
                    "strict_f7_relaxed": {"path": str(paths[1]), "sha256": "0" * 64},
                },
            }, "1" * 64
        return {}, "2" * 64

    replay._prediction_paths = fake_paths
    replay.read_json = fake_read_json
    try:
        try:
            replay._load_prediction_manifest(subject, Path("/dev/shm/replay-test"))
        except ValueError as exc:
            assert "prediction bytes do not match manifest hashes" in str(exc)
        else:
            raise AssertionError("stale prediction hash was accepted")
    finally:
        replay._prediction_paths = original_paths
        replay.read_json = original_loader
    assert reads == [paths[2], paths[0], paths[1]]


def _fake_score_context():
    strict = {"provenance": {}, "universe": {"target_ids": [A, B]}}
    rescue = {}
    candidates = {}
    hashes = {
        "body": "b",
        "candidates": "c",
        "strict": "s",
        "rescue": "r",
        "rescue_canonical": "rc",
    }
    manifest = {
        "status": "predictions-built",
        "inputs": {
            "body": {"sha256": "b"},
            "candidates": {"sha256": "c"},
            "strict": {"sha256": "s"},
            "rescue": {"sha256": "r", "canonical_sha256": "rc"},
            "config": {"sha256": "cfg"},
        },
        "predictions": {
            "strict_relaxed": {"path": "x", "sha256": "x"},
            "strict_f7_relaxed": {"path": "y", "sha256": "y"},
        },
    }
    return strict, rescue, candidates, hashes, manifest


def test_stale_prediction_or_v0_fails_before_oracle_json_loader():
    subject = replay.Subject(
        "fake", Path("."), *(Path("/does/not/exist") for _ in range(7))
    )
    original_loader = replay.read_json
    oracle_reads = []

    def forbidden_oracle_read(path):
        if path in (subject.ground_truth, subject.linkage_audit):
            oracle_reads.append(path)
            raise AssertionError("oracle JSON opened before stale non-oracle failure")
        raise AssertionError(f"unexpected read: {path}")

    replay.read_json = forbidden_oracle_read
    try:
        original_manifest_loader = replay._load_prediction_manifest
        replay._load_prediction_manifest = lambda *_args: (_ for _ in ()).throw(ValueError("stale prediction manifest"))
        try:
            try:
                replay.score_subject(subject, Path("/dev/shm/replay-test"))
            except ValueError as exc:
                assert "stale prediction" in str(exc)
            else:
                raise AssertionError("stale prediction manifest was accepted")
        finally:
            replay._load_prediction_manifest = original_manifest_loader

        strict, rescue, candidates, hashes, manifest = _fake_score_context()
        replay._load_prediction_manifest = lambda *_args: (manifest, {}, {})
        original_inputs = replay._subject_inputs
        original_config = replay._load_config
        original_groups = replay.groups_for_scoring
        original_core = replay._core_partitions
        original_assert_pin = replay._assert_pinned_file
        original_v0 = replay._load_v0_groups
        replay._subject_inputs = lambda _subject: (
            {"strict": strict, "rescue": rescue, "candidates": candidates}, hashes,
        )
        replay._load_config = lambda: (None, Path("cfg"), "cfg")
        replay.groups_for_scoring = lambda *args, **kwargs: [[A, B]]
        replay._core_partitions = lambda *args, **kwargs: ({}, {})
        replay._assert_pinned_file = lambda *_args: "pin"
        replay._load_v0_groups = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("stale V0 result"))
        try:
            try:
                replay.score_subject(subject, Path("/dev/shm/replay-test"))
            except ValueError as exc:
                assert "stale V0" in str(exc)
            else:
                raise AssertionError("stale V0 result was accepted")
        finally:
            replay._subject_inputs = original_inputs
            replay._load_config = original_config
            replay.groups_for_scoring = original_groups
            replay._core_partitions = original_core
            replay._assert_pinned_file = original_assert_pin
            replay._load_v0_groups = original_v0
            replay._load_prediction_manifest = original_manifest_loader
    finally:
        replay.read_json = original_loader
    assert oracle_reads == []


if __name__ == "__main__":
    test_wsl_frozen_paths_translate_only_for_windows_runtime()
    test_oracle_metadata_may_omit_scope_but_not_conflict()
    test_replay_scores_prediction_only_after_it_is_built()
    test_micro_aggregate_sums_pair_counts_before_rounding()
    test_crlf_rescue_uses_canonical_digest_for_f7_validation()
    test_frozen_input_pins_match_and_drift_is_rejected()
    test_budget_refusal_is_reported_before_prediction_execution()
    test_direct_predict_subject_checks_formal_runtime_before_feature_work()
    test_stale_prediction_manifest_hash_is_rejected_before_scoring()
    test_stale_prediction_or_v0_fails_before_oracle_json_loader()
    print("test_replay_relaxed: PASS")
