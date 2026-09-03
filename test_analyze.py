"""R8: one command produces every artifact, and says what it could not do.

Gate R4 asks for a full run on one stripped ELF and one stripped PE, and for
`analyze` to succeed in an environment where ground truth cannot be read. The
second half is the sharper test: a pipeline that quietly works better when an
oracle happens to be on disk is not an oracle-free pipeline.

The other thing checked here belongs to no single stage. A stage that cannot
run must be recorded with a reason rather than leaving a missing file, because
a missing file with nothing beside it is indistinguishable from a bug. Every
stage appears in the manifest whether or not it produced anything.

Set CALLKIN_REAL_TEST_BINARY for the real-binary parts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import analyze

HERE = Path(__file__).resolve().parent
EXPECTED_STAGES = (
    "discovery", "labels.direct", "f5.retrieval", "f6.strict",
    "f7.rescue", "v1.relaxed", "f10.propagation",
)
# Gate R4's artifact list, minus the ones that depend on FLIRT or on F6
# having accepted something.
ALWAYS = (
    "discovery", "body", "universe", "relation",
    "candidates.consensus3", "candidates.consensus2",
)


def _fake_pipeline_patches(room: Path, *, budgeted: bool, seen: dict) -> ExitStack:
    """Patch the expensive pipeline stages with a tiny deterministic run."""
    import real_v1_adapter
    import v1_component_budget
    import v1_grouping
    import v1_relaxed
    import v1_rescue
    import v1_retrieval

    stage_names = ("discovery", "body", "universe", "relation")
    source = mock.Mock(
        binary_sha256="b" * 64,
        stage_sha256={"body": "d" * 64, "discovery": "e" * 64},
    )
    original = {"artifact": "candidate", "pairs": [{"first": "a", "second": "b"}]}
    derived = {"artifact": "candidate", "pairs": []}
    queues = {
        "multi": {"artifact": "multi", "pairs": []},
        "consensus3": original,
        "consensus2": {"artifact": "consensus2", "pairs": []},
    }

    def fake_callkin(argv: list[str]) -> int:
        run_path = Path(argv[argv.index("--output") + 1])
        artifacts = {}
        for name in stage_names:
            path = run_path.parent / f"{name}.json"
            path.write_text("{}\n", encoding="utf-8")
            artifacts[name] = {"path": path.name, "sha256": analyze._sha256(path)}
        run = {
            "binary": {"sha256": "b" * 64, "format": "ELF"},
            "toolchain": {"python": "synthetic"},
            "artifacts": artifacts,
            "summary": {"grouping_role": {}},
            "flirt": {"status": "skipped"},
        }
        run_path.write_text(json.dumps(run), encoding="utf-8")
        return 0

    def fake_write_candidates(items, output_dir, stem, *, top_k):
        written = {}
        for name, artifact in items.items():
            path = output_dir / f"{stem}.{name}.json"
            path.write_text(json.dumps(artifact, sort_keys=True), encoding="utf-8")
            written[name] = {"path": str(path), "sha256": analyze._sha256(path)}
        return written

    def fake_budget(candidate_artifact, source_input, config, source_sha256):
        seen["budget_args"] = (candidate_artifact, source_input, config, source_sha256)
        return derived, {
            "selected_component_count": 1,
            "deferred_component_count": 2,
            "selected_member_count": 2,
            "deferred_member_count": 3,
        }

    def fake_strict(queue, source_input, *, config, candidate_sha256):
        seen["strict_queue"] = queue
        seen["strict_sha256"] = candidate_sha256
        families = {
            "clusters": [],
            "status_members": {"accepted": [], "abstain": []},
            "blocked_merges": [],
            "metrics": {},
        }
        return v1_grouping.COMPLETED, families, {"within_budget": True}

    def fake_rescue(*args, **kwargs):
        return {"summary": {"selected": 0}}

    def fake_relaxed(*args, **kwargs):
        return {"summary": {"selected": 0}}

    stack = ExitStack()
    stack.enter_context(mock.patch.object(analyze.callkin_real, "main", fake_callkin))
    stack.enter_context(mock.patch.object(real_v1_adapter, "load_from_run", lambda _: source))
    stack.enter_context(mock.patch.object(v1_retrieval, "build_candidate_artifacts", lambda *_a, **_k: queues))
    stack.enter_context(mock.patch.object(v1_retrieval, "write_candidate_artifacts", fake_write_candidates))
    stack.enter_context(mock.patch.object(v1_grouping, "build_strict_families", fake_strict))
    stack.enter_context(mock.patch.object(v1_rescue, "discovery_payload_for", lambda _: {}))
    stack.enter_context(mock.patch.object(v1_rescue, "build_rescue_artifact", fake_rescue))
    stack.enter_context(mock.patch.object(v1_relaxed, "build_provisional_artifact", fake_relaxed))
    if budgeted:
        stack.enter_context(mock.patch.object(v1_component_budget, "build_budgeted_candidate_artifact", fake_budget))
    else:
        stack.enter_context(mock.patch.object(
            v1_component_budget,
            "build_budgeted_candidate_artifact",
            mock.Mock(side_effect=AssertionError("budget derivation was not opt-in")),
        ))
    return stack


def test_the_label_blind_artifact_list_is_the_one_the_spec_names():
    # Spec 8.1: discovery through families.rescue, universe included.
    for name in ("discovery", "body", "universe", "relation",
                 "families.strict", "families.rescue"):
        assert name in analyze.LABEL_BLIND_ARTIFACTS, name
    # The label artifacts are deliberately absent: they are what may differ.
    for name in analyze.LABEL_BLIND_ARTIFACTS:
        assert "label" not in name, name


def test_every_stage_is_recorded_even_when_it_does_nothing() -> str:
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the real-binary check)"

    with tempfile.TemporaryDirectory(prefix="callkin-analyze-") as directory:
        room = Path(directory)
        manifest = analyze.analyze(
            Path(target), room / "out", case="test", no_flirt=True
        )
        recorded = [item["stage"] for item in manifest["stages"]]
        assert recorded == list(EXPECTED_STAGES), recorded
        for item in manifest["stages"]:
            assert item["status"] in {"completed", "skipped", "unavailable",
                                      "budget-refused"}, item
            if item["status"] != "completed":
                # A stage that did not run says why, in the manifest, beside
                # the artifact that is not there.
                assert item.get("reason") or item.get("required_alignment_cells"), item
        for name in ALWAYS:
            assert name in manifest["artifacts"], name
            path = room / "out" / manifest["artifacts"][name]["path"]
            assert path.is_file(), name

        # And the manifest names a hash for every file it claims.
        for name, item in manifest["artifacts"].items():
            path = room / "out" / item["path"]
            assert analyze._sha256(path) == item["sha256"], name
        statuses = {item["stage"]: item["status"] for item in manifest["stages"]}
    return (
        f"  ({len(manifest['artifacts'])} artifacts; "
        f"f6={statuses['f6.strict']}, f7={statuses['f7.rescue']})"
    )


def test_analyze_succeeds_with_ground_truth_unreadable() -> str:
    """Gate R4. Run in a subprocess whose ground-truth path does not resolve.

    A pipeline that quietly works better when an oracle is on disk is not an
    oracle-free pipeline, and the only way to know is to take the oracle away.
    """
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the oracle-free check)"

    with tempfile.TemporaryDirectory(prefix="callkin-no-oracle-") as directory:
        room = Path(directory)
        # A sitecustomize that makes any open() of an oracle path raise, so a
        # read would fail loudly rather than being silently absent.
        guard = room / "sitecustomize.py"
        guard.write_bytes(
            "import builtins\n"
            "_open = builtins.open\n"
            "_BANNED = ('ground_truth', 'all_rust_catalog', 'gt.json')\n"
            "def open(file, *args, **kwargs):\n"
            "    name = str(file).replace(chr(92), '/').lower()\n"
            "    if any(part in name for part in _BANNED):\n"
            "        raise PermissionError('oracle path blocked: ' + str(file))\n"
            "    return _open(file, *args, **kwargs)\n"
            "builtins.open = open\n".encode("utf-8")
        )
        environment = {
            **os.environ,
            "PYTHONPATH": f"{room}{os.pathsep}{HERE}",
        }
        completed = subprocess.run(
            [sys.executable, str(HERE / "analyze.py"), target,
             "--case", "no-oracle", "--output-dir", str(room / "out"),
             "--no-flirt"],
            capture_output=True, text=True, env=environment, cwd=str(HERE),
            timeout=3600,
        )
        if completed.returncode != 0:
            raise AssertionError(
                "analyze failed without ground truth:\n"
                + (completed.stderr or completed.stdout)[-2000:]
            )
        manifest = json.loads(
            (room / "out" / "run.manifest.json").read_text(encoding="utf-8")
        )
        assert manifest["artifact"] == "callkin-real-analysis-manifest"
        for name in ALWAYS:
            assert name in manifest["artifacts"], name
    return f"  (ran with oracle paths blocked; {len(manifest['artifacts'])} artifacts)"


def test_the_manifest_records_the_toolchain_and_the_command():
    # Two runs of different toolchains that disagree must be tellable apart,
    # and a run must say how it was invoked.
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return
    with tempfile.TemporaryDirectory(prefix="callkin-analyze-") as directory:
        manifest = analyze.analyze(
            Path(target), Path(directory) / "out", case="test", no_flirt=True
        )
    assert manifest["toolchain"]["python"]
    assert manifest["command"] == {"no_flirt": True, "top_k": 16}
    assert manifest["binary"]["sha256"]


def test_component_budgeted_v1_derives_and_feeds_the_strict_queue():
    """The opt-in mode records its queue/costs and gives F6 that queue."""
    with tempfile.TemporaryDirectory(prefix="callkin-budgeted-") as directory:
        room = Path(directory)
        seen: dict = {}
        with _fake_pipeline_patches(room, budgeted=True, seen=seen):
            manifest = analyze.analyze(
                room / "input.bin", room / "out", case="synthetic",
                no_flirt=True, component_budgeted_v1=True,
            )

        assert seen["strict_queue"]["pairs"] == []
        assert seen["budget_args"][0]["pairs"] == [{"first": "a", "second": "b"}]
        assert seen["strict_sha256"] == manifest["artifacts"][
            "candidates.consensus3-budgeted"
        ]["sha256"]
        assert "candidates.consensus3-budgeted" in manifest["artifacts"]
        assert "candidates.consensus3-budgeted" in manifest["label_blind_sha256"]
        assert manifest["command"] == {
            "no_flirt": True, "top_k": 16, "component_budgeted_v1": True,
        }
        budget_stage = next(
            item for item in manifest["stages"]
            if item["stage"] == "f5.component-budget"
        )
        assert budget_stage["status"] == "completed"
        assert budget_stage["selected_component_count"] == 1
        assert budget_stage["deferred_component_count"] == 2


def test_component_budgeted_v1_absent_preserves_the_original_queue_and_artifacts():
    """The default path does not derive or expose an extra candidate queue."""
    with tempfile.TemporaryDirectory(prefix="callkin-unbudgeted-") as directory:
        room = Path(directory)
        seen: dict = {}
        with _fake_pipeline_patches(room, budgeted=False, seen=seen):
            manifest = analyze.analyze(
                room / "input.bin", room / "out", case="synthetic", no_flirt=True
            )

        assert seen["strict_queue"]["pairs"] == [{"first": "a", "second": "b"}]
        assert "candidates.consensus3-budgeted" not in manifest["artifacts"]
        assert "candidates.consensus3-budgeted" not in manifest["label_blind_sha256"]
        assert manifest["command"] == {"no_flirt": True, "top_k": 16}
        assert not any(item["stage"] == "f5.component-budget" for item in manifest["stages"])


def test_component_budgeted_v1_is_a_cli_flag():
    args = analyze.build_arg_parser().parse_args([
        "binary", "--output-dir", "out", "--component-budgeted-v1",
    ])
    assert args.component_budgeted_v1 is True


def main() -> int:
    test_the_label_blind_artifact_list_is_the_one_the_spec_names()
    notes = [test_every_stage_is_recorded_even_when_it_does_nothing()]
    test_the_manifest_records_the_toolchain_and_the_command()
    test_component_budgeted_v1_derives_and_feeds_the_strict_queue()
    test_component_budgeted_v1_absent_preserves_the_original_queue_and_artifacts()
    test_component_budgeted_v1_is_a_cli_flag()
    notes.append(test_analyze_succeeds_with_ground_truth_unreadable())
    print("CallKin-Real analyze pipeline: PASS")
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
