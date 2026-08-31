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
from pathlib import Path

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


def main() -> int:
    test_the_label_blind_artifact_list_is_the_one_the_spec_names()
    notes = [test_every_stage_is_recorded_even_when_it_does_nothing()]
    test_the_manifest_records_the_toolchain_and_the_command()
    notes.append(test_analyze_succeeds_with_ground_truth_unreadable())
    print("CallKin-Real analyze pipeline: PASS")
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
