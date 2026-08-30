"""End to end: running FLIRT must not move discovery, body, universe or relation.

The unit tests pin this on constructed records. This one pins it on a real
binary, because the ordering that makes it true lives in `main()`: bodies are
decoded, roles assigned and 1-WL run before any label is attached. A future
edit that moves the FLIRT call one step earlier would pass every unit test and
fail here.

FLIRT itself is not run. Oxidizer needs its own environment, and what is under
test is what CallKin-Real does with labels, not whether Oxidizer found any. The
probe is replaced with a stub that labels every third function, which is a
harder test than a real run: it guarantees labels exist.

It also checks the artifact chain itself: every stage file must hash to what
the run record says, name the hash of the artifact it was built from, and be
written with LF so the same run hashes the same on Windows and Linux.

Set CALLKIN_REAL_TEST_BINARY to a stripped x86-64 binary to run it. Needs
radare2 on PATH.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import callkin_real

STAGE_KEYS = ("discovery", "body", "universe", "relation")


def _stub_flirt(addresses: list[int]):
    labelled = sorted(addresses)[::3]

    def run_flirt(binary, oxidizer_dir, probe_path, timeout):
        matches = {
            address: {
                "address": hex(address),
                "name": f"core::ptr::drop_in_place<T{index}>",
                "canonical_origin": "core::ptr::drop_in_place",
                "owner": "core",
            }
            for index, address in enumerate(labelled)
        }
        return matches, {"status": "stub", "direct_match_count": len(matches)}

    return run_flirt


def _run(binary: Path, output: Path, flirt: bool, addresses=None) -> dict:
    argv = [str(binary), "--output", str(output)]
    original = callkin_real.run_flirt
    if flirt:
        callkin_real.run_flirt = _stub_flirt(addresses or [])
    else:
        argv.append("--no-flirt")
    try:
        code = callkin_real.main(argv)
    finally:
        callkin_real.run_flirt = original
    if code != 0:
        raise SystemExit(f"callkin_real failed on {binary}")
    return json.loads(output.read_text(encoding="utf-8"))


def _stage_files(output: Path) -> dict[str, dict]:
    return {
        stage: json.loads(
            callkin_real.stage_artifact_path(output, stage).read_text(encoding="utf-8")
        )
        for stage in STAGE_KEYS
    }


def _check_chain(run: dict, output: Path) -> None:
    """Each artifact must hash to what the run says, and name its own inputs."""
    stages = _stage_files(output)
    for stage in STAGE_KEYS:
        path = callkin_real.stage_artifact_path(output, stage)
        on_disk = hashlib.sha256(path.read_bytes()).hexdigest()
        assert run["stage_sha256"][stage] == on_disk, f"{stage} hash is not the file"
        assert run["artifacts"][stage]["sha256"] == on_disk, stage
        assert stages[stage]["binary"]["sha256"] == run["binary"]["sha256"], stage
        assert stages[stage]["toolchain"] == run["toolchain"], stage
        for name, digest in stages[stage]["inputs"].items():
            assert digest == run["stage_sha256"][name], f"{stage} names a stale {name}"
        assert 13 not in path.read_bytes(), f"{stage} was written with CRLF"


def main() -> int:
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target:
        print("CallKin-Real FLIRT invariance: SKIP (set CALLKIN_REAL_TEST_BINARY)")
        return 0
    binary = Path(target)
    if not binary.is_file():
        print(f"CallKin-Real FLIRT invariance: SKIP (missing {binary})")
        return 0

    with tempfile.TemporaryDirectory(prefix="callkin-real-invariance-") as directory:
        room = Path(directory)
        plain_out = room / "no-flirt.json"
        without = _run(binary, plain_out, flirt=False)
        addresses = [
            int(record["address"], 16)
            for record in _stage_files(plain_out)["discovery"]["payload"]["functions"]
        ]
        _check_chain(without, plain_out)

        flirt_out = room / "flirt.json"
        with_flirt = _run(binary, flirt_out, flirt=True, addresses=addresses)
        _check_chain(with_flirt, flirt_out)

        assert with_flirt["flirt"]["direct_match_count"] > 0, "the stub labelled nothing"
        labelled = with_flirt["labels"]
        assert labelled, "no function carries a direct label"

        for stage in STAGE_KEYS:
            assert without["stage_sha256"][stage] == with_flirt["stage_sha256"][stage], (
                f"{stage} moved when FLIRT ran"
            )
        assert without["grouping_core_sha256"] == with_flirt["grouping_core_sha256"]

        # And no stage file carries the label text, whatever its hash says.
        for stage, payload in _stage_files(flirt_out).items():
            text = json.dumps(payload)
            for leaked in ("drop_in_place", "canonical_origin", "label_status"):
                assert leaked not in text, f"{stage} carries {leaked}"

    # The labels really did reach functions grouping kept as members, which is
    # the case the frozen V1 could not express.
    members = [f for f in labelled if f["grouping_role"] == callkin_real.ROLE_MEMBER]
    assert members, "every labelled function was excluded from grouping"

    print(
        "CallKin-Real FLIRT invariance: PASS "
        f"({len(labelled)} labelled, {len(members)} of them grouping members)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
