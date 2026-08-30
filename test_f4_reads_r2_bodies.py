"""R3: a body CallKin-Real wrote is a body the frozen F4 can score.

The golden proves the comparator did not change. This proves the other half:
that the records `body_builder` produces satisfy the schema `parse_body`
enforces, and that scoring them needs no conversion step where a value could
drift.

The real-binary part runs when CALLKIN_REAL_TEST_BINARY is set.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import callkin_real
from body_builder import build_bodies
from body_comparison import (
    METRIC_NAMES,
    QUALITY_NAMES,
    body_records,
    comparable_bodies,
    load_bodies,
    score_pair,
)
from body_similarity import parse_body

# xor eax, eax ; ret   /   xor eax, eax ; <undecodable> ; ret
CLEAN = bytes([0x31, 0xC0, 0xC3])
GAPPED = bytes([0x31, 0xC0, 0x06, 0xC3])
# push rbp ; mov rbp, rsp ; xor eax, eax ; pop rbp ; ret
LONGER = bytes([0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3])


class _Image:
    def __init__(self, blocks):
        self.blocks = blocks

    def read(self, address: int, size: int) -> bytes:
        data = self.blocks.get(address)
        if data is None:
            raise ValueError("not file backed")
        return data[:size]


def _artifact():
    image = _Image({0x1000: CLEAN, 0x2000: CLEAN, 0x3000: GAPPED, 0x4000: LONGER})
    return build_bodies(image, {
        0x1000: ("FUN_00101000", len(CLEAN)),
        0x2000: ("FUN_00102000", len(CLEAN)),
        0x3000: ("FUN_00103000", len(GAPPED)),
        0x4000: ("FUN_00104000", len(LONGER)),
    })


def test_an_r2_body_record_satisfies_the_frozen_schema():
    # parse_body refuses any record whose key set is not exactly what V1 wrote.
    # This is the single place the two formats could have diverged.
    for record in _artifact()["functions"]:
        parse_body(record)


def test_the_stage_envelope_and_a_bare_artifact_both_load():
    artifact = _artifact()
    envelope = callkin_real.artifact_envelope(
        stage="body",
        binary_sha256="a" * 64,
        inputs={"discovery": "b" * 64},
        payload=artifact,
    )
    assert body_records(envelope) == body_records(artifact)
    assert set(load_bodies(envelope)) == set(load_bodies(artifact))


def test_only_complete_bodies_are_offered_for_comparison():
    bodies = comparable_bodies(_artifact())
    assert "FUN_00103000" not in bodies, "an incomplete body was offered to F4"
    assert set(bodies) == {"FUN_00101000", "FUN_00102000", "FUN_00104000"}


def test_two_identical_bodies_score_as_identical():
    bodies = comparable_bodies(_artifact())
    metrics, quality = score_pair(bodies["FUN_00101000"], bodies["FUN_00102000"])
    assert sorted(metrics) == sorted(METRIC_NAMES)
    assert sorted(quality) == sorted(QUALITY_NAMES)
    assert quality["both_complete"] is True
    for name in ("size_ratio", "instruction_count_ratio",
                 "mnemonic_multiset_jaccard", "sequence_ratio",
                 "aligned_instruction_ratio"):
        assert metrics[name] == 1.0, f"{name} = {metrics[name]}"
    assert metrics["opaque_cfg_penalty"] == 0.0


def test_two_different_bodies_do_not():
    bodies = comparable_bodies(_artifact())
    metrics, _ = score_pair(bodies["FUN_00101000"], bodies["FUN_00104000"])
    assert metrics["size_ratio"] < 1.0
    assert metrics["instruction_count_ratio"] < 1.0


def test_the_score_is_the_same_whether_it_came_from_a_file_or_from_memory():
    # The join must not be a conversion. A round trip through the artifact on
    # disk has to produce the same numbers, bit for bit.
    artifact = _artifact()
    in_memory = comparable_bodies(artifact)
    with tempfile.TemporaryDirectory(prefix="callkin-real-f4-") as directory:
        path = Path(directory) / "body.json"
        callkin_real.write_json(path, callkin_real.artifact_envelope(
            stage="body",
            binary_sha256="a" * 64,
            inputs={"discovery": "b" * 64},
            payload=artifact,
        ))
        from_disk = comparable_bodies(path)

    for first, second in (("FUN_00101000", "FUN_00104000"),
                          ("FUN_00101000", "FUN_00102000")):
        memory_metrics, memory_quality = score_pair(in_memory[first], in_memory[second])
        disk_metrics, disk_quality = score_pair(from_disk[first], from_disk[second])
        for name in METRIC_NAMES:
            assert float(memory_metrics[name]).hex() == float(disk_metrics[name]).hex(), name
        assert memory_quality == disk_quality


def test_a_real_binary_body_artifact_feeds_f4() -> str:
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the real-binary check)"

    with tempfile.TemporaryDirectory(prefix="callkin-real-f4-real-") as directory:
        output = Path(directory) / "run.json"
        code = callkin_real.main([target, "--no-flirt", "--output", str(output)])
        assert code == 0
        run = json.loads(output.read_text(encoding="utf-8"))
        body_path = callkin_real.stage_artifact_path(output, "body")

        # Every record parses, not just the complete ones.
        parsed = load_bodies(body_path)
        assert len(parsed) == run["summary"]["body"]["function_count"]
        bodies = comparable_bodies(body_path)
        assert len(bodies) == run["summary"]["body"]["complete_count"]

        ordered = sorted(bodies)
        pairs = [(ordered[i], ordered[i + 1]) for i in range(0, min(200, len(ordered) - 1), 2)]
        for first, second in pairs:
            metrics, quality = score_pair(bodies[first], bodies[second])
            assert sorted(metrics) == sorted(METRIC_NAMES)
            assert sorted(quality) == sorted(QUALITY_NAMES)
            assert quality["both_complete"] is True
            for name, value in metrics.items():
                assert 0.0 <= value <= 1.0, f"{first}/{second} {name} = {value}"
    return (
        f"  ({len(parsed)} bodies parsed, {len(bodies)} comparable, "
        f"{len(pairs)} pairs scored)"
    )


def main() -> int:
    test_an_r2_body_record_satisfies_the_frozen_schema()
    test_the_stage_envelope_and_a_bare_artifact_both_load()
    test_only_complete_bodies_are_offered_for_comparison()
    test_two_identical_bodies_score_as_identical()
    test_two_different_bodies_do_not()
    test_the_score_is_the_same_whether_it_came_from_a_file_or_from_memory()
    note = test_a_real_binary_body_artifact_feeds_f4()
    print("CallKin-Real F4 reads R2 bodies: PASS")
    print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
