"""R3: the CallKin-Real port of F4 must not move a single bit.

The fixture is the frozen V1's own golden, copied byte-for-byte: 219 real
ripgrep bodies and the 13 numeric fields plus 4 quality fields the feasibility
stage recorded for its 556 pair sample. Values are compared as `float.hex()`,
so one least-significant bit of drift fails.

This is the whole of R3's claim. If these 7,228 numbers and 2,224 quality
values reproduce, the comparator did not change when it moved here, and a
CallKin-Real body can be fed to it without rescoring anything.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from body_comparison import METRIC_NAMES, QUALITY_NAMES, score_pair
from body_similarity import parse_body
from frozen_reference import expected_hash

# The frozen layout, because the frozen F7 control suite reads the same two
# files from this path and a second copy could drift from the first.
FIXTURE_DIR = (
    Path(__file__).resolve().parent
    / "frozen_v1" / "tests" / "fixtures" / "f7_alignment"
)
BODIES_PATH = FIXTURE_DIR / "ripgrep_219_bodies.json.gz"
SCORES_PATH = FIXTURE_DIR / "ripgrep_556_scores.json"


def _load():
    with gzip.open(BODIES_PATH, "rt", encoding="utf-8") as handle:
        bodies_fixture = json.load(handle)
    scores = json.loads(SCORES_PATH.read_text(encoding="utf-8"))
    bodies = {item["id"]: parse_body(item) for item in bodies_fixture["functions"]}
    return bodies, bodies_fixture, scores


def test_the_fixture_is_the_one_the_golden_claims():
    bodies, bodies_fixture, scores = _load()
    assert len(bodies) == 219, len(bodies)
    assert len(scores["pairs"]) == 556, len(scores["pairs"])
    assert tuple(scores["metric_names"]) == METRIC_NAMES
    assert bodies_fixture["provenance"] == scores["provenance"]
    labels = [entry["label"] for entry in scores["pairs"]]
    assert labels.count("positive") == 460, labels.count("positive")
    assert labels.count("negative") == 96, labels.count("negative")


def test_every_pair_reproduces_its_golden_scores_exactly():
    bodies, _, scores = _load()
    mismatches: list[str] = []
    compared = 0

    for entry in scores["pairs"]:
        first_id, second_id = entry["pair"]
        metrics, quality = score_pair(bodies[first_id], bodies[second_id])

        if sorted(metrics) != sorted(METRIC_NAMES):
            raise AssertionError(
                f"metric set changed: {sorted(set(metrics) ^ set(METRIC_NAMES))}"
            )
        for name in METRIC_NAMES:
            actual = float(metrics[name]).hex()
            expected = entry["metrics"][name]
            compared += 1
            if actual != expected:
                mismatches.append(
                    f"{first_id}/{second_id} {name}: {expected} != {actual}"
                )

        if sorted(quality) != sorted(QUALITY_NAMES):
            raise AssertionError(f"quality set changed: {sorted(quality)}")
        for name in QUALITY_NAMES:
            compared += 1
            if quality[name] != entry["quality"][name]:
                mismatches.append(
                    f"{first_id}/{second_id} quality.{name}: "
                    f"{entry['quality'][name]} != {quality[name]}"
                )

    if mismatches:
        raise AssertionError(
            f"{len(mismatches)} F4 values changed, first 5:\n  "
            + "\n  ".join(mismatches[:5])
        )
    assert compared == 556 * (len(METRIC_NAMES) + len(QUALITY_NAMES)), compared


def test_the_comparator_is_byte_identical_to_the_frozen_one():
    # The port is a copy, not a rewrite. If someone edits it, the golden above
    # is the guard -- but this says plainly that editing it is not the plan.
    import hashlib

    here = Path(__file__).resolve().parent / "body_similarity.py"
    assert (
        hashlib.sha256(here.read_bytes()).hexdigest()
        == expected_hash("body_similarity.py", root_file=True)
    ), "body_similarity.py diverged from the frozen V1"


def main() -> int:
    test_the_fixture_is_the_one_the_golden_claims()
    test_every_pair_reproduces_its_golden_scores_exactly()
    test_the_comparator_is_byte_identical_to_the_frozen_one()
    print("CallKin-Real F4 golden: PASS (556 pairs x 13 metrics + 4 quality fields)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
