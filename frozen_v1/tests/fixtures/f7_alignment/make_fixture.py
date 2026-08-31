"""Regenerate the F7.0 golden regression fixture.

Run this deliberately, never from the test suite. The golden files pin the F4
scores as they were BEFORE instruction-level alignment existed, so overwriting
them with post-change output would destroy the regression check.

    python tests/fixtures/f7_alignment/make_fixture.py \
        results/ripgrep-main/plain/v1.feasibility.json \
        body_evidence/rust-nonstd/plain/ripgrep-main.O3S.body.json
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from pathlib import Path
from typing import Any


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

from analysis.v1_feasibility import _evidence_slots, _multiset_jaccard  # noqa: E402
from body_similarity import compare_bodies, parse_body  # noqa: E402
from build_manifest import sha256_file  # noqa: E402


FIXTURE_DIR = Path(__file__).resolve().parent
BODIES_PATH = FIXTURE_DIR / "ripgrep_219_bodies.json.gz"
SCORES_PATH = FIXTURE_DIR / "ripgrep_556_scores.json"


def score_pair(
    first: Any,
    second: Any,
) -> tuple[dict[str, float], dict[str, bool | int]]:
    """Reproduce every numeric field `v1_feasibility.py` records for a pair."""
    comparison = compare_bodies(first, second).to_dict()
    comparison.pop("pair")
    quality = comparison.pop("quality")
    evidence_slot_consistency = _multiset_jaccard(
        _evidence_slots(first), _evidence_slots(second)
    )
    variation_support = (
        comparison["constant_slot_consistency"]
        + comparison["call_slot_shape_consistency"]
        + evidence_slot_consistency
    ) / 3.0
    comparison["evidence_slot_consistency"] = evidence_slot_consistency
    comparison["slot_adjusted_aligned_instruction_ratio"] = min(
        comparison["aligned_instruction_ratio"], variation_support
    )
    return comparison, quality


def build_fixture(
    feasibility: dict[str, Any],
    body_artifact: dict[str, Any],
    body_evidence_sha256: str,
    *,
    allow_provenance_drift: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    # The feasibility artifact supplies the pair sample. Its own metric values
    # are only trustworthy when it was scored against these exact bodies.
    recorded = feasibility.get("provenance", {}).get("body_evidence_sha256")
    in_sync = recorded == body_evidence_sha256
    if not in_sync and not allow_provenance_drift:
        raise ValueError(
            "the feasibility artifact was scored against body evidence "
            f"{recorded} but the supplied artifact is {body_evidence_sha256}; "
            "re-run analysis/v1_feasibility.py, or pass "
            "--allow-provenance-drift to pin the golden to the supplied bodies"
        )

    wanted: set[str] = set()
    for record in feasibility["pairs"]:
        wanted.update(record["pair"])

    records = [item for item in body_artifact["functions"] if item["id"] in wanted]
    missing = wanted - {item["id"] for item in records}
    if missing:
        raise ValueError(f"body evidence is missing {len(missing)} functions")

    bodies = {item["id"]: parse_body(item) for item in records}
    entries = []
    drift = 0
    for record in feasibility["pairs"]:
        first_id, second_id = record["pair"]
        metrics, quality = score_pair(bodies[first_id], bodies[second_id])
        drift += sum(
            1
            for name, value in metrics.items()
            if name in record and record[name] != value
        )
        entries.append(
            {
                "pair": [first_id, second_id],
                "label": record["label"],
                "metrics": {name: float(value).hex() for name, value in sorted(metrics.items())},
                "quality": quality,
            }
        )
    if in_sync and drift:
        raise ValueError(
            f"{drift} metrics disagree with a feasibility artifact that claims "
            "the same body evidence; the scoring code has changed"
        )

    provenance = {
        "body_evidence_sha256": body_evidence_sha256,
        "feasibility_body_evidence_sha256": recorded,
        "feasibility_in_sync": in_sync,
        "feasibility_metric_disagreements": drift,
        "gt_stripped_sha256": feasibility.get("provenance", {}).get("gt_stripped_sha256"),
    }
    bodies_fixture = {
        "source": "ripgrep-main.O3S.plain body evidence, restricted to the "
                  "functions used by the v1 feasibility pair sample",
        "provenance": provenance,
        "functions": sorted(records, key=lambda item: item["id"]),
    }
    scores_fixture = {
        "note": "F4 scores recorded before F7.0 instruction alignment existed; "
                "float.hex() so the comparison is exact",
        "provenance": provenance,
        "metric_names": sorted(entries[0]["metrics"]),
        "pairs": entries,
    }
    return bodies_fixture, scores_fixture


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feasibility")
    parser.add_argument("body_evidence")
    parser.add_argument(
        "--allow-provenance-drift",
        action="store_true",
        help="pin the golden to the supplied bodies even when the feasibility "
             "artifact was scored against different ones",
    )
    args = parser.parse_args(argv)

    feasibility = json.loads(Path(args.feasibility).read_text(encoding="utf-8"))
    body_artifact = json.loads(Path(args.body_evidence).read_text(encoding="utf-8"))
    bodies_fixture, scores_fixture = build_fixture(
        feasibility,
        body_artifact,
        sha256_file(args.body_evidence),
        allow_provenance_drift=args.allow_provenance_drift,
    )

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        bodies_fixture, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    # mtime=0 keeps regeneration byte-identical when the content is unchanged.
    with open(BODIES_PATH, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as handle:
            handle.write(payload)
    SCORES_PATH.write_text(
        json.dumps(scores_fixture, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"functions={len(bodies_fixture['functions'])}")
    print(f"pairs={len(scores_fixture['pairs'])}")
    print(f"metrics={len(scores_fixture['metric_names'])}")
    print(f"wrote {BODIES_PATH} ({BODIES_PATH.stat().st_size} bytes)")
    print(f"wrote {SCORES_PATH} ({SCORES_PATH.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
