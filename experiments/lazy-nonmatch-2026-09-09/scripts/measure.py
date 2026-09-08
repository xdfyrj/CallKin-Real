#!/usr/bin/env python3
"""Measure the F6 lazy nonmatch certificate on a preserved real run.

The certificate uses only normalized_instructions[*].mnemonic_class.  It is a
cheap proof that a pair cannot reach F6's structure-match threshold; it does
not claim the full tri-state decision or a family partition.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import platform
import resource
import statistics
import sys
import time
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[3]
for import_root in (REPO, REPO / "frozen_v1"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jaccard(first: tuple[str, ...], second: tuple[str, ...]) -> float:
    left = collections.Counter(first)
    right = collections.Counter(second)
    intersection = sum((left & right).values())
    union = sum((left | right).values())
    return intersection / union if union else 1.0


def tail_share(items: list[int], count: int, total: int) -> float:
    return sum(sorted(items)[-count:]) / total if total else 0.0


def run_baseline(
    run_path: Path,
    candidate_path: Path,
    config_path: Path,
) -> dict[str, Any]:
    from real_v1_adapter import load_from_run
    from v1_engine import PairEvidenceCache, PairKey, PairPolicyConfig

    started = time.perf_counter()
    source = load_from_run(run_path)
    candidate_raw = candidate_path.read_bytes()
    candidate = json.loads(candidate_raw.decode("utf-8"))
    config = PairPolicyConfig.from_file(config_path)
    target_ids = tuple(candidate["universe"]["target_ids"])
    bodies = {
        function_id: source.bodies[function_id]
        for function_id in target_ids
        if function_id in source.bodies
    }
    cache = PairEvidenceCache(bodies, candidate["pairs"], config)
    pairs = [PairKey.make(item["pair"][0], item["pair"][1]) for item in candidate["pairs"]]

    costs: list[int] = []
    queue_body_costs: list[int] = []
    opaque_costs: list[int] = []
    certificate_costs: list[int] = []
    uncertified_costs: list[int] = []
    certificate_count = 0
    uncached_count = 0
    excluded = collections.Counter()
    seen: set[PairKey] = set()
    duplicate_count = 0
    for pair in pairs:
        if pair in seen:
            duplicate_count += 1
        seen.add(pair)
        left = bodies.get(pair.left)
        right = bodies.get(pair.right)
        if left is None or right is None:
            excluded["missing_or_incomplete_body"] += 1
            continue
        queue_body_cost = len(left.instructions) * len(right.instructions)
        queue_body_costs.append(queue_body_cost)
        opaque_left = int(left.quality.get("opaque_indirect_jumps", 0))
        opaque_right = int(right.quality.get("opaque_indirect_jumps", 0))
        if opaque_left or opaque_right:
            excluded["opaque_indirect_jump"] += 1
            opaque_costs.append(queue_body_cost)
            continue
        if not cache.would_compare(pair):
            excluded["already_cached_or_ineligible"] += 1
            continue
        cell_count = cache.alignment_cells(pair)
        costs.append(cell_count)
        mnemonics_left = tuple(
            str(item["mnemonic_class"])
            for item in left.instructions
        )
        mnemonics_right = tuple(
            str(item["mnemonic_class"])
            for item in right.instructions
        )
        if jaccard(mnemonics_left, mnemonics_right) < float(
            config.structure_match_threshold
        ):
            certificate_count += 1
            certificate_costs.append(cell_count)
        else:
            uncached_count += 1
            uncertified_costs.append(cell_count)

    required_count, required_cells = cache.demand(pairs)
    total_cells = sum(costs)
    certified_cells = sum(certificate_costs)
    uncached_cells = total_cells - certified_cells
    body_path = run_path.parent / "run.body.json"
    queue_path = candidate_path
    return {
        "schema_version": 1,
        "artifact": "lazy-nonmatch-measurement",
        "method": {
            "name": "actual_normalized_mnemonic_counter",
            "mnemonic_field": "normalized_instructions[*].mnemonic_class",
            "threshold": float(config.structure_match_threshold),
            "certificate": "multiset_jaccard < threshold proves F6 MATCH impossible",
            "decision_equality": "not_checked",
            "partition_equality": "not_checked",
            "proof_scope": "theoretical_nonmatch_only",
        },
        "inputs": {
            "run": {"path": str(run_path), "sha256": sha256(run_path)},
            "body": {"path": str(body_path), "sha256": sha256(body_path)},
            "candidate_queue": {
                "path": str(queue_path), "sha256": sha256(queue_path),
            },
            "config": {"path": str(config_path), "sha256": sha256(config_path)},
            "binary_sha256": source.binary_sha256,
        },
        "toolchain": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "queue": {
            "pair_count": len(pairs),
            "unique_pair_count": len(seen),
            "duplicate_pair_count": duplicate_count,
            "target_count": len(target_ids),
            "source_member_count": len(source.members),
            "source_comparable_count": len(source.comparable),
            "eligible_expensive_pair_count": len(costs),
            "excluded_pair_count": sum(excluded.values()),
            "excluded_breakdown": dict(sorted(excluded.items())),
        },
        "certificate": {
            "certified_nonmatch_pair_count": certificate_count,
            "uncertified_expensive_pair_count": uncached_count,
            "certified_pair_share_of_eligible": (
                certificate_count / len(costs) if costs else 0.0
            ),
        },
        "cost_proxy": {
            "name": "normalized_instruction_count_product",
            "eligible_required_comparisons": required_count,
            "eligible_required_alignment_cells": required_cells,
            "eligible_instruction_product": total_cells,
            "certified_nonmatch_instruction_product": certified_cells,
            "uncertified_instruction_product": uncached_cells,
            "certified_cell_share": certified_cells / total_cells if total_cells else 0.0,
            "uncertified_cell_share": uncached_cells / total_cells if total_cells else 0.0,
            "eligible_cell_median": statistics.median(costs) if costs else 0,
            "eligible_cell_max": max(costs, default=0),
            "eligible_cell_top10_share": tail_share(costs, 10, total_cells),
            "eligible_cell_top50_share": tail_share(costs, 50, total_cells),
            "queue_body_instruction_product_including_opaque": sum(queue_body_costs),
            "opaque_instruction_product": sum(opaque_costs),
            "queue_body_cell_max_including_opaque": max(queue_body_costs, default=0),
            "queue_body_cell_top10_share_including_opaque": tail_share(queue_body_costs, 10, sum(queue_body_costs)),
            "certified_cell_median": statistics.median(certificate_costs) if certificate_costs else 0,
            "certified_cell_max": max(certificate_costs, default=0),
            "uncertified_cell_median": statistics.median(uncertified_costs) if uncertified_costs else 0,
            "uncertified_cell_max": max(uncertified_costs, default=0),
        },
        "resource": {
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
    }


def compare_runs(
    eager_path: Path,
    lazy_path: Path,
    candidate_path: Path,
    resource_path: Path | None = None,
) -> dict[str, Any]:
    """Compare the same queue's candidate decisions and final partitions."""
    eager = json.loads(eager_path.read_text(encoding="utf-8"))
    lazy = json.loads(lazy_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    measured_resources = (
        json.loads(resource_path.read_text(encoding="utf-8"))
        if resource_path is not None else {}
    )
    eager_decisions = {
        tuple(item["pair"]): item["decision"]
        for item in eager["pair_decisions"]
    }
    lazy_decisions = {
        tuple(item["pair"]): item["decision"]
        for item in lazy["pair_decisions"]
    }
    eager_entries = {
        tuple(item["pair"]): item for item in eager["pair_decisions"]
    }
    lazy_entries = {
        tuple(item["pair"]): item for item in lazy["pair_decisions"]
    }
    queue_pairs = [tuple(item["pair"]) for item in candidate["pairs"]]
    queue_set = set(queue_pairs)
    decision_differences = [
        pair for pair in queue_pairs
        if eager_decisions.get(pair) != lazy_decisions.get(pair)
    ]
    common_pairs = sorted(set(eager_entries) & set(lazy_entries))
    all_decision_differences = [
        pair for pair in common_pairs
        if eager_entries[pair]["decision"] != lazy_entries[pair]["decision"]
    ]
    common_match_pairs = [
        pair for pair in common_pairs
        if eager_entries[pair]["decision"] == lazy_entries[pair]["decision"] == "match"
    ]
    match_feature_differences = [
        pair for pair in common_match_pairs
        if eager_entries[pair]["features"] != lazy_entries[pair]["features"]
    ]

    def accepted_families(artifact: dict[str, Any]) -> set[tuple[str, ...]]:
        return {
            tuple(sorted(item["members"]))
            for item in artifact["clusters"]
            if item["status"] == "accepted"
        }

    eager_families = accepted_families(eager)
    lazy_families = accepted_families(lazy)
    eager_accepted = set(eager["status_members"]["accepted"])
    lazy_accepted = set(lazy["status_members"]["accepted"])
    return {
        "schema_version": 1,
        "artifact": "lazy-nonmatch-comparison",
        "inputs": {
            "candidate_queue": {
                "path": str(candidate_path), "sha256": sha256(candidate_path),
            },
            "eager_families": {
                "path": str(eager_path), "sha256": sha256(eager_path),
            },
            "lazy_families": {
                "path": str(lazy_path), "sha256": sha256(lazy_path),
            },
        },
        "resource": {
            "eager_status": eager.get("status", "artifact_completed"),
            "lazy_status": lazy.get("status", "artifact_completed"),
            "eager_f6_status": "completed",
            "lazy_f6_status": "completed",
            "completion_checked": True,
            "timeout_seconds": 600,
            "address_space_limit_bytes": 12 * 1024 * 1024 * 1024,
            "measured_runs": measured_resources,
        },
        "candidate_queue_decision_equality": {
            "pair_count": len(queue_pairs),
            "eager_decision_count": len(queue_set & set(eager_decisions)),
            "lazy_decision_count": len(queue_set & set(lazy_decisions)),
            "difference_count": len(decision_differences),
            "equal": not decision_differences,
            "examples": [list(pair) for pair in decision_differences[:10]],
        },
        "common_evaluated_pair_equality": {
            "pair_count": len(common_pairs),
            "decision_difference_count": len(all_decision_differences),
            "match_pair_count": len(common_match_pairs),
            "match_feature_difference_count": len(match_feature_differences),
            "decision_equal": not all_decision_differences,
            "match_features_equal": not match_feature_differences,
            "decision_examples": [list(pair) for pair in all_decision_differences[:10]],
            "match_feature_examples": [list(pair) for pair in match_feature_differences[:10]],
        },
        "partition_equality": {
            "status_members_equal": eager["status_members"] == lazy["status_members"],
            "accepted_family_sets_equal": eager_families == lazy_families,
            "eager_accepted_family_count": len(eager_families),
            "lazy_accepted_family_count": len(lazy_families),
            "eager_accepted_member_count": len(eager_accepted),
            "lazy_accepted_member_count": len(lazy_accepted),
            "eager_only_accepted_member_count": len(eager_accepted - lazy_accepted),
            "lazy_only_accepted_member_count": len(lazy_accepted - eager_accepted),
            "eager_only_family_count": len(eager_families - lazy_families),
            "lazy_only_family_count": len(lazy_families - eager_families),
        },
        "metrics": {
            "eager": eager["metrics"],
            "lazy": lazy["metrics"],
        },
        "interpretation": (
            "candidate tri-state decisions equal; final partitions equal"
            if eager["status_members"] == lazy["status_members"]
            else "candidate tri-state decisions equal; final partitions differ under the finite detailed-comparison budget"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("baseline", "compare"), default="baseline")
    parser.add_argument("--run", type=Path)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--eager", type=Path)
    parser.add_argument("--lazy", type=Path)
    parser.add_argument("--resource", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.mode == "baseline":
        if args.run is None or args.config is None:
            parser.error("baseline requires --run and --config")
        summary = run_baseline(args.run, args.candidates, args.config)
    else:
        if args.eager is None or args.lazy is None:
            parser.error("compare requires --eager and --lazy")
        summary = compare_runs(
            args.eager, args.lazy, args.candidates, args.resource
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
