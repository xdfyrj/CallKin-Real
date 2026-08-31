"""Replay the frozen relaxed scorer on immutable subject artifacts.

The replay has one deliberately hard boundary: strict-core and F7-core
relaxed prediction artifacts are built, published, and hash-checked before the
ground-truth or linkage audit is opened.  The relaxed builder receives only
the frozen body, candidate, strict-family and rescue artifacts.  Evaluation is
the separate step below, and delegates pair scoring to :mod:`evaluate`.

The command-line replay must run under ``C:/Python314/python.exe`` (Python
3.14.7).  Importing this module is intentionally safe under the development
interpreter so the small evaluator tests do not accidentally perform a frozen
pair comparison.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import evaluate
from body_similarity import load_body_evidence
from v1_relaxed import (
    PairEvidenceCache,
    PairPolicyConfig,
    build_relaxed_artifacts,
    groups_for_scoring,
    possible_cross_pairs,
    validate_rescue_partition,
    write_json,
    write_json_pair,
)


FORMAL_VERSION = (3, 14, 7)
FORMAL_RUNTIME = "/mnt/c/Python314/python.exe"
FORMAL_RUNTIME_DISPLAY = "C:/Python314/python.exe"
MAX_COMPARISONS = 10_000
MAX_ALIGNMENT_CELLS = 500_000_000
RESULTS_ROOT = Path(__file__).resolve().parent / "results" / "replay-relaxed-v1"


@dataclass(frozen=True)
class Subject:
    name: str
    root: Path
    body: Path
    candidates: Path
    strict: Path
    rescue: Path
    ground_truth: Path
    linkage_audit: Path
    v0: Path


F1 = Path("/mnt/c/users/sumyr/playground/REV/v0-engine-py-f1")
FROZEN = Path("/mnt/c/users/sumyr/playground/REV/v0-engine-py-frozen")
V0 = Path("/mnt/c/users/sumyr/playground/REV/v0-engine-py")

SUBJECTS: dict[str, Subject] = {
    "ripgrep-main": Subject(
        "ripgrep-main", F1,
        F1 / "body_evidence/rust-nonstd/plain/ripgrep-main.O3S.body.json",
        F1 / "results/ripgrep-main/plain/ripgrep-main.O3S.v1.consensus2.k16.candidates.json",
        F1 / "results/ripgrep-main/plain/ripgrep-main.O3S.v1.consensus3.k16.formal.families.json",
        F1 / "results/ripgrep-main/plain/ripgrep-main.O3S.v1.consensus3.k16.formal.rescue.json",
        F1 / "ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json",
        F1 / "results/ripgrep-main/plain/ripgrep-main.O3S.gt-mangled-audit.json",
        V0 / "results/ripgrep-main/plain/angr.role.out-in.json",
    ),
    "fd": Subject(
        "fd", F1,
        F1 / "body_evidence/rust-nonstd/plain/fd.O3S.body.json",
        F1 / "results/fd/plain/fd.O3S.v1.consensus2.k16.candidates.json",
        F1 / "results/fd/plain/fd.O3S.v1.consensus3.k16.formal.families.json",
        F1 / "results/fd/plain/fd.O3S.v1.consensus3.k16.formal.rescue.json",
        F1 / "ground_truth/rust-nonstd/plain/fd.O3S.gt.json",
        F1 / "results/fd/plain/fd.O3S.gt-mangled-audit.json",
        V0 / "results/fd/plain/angr.role.out-in.json",
    ),
    "zoxide": Subject(
        "zoxide", FROZEN,
        FROZEN / "body_evidence/plain/zoxide.O3S.body.json",
        FROZEN / "results/zoxide/plain/zoxide.O3S.v1.consensus2.k16.candidates.json",
        FROZEN / "results/zoxide/plain/zoxide.O3S.v1.consensus3.k16.formal.families.json",
        FROZEN / "results/zoxide/plain/zoxide.O3S.v1.consensus3.k16.formal.rescue.json",
        FROZEN / "ground_truth/rust-nonstd/plain/zoxide.O3S.gt.json",
        FROZEN / "results/zoxide/plain/zoxide.O3S.gt-mangled-audit.json",
        FROZEN / "results/zoxide/plain/zoxide.O3S.v0.out-in.scores.json",
    ),
}


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def canonical_artifact_sha(value: Mapping[str, Any]) -> str:
    """Digest the canonical bytes expected by frozen artifact validators."""
    return sha256_bytes(canonical_bytes(value))


def read_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value, sha256_bytes(raw)


def _record(path: Path, digest: str) -> dict[str, str]:
    return {"path": str(path), "sha256": digest}


def _metadata_match(*values: Mapping[str, Any]) -> None:
    for key in ("case", "build", "profile", "scope"):
        observed = {item.get(key) for item in values}
        if len(observed) != 1:
            raise ValueError(f"frozen artifacts disagree on {key}: {sorted(observed)!r}")


def _subject_inputs(subject: Subject) -> tuple[dict[str, Any], dict[str, str]]:
    paths = {
        "body": subject.body,
        "candidates": subject.candidates,
        "strict": subject.strict,
        "rescue": subject.rescue,
    }
    artifacts: dict[str, Any] = {}
    hashes: dict[str, str] = {}
    for name, path in paths.items():
        artifacts[name], hashes[name] = read_json(path)

    body, candidates = artifacts["body"], artifacts["candidates"]
    strict, rescue = artifacts["strict"], artifacts["rescue"]
    _metadata_match(body, candidates, strict, rescue)
    if body.get("schema_version") != 2:
        raise ValueError("frozen body artifact schema is not v2")
    body_provenance = body.get("provenance", {})
    strict_provenance = strict.get("provenance", {})
    candidate_provenance = candidates.get("provenance", {})
    if strict_provenance.get("body_evidence_sha256") != hashes["body"]:
        raise ValueError("strict artifact does not name the supplied body bytes")
    if candidate_provenance.get("body_evidence_sha256") != hashes["body"]:
        raise ValueError("candidate artifact does not name the supplied body bytes")
    if body_provenance.get("stripped_sha256") != strict_provenance.get("stripped_sha256"):
        raise ValueError("body/strict stripped binary provenance mismatch")
    if strict_provenance.get("candidate_artifact_sha256") is None:
        raise ValueError("strict artifact has no candidate provenance")
    if rescue.get("provenance", {}).get("family_artifact_sha256") != hashes["strict"]:
        raise ValueError("rescue artifact does not name the supplied strict bytes")
    if rescue.get("provenance", {}).get("candidate_artifact_sha256") != hashes["candidates"]:
        raise ValueError("rescue artifact does not name the supplied candidate bytes")
    if rescue.get("provenance", {}).get("body_evidence_sha256") != hashes["body"]:
        raise ValueError("rescue artifact does not name the supplied body bytes")
    targets = (strict.get("universe") or {}).get("target_ids")
    candidate_targets = (candidates.get("universe") or {}).get("target_ids")
    if not isinstance(targets, list) or targets != candidate_targets:
        raise ValueError("strict/candidate target universes differ")
    return artifacts, hashes


def _load_config() -> tuple[PairPolicyConfig, Path, str]:
    path = Path(__file__).resolve().parent / "frozen_v1" / "configs" / "v1.formal.json"
    raw = path.read_bytes()
    return PairPolicyConfig.from_file(path), path, sha256_bytes(raw)


def _comparable_bodies(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Match the adapter boundary: F4/F7 see complete bodies only."""
    return {
        function_id: body
        for function_id, body in load_body_evidence(dict(payload)).items()
        if body.complete
    }


def _core_partitions(
    strict: Mapping[str, Any], candidates: Mapping[str, Any], rescue: Mapping[str, Any],
    strict_sha: str, rescue_sha: str, candidate_sha: str,
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    strict_cores, _, _ = _strict_view(strict)
    f7_cores = validate_rescue_partition(
        strict, rescue, strict_sha, rescue_sha, candidate_sha,
        candidate_artifact=candidates,
    )
    return strict_cores, f7_cores


def _strict_view(artifact: Mapping[str, Any]) -> tuple[dict[str, tuple[str, ...]], list[str], dict[Any, Any]]:
    """Use the frozen validator without duplicating its strict schema."""
    # v1_relaxed keeps this helper private; importing it here is intentional:
    # replay must consume the frozen partition exactly as the builder does.
    from v1_relaxed import _strict_view as frozen_strict_view
    return frozen_strict_view(artifact)


def dry_price(
    strict: Mapping[str, Any], candidates: Mapping[str, Any], bodies: Mapping[str, Any],
    config: PairPolicyConfig, rescue: Mapping[str, Any],
    strict_sha: str, rescue_sha: str, candidate_sha: str,
) -> dict[str, Any]:
    """Price the complete strict/F7 union without evaluating a pair."""
    strict_cores, f7_cores = _core_partitions(
        strict, candidates, rescue, strict_sha, canonical_artifact_sha(rescue), candidate_sha,
    )
    partitions = {"strict-core": strict_cores, "f7-core": f7_cores}
    possible = possible_cross_pairs(strict, candidates, partitions)
    cache = PairEvidenceCache(bodies, candidates["pairs"], config)
    required, cells = cache.demand(possible)
    within = required <= MAX_COMPARISONS and cells <= MAX_ALIGNMENT_CELLS
    return {
        "possible_pair_count": len(possible),
        "required_comparisons": required,
        "required_alignment_cells": cells,
        "max_comparison_count": MAX_COMPARISONS,
        "max_alignment_cell_budget": MAX_ALIGNMENT_CELLS,
        "within_budget": within,
        "status": "priced" if within else "budget-refused",
    }


def _load_v0_groups(path: Path, strict: Mapping[str, Any]) -> tuple[list[list[str]], dict[str, str]]:
    payload, digest = read_json(path)
    runs = payload.get("results", [])
    if not isinstance(runs, list):
        raise ValueError("V0 result has no results list")
    runs = [item for item in runs if item.get("mode") == "out-in"]
    if len(runs) != 1:
        raise ValueError("V0 result must contain exactly one out-in run")
    run = runs[0]
    strict_provenance = strict.get("provenance", {})
    run_analysis = run.get("analysis", {})
    for key in ("case", "build", "profile"):
        if run.get(key) != strict.get(key):
            raise ValueError(f"V0/strict {key} mismatch")
    if run.get("provenance", {}).get("stripped_sha256") != strict_provenance.get("stripped_sha256"):
        raise ValueError("V0/strict stripped binary provenance mismatch")
    for key in ("raw_graph_sha256", "candidate_selection_sha256", "projection_config_sha256", "anchor_policy", "edge_policy"):
        if run_analysis.get(key) != strict_provenance.get(key):
            raise ValueError(f"V0/strict {key} mismatch")
    groups = [
        [str(member["id"]) for member in cluster.get("members", [])]
        for cluster in run.get("clusters", [])
    ]
    observed = set(member for group in groups for member in group)
    observed.update(item["id"] for item in run.get("abstentions", []))
    target_ids = set((strict.get("universe") or {}).get("target_ids", []))
    if observed != target_ids:
        raise ValueError("V0 and strict target universes differ")
    return groups, {"path": str(path), "sha256": digest}


def _linkage_label(
    left: str, right: str, addresses: Mapping[str, Any],
) -> str | None:
    first, second = addresses.get(left), addresses.get(right)
    if not isinstance(first, Mapping) or not isinstance(second, Mapping):
        return evaluate.UNRESOLVED_NEUTRAL
    first_ids = set(first.get("identities", ()))
    second_ids = set(second.get("identities", ()))
    first_origins = set(first.get("origins", ()))
    second_origins = set(second.get("origins", ()))
    if not first_ids or not second_ids or not first_origins or not second_origins:
        return evaluate.UNRESOLVED_NEUTRAL
    if len(first_origins) > 1 or len(second_origins) > 1:
        return evaluate.AMBIGUOUS_NEUTRAL
    if first_origins == second_origins and first_ids.intersection(second_ids):
        return evaluate.DUPLICATE_NEUTRAL
    return None


def _normalized_linkage(
    audit: Mapping[str, Any], universe: set[str], path: Path,
) -> tuple[dict[str, Any], str, dict[str, int]]:
    """Convert the frozen address overlay to evaluate.py's pair-label schema."""
    addresses = audit.get("addresses")
    if not isinstance(addresses, Mapping):
        raise ValueError("linkage audit has no addresses overlay")
    pairs: list[dict[str, Any]] = []
    counts = {
        evaluate.DUPLICATE_NEUTRAL: 0,
        evaluate.AMBIGUOUS_NEUTRAL: 0,
        evaluate.UNRESOLVED_NEUTRAL: 0,
    }
    ordered = sorted(universe)
    for left, right in combinations(ordered, 2):
        label = _linkage_label(left, right, addresses)
        if label is not None:
            pairs.append({"pair": [left, right], "label": label})
            counts[label] += 1
    normalized = {
        "schema_version": 1,
        "artifact": "replay-linkage-pairs",
        "source_artifact": "v1-gt-mangled-audit",
        "pairs": pairs,
    }
    digest = write_json(path, normalized)
    return normalized, digest, counts


def score_replay(
    strict_groups: Sequence[Sequence[str]],
    rescue_groups: Sequence[Sequence[str]],
    strict_relaxed_groups: Sequence[Sequence[str]],
    rescue_relaxed_groups: Sequence[Sequence[str]],
    ground_truth: Mapping[str, Any],
    universe: Iterable[str],
    neutral: Mapping[tuple[str, str], str] | None = None,
    v0_groups: Sequence[Sequence[str]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Score the five replay methods on one common universe."""
    universe_set = set(universe)
    methods: dict[str, Sequence[Sequence[str]]] = {
        "v0": v0_groups or [],
        "strict": strict_groups,
        "strict_f7": rescue_groups,
        "strict_relaxed": strict_relaxed_groups,
        "strict_f7_relaxed": rescue_relaxed_groups,
    }
    return {
        name: evaluate.score_partition(list(groups), dict(ground_truth), universe_set, dict(neutral or {}))
        for name, groups in methods.items()
    }


def micro_aggregate(case_reports: Sequence[Mapping[str, Mapping[str, Any]]]) -> dict[str, dict[str, Any]]:
    """Aggregate pair confusion counts, then derive micro precision/recall/F1."""
    names = ("v0", "strict", "strict_f7", "strict_relaxed", "strict_f7_relaxed")
    output: dict[str, dict[str, Any]] = {}
    for name in names:
        totals = {key: 0 for key in ("true_positive", "false_positive", "false_negative", "true_negative")}
        scored_members = 0
        neutral_total = 0
        neutral_counts = {
            evaluate.DUPLICATE_NEUTRAL: 0,
            evaluate.AMBIGUOUS_NEUTRAL: 0,
            evaluate.UNRESOLVED_NEUTRAL: 0,
        }
        for report in case_reports:
            metrics = report.get(name)
            if not metrics or "true_positive" not in metrics:
                continue
            for key in totals:
                totals[key] += int(metrics[key])
            scored_members += int(metrics.get("scored_member_count", 0))
            neutral_total += int(metrics.get("neutral_pair_total", 0))
            for label in neutral_counts:
                neutral_counts[label] += int(metrics.get("neutral_pair_counts", {}).get(label, 0))
        tp, fp, fn = totals["true_positive"], totals["false_positive"], totals["false_negative"]
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = 2 * precision * recall / (precision + recall) if precision and recall else (0.0 if precision is not None and recall is not None else None)
        output[name] = {
            **totals,
            "scored_member_count": scored_members,
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "neutral_pair_counts": neutral_counts,
            "neutral_pair_total": neutral_total,
        }
    return output


def _groups_from_strict(artifact: Mapping[str, Any]) -> list[list[str]]:
    return [sorted(item["members"]) for item in artifact.get("clusters", []) if item.get("status") == "accepted"]


def _groups_from_rescue(artifact: Mapping[str, Any]) -> list[list[str]]:
    return [sorted(item["members"]) for item in artifact.get("final_partition", [])]


def _prediction_paths(subject: Subject, output_root: Path) -> tuple[Path, Path, Path]:
    directory = output_root / subject.name
    return (
        directory / f"{subject.name}.v1.families.relaxed.json",
        directory / f"{subject.name}.v1.families.rescue-relaxed.json",
        directory / "prediction-manifest.json",
    )


def predict_subject(subject: Subject, output_root: Path) -> dict[str, Any]:
    """Build and publish both relaxed prediction artifacts, never opening GT."""
    output_root = Path(output_root).resolve()
    artifacts, hashes = _subject_inputs(subject)
    config, config_path, config_sha = _load_config()
    bodies = _comparable_bodies(artifacts["body"])
    price = dry_price(
        artifacts["strict"], artifacts["candidates"], bodies, config,
        artifacts["rescue"], hashes["strict"], hashes["rescue"], hashes["candidates"],
    )
    inputs = {
        name: _record(path, hashes[name])
        for name, path in {
            "body": subject.body,
            "candidates": subject.candidates,
            "strict": subject.strict,
            "rescue": subject.rescue,
        }.items()
    }
    inputs["config"] = _record(config_path, config_sha)
    relaxed_path, rescue_relaxed_path, manifest_path = _prediction_paths(subject, output_root)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "artifact": "callkin-real-relaxed-prediction-manifest",
        "case": subject.name,
        "runtime": {"required": FORMAL_RUNTIME_DISPLAY, "python": list(FORMAL_VERSION)},
        "inputs": inputs,
        "price": price,
        "oracle_boundary": {"ground_truth_opened": False, "linkage_audit_opened": False},
    }
    if not price["within_budget"]:
        manifest["status"] = "budget-refused"
        write_json(manifest_path, manifest)
        return manifest

    strict_relaxed, rescue_relaxed = build_relaxed_artifacts(
        artifacts["strict"], artifacts["candidates"], bodies, config,
        family_artifact_sha256=hashes["strict"],
        candidate_artifact_sha256=hashes["candidates"],
        rescue_artifact=artifacts["rescue"],
        # The frozen rescue input is a Windows CRLF file.  Its provenance is
        # recorded using the bytes on disk, while the validator's artifact
        # identity is the canonical JSON digest.
        rescue_artifact_sha256=canonical_artifact_sha(artifacts["rescue"]),
    )
    if rescue_relaxed is None:
        raise ValueError("frozen F7 rescue input did not produce an F7 relaxed artifact")
    strict_digest, rescue_digest = write_json_pair(
        relaxed_path, strict_relaxed, rescue_relaxed_path, rescue_relaxed,
    )
    # Read-back is part of the oracle boundary: hashes refer to bytes on disk,
    # not only to the in-memory return value from the builder.
    strict_disk, strict_disk_sha = read_json(relaxed_path)
    rescue_disk, rescue_disk_sha = read_json(rescue_relaxed_path)
    if (strict_digest, rescue_digest) != (strict_disk_sha, rescue_disk_sha):
        raise ValueError("published relaxed prediction hash mismatch")
    groups_for_scoring(
        strict_disk, artifacts["strict"], family_artifact_sha256=hashes["strict"],
    )
    groups_for_scoring(
        rescue_disk, artifacts["strict"], family_artifact_sha256=hashes["strict"],
        rescue_artifact=artifacts["rescue"], rescue_artifact_sha256=hashes["rescue"],
    )
    manifest.update({
        "status": "predictions-built",
        "predictions": {
            "strict_relaxed": _record(relaxed_path, strict_disk_sha),
            "strict_f7_relaxed": _record(rescue_relaxed_path, rescue_disk_sha),
        },
        "oracle_boundary": {"ground_truth_opened": False, "linkage_audit_opened": False,
                            "predictions_written_and_hashed": True},
    })
    write_json(manifest_path, manifest)
    return manifest


def _load_prediction_manifest(subject: Subject, output_root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    relaxed_path, rescue_relaxed_path, manifest_path = _prediction_paths(subject, output_root)
    manifest, _ = read_json(manifest_path)
    if manifest.get("status") != "predictions-built":
        raise ValueError(f"{subject.name} has no complete prediction manifest")
    predictions = manifest.get("predictions", {})
    if predictions.get("strict_relaxed", {}).get("path") != str(relaxed_path):
        raise ValueError("strict relaxed prediction path is not the manifest path")
    if predictions.get("strict_f7_relaxed", {}).get("path") != str(rescue_relaxed_path):
        raise ValueError("F7 relaxed prediction path is not the manifest path")
    strict, strict_sha = read_json(relaxed_path)
    rescue_relaxed, rescue_sha = read_json(rescue_relaxed_path)
    if strict_sha != predictions["strict_relaxed"].get("sha256") or rescue_sha != predictions["strict_f7_relaxed"].get("sha256"):
        raise ValueError("relaxed prediction bytes do not match manifest hashes")
    return manifest, strict, rescue_relaxed


def score_subject(subject: Subject, output_root: Path) -> dict[str, Any]:
    """Validate predictions first, then open GT/linkage and score one subject."""
    output_root = Path(output_root).resolve()
    manifest, strict_relaxed, rescue_relaxed = _load_prediction_manifest(subject, output_root)
    inputs, input_hashes = _subject_inputs(subject)
    config_sha = _load_config()[2]
    for name in ("body", "candidates", "strict", "rescue", "config"):
        recorded = (manifest.get("inputs", {}).get(name) or {}).get("sha256")
        current = input_hashes.get(name)
        if name == "config":
            current = config_sha
        if recorded != current:
            raise ValueError(f"prediction manifest {name} hash does not match frozen input")
    strict_sha = input_hashes["strict"]
    rescue_sha = input_hashes["rescue"]
    relaxed_path, rescue_relaxed_path, _ = _prediction_paths(subject, output_root)
    strict = inputs["strict"]
    # Validate the complete prediction payloads before opening either oracle.
    # This keeps score mode fail-closed even when a caller edits a manifest and
    # prediction files together.
    relaxed_groups = groups_for_scoring(
        strict_relaxed, strict, family_artifact_sha256=strict_sha,
    )
    rescue_relaxed_groups = groups_for_scoring(
        rescue_relaxed, strict, family_artifact_sha256=strict_sha,
        rescue_artifact=inputs["rescue"],
        rescue_artifact_sha256=canonical_artifact_sha(inputs["rescue"]),
    )
    # This is the first point at which either oracle file is read.
    ground_truth, gt_sha = read_json(subject.ground_truth)
    linkage, linkage_sha = read_json(subject.linkage_audit)
    _metadata_match(strict, ground_truth, linkage)
    if ground_truth.get("provenance", {}).get("stripped_sha256") != strict.get("provenance", {}).get("stripped_sha256"):
        raise ValueError("ground truth and strict artifact describe different binaries")
    if linkage.get("provenance", {}).get("ground_truth_sha256") != gt_sha:
        raise ValueError("linkage audit was built from a different ground truth")
    universe = set((strict.get("universe") or {}).get("target_ids", []))
    normalized_path = output_root / subject.name / "linkage-pairs.json"
    _, normalized_sha, neutral_counts = _normalized_linkage(linkage, universe, normalized_path)
    neutral = evaluate.load_neutral_pairs(normalized_path)
    v0_groups, v0_record = _load_v0_groups(subject.v0, strict)
    strict_groups = _groups_from_strict(strict)
    rescue_groups = _groups_from_rescue(inputs["rescue"])
    metrics = score_replay(
        strict_groups=strict_groups, rescue_groups=rescue_groups,
        strict_relaxed_groups=relaxed_groups,
        rescue_relaxed_groups=rescue_relaxed_groups,
        ground_truth=ground_truth, universe=universe, neutral=neutral,
        v0_groups=v0_groups,
    )
    eval_path = output_root / subject.name / f"{subject.name}.evaluation.json"
    report = {
        "schema_version": 1,
        "artifact": "callkin-real-relaxed-evaluation",
        "case": subject.name,
        "methods": metrics,
        "provenance": {
            "inputs": {
                **manifest.get("inputs", {}),
                "v0": v0_record,
                "ground_truth": _record(subject.ground_truth, gt_sha),
                "linkage_audit": _record(subject.linkage_audit, linkage_sha),
            },
            "predictions": {
                "strict_relaxed": _record(relaxed_path, manifest["predictions"]["strict_relaxed"]["sha256"]),
                "strict_f7_relaxed": _record(rescue_relaxed_path, manifest["predictions"]["strict_f7_relaxed"]["sha256"]),
            },
            "normalized_linkage": _record(normalized_path, normalized_sha),
            "neutral_pair_counts": neutral_counts,
            "oracle_boundary": {
                "predictions_written_and_hashed_before_ground_truth": True,
                "ground_truth_sha256": gt_sha,
                "linkage_audit_sha256": linkage_sha,
            },
        },
        "output_path": str(eval_path),
    }
    write_json(eval_path, report)
    return report


def _require_formal_runtime() -> None:
    version = sys.version_info[:3]
    executable = str(sys.executable).replace("\\", "/").lower()
    if version != FORMAL_VERSION or "python314" not in executable:
        observed = ".".join(str(item) for item in version)
        required = ".".join(str(item) for item in FORMAL_VERSION)
        raise RuntimeError(
            f"frozen pair decisions require {FORMAL_RUNTIME_DISPLAY} Python {required}; "
            f"this process is Python {observed} ({sys.executable})"
        )


def run_replay(
    subjects: Sequence[Subject], output_root: Path, mode: str,
) -> dict[str, Any]:
    output_root = Path(output_root).resolve()
    if mode in {"predict", "replay"}:
        _require_formal_runtime()
    case_reports: list[dict[str, Any]] = []
    for subject in subjects:
        if mode == "dry-price":
            artifacts, hashes = _subject_inputs(subject)
            config, config_path, config_sha = _load_config()
            bodies = _comparable_bodies(artifacts["body"])
            price = dry_price(
                artifacts["strict"], artifacts["candidates"], bodies, config,
                artifacts["rescue"], hashes["strict"], hashes["rescue"], hashes["candidates"],
            )
            case_reports.append({
                "case": subject.name, "status": price["status"], "price": price,
                "inputs": {name: _record(path, digest) for name, (path, digest) in {
                    "body": (subject.body, hashes["body"]), "candidates": (subject.candidates, hashes["candidates"]),
                    "strict": (subject.strict, hashes["strict"]), "rescue": (subject.rescue, hashes["rescue"]),
                    "config": (config_path, config_sha),
                }.items()},
            })
            continue
        if mode == "predict":
            case_reports.append(predict_subject(subject, output_root))
            continue
        if mode == "score":
            case_reports.append(score_subject(subject, output_root))
            continue
        prediction = predict_subject(subject, output_root)
        if prediction.get("status") != "predictions-built":
            case_reports.append(prediction)
            continue
        case_reports.append(score_subject(subject, output_root))
    result: dict[str, Any] = {
        "schema_version": 1,
        "artifact": "callkin-real-relaxed-replay",
        "mode": mode,
        "runtime": {"required": FORMAL_RUNTIME_DISPLAY, "python": list(FORMAL_VERSION)},
        "cases": case_reports,
    }
    scored = [item["methods"] for item in case_reports if "methods" in item]
    result["micro"] = micro_aggregate(scored)
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("dry-price", "predict", "score", "replay"), default="replay")
    parser.add_argument("--subject", choices=tuple(SUBJECTS), action="append")
    parser.add_argument("--output-root", type=Path, default=RESULTS_ROOT)
    parser.add_argument("--report", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    subjects = [SUBJECTS[name] for name in (args.subject or ("ripgrep-main", "fd", "zoxide"))]
    try:
        report = run_replay(subjects, args.output_root, args.mode)
        report_path = args.report or args.output_root / f"{args.mode}-report.json"
        write_json(report_path, report)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
