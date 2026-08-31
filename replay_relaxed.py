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
FORMAL_RUNTIME_DISPLAY = "C:/Python314/python.exe"
MAX_COMPARISONS = 10_000
MAX_ALIGNMENT_CELLS = 500_000_000
RESULTS_ROOT = Path(__file__).resolve().parent / "results" / "replay-relaxed-v1"
FORMAL_CONFIG_PATH = Path(__file__).resolve().parent / "frozen_v1" / "configs" / "v1.formal.json"
FORMAL_CONFIG_SHA256 = "77f394244c67b6633698e80af5265da4544c8ad5033aff7d0474a5ff8f1eebfa"


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

# These are immutable pins discovered from the sibling frozen repositories.
# A same-run manifest is never trusted as a substitute: replacing a frozen
# input and updating its manifest must still fail closed.
FROZEN_PINS: dict[str, dict[str, str]] = {
    "ripgrep-main": {
        "body": "4bcc861d59b8e28064184d69b471314e6486e6ce5d23f04cfbcef84eac79d8db",
        "candidates": "e13ff3713b698706c95c6af4e35ae485b7d83caca161b0246f0421a5d7a9ebfd",
        "strict": "fcf9ab00f55d7df01e8aa6afc3b84b52b5688519a61f3bd06c8d758f7fd0218e",
        "rescue": "a85adae6d3a0d7868416e346d067c8ff8c01bc87b587de5ce2229206f41f46b2",
        "ground_truth": "e792a9c8442ffb833b5d47f34fbcf5f26395c8369230780f0a46a5903b5bf166",
        "linkage_audit": "fb939a2e6120514a8b67cdff2b5236ee31f3fa4752fb520722b7d7a8a7fd314e",
        "v0": "696ba61b32fa2bfdc780b16f0e9496415e3925e1a17eb98fa3a5d742838323ff",
        "config": FORMAL_CONFIG_SHA256,
    },
    "fd": {
        "body": "ebed20a449a0d758a3e134b985ffb8764455d75d56682415fe5b393d57ec0743",
        "candidates": "3e99e07b7255f722cc9342b7389fc61a4bbd1b407a1950ff938d0ede3f7dbac2",
        "strict": "7cd92784e734b3fcfc67455010af92c1cbf0e252774afbfa1a570007612c5320",
        "rescue": "87a39e77561a723bf2ec98ea7dbe2a3281939a9cc024ab6d1e85d5ef2f28d380",
        "ground_truth": "ada83ff652f59decbde72328b3d34daa1d0e73b19aa80f96c6dd4a8c578818af",
        "linkage_audit": "d30d5389c7f09c830962f26110f2f65ca1d46f429005c37e7357d1784331aaf6",
        "v0": "c711e11d2a6e3985569595c9bc58f88a9804fd4418623dc35fecf98b5baad671",
        "config": FORMAL_CONFIG_SHA256,
    },
    "zoxide": {
        "body": "e1776d94199d13d2f995097f191ac78f5de3a5f5c00df80bd7dd78dd42a182cd",
        "candidates": "c60aca1fccfc175d0e2dc1325d74818be7e4ea4408f38c4f0bd3f3f40911697e",
        "strict": "9cf218e2a04965ab3e4c1924464da841ebfcab9df1580595af0546d008e91264",
        "rescue": "9d273f6028ef698c4144f57207f0548c3616e51c36d03e0183acd58bf21884b3",
        "ground_truth": "b5e641338cd098ead94ea299b7dccd3a4ca2b8242743656762cf8f01617d967d",
        "linkage_audit": "aea76c11cb78074695ea2ac4acc8f08026f61d81fa747d9d42948bf82f3da579",
        "v0": "11fe9ef1c0ee3a26013502289502c620a92e73b4f97657de1f68f29f653365a4",
        "config": FORMAL_CONFIG_SHA256,
    },
}

FROZEN_CANONICAL_RESCUE_PINS: dict[str, str] = {
    "ripgrep-main": "7bcda77c522ec3cf91cc0c8235b8aa6df205157eca056da263f3bc5c98a4753d",
    "fd": "b4f16c026664fc1ef048b4b15daa0de13d49a528427fd73ce79958569f8ce889",
    "zoxide": "6337128a57eec932695e84bdf8736cb6582cadbf97d0523479f40827236e3d7e",
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


def _pin(subject: Subject, name: str) -> str:
    try:
        return FROZEN_PINS[subject.name][name]
    except KeyError as exc:
        raise ValueError(f"no immutable pin for {subject.name}/{name}") from exc


def _assert_pinned_digest(subject: Subject, name: str, path: Path, digest: str) -> None:
    expected = _pin(subject, name)
    if digest != expected:
        raise ValueError(
            f"frozen {subject.name}/{name} hash drift: {path} is {digest}, "
            f"expected pinned {expected}"
        )


def _assert_pinned_file(subject: Subject, name: str, path: Path) -> str:
    digest = sha256_file(path)
    _assert_pinned_digest(subject, name, path, digest)
    return digest


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
        _assert_pinned_digest(subject, name, path, hashes[name])

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
    canonical_rescue_sha = canonical_artifact_sha(rescue)
    if canonical_rescue_sha != FROZEN_CANONICAL_RESCUE_PINS[subject.name]:
        raise ValueError(
            f"frozen {subject.name}/rescue canonical hash drift: "
            f"{canonical_rescue_sha} != {FROZEN_CANONICAL_RESCUE_PINS[subject.name]}"
        )
    hashes["rescue_canonical"] = canonical_rescue_sha
    targets = (strict.get("universe") or {}).get("target_ids")
    candidate_targets = (candidates.get("universe") or {}).get("target_ids")
    if not isinstance(targets, list) or targets != candidate_targets:
        raise ValueError("strict/candidate target universes differ")
    return artifacts, hashes


def _load_config() -> tuple[PairPolicyConfig, Path, str]:
    path = FORMAL_CONFIG_PATH
    raw = path.read_bytes()
    digest = sha256_bytes(raw)
    if digest != FORMAL_CONFIG_SHA256:
        raise ValueError(
            f"formal config hash drift: {path} is {digest}, "
            f"expected pinned {FORMAL_CONFIG_SHA256}"
        )
    return PairPolicyConfig.from_file(path), path, digest


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
    strict_sha: str, candidate_sha: str,
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


def _load_v0_groups(
    path: Path,
    strict: Mapping[str, Any],
    *,
    expected_sha256: str | None = None,
) -> tuple[list[list[str]], dict[str, str]]:
    payload, digest = read_json(path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError(f"V0 result hash drift: {path} is {digest}, expected {expected_sha256}")
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
    _require_formal_runtime()
    output_root = Path(output_root).resolve()
    artifacts, hashes = _subject_inputs(subject)
    config, config_path, config_sha = _load_config()
    bodies = _comparable_bodies(artifacts["body"])
    price = dry_price(
        artifacts["strict"], artifacts["candidates"], bodies, config,
        artifacts["rescue"], hashes["strict"], hashes["candidates"],
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
    inputs["rescue"]["canonical_sha256"] = hashes["rescue_canonical"]
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
        rescue_artifact_sha256=hashes["rescue_canonical"],
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
        rescue_artifact=artifacts["rescue"],
        rescue_artifact_sha256=hashes["rescue_canonical"],
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
    recorded_rescue_canonical = (
        (manifest.get("inputs", {}).get("rescue") or {}).get("canonical_sha256")
    )
    if recorded_rescue_canonical != input_hashes["rescue_canonical"]:
        raise ValueError(
            "prediction manifest rescue canonical hash does not match frozen input"
        )
    strict_sha = input_hashes["strict"]
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
        rescue_artifact_sha256=input_hashes["rescue_canonical"],
    )
    strict_groups = _groups_from_strict(strict)
    rescue_groups = _groups_from_rescue(inputs["rescue"])
    _core_partitions(
        strict,
        inputs["candidates"],
        inputs["rescue"],
        strict_sha,
        input_hashes["rescue_canonical"],
        input_hashes["candidates"],
    )
    # Hash and parse every remaining non-oracle frozen input before opening the
    # oracle files.  A stale V0 partition is therefore rejected at the same
    # boundary as a stale prediction.
    v0_sha = _assert_pinned_file(subject, "v0", subject.v0)
    v0_groups, v0_record = _load_v0_groups(
        subject.v0, strict, expected_sha256=v0_sha,
    )
    # This is the first point at which either oracle file is read.
    _assert_pinned_file(subject, "ground_truth", subject.ground_truth)
    _assert_pinned_file(subject, "linkage_audit", subject.linkage_audit)
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
                artifacts["rescue"], hashes["strict"], hashes["candidates"],
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
