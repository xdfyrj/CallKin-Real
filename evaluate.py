"""R7: score a finished analysis against ground truth. Never part of analysis.

This module is the only place in CallKin-Real that reads ground truth, and
nothing in the analysis path imports it. That is checked, not asserted:
`test_oracle_firewall.py` walks the import graph of every analysis module and
fails if this file, a catalog, or a scorer appears in it.

Three score groups, kept apart, because combining them hides which stage failed.

    discovery   did the tool find the function, with the right extent, and
                did its bytes decode
    grouping    V0 relation-only, V1 strict, V1 strict+F7 and the experimental
                strict-core and F7-core provisional attachments on the same
                discovered universe
    label       direct FLIRT correctness, and what propagation added

Spec 12.1 is explicit that boundary evaluation stays its own result and is
never folded into the grouping score. A tool that found half the functions and
grouped them perfectly is not the same as one that found all of them and
grouped half correctly, and one number cannot say which happened.

Ground truth is read here and only here. It never reaches an artifact this
scores: `evaluate` writes a new score file and does not touch the analysis
output.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Mapping

import v1_relaxed

# The linkage-overlay vocabulary. A pair that ground truth cannot decide is not
# a wrong answer, so it is counted apart rather than charged to precision.
POSITIVE = "positive"
NEGATIVE = "negative"
DUPLICATE_NEUTRAL = "duplicate-neutral"
AMBIGUOUS_NEUTRAL = "ambiguous-neutral"
UNRESOLVED_NEUTRAL = "unresolved-neutral"
NEUTRAL_LABELS = (DUPLICATE_NEUTRAL, AMBIGUOUS_NEUTRAL, UNRESOLVED_NEUTRAL)


class EvaluationError(ValueError):
    """The artifacts and the ground truth do not describe the same binary."""


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def check_same_binary(run: dict[str, Any], ground_truth: dict[str, Any]) -> str:
    """Refuse to score a run against another binary's ground truth.

    Silent here would be worse than anywhere else: every number would still be
    computable and every one of them would be meaningless.
    """
    analysed = run["binary"]["sha256"]
    expected = ground_truth.get("provenance", {}).get("stripped_sha256")
    if expected is None:
        raise EvaluationError("ground truth records no stripped_sha256")
    if analysed != expected:
        raise EvaluationError(
            f"the run analysed {analysed[:12]} but the ground truth describes "
            f"{expected[:12]}"
        )
    return analysed


def gt_members(ground_truth: dict[str, Any]) -> dict[str, str]:
    """member id -> origin, from the ground truth's origin families."""
    members: dict[str, str] = {}
    for family in ground_truth["origins"]:
        for member in family["members"]:
            members[member] = family["origin"]
    return members


def score_discovery(
    ground_truth: dict[str, Any],
    universe_payload: dict[str, Any],
    body_payload: dict[str, Any],
) -> dict[str, Any]:
    """Spec 12.1. A separate result, never folded into the grouping score."""
    known = set(ground_truth["symbols"]) | set(gt_members(ground_truth))
    universe = {record["id"]: record for record in universe_payload["functions"]}
    bodies = {record["id"]: record for record in body_payload["functions"]}

    found = known & set(universe)
    statuses: dict[str, int] = {}
    for record in universe.values():
        statuses[record["analysis_status"]] = statuses.get(
            record["analysis_status"], 0
        ) + 1

    complete = {
        function_id for function_id in found
        if bodies.get(function_id, {}).get("quality", {}).get("complete_decode")
    }
    # An extent that was read but did not decode end to end. `truncated_extent`
    # and `extent_not_file_backed` mean the bytes were never obtained, which is
    # a different failure from a boundary that was wrong.
    wrong_extent = {
        function_id for function_id in found - complete
        if bodies.get(function_id, {}).get("quality", {}).get("failure_reason")
        in {"decode_gap", "zero_instruction_decode"}
    }
    return {
        "ground_truth_function_count": len(known),
        "discovered_count": len(found),
        "missed_count": len(known - set(universe)),
        "discovered_with_failed_decode_count": len(wrong_extent),
        "complete_body_coverage": round(len(complete) / len(known), 4) if known else None,
        "complete_body_count": len(complete),
        "analysis_status_counts": dict(sorted(statuses.items())),
        "address_only_count": statuses.get("address-only", 0),
        "incomplete_count": statuses.get("incomplete", 0),
        "note": (
            "boundary recovery is scored on its own; it is never combined with "
            "the grouping score, because one number cannot say whether the tool "
            "missed functions or mis-grouped the ones it found"
        ),
    }


def _pairs(groups: list[list[str]]) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for members in groups:
        ordered = sorted(members)
        for i, left in enumerate(ordered):
            for right in ordered[i + 1:]:
                result.add((left, right))
    return result


def score_partition(
    predicted: list[list[str]],
    ground_truth: dict[str, Any],
    universe: set[str],
    neutral: dict[tuple[str, str], str] | None = None,
) -> dict[str, Any]:
    """Pair-level scoring over one discovered universe.

    Neutral pairs are removed from the denominators rather than counted as
    errors. A pair ground truth cannot decide -- two codegen duplicates of one
    another, or two functions whose origin is ambiguous -- is not evidence
    either way, and charging it to precision would score the tool on a question
    the oracle never answered.
    """
    members = gt_members(ground_truth)
    scored = {item for item in universe if item in members}
    truth = _pairs([
        sorted(m for m in family["members"] if m in scored)
        for family in ground_truth["origins"]
    ])
    predicted_pairs = _pairs([
        sorted(m for m in group if m in scored) for group in predicted
    ])
    neutral = neutral or {}
    neutral_pairs = {pair for pair, label in neutral.items() if label in NEUTRAL_LABELS}

    truth -= neutral_pairs
    predicted_pairs -= neutral_pairs
    total = len(scored) * (len(scored) - 1) // 2 - len(neutral_pairs)

    tp = len(truth & predicted_pairs)
    fp = len(predicted_pairs - truth)
    fn = len(truth - predicted_pairs)
    tn = max(total - tp - fp - fn, 0)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall else (0.0 if precision is not None and recall is not None else None)
    )
    counts: dict[str, int] = {}
    for label in NEUTRAL_LABELS:
        counts[label] = sum(1 for value in neutral.values() if value == label)
    return {
        "scored_member_count": len(scored),
        "true_positive": tp, "false_positive": fp,
        "false_negative": fn, "true_negative": tn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
        "neutral_pair_counts": counts,
        "neutral_pair_total": len(neutral_pairs),
    }


def score_grouping(
    ground_truth: dict[str, Any],
    universe_payload: dict[str, Any],
    relation_payload: dict[str, Any],
    families: dict[str, Any] | None,
    rescue: dict[str, Any] | None,
    neutral: dict[tuple[str, str], str] | None = None,
    *,
    relaxed: dict[str, Any] | None = None,
    rescue_relaxed: dict[str, Any] | None = None,
    family_artifact_sha256: str | None = None,
    rescue_artifact_sha256: str | None = None,
) -> dict[str, Any]:
    """Spec 12.2. The grouping methods on one universe, so they are comparable."""
    universe = {
        record["id"] for record in universe_payload["functions"]
        if record["grouping_role"] == "member"
    }
    methods: dict[str, Any] = {
        "v0_relation_only": {
            **score_partition(
                [sorted(group) for group in
                 relation_payload["predicted_clusters"].values()],
                ground_truth, universe, neutral,
            ),
            "cluster_count": len(relation_payload["predicted_clusters"]),
        },
    }

    if families is None:
        methods["v1_strict"] = {"status": "not produced"}
    else:
        accepted = [
            sorted(cluster["members"]) for cluster in families["clusters"]
            if cluster["status"] == "accepted"
        ]
        metrics = families.get("metrics", {})
        methods["v1_strict"] = {
            **score_partition(accepted, ground_truth, universe, neutral),
            "accepted_family_count": len(accepted),
            "accepted_member_coverage": round(
                len(families["status_members"]["accepted"]) / len(universe), 4
            ) if universe else None,
            "abstain_coverage": round(
                len(families["status_members"]["abstain"]) / len(universe), 4
            ) if universe else None,
            "comparison_count": metrics.get("total_detailed_comparisons"),
            "alignment_cell_count": metrics.get("total_alignment_cells"),
            "budget_limited": metrics.get("budget_limited"),
        }

    if rescue is None:
        methods["v1_strict_rescue"] = {"status": "not produced"}
    else:
        final = [sorted(item["members"]) for item in rescue["final_partition"]]
        summary = rescue["summary"]
        methods["v1_strict_rescue"] = {
            **score_partition(final, ground_truth, universe, neutral),
            "final_family_count": summary["final_family_count"],
            "rescued_family_count": summary["rescued_family_count"],
            "comparison_count": summary["reserved_comparisons"],
            "alignment_cell_count": summary["reserved_alignment_cells"],
        }

    def score_relaxed_variant(
        artifact: dict[str, Any],
        *,
        method: str,
        rescue: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if families is None or family_artifact_sha256 is None:
            raise EvaluationError(
                "a relaxed artifact requires the strict family artifact it extends"
            )
        if method == "v1_strict_rescue_relaxed_provisional":
            if rescue is None or rescue_artifact_sha256 is None:
                raise EvaluationError(
                    "an F7 relaxed artifact requires the rescue artifact and its SHA-256"
                )
        rescue_for_scoring = (
            rescue if method == "v1_strict_rescue_relaxed_provisional" else None
        )
        rescue_sha_for_scoring = (
            rescue_artifact_sha256
            if method == "v1_strict_rescue_relaxed_provisional"
            else None
        )
        groups = v1_relaxed.groups_for_scoring(
            artifact,
            families,
            family_artifact_sha256=family_artifact_sha256,
            rescue_artifact=rescue_for_scoring,
            rescue_artifact_sha256=rescue_sha_for_scoring,
        )
        partition = artifact.get(
            "partition",
            "f7-core" if method == "v1_strict_rescue_relaxed_provisional" else "strict-core",
        )
        provenance = artifact.get("provenance")
        if not isinstance(provenance, dict):
            raise EvaluationError(f"{method} has no provenance")
        metrics = artifact.get("metrics", {})
        return {
            **score_partition(groups, ground_truth, universe, neutral),
            "partition": partition,
            "provenance": dict(provenance),
            "attachment_count": artifact["summary"]["attached_member_count"],
            "ambiguous_member_count": artifact["summary"]["ambiguous_member_count"],
            "vetoed_hypothesis_count": artifact["summary"]["vetoed_hypothesis_count"],
            "comparison_count": metrics.get("total_detailed_comparisons"),
            "alignment_cell_count": metrics.get("total_alignment_cells"),
            "budget_limited": metrics.get("budget_limited"),
            "note": (
                "experimental provisional attachments; not accepted families "
                "and never used for FLIRT propagation"
            ),
        }

    methods["v1_relaxed_provisional"] = (
        {"status": "not produced"}
        if relaxed is None
        else score_relaxed_variant(
            relaxed,
            method="v1_relaxed_provisional",
        )
    )
    methods["v1_strict_rescue_relaxed_provisional"] = (
        {"status": "not produced"}
        if rescue_relaxed is None
        else score_relaxed_variant(
            rescue_relaxed,
            method="v1_strict_rescue_relaxed_provisional",
            rescue=rescue,
        )
    )
    return {"universe_member_count": len(universe), "methods": methods}


def score_labels(
    ground_truth: dict[str, Any],
    label_artifact: dict[str, Any] | None,
    propagation: dict[str, Any] | None,
    universe_payload: dict[str, Any],
) -> dict[str, Any]:
    """Spec 12.3. Direct correctness, then what propagation added to it."""
    if label_artifact is None:
        return {"status": "unavailable"}

    symbols = ground_truth["symbols"]
    members = gt_members(ground_truth)

    def verdict(member: str, origin: str) -> str:
        names = symbols.get(member)
        if not names:
            return "unknown"
        return "correct" if any(origin in name for name in names) else "incorrect"

    direct = {
        record["member"]: record["canonical_origin"]
        for record in label_artifact["matches"]
    }
    tally = {"correct": 0, "incorrect": 0, "unknown": 0}
    for member, origin in direct.items():
        tally[verdict(member, origin)] += 1
    judged = tally["correct"] + tally["incorrect"]

    result: dict[str, Any] = {
        "direct": {
            **tally,
            "count": len(direct),
            "exact_precision": round(tally["correct"] / judged, 4) if judged else None,
            "coverage": round(len(direct) / len(members), 4) if members else None,
        },
        "seedable_policy": label_artifact["policy"]["seed_policy"],
        "recorded_but_never_seeded": {
            "propagated_wrappers": len(label_artifact["propagated_wrappers"]),
            "cleanup_heuristics": len(label_artifact["cleanup_heuristics"]),
        },
    }

    if propagation is None:
        result["propagated"] = {"status": "not produced"}
        return result

    propagated = {
        record["member"]: record["canonical_origin"]
        for record in propagation["propagated_labels"]
    }
    ptally = {"correct": 0, "incorrect": 0, "unknown": 0}
    for member, origin in propagated.items():
        ptally[verdict(member, origin)] += 1
    # A member that had no direct label and now has a correct one is the only
    # thing propagation can actually add.
    newly_correct = sum(
        1 for member, origin in propagated.items()
        if member not in direct and verdict(member, origin) == "correct"
    )
    selected = {
        member for family in propagation["families"] for member in family["members"]
    }
    universe = {
        record["id"] for record in universe_payload["functions"]
        if record["grouping_role"] == "member"
    }
    # What ground truth says propagation could have reached: an unlabelled
    # member sharing an origin family with a direct seed, inside the universe.
    seeded_origins = {
        members[member] for member in direct if member in members
    }
    upper_bound = sum(
        1 for member, origin in members.items()
        if origin in seeded_origins and member not in direct and member in universe
    )
    result["propagated"] = {
        **ptally,
        "count": len(propagated),
        "newly_correct_member": newly_correct,
        "wrongly_propagated_member": ptally["incorrect"],
        "conflict_family": len(propagation["conflicts"]),
        "method": propagation["method"],
        "direct_seed_in_selected_partition": sum(
            1 for member in direct if member in selected
        ),
        "gt_upper_bound_newly_propagatable": upper_bound,
        "opportunity_gap": upper_bound - newly_correct,
    }
    return result


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _audit_provenance(
    audit: Mapping[str, Any],
    *,
    run: Mapping[str, Any],
    ground_truth: Mapping[str, Any],
    ground_truth_sha256: str,
) -> None:
    """Check that a linkage audit belongs to this exact scoring input.

    The linkage audit is generated from a non-stripped build and the ground
    truth.  It is therefore not enough for its filename, case, or binary name
    to match.  The raw ground-truth digest is mandatory, and optional binary
    digests are checked whenever the producer recorded them.
    """
    if not _is_sha256(ground_truth_sha256):
        raise EvaluationError("the supplied ground truth has an invalid SHA-256")
    provenance = audit.get("provenance")
    if not isinstance(provenance, Mapping):
        raise EvaluationError("linkage audit has no provenance mapping")

    audited_gt = provenance.get("ground_truth_sha256")
    if not _is_sha256(audited_gt):
        raise EvaluationError(
            "linkage audit does not record a valid ground_truth_sha256"
        )
    if audited_gt != ground_truth_sha256:
        raise EvaluationError(
            "linkage audit ground_truth_sha256 mismatch: audit was built from "
            f"{audited_gt}, supplied ground truth is {ground_truth_sha256}"
        )

    gt_provenance = ground_truth.get("provenance")
    if not isinstance(gt_provenance, Mapping):
        gt_provenance = {}
    run_binary = (run.get("binary") or {}).get("sha256")
    audit_stripped = provenance.get("stripped_sha256")
    if audit_stripped is not None:
        if not _is_sha256(audit_stripped):
            raise EvaluationError("linkage audit has an invalid stripped_sha256")
        if run_binary is not None and audit_stripped != run_binary:
            raise EvaluationError(
                "linkage audit stripped_sha256 does not match the analysed binary"
            )
        gt_stripped = gt_provenance.get("stripped_sha256")
        if gt_stripped is not None and audit_stripped != gt_stripped:
            raise EvaluationError(
                "linkage audit stripped_sha256 does not match ground truth"
            )

    audit_non_stripped = provenance.get("non_stripped_sha256")
    if audit_non_stripped is not None:
        if not _is_sha256(audit_non_stripped):
            raise EvaluationError(
                "linkage audit has an invalid non_stripped_sha256"
            )
        gt_non_stripped = gt_provenance.get("non_stripped_sha256")
        if gt_non_stripped is None:
            raise EvaluationError(
                "linkage audit records non_stripped_sha256 but ground truth does not"
            )
        if audit_non_stripped != gt_non_stripped:
            raise EvaluationError(
                "linkage audit non_stripped_sha256 does not match ground truth"
            )

    # These fields are optional in the hand-built run fixture, but if either
    # side records one, an audit from another case/build/profile is invalid.
    for field in ("case", "build", "profile"):
        audit_value = audit.get(field)
        if audit_value is None:
            raise EvaluationError(f"linkage audit has no {field}")
        gt_value = ground_truth.get(field)
        if gt_value is not None and audit_value != gt_value:
            raise EvaluationError(
                f"linkage audit disagrees on {field}: "
                f"{audit_value!r} vs {gt_value!r}"
            )
        run_value = run.get(field)
        if run_value is not None and audit_value != run_value:
            raise EvaluationError(
                f"linkage audit disagrees on {field}: "
                f"{audit_value!r} vs {run_value!r}"
            )


def _neutral_label(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> str | None:
    """Copy the frozen linkage-overlay pair semantics for neutral pairs.

    Positive and negative labels are deliberately discarded here.  The
    evaluator needs only the pairs that the binary-level linkage evidence
    cannot fairly charge to a prediction.
    """
    left_ids = set(left["identities"])
    right_ids = set(right["identities"])
    if not left_ids or not right_ids:
        return UNRESOLVED_NEUTRAL

    left_origins = set(left["origins"])
    right_origins = set(right["origins"])
    if not left_origins or not right_origins:
        return UNRESOLVED_NEUTRAL
    if len(left_origins) > 1 or len(right_origins) > 1:
        return AMBIGUOUS_NEUTRAL
    if left_origins != right_origins:
        return None
    if left_ids & right_ids:
        return DUPLICATE_NEUTRAL
    return None


def load_neutral_pairs(
    path: Path | None,
    *,
    universe: set[str] | None = None,
    run: Mapping[str, Any] | None = None,
    ground_truth: Mapping[str, Any] | None = None,
    ground_truth_sha256: str | None = None,
) -> dict[tuple[str, str], str]:
    """Derive neutral pair labels from the real address linkage overlay.

    The old pair-list shortcut accepted labels without proving where they came
    from.  A supplied audit must now be the frozen
    ``v1-gt-mangled-audit`` artifact and must contain its ``addresses`` map.
    Only address pairs whose *both* IDs are grouping members are considered;
    addresses for abstained/context-only functions are ignored.
    """
    if path is None:
        return {}
    if universe is None or run is None or ground_truth is None or ground_truth_sha256 is None:
        raise EvaluationError(
            "linkage audit validation requires run, ground truth and grouping universe"
        )
    data, _ = _read(path)
    if data.get("artifact") != "v1-gt-mangled-audit":
        raise EvaluationError(
            "linkage audit has no addresses overlay: expected "
            "v1-gt-mangled-audit"
        )
    if data.get("schema_version") != 1:
        raise EvaluationError(
            f"unsupported linkage audit schema: {data.get('schema_version')!r}"
        )
    _audit_provenance(
        data,
        run=run,
        ground_truth=ground_truth,
        ground_truth_sha256=ground_truth_sha256,
    )

    addresses = data.get("addresses")
    if not isinstance(addresses, Mapping) or not addresses:
        raise EvaluationError("linkage audit has no addresses overlay")
    records: dict[str, Mapping[str, Any]] = {}
    for function_id, record in addresses.items():
        if not isinstance(function_id, str) or not isinstance(record, Mapping):
            raise EvaluationError("linkage audit addresses overlay is malformed")
        identities = record.get("identities")
        origins = record.get("origins")
        raw_symbols = record.get("raw_symbols")
        if not isinstance(identities, list) or not all(
            isinstance(item, str) for item in identities
        ):
            raise EvaluationError(
                f"linkage audit address {function_id!r} has invalid identities"
            )
        if not isinstance(origins, list) or not all(
            isinstance(item, str) for item in origins
        ):
            raise EvaluationError(
                f"linkage audit address {function_id!r} has invalid origins"
            )
        if not isinstance(raw_symbols, list) or not all(
            isinstance(item, str) for item in raw_symbols
        ):
            raise EvaluationError(
                f"linkage audit address {function_id!r} has invalid raw_symbols"
            )
        records[function_id] = {"identities": identities, "origins": origins}

    # Neutral pairs are meaningful only on the same scored universe used by
    # score_partition: discovered grouping members that the GT actually
    # describes.  A linkage audit may contain more addresses than this run
    # (or this run may contain more members than the GT); keeping those pairs
    # would inflate neutral_pair_total and corrupt TN.
    gt_member_ids = set(gt_members(ground_truth))
    available = sorted(set(universe) & gt_member_ids & set(records))
    if len(available) < 2:
        raise EvaluationError(
            "linkage audit has fewer than two addresses in the grouping-member universe"
        )

    pairs: dict[tuple[str, str], str] = {}
    for left_id, right_id in itertools.combinations(available, 2):
        label = _neutral_label(records[left_id], records[right_id])
        if label in NEUTRAL_LABELS:
            pairs[(left_id, right_id)] = label
    return pairs


def evaluate(
    run_path: Path,
    ground_truth_path: Path,
    *,
    linkage_audit: Path | None = None,
) -> dict[str, Any]:
    run, run_sha256 = _read(run_path)
    if run.get("artifact") != "callkin-real-run":
        raise EvaluationError(f"{run_path.name} is not a run manifest")
    ground_truth, gt_sha256 = _read(ground_truth_path)
    binary_sha256 = check_same_binary(run, ground_truth)

    def stage(name: str) -> dict[str, Any]:
        path = run_path.parent / run["artifacts"][name]["path"]
        artifact, digest = _read(path)
        if digest != run["stage_sha256"][name]:
            raise EvaluationError(f"{name} on disk is not the {name} this run recorded")
        return artifact["payload"]

    def optional(suffix: str) -> tuple[dict[str, Any] | None, str | None]:
        path = run_path.parent / f"{run_path.stem}{suffix}"
        if not path.is_file():
            return None, None
        artifact, digest = _read(path)
        return artifact, digest

    families, families_sha = optional(".v1.families.strict.json")
    rescue, rescue_sha = optional(".v1.families.rescue.json")
    relaxed, relaxed_sha = optional(".v1.families.relaxed.json")
    rescue_relaxed, rescue_relaxed_sha = optional(
        ".v1.families.rescue-relaxed.json"
    )
    labels, labels_sha = optional(".labels.direct.json")
    propagation, propagation_sha = optional(".v1.labels.strict.json")

    universe, body, relation = stage("universe"), stage("body"), stage("relation")
    grouping_universe = {
        record["id"] for record in universe["functions"]
        if record["grouping_role"] == "member"
    }
    neutral = load_neutral_pairs(
        linkage_audit,
        universe=grouping_universe,
        run=run,
        ground_truth=ground_truth,
        ground_truth_sha256=gt_sha256,
    )

    return {
        "schema_version": 1,
        "artifact": "callkin-real-evaluation",
        "ground_truth": {
            "used_for": "scoring only",
            "path": str(ground_truth_path),
            "sha256": gt_sha256,
        },
        "scored": {
            "binary_sha256": binary_sha256,
            "run_manifest_sha256": run_sha256,
            "stage_sha256": run["stage_sha256"],
            "families_strict_sha256": families_sha,
            "families_rescue_sha256": rescue_sha,
            "families_relaxed_sha256": relaxed_sha,
            "families_rescue_relaxed_sha256": rescue_relaxed_sha,
            "labels_direct_sha256": labels_sha,
            "label_propagation_sha256": propagation_sha,
            "linkage_audit_sha256": (
                _sha256_file(linkage_audit) if linkage_audit else None
            ),
        },
        "toolchain": run.get("toolchain"),
        "runtime_seconds": run.get("execution", {}).get("duration_seconds"),
        "discovery": score_discovery(ground_truth, universe, body),
        "grouping": score_grouping(
            ground_truth,
            universe,
            relation,
            families,
            rescue,
            neutral,
            relaxed=relaxed,
            rescue_relaxed=rescue_relaxed,
            family_artifact_sha256=families_sha,
            rescue_artifact_sha256=rescue_sha,
        ),
        "label": score_labels(ground_truth, labels, propagation, universe),
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-manifest", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--linkage-audit")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = evaluate(
            Path(args.run_manifest),
            Path(args.ground_truth),
            linkage_audit=Path(args.linkage_audit) if args.linkage_audit else None,
        )
        encoded = (
            json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(encoded)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "output": args.output,
        "discovery": {
            key: report["discovery"][key] for key in
            ("discovered_count", "missed_count", "complete_body_coverage")
        },
        "grouping": {
            name: {k: block.get(k) for k in ("precision", "recall", "f1")}
            for name, block in report["grouping"]["methods"].items()
        },
        "label": report["label"],
    }, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
