"""Attach uncertain singleton fragments to strict F6 cores, provisionally.

This is deliberately a post-processing experiment.  It never changes the
strict family artifact and its output is not accepted by label propagation.
One consensus2 candidate MATCH supplies positive evidence; UNKNOWN and
ABSTAIN do not veto it, while REJECT does.  A member compatible with more than
one strict core stays ambiguous.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from collections.abc import Sequence
from typing import Any, Callable, Mapping

from body_similarity import FunctionBody

_FROZEN = Path(__file__).resolve().parent / "frozen_v1"
if str(_FROZEN) not in sys.path:
    sys.path.insert(0, str(_FROZEN))

from v1_candidates import PairKey, validate_candidate_artifact  # noqa: E402
from v1_engine import (  # noqa: E402
    PairEvidenceCache,
    PairEvaluation,
    PairFeatures,
    PairPolicyConfig,
)


ARTIFACT = "v1-provisional-attachments"
SCHEMA_VERSION = 1
RULE_VERSION = "strict-core-attachment-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DECISIONS = {"match", "reject", "unknown", "abstain"}
_SOURCES = {"candidate", "on-demand"}


def _digest(value: str, where: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{where} must be a SHA-256 digest")
    return value


def _pair(first: str, second: str) -> tuple[str, str]:
    if first == second:
        raise ValueError("self pair in strict family artifact")
    return tuple(sorted((first, second)))


def _strict_view(
    family_artifact: Mapping[str, Any],
) -> tuple[dict[str, tuple[str, ...]], list[str], dict[tuple[str, str], Mapping[str, Any]]]:
    if family_artifact.get("artifact") != "v1-family-grouping":
        raise ValueError("expected a v1-family-grouping artifact")
    if family_artifact.get("schema_version") != 1:
        raise ValueError("unsupported strict family artifact schema")
    provenance = family_artifact.get("provenance")
    derivation = (
        provenance.get("candidate_derivation")
        if isinstance(provenance, Mapping)
        else None
    )
    if (
        not isinstance(derivation, Mapping)
        or derivation.get("kind") != "minimum-view-consensus"
        or derivation.get("minimum_view_count") != 3
    ):
        raise ValueError("relaxed attachment support requires a consensus3 strict queue")

    universe = family_artifact.get("universe")
    statuses = family_artifact.get("status_members")
    if not isinstance(universe, Mapping) or not isinstance(statuses, Mapping):
        raise ValueError("strict family artifact has no universe/status mapping")
    required = {"accepted", "provisional", "unresolved", "abstain"}
    if set(statuses) != required:
        raise ValueError("strict family status buckets are invalid")
    target_ids = universe.get("target_ids")
    if not isinstance(target_ids, list) or len(set(target_ids)) != len(target_ids):
        raise ValueError("strict family target universe is invalid")
    buckets = {name: set(statuses[name]) for name in required}
    if any(
        left & right
        for index, left in enumerate(buckets.values())
        for right in list(buckets.values())[index + 1 :]
    ):
        raise ValueError("strict family status buckets overlap")
    if set().union(*buckets.values()) != set(target_ids):
        raise ValueError("strict family status buckets do not cover the universe")

    cores: dict[str, tuple[str, ...]] = {}
    seen: set[str] = set()
    for cluster in family_artifact.get("clusters", []):
        if cluster.get("status") != "accepted":
            continue
        identifier = cluster.get("id")
        members = cluster.get("members")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in cores
            or not isinstance(members, list)
            or len(members) < 2
            or len(set(members)) != len(members)
            or seen.intersection(members)
            or not set(members) <= buckets["accepted"]
        ):
            raise ValueError("strict accepted family is invalid")
        cores[identifier] = tuple(sorted(members))
        seen.update(members)
    if seen != buckets["accepted"]:
        raise ValueError("strict accepted clusters do not cover accepted members")

    decisions: dict[tuple[str, str], Mapping[str, Any]] = {}
    for record in family_artifact.get("pair_decisions", []):
        members = record.get("pair")
        if not isinstance(members, list) or len(members) != 2:
            raise ValueError("strict pair decision has an invalid pair")
        pair = _pair(*members)
        if pair in decisions:
            raise ValueError(f"duplicate strict pair decision: {list(pair)}")
        if record.get("decision") not in _DECISIONS:
            raise ValueError("strict pair decision has an invalid decision")
        if record.get("source") not in _SOURCES:
            raise ValueError("strict pair decision has an invalid source")
        decisions[pair] = record
    candidates = buckets["provisional"] | buckets["unresolved"]
    return cores, sorted(candidates), decisions


def build_provisional_artifact(
    family_artifact: Mapping[str, Any],
    *,
    family_artifact_sha256: str,
) -> dict[str, Any]:
    """Build auditable, non-transitive attachments around strict cores."""
    strict_sha = _digest(family_artifact_sha256, "family_artifact_sha256")
    cores, provisional, decisions = _strict_view(family_artifact)
    core_of = {
        member: identifier
        for identifier, members in cores.items()
        for member in members
    }

    candidate_cores: dict[str, set[str]] = {member: set() for member in provisional}
    for pair, record in decisions.items():
        if record["decision"] != "match" or record["source"] != "candidate":
            continue
        left, right = pair
        if left in candidate_cores and right in core_of:
            candidate_cores[left].add(core_of[right])
        if right in candidate_cores and left in core_of:
            candidate_cores[right].add(core_of[left])

    attachments: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    vetoed: list[dict[str, Any]] = []
    unassigned: list[str] = []
    for member in provisional:
        eligible: list[tuple[str, dict[str, list[list[str]]]]] = []
        for identifier in sorted(candidate_cores[member]):
            evidence = {
                "support_pairs": [],
                "unknown_pairs": [],
                "abstain_pairs": [],
                "missing_pairs": [],
            }
            rejects: list[list[str]] = []
            has_candidate_support = False
            for core_member in cores[identifier]:
                pair = _pair(member, core_member)
                record = decisions.get(pair)
                if record is None:
                    evidence["missing_pairs"].append(list(pair))
                elif record["decision"] == "match":
                    evidence["support_pairs"].append(list(pair))
                    has_candidate_support |= record["source"] == "candidate"
                elif record["decision"] == "reject":
                    rejects.append(list(pair))
                else:
                    evidence[f"{record['decision']}_pairs"].append(list(pair))
            if rejects:
                vetoed.append({
                    "member": member,
                    "family_id": identifier,
                    "reject_pairs": sorted(rejects),
                })
            elif has_candidate_support:
                eligible.append((identifier, evidence))

        if len(eligible) == 1:
            identifier, evidence = eligible[0]
            attachments.append({
                "member": member,
                "family_id": identifier,
                **{name: sorted(pairs) for name, pairs in evidence.items()},
            })
        elif len(eligible) > 1:
            ambiguous.append({
                "member": member,
                "candidate_family_ids": sorted(identifier for identifier, _ in eligible),
            })
        else:
            unassigned.append(member)

    provenance = family_artifact.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("strict family artifact has no provenance")
    copied = {}
    for key in (
        "stripped_sha256",
        "body_evidence_sha256",
        "candidate_artifact_sha256",
    ):
        copied[key] = _digest(provenance.get(key), f"strict provenance.{key}")
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact": ARTIFACT,
        "rule_version": RULE_VERSION,
        "case": family_artifact.get("case"),
        "build": family_artifact.get("build"),
        "profile": family_artifact.get("profile"),
        "scope": family_artifact.get("scope"),
        "ground_truth": {"used_for": "not used"},
        "provenance": {
            "family_artifact_sha256": strict_sha,
            **copied,
        },
        "policy": {
            "support": "candidate match from the strict consensus3 queue",
            "non_veto": ["unknown", "abstain", "missing"],
            "veto": "reject",
            "veto_limit": (
                "the frozen formal config has no structure_reject_threshold, "
                "so current strict artifacts may contain no reject decisions"
            ),
            "ambiguity": "attach only when exactly one strict core is eligible",
            "transitivity": "each provisional member is a separate attachment",
            "label_propagation": "forbidden",
        },
        "strict_partition": [
            {"id": identifier, "members": list(members)}
            for identifier, members in sorted(cores.items())
        ],
        "attachments": sorted(attachments, key=lambda item: item["member"]),
        "ambiguous_members": sorted(ambiguous, key=lambda item: item["member"]),
        "vetoed_hypotheses": sorted(
            vetoed, key=lambda item: (item["member"], item["family_id"])
        ),
        "unassigned_members": sorted(unassigned),
        "summary": {
            "strict_family_count": len(cores),
            "strict_accepted_member_count": sum(len(members) for members in cores.values()),
            "input_provisional_member_count": len(
                family_artifact["status_members"]["provisional"]
            ),
            "input_unresolved_member_count": len(
                family_artifact["status_members"]["unresolved"]
            ),
            "candidate_member_count": len(provisional),
            "attached_member_count": len(attachments),
            "ambiguous_member_count": len(ambiguous),
            "vetoed_hypothesis_count": len(vetoed),
            "unassigned_member_count": len(unassigned),
        },
    }


def _consensus2(candidate_artifact: Mapping[str, Any]) -> None:
    validate_candidate_artifact(candidate_artifact)
    provenance = candidate_artifact.get("provenance")
    derivation = (
        provenance.get("candidate_derivation")
        if isinstance(provenance, Mapping)
        else None
    )
    if (
        not isinstance(derivation, Mapping)
        or derivation.get("kind") != "minimum-view-consensus"
        or derivation.get("minimum_view_count") != 2
    ):
        raise ValueError("relaxed attachments require a consensus2 candidate queue")


def _check_relaxed_inputs(
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
) -> None:
    _consensus2(candidate_artifact)
    for key in ("case", "build", "profile", "scope"):
        family_value = family_artifact.get(key)
        candidate_value = candidate_artifact.get(key)
        if not isinstance(family_value, str) or not family_value:
            raise ValueError(f"strict artifact {key} is missing")
        if family_value != candidate_value:
            raise ValueError(f"strict/candidate {key} mismatch")
    family_universe = family_artifact.get("universe")
    candidate_universe = candidate_artifact.get("universe")
    if not isinstance(family_universe, Mapping):
        raise ValueError("strict artifact universe is missing")
    if not isinstance(candidate_universe, Mapping):
        raise ValueError("candidate artifact universe is missing")
    family_targets = family_universe.get("target_ids")
    candidate_targets = candidate_universe.get("target_ids")
    if family_targets != candidate_targets:
        raise ValueError("strict/candidate target universe mismatch")
    family_provenance = family_artifact.get("provenance")
    candidate_provenance = candidate_artifact.get("provenance")
    if not isinstance(family_provenance, Mapping) or not isinstance(
        candidate_provenance, Mapping
    ):
        raise ValueError("strict/candidate provenance is missing")
    for key in ("stripped_sha256", "body_evidence_sha256"):
        family_digest = _digest(family_provenance.get(key), f"strict provenance.{key}")
        candidate_digest = _digest(
            candidate_provenance.get(key), f"candidate provenance.{key}"
        )
        if family_digest != candidate_digest:
            raise ValueError(f"strict/candidate {key} mismatch")


def _normalize_core_partitions(
    core_partitions: Mapping[str, Any] | Sequence[Any],
) -> list[dict[str, tuple[str, ...]]]:
    """Normalize one or more ``family_id -> members`` partitions.

    Task 1 evaluates one strict partition.  Task 2 passes the strict and F7
    partitions together, so accepting both shapes here keeps the cache gate
    shared without making either caller manufacture a wrapper type.
    """
    def is_partition_shape(value: Any) -> bool:
        if isinstance(value, Mapping):
            if "members" in value:
                return True
            values = list(value.values())
            return not values or all(
                isinstance(item, Sequence) and not isinstance(item, (str, bytes))
                for item in values
            )
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            values = list(value)
            return not values or (
                all(
                    isinstance(item, Mapping) and "members" in item
                    for item in values
                )
                or all(
                    isinstance(item, Sequence)
                    and not isinstance(item, (str, bytes))
                    for item in values
                )
            )
        return False

    if isinstance(core_partitions, Mapping):
        values = list(core_partitions.values())
        if values and all(is_partition_shape(value) for value in values):
            raw_partitions: list[Any] = values
        else:
            raw_partitions = [core_partitions]
    elif isinstance(core_partitions, Sequence) and not isinstance(
        core_partitions, (str, bytes)
    ):
        values = list(core_partitions)
        # A rescue artifact exposes ``final_partition`` as records rather
        # than an id-to-members mapping.  Treat that list as one partition;
        # a list of mappings without ``members`` remains a list of partitions.
        if values and all(
            isinstance(value, Mapping) and "members" in value
            for value in values
        ):
            raw_partitions = [values]
        elif values and all(
            isinstance(value, Sequence) and not isinstance(value, (str, bytes))
            for value in values
        ):
            raw_partitions = [values]
        else:
            raw_partitions = values
    else:
        raise ValueError("core_partitions must be a partition or sequence of partitions")

    normalized: list[dict[str, tuple[str, ...]]] = []
    for raw_partition in raw_partitions:
        if isinstance(raw_partition, Mapping) and "members" in raw_partition:
            entries = [(
                raw_partition.get("id"),
                raw_partition.get("members"),
            )]
        elif isinstance(raw_partition, Mapping):
            entries = list(raw_partition.items())
        elif isinstance(raw_partition, Sequence) and not isinstance(
            raw_partition, (str, bytes)
        ):
            values = list(raw_partition)
            if values and all(
                isinstance(value, Mapping) and "members" in value
                for value in values
            ):
                entries = [
                    (value.get("id"), value.get("members"))
                    for value in values
                ]
            else:
                entries = [(str(index), value) for index, value in enumerate(values)]
        else:
            raise ValueError("each core partition must be an object or sequence")
        partition: dict[str, tuple[str, ...]] = {}
        seen: set[str] = set()
        for identifier, members in entries:
            if not isinstance(identifier, str) or not identifier:
                raise ValueError("core family id must be a non-empty string")
            if (
                isinstance(members, (str, bytes))
                or not isinstance(members, Sequence)
                or len(members) < 2
                or any(not isinstance(member, str) or not member for member in members)
                or len(set(members)) != len(members)
                or seen.intersection(members)
            ):
                raise ValueError("core family members are invalid")
            partition[identifier] = tuple(sorted(members))
            seen.update(members)
        normalized.append(partition)
    return normalized


def possible_cross_pairs(
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
    core_partitions: Mapping[str, Any] | Sequence[Any],
) -> set[PairKey]:
    """Return every singleton-to-core pair reachable from consensus2.

    A candidate pair only identifies a core as reachable.  Once reached, all
    singleton/member cross pairs are priced, including pairs that were absent
    from retrieval.  This makes the pre-F4 budget independent of match
    outcomes and leaves on-demand matches unable to create retrieval support.
    """
    _check_relaxed_inputs(family_artifact, candidate_artifact)
    _, candidates, _ = _strict_view(family_artifact)
    candidate_members = set(candidates)
    possible: set[PairKey] = set()
    for cores in _normalize_core_partitions(core_partitions):
        core_of = {
            member: identifier
            for identifier, members in cores.items()
            for member in members
        }
        reached: dict[str, set[str]] = {member: set() for member in candidate_members}
        for record in candidate_artifact["pairs"]:
            left, right = record["pair"]
            if left in reached and right in core_of:
                reached[left].add(core_of[right])
            if right in reached and left in core_of:
                reached[right].add(core_of[left])
        possible.update(
            PairKey.make(member, core_member)
            for member, identifiers in reached.items()
            for identifier in identifiers
            for core_member in cores[identifier]
        )
    return possible


def _relaxed_accounting(
    cache: PairEvidenceCache,
    possible_count: int,
    required_count: int,
    required_cells: int,
) -> dict[str, Any]:
    """Expose deterministic cost and source accounting for a relaxed run."""
    return {
        "pair_count": possible_count,
        "possible_pair_count": possible_count,
        "required_comparisons": required_count,
        "required_alignment_cells": required_cells,
        "within_budget": True,
        "budget_limited": False,
        "max_comparison_count": cache.config.max_comparison_count,
        "max_alignment_cell_budget": cache.config.max_alignment_cell_budget,
        "candidate_detailed_comparison_count": cache.candidate_comparisons,
        "on_demand_comparison_count": cache.on_demand_comparisons,
        "abstain_comparison_count": cache.abstain_comparisons,
        "cache_hit_count": cache.cache_hits,
        "total_detailed_comparisons": cache.total_comparisons,
        "candidate_alignment_cells": cache.candidate_alignment_cells,
        "on_demand_alignment_cells": cache.on_demand_alignment_cells,
        "total_alignment_cells": cache.total_alignment_cells,
        **cache.remaining(),
    }


def evaluate_relaxed_pairs(
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    config: PairPolicyConfig,
    core_partitions: Mapping[str, Any] | Sequence[Any],
    *,
    feature_provider: Callable[[PairKey], PairFeatures] | None = None,
) -> tuple[list[PairEvaluation], dict[str, Any]]:
    """Pre-price and evaluate one shared relaxed pair set.

    The candidate queue is consensus2 retrieval evidence; ``core_partitions``
    may contain strict and F7 cores, but all variants use this one cache and
    one budget gate.  No feature provider or body alignment is invoked until
    the complete union has been priced successfully.
    """
    _check_relaxed_inputs(family_artifact, candidate_artifact)
    possible = possible_cross_pairs(
        family_artifact, candidate_artifact, core_partitions
    )
    cache = PairEvidenceCache(
        bodies,
        candidate_artifact["pairs"],
        config,
        feature_provider=feature_provider,
    )
    required_count, required_cells = cache.demand(possible)
    if not cache.within_budget(required_count, required_cells):
        raise ValueError(
            "relaxed candidate set exceeds the formal comparison budget: "
            f"{required_count} comparisons and {required_cells} alignment cells"
        )
    evaluations = [cache.get_evaluation(pair) for pair in sorted(possible)]
    return evaluations, _relaxed_accounting(
        cache, len(possible), required_count, required_cells
    )


def build_relaxed_artifacts(
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    config: PairPolicyConfig,
    *,
    family_artifact_sha256: str,
    candidate_artifact_sha256: str,
    rescue_artifact: Mapping[str, Any] | None = None,
    rescue_artifact_sha256: str | None = None,
    feature_provider: Callable[[PairKey], PairFeatures] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Evaluate consensus2 singleton-to-core evidence under the formal policy."""
    family_sha = _digest(family_artifact_sha256, "family_artifact_sha256")
    candidate_sha = _digest(
        candidate_artifact_sha256, "candidate_artifact_sha256"
    )
    cores, _, _ = _strict_view(family_artifact)
    evaluations, accounting = evaluate_relaxed_pairs(
        family_artifact,
        candidate_artifact,
        bodies,
        config,
        {"strict-core": cores},
        feature_provider=feature_provider,
    )

    evaluated_family = dict(family_artifact)
    evaluated_family["pair_decisions"] = [item.to_dict() for item in evaluations]
    strict = build_provisional_artifact(
        evaluated_family, family_artifact_sha256=family_sha
    )
    strict["rule_version"] = "consensus2-strict-core-attachment-v2"
    strict["partition"] = "strict-core"
    strict["provenance"]["relaxed_candidate_artifact_sha256"] = candidate_sha
    strict["policy"]["support"] = (
        "consensus2 candidate match under the frozen formal pair policy"
    )
    strict["pair_decisions"] = [item.to_dict() for item in evaluations]
    strict["metrics"] = accounting
    if rescue_artifact is not None or rescue_artifact_sha256 is not None:
        raise NotImplementedError("F7-core relaxed attachments are not implemented")
    return strict, None


def groups_for_scoring(
    artifact: Mapping[str, Any],
    family_artifact: Mapping[str, Any],
    *,
    family_artifact_sha256: str,
) -> list[list[str]]:
    """Validate the artifact and return strict plus one-member hypotheses."""
    expected = build_provisional_artifact(
        family_artifact,
        family_artifact_sha256=family_artifact_sha256,
    )
    if artifact != expected:
        recorded = (artifact.get("provenance") or {}).get("family_artifact_sha256")
        if recorded != family_artifact_sha256:
            raise ValueError(
                "relaxed artifact was built from a different family artifact"
            )
        raise ValueError("relaxed artifact does not match the deterministic rule")
    cores = {
        item["id"]: sorted(item["members"])
        for item in artifact["strict_partition"]
    }
    groups = [members for _, members in sorted(cores.items())]
    groups.extend(
        sorted(cores[item["family_id"]] + [item["member"]])
        for item in artifact["attachments"]
    )
    return groups


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> str:
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return _sha256(encoded)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="a CallKin-Real run manifest")
    parser.add_argument("--families", help="strict F6 family artifact")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        run_path = Path(args.run)
        run = json.loads(run_path.read_text(encoding="utf-8"))
        family_path = (
            Path(args.families)
            if args.families
            else run_path.parent / f"{run_path.stem}.v1.families.strict.json"
        )
        raw = family_path.read_bytes()
        families = json.loads(raw.decode("utf-8"))
        if run["binary"]["sha256"] != families["provenance"]["stripped_sha256"]:
            raise ValueError("run and strict families describe different binaries")
        artifact = build_provisional_artifact(
            families, family_artifact_sha256=_sha256(raw)
        )
        output = (
            Path(args.output)
            if args.output
            else run_path.parent / f"{run_path.stem}.v1.families.relaxed.json"
        )
        digest = write_json(output, artifact)
    except Exception as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps({
        "output": str(output),
        "sha256": digest,
        "artifact": ARTIFACT,
        "summary": artifact["summary"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
