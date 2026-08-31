"""Attach uncertain singleton fragments to strict/F7 cores, provisionally.

This is deliberately a post-processing experiment.  It never changes the
strict family artifact and its output is not accepted by label propagation.
One consensus2 candidate MATCH supplies positive evidence; UNKNOWN and
ABSTAIN do not veto it, while REJECT does.  A member compatible with more than
one core stays ambiguous.  A validated F7 final partition is handled as a
separate evaluation-only variant.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from collections.abc import Sequence
from typing import Any, Callable, Mapping

from body_similarity import FunctionBody
from real_v1_adapter import load_from_run

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
STRICT_RULE_VERSION = "consensus2-strict-core-attachment-v2"
F7_RULE_VERSION = "consensus2-f7-core-attachment-v2"
FORMAL_CONFIG = _FROZEN / "configs" / "v1.formal.json"
RELAXED_QUEUE = "consensus2"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DECISIONS = {"match", "reject", "unknown", "abstain"}
_SOURCES = {"candidate", "on-demand"}
_FORMAL_POLICY = {
    "version": "v1",
    "structure_match_threshold": 0.95,
    "slot_match_threshold": 1.0,
    "structure_reject_threshold": None,
    "require_informative_slot": True,
    "abstain_on_opaque_indirect": True,
}
_MAX_COMPARISONS = 10_000
_MAX_ALIGNMENT_CELLS = 500_000_000
_RESCUE_FIELDS = {
    "artifact",
    "schema_version",
    "rescue_rule_version",
    "case",
    "build",
    "profile",
    "scope",
    "ground_truth",
    "provenance",
    "verified_provenance",
    "budget",
    "summary",
    "strict_partition",
    "final_partition",
    "components",
}
_RESCUE_PROVENANCE_FIELDS = {
    "family_artifact_sha256",
    "candidate_artifact_sha256",
    "body_evidence_sha256",
    "raw_graph_sha256",
}
_RESCUE_SHARED_PROVENANCE = (
    "stripped_sha256",
    "body_evidence_sha256",
    "raw_graph_sha256",
    "candidate_selection_sha256",
    "projection_config_sha256",
    "anchor_policy",
    "edge_policy",
)


def _digest(value: str, where: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{where} must be a SHA-256 digest")
    return value


def _canonical_artifact_sha256(value: Mapping[str, Any]) -> str:
    """Hash the canonical JSON bytes emitted by the artifact writers."""
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _partition_records(
    cores: Mapping[str, Sequence[str]],
) -> list[dict[str, Any]]:
    return [
        {"id": identifier, "members": list(members)}
        for identifier, members in sorted(cores.items())
    ]


def _partition_mapping(
    records: Any,
    *,
    where: str,
    min_members: int = 2,
) -> dict[str, tuple[str, ...]]:
    if not isinstance(records, list):
        raise ValueError(f"{where} must be a list")
    cores: dict[str, tuple[str, ...]] = {}
    seen: set[str] = set()
    for index, item in enumerate(records):
        if not isinstance(item, Mapping):
            raise ValueError(f"{where}[{index}] is invalid")
        identifier = item.get("id")
        members = item.get("members")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in cores
            or not isinstance(members, list)
            or len(members) < min_members
            or any(not isinstance(member, str) or not member for member in members)
            or len(set(members)) != len(members)
            or seen.intersection(members)
        ):
            raise ValueError(f"{where}[{index}] is invalid")
        cores[identifier] = tuple(sorted(members))
        seen.update(members)
    return cores


def _validate_rescue_provenance(
    rescue: Mapping[str, Any],
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any] | None,
    family_sha: str,
    candidate_sha: str | None,
) -> None:
    """Apply the frozen F7 rescue schema/provenance checks locally.

    This intentionally mirrors the frozen validator's fail-closed contract
    without importing its propagation/oracle path.  The rescue bytes' actual
    SHA is validated by the caller before this function is reached.
    """
    if set(rescue) != _RESCUE_FIELDS:
        raise ValueError("unsupported v1 family rescue artifact schema")
    if rescue.get("artifact") != "v1-family-rescue":
        raise ValueError("expected a v1-family-rescue artifact")
    if rescue.get("schema_version") != 1:
        raise ValueError("unsupported v1 family rescue artifact")
    if rescue.get("rescue_rule_version") != "f7-rescue-v1":
        raise ValueError("unsupported v1 family rescue rule version")
    for key in ("case", "build", "profile", "scope"):
        value = rescue.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"rescue artifact.{key} must be a non-empty string")
        if value != family_artifact.get(key):
            raise ValueError(f"family and rescue artifacts disagree on {key}")

    provenance = rescue.get("provenance")
    if (
        not isinstance(provenance, Mapping)
        or set(provenance) != _RESCUE_PROVENANCE_FIELDS
    ):
        raise ValueError("rescue artifact provenance must be an object")
    for key, value in provenance.items():
        _digest(value, f"rescue artifact provenance.{key}")
    if provenance["family_artifact_sha256"] != family_sha:
        raise ValueError("rescue was built from another strict family artifact")
    if (
        candidate_sha is not None
        and provenance["candidate_artifact_sha256"] != candidate_sha
    ):
        raise ValueError("rescue was built from another candidate artifact")

    family_provenance = family_artifact.get("provenance")
    if not isinstance(family_provenance, Mapping):
        raise ValueError("strict artifact provenance is missing")
    for key in _RESCUE_SHARED_PROVENANCE:
        expected = family_provenance.get(key)
        if expected is None:
            raise ValueError(f"strict provenance.{key} is missing")
        if key.endswith("_sha256"):
            _digest(expected, f"strict provenance.{key}")

    verified = rescue.get("verified_provenance")
    if (
        not isinstance(verified, Mapping)
        or set(verified) != set(_RESCUE_SHARED_PROVENANCE) | {"target_count"}
    ):
        raise ValueError("rescue artifact verified_provenance has an invalid field set")
    for key in _RESCUE_SHARED_PROVENANCE:
        if verified[key] != family_provenance[key]:
            raise ValueError(f"family/rescue provenance mismatch on {key}")
    target_ids = (family_artifact.get("universe") or {}).get("target_ids")
    if not isinstance(target_ids, list):
        raise ValueError("strict artifact universe is missing")
    if verified["target_count"] != len(target_ids):
        raise ValueError("family/rescue target_count mismatch")
    if provenance["body_evidence_sha256"] != verified["body_evidence_sha256"]:
        raise ValueError("family/rescue provenance mismatch on body_evidence_sha256")
    if provenance["raw_graph_sha256"] != verified["raw_graph_sha256"]:
        raise ValueError("family/rescue provenance mismatch on raw_graph_sha256")

    if rescue.get("ground_truth") != {"used_for": "not used"}:
        raise ValueError("rescue artifact ground_truth policy is invalid")
    if not isinstance(rescue.get("budget"), Mapping):
        raise ValueError("rescue artifact budget must be an object")
    if not isinstance(rescue.get("summary"), Mapping):
        raise ValueError("rescue artifact summary must be an object")
    if not isinstance(rescue.get("components"), list):
        raise ValueError("rescue artifact components must be a list")

    if candidate_sha is not None:
        if not isinstance(candidate_artifact, Mapping):
            raise ValueError("candidate artifact is required for rescue provenance")
        candidate_provenance = candidate_artifact.get("provenance")
        if not isinstance(candidate_provenance, Mapping):
            raise ValueError("candidate artifact provenance is missing")
        for key in _RESCUE_SHARED_PROVENANCE:
            candidate_value = candidate_provenance.get(key)
            if candidate_value is None:
                raise ValueError(f"candidate provenance.{key} is missing")
            if key.endswith("_sha256"):
                _digest(candidate_value, f"candidate provenance.{key}")
            if candidate_value != family_provenance[key]:
                raise ValueError(f"strict/candidate {key} mismatch")


def validate_rescue_partition(
    families: Mapping[str, Any],
    rescue: Mapping[str, Any],
    family_sha: str,
    rescue_sha: str,
    candidate_sha: str | None = None,
    *,
    candidate_artifact: Mapping[str, Any] | None = None,
) -> dict[str, tuple[str, ...]]:
    """Validate one complete F7 result and return its final core partition."""
    strict_sha = _digest(family_sha, "family_artifact_sha256")
    _digest(rescue_sha, "rescue_artifact_sha256")
    if not isinstance(rescue, Mapping):
        raise ValueError("rescue artifact must be an object")
    actual_rescue_sha = _canonical_artifact_sha256(rescue)
    if actual_rescue_sha != rescue_sha:
        raise ValueError("rescue artifact SHA-256 does not match its contents")
    candidate_digest = (
        _digest(candidate_sha, "candidate_artifact_sha256")
        if candidate_sha is not None
        else None
    )
    _validate_rescue_provenance(
        rescue,
        families,
        candidate_artifact,
        strict_sha,
        candidate_digest,
    )

    strict_cores, _, _ = _strict_view(families)
    declared_strict = rescue.get("strict_partition")
    if not isinstance(declared_strict, list):
        raise ValueError("rescue artifact strict_partition must be a list")
    strict_ids: set[str] = set()
    strict_members: set[str] = set()
    strict_map: dict[str, tuple[str, ...]] = {}
    for index, item in enumerate(declared_strict):
        if not isinstance(item, Mapping) or set(item) != {"id", "members"}:
            raise ValueError(
                f"rescue artifact strict_partition[{index}] has invalid fields"
            )
        identifier = item.get("id")
        members = item.get("members")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in strict_ids
            or not isinstance(members, list)
            or not members
            or any(not isinstance(member, str) or not member for member in members)
            or len(set(members)) != len(members)
            or strict_members.intersection(members)
        ):
            raise ValueError(f"rescue artifact strict_partition[{index}] is invalid")
        strict_ids.add(identifier)
        strict_members.update(members)
        strict_map[identifier] = tuple(sorted(members))
    if strict_map != strict_cores:
        raise ValueError(
            "rescue strict_partition does not match strict accepted partition"
        )

    final_records = rescue.get("final_partition")
    if not isinstance(final_records, list):
        raise ValueError("rescue artifact final_partition is invalid")
    final: dict[str, tuple[str, ...]] = {}
    final_members_flat: list[str] = []
    final_ids: set[str] = set()
    for index, item in enumerate(final_records):
        if not isinstance(item, Mapping) or set(item) != {"id", "members", "origin"}:
            raise ValueError(
                f"rescue artifact final_partition[{index}] has invalid fields"
            )
        identifier = item.get("id")
        members = item.get("members")
        origin = item.get("origin")
        if not isinstance(identifier, str) or not identifier or identifier in final_ids:
            raise ValueError(f"rescue artifact final_partition[{index}].id is invalid")
        if (
            not isinstance(members, list)
            or any(not isinstance(member, str) or not member for member in members)
            or len(set(members)) != len(members)
            or origin not in {"strict", "rescued"}
        ):
            raise ValueError(f"rescue artifact final_partition[{index}] is invalid")
        final_ids.add(identifier)
        final[identifier] = tuple(sorted(members))
        final_members_flat.extend(members)
    duplicates = sorted(
        {
            member
            for member in final_members_flat
            if final_members_flat.count(member) > 1
        }
    )
    if duplicates:
        raise ValueError("rescue final_partition has duplicate accepted members")
    accepted_members = {
        member for members in strict_cores.values() for member in members
    }
    final_members = set(final_members_flat)
    if final_members != accepted_members:
        missing = sorted(accepted_members - final_members)
        added = sorted(final_members - accepted_members)
        if missing:
            raise ValueError(
                "rescue final_partition is missing strict accepted member "
                f"{missing[0]!r}"
            )
        raise ValueError(
            "rescue final_partition added a non-strict member "
            f"{added[0]!r}"
        )
    return final


def _validate_relaxed_config(config: PairPolicyConfig) -> None:
    """Require the frozen formal policy, allowing only lower test ceilings."""
    if not isinstance(config, PairPolicyConfig):
        raise ValueError("relaxed evaluation requires a PairPolicyConfig")
    for name, expected in _FORMAL_POLICY.items():
        if getattr(config, name) != expected:
            raise ValueError(
                f"relaxed evaluation requires frozen {name}={expected!r}"
            )
    for name, ceiling in (
        ("max_comparison_count", _MAX_COMPARISONS),
        ("max_alignment_cell_budget", _MAX_ALIGNMENT_CELLS),
    ):
        value = getattr(config, name)
        if (
            value is None
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > ceiling
        ):
            raise ValueError(
                f"relaxed {name} budget must be an integer in [0, {ceiling}]"
            )


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

    decisions = _parse_pair_decisions(family_artifact.get("pair_decisions", []))
    candidates = buckets["provisional"] | buckets["unresolved"]
    return cores, sorted(candidates), decisions


def _parse_pair_decisions(
    records: Any,
) -> dict[tuple[str, str], Mapping[str, Any]]:
    if not isinstance(records, list):
        raise ValueError("pair decisions must be a list")
    decisions: dict[tuple[str, str], Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("pair decision must be an object")
        members = record.get("pair")
        if not isinstance(members, list) or len(members) != 2:
            raise ValueError("pair decision has an invalid pair")
        pair = _pair(*members)
        if pair in decisions:
            raise ValueError(f"duplicate pair decision: {list(pair)}")
        if record.get("decision") not in _DECISIONS:
            raise ValueError("pair decision has an invalid decision")
        if record.get("source") not in _SOURCES:
            raise ValueError("pair decision has an invalid source")
        decisions[pair] = record
    return decisions


def _pair_decisions_digest(records: Sequence[Mapping[str, Any]]) -> str:
    encoded = json.dumps(
        list(records), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _attachment_outputs(
    cores: Mapping[str, tuple[str, ...]],
    candidates: Sequence[str],
    decisions: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[str],
]:
    """Derive attachment outcomes from a complete relaxed decision table."""
    core_of = {
        member: identifier
        for identifier, members in cores.items()
        for member in members
    }
    candidate_cores: dict[str, set[str]] = {member: set() for member in candidates}
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
    for member in candidates:
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
    return attachments, ambiguous, vetoed, unassigned


def build_provisional_artifact(
    family_artifact: Mapping[str, Any],
    *,
    family_artifact_sha256: str,
) -> dict[str, Any]:
    """Build auditable, non-transitive attachments around strict cores."""
    strict_sha = _digest(family_artifact_sha256, "family_artifact_sha256")
    cores, provisional, decisions = _strict_view(family_artifact)
    attachments, ambiguous, vetoed, unassigned = _attachment_outputs(
        cores, provisional, decisions
    )

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
    evaluations, accounting, _ = _evaluate_relaxed_pair_union(
        family_artifact,
        candidate_artifact,
        bodies,
        config,
        core_partitions,
        feature_provider=feature_provider,
    )
    return evaluations, accounting


def _evaluate_relaxed_pair_union(
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    config: PairPolicyConfig,
    core_partitions: Mapping[str, Any] | Sequence[Any],
    *,
    feature_provider: Callable[[PairKey], PairFeatures] | None = None,
) -> tuple[list[PairEvaluation], dict[str, Any], set[PairKey]]:
    """Evaluate one pre-priced union and return its pair identities too."""
    _validate_relaxed_config(config)
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
    return (
        evaluations,
        _relaxed_accounting(cache, len(possible), required_count, required_cells),
        possible,
    )


def _build_variant_artifact(
    family_artifact: Mapping[str, Any],
    strict_cores: Mapping[str, tuple[str, ...]],
    cores: Mapping[str, tuple[str, ...]],
    evaluations: Sequence[PairEvaluation],
    *,
    family_sha: str,
    candidate_sha: str,
    accounting: Mapping[str, Any],
    partition: str,
    rescue_sha: str | None,
) -> dict[str, Any]:
    """Build one deterministic attachment artifact from cached evaluations."""
    records = [
        item.to_dict() for item in sorted(evaluations, key=lambda item: item.pair)
    ]
    evaluated_family = dict(family_artifact)
    evaluated_family["pair_decisions"] = records
    if partition == "f7-core":
        evaluated_family["clusters"] = [
            {
                "id": identifier,
                "status": "accepted",
                "members": list(members),
            }
            for identifier, members in sorted(cores.items())
        ] + [
            cluster
            for cluster in family_artifact["clusters"]
            if cluster.get("status") != "accepted"
        ]
    artifact = build_provisional_artifact(
        evaluated_family, family_artifact_sha256=family_sha
    )
    artifact["rule_version"] = (
        STRICT_RULE_VERSION if partition == "strict-core" else F7_RULE_VERSION
    )
    artifact["partition"] = partition
    artifact["provenance"]["relaxed_candidate_artifact_sha256"] = candidate_sha
    artifact["provenance"]["relaxed_pair_decisions_sha256"] = (
        _pair_decisions_digest(records)
    )
    if rescue_sha is not None:
        artifact["provenance"]["rescue_artifact_sha256"] = rescue_sha
    artifact["policy"]["support"] = (
        "consensus2 candidate match under the frozen formal pair policy"
    )
    if partition == "f7-core":
        artifact["policy"]["ambiguity"] = (
            "attach only when exactly one F7 core is eligible"
        )
        artifact["strict_partition"] = _partition_records(strict_cores)
        artifact["core_partition"] = _partition_records(cores)
        artifact["summary"]["strict_family_count"] = len(strict_cores)
        artifact["summary"]["strict_accepted_member_count"] = sum(
            len(members) for members in strict_cores.values()
        )
    artifact["pair_decisions"] = records
    artifact["metrics"] = dict(accounting)
    return artifact


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
    if rescue_artifact is None and rescue_artifact_sha256 is not None:
        raise ValueError("rescue_artifact_sha256 requires a rescue artifact")
    if rescue_artifact is not None and rescue_artifact_sha256 is None:
        raise ValueError("rescue_artifact_sha256 is required with a rescue artifact")

    _validate_relaxed_config(config)
    strict_cores, _, _ = _strict_view(family_artifact)
    rescue_sha: str | None = None
    f7_cores: dict[str, tuple[str, ...]] | None = None
    if rescue_artifact is not None:
        rescue_sha = _digest(rescue_artifact_sha256, "rescue_artifact_sha256")
        f7_cores = validate_rescue_partition(
            family_artifact,
            rescue_artifact,
            family_sha,
            rescue_sha,
            candidate_sha,
            candidate_artifact=candidate_artifact,
        )

    partitions: dict[str, Mapping[str, tuple[str, ...]]] = {
        "strict-core": strict_cores,
    }
    if f7_cores is not None:
        partitions["f7-core"] = f7_cores
    evaluations, accounting, possible = _evaluate_relaxed_pair_union(
        family_artifact,
        candidate_artifact,
        bodies,
        config,
        partitions,
        feature_provider=feature_provider,
    )

    strict_possible = possible_cross_pairs(
        family_artifact, candidate_artifact, {"strict-core": strict_cores}
    )
    strict_evaluations = [
        item for item in evaluations if item.pair in strict_possible
    ]
    strict = _build_variant_artifact(
        family_artifact,
        strict_cores,
        strict_cores,
        strict_evaluations,
        family_sha=family_sha,
        candidate_sha=candidate_sha,
        accounting=accounting,
        partition="strict-core",
        rescue_sha=None,
    )
    if f7_cores is None:
        return strict, None

    f7_possible = possible_cross_pairs(
        family_artifact, candidate_artifact, {"f7-core": f7_cores}
    )
    f7_evaluations = [item for item in evaluations if item.pair in f7_possible]
    rescue_relaxed = _build_variant_artifact(
        family_artifact,
        strict_cores,
        f7_cores,
        f7_evaluations,
        family_sha=family_sha,
        candidate_sha=candidate_sha,
        accounting=accounting,
        partition="f7-core",
        rescue_sha=rescue_sha,
    )
    return strict, rescue_relaxed


def _validate_relaxed_artifact(
    artifact: Mapping[str, Any],
    family_artifact: Mapping[str, Any],
    family_artifact_sha256: str,
    *,
    rescue_artifact: Mapping[str, Any] | None = None,
    rescue_artifact_sha256: str | None = None,
) -> tuple[dict[str, tuple[str, ...]], list[dict[str, Any]]]:
    """Validate a generated relaxed artifact without rerunning F4 inputs."""
    strict_sha = _digest(family_artifact_sha256, "family_artifact_sha256")
    if artifact.get("artifact") != ARTIFACT:
        raise ValueError("relaxed artifact has an unsupported artifact name")
    rule_version = artifact.get("rule_version")
    if rule_version not in (STRICT_RULE_VERSION, F7_RULE_VERSION):
        raise ValueError("relaxed artifact does not match the deterministic rule")
    partition = artifact.get("partition")
    expected_partition = (
        "strict-core" if rule_version == STRICT_RULE_VERSION else "f7-core"
    )
    if partition != expected_partition:
        raise ValueError("relaxed artifact does not match the deterministic rule")
    strict_cores, candidates, _ = _strict_view(family_artifact)
    cores = strict_cores
    if partition == "f7-core":
        cores = _partition_mapping(
            artifact.get("core_partition"), where="relaxed core_partition"
        )
        accepted = {
            member for members in strict_cores.values() for member in members
        }
        observed = {member for members in cores.values() for member in members}
        if observed != accepted:
            raise ValueError(
                "relaxed core_partition does not cover strict accepted members"
            )
        if artifact.get("core_partition") != _partition_records(cores):
            raise ValueError("relaxed core_partition is not canonical")

    for key in ("case", "build", "profile", "scope"):
        if artifact.get(key) != family_artifact.get(key):
            raise ValueError("relaxed artifact does not match the deterministic rule")
    provenance = artifact.get("provenance")
    family_provenance = family_artifact.get("provenance")
    if not isinstance(provenance, Mapping) or not isinstance(
        family_provenance, Mapping
    ):
        raise ValueError("relaxed artifact does not match the deterministic rule")
    if provenance.get("family_artifact_sha256") != strict_sha:
        raise ValueError("relaxed artifact was built from a different family artifact")
    for key in ("stripped_sha256", "body_evidence_sha256"):
        if provenance.get(key) != family_provenance.get(key):
            raise ValueError("relaxed artifact does not match the deterministic rule")
        _digest(provenance.get(key), f"relaxed provenance.{key}")
    _digest(
        provenance.get("relaxed_candidate_artifact_sha256"),
        "relaxed provenance.relaxed_candidate_artifact_sha256",
    )
    recorded_rescue_sha = provenance.get("rescue_artifact_sha256")
    if partition == "f7-core":
        if recorded_rescue_sha is None:
            raise ValueError("relaxed F7 artifact has no rescue artifact hash")
        _digest(recorded_rescue_sha, "relaxed provenance.rescue_artifact_sha256")
        if rescue_artifact is not None and rescue_artifact_sha256 is None:
            raise ValueError(
                "rescue_artifact_sha256 is required with a rescue artifact"
            )
        if rescue_artifact_sha256 is not None:
            expected_rescue_sha = _digest(
                rescue_artifact_sha256, "rescue_artifact_sha256"
            )
            if recorded_rescue_sha != expected_rescue_sha:
                raise ValueError(
                    "relaxed artifact was built from a different rescue artifact"
                )
            if rescue_artifact is not None:
                validated = validate_rescue_partition(
                    family_artifact,
                    rescue_artifact,
                    strict_sha,
                    expected_rescue_sha,
                    candidate_sha=None,
                )
                if validated != cores:
                    raise ValueError(
                        "relaxed core_partition does not match rescue final_partition"
                    )

    strict_partition = _partition_records(strict_cores)
    if artifact.get("strict_partition") != strict_partition:
        raise ValueError("relaxed artifact does not match the deterministic rule")

    records = artifact.get("pair_decisions")
    decisions = _parse_pair_decisions(records)
    if not isinstance(records, list) or records != [
        decisions[pair] for pair in sorted(decisions)
    ]:
        raise ValueError("relaxed artifact does not match the deterministic rule")
    for record in records:
        if not isinstance(record.get("features"), Mapping):
            raise ValueError("relaxed artifact does not match the deterministic rule")
    expected_digest = provenance.get("relaxed_pair_decisions_sha256")
    if not isinstance(expected_digest, str) or expected_digest != _pair_decisions_digest(
        records
    ):
        raise ValueError("relaxed artifact does not match the deterministic rule")

    attachments, ambiguous, vetoed, unassigned = _attachment_outputs(
        cores, candidates, decisions
    )
    expected_fields = {
        "attachments": sorted(attachments, key=lambda item: item["member"]),
        "ambiguous_members": sorted(ambiguous, key=lambda item: item["member"]),
        "vetoed_hypotheses": sorted(
            vetoed, key=lambda item: (item["member"], item["family_id"])
        ),
        "unassigned_members": sorted(unassigned),
    }
    for key, expected in expected_fields.items():
        if artifact.get(key) != expected:
            raise ValueError("relaxed artifact does not match the deterministic rule")
    summary = artifact.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError("relaxed artifact does not match the deterministic rule")
    expected_summary = {
        "strict_family_count": len(strict_cores),
        "strict_accepted_member_count": sum(
            len(members) for members in strict_cores.values()
        ),
        "input_provisional_member_count": len(
            family_artifact["status_members"]["provisional"]
        ),
        "input_unresolved_member_count": len(
            family_artifact["status_members"]["unresolved"]
        ),
        "candidate_member_count": len(candidates),
        "attached_member_count": len(expected_fields["attachments"]),
        "ambiguous_member_count": len(expected_fields["ambiguous_members"]),
        "vetoed_hypothesis_count": len(expected_fields["vetoed_hypotheses"]),
        "unassigned_member_count": len(expected_fields["unassigned_members"]),
    }
    if any(summary.get(key) != value for key, value in expected_summary.items()):
        raise ValueError("relaxed artifact does not match the deterministic rule")
    return cores, expected_fields["attachments"]


def groups_for_scoring(
    artifact: Mapping[str, Any],
    family_artifact: Mapping[str, Any],
    *,
    family_artifact_sha256: str,
    rescue_artifact: Mapping[str, Any] | None = None,
    rescue_artifact_sha256: str | None = None,
) -> list[list[str]]:
    """Validate the artifact and return strict plus one-member hypotheses."""
    has_rescue_input = (
        rescue_artifact is not None or rescue_artifact_sha256 is not None
    )
    if has_rescue_input and artifact.get("rule_version") != F7_RULE_VERSION:
        raise ValueError(
            "F7 relaxed scoring requires an f7-core relaxed artifact"
        )
    if artifact.get("rule_version") in (STRICT_RULE_VERSION, F7_RULE_VERSION):
        if (
            artifact.get("rule_version") == F7_RULE_VERSION
            and (rescue_artifact is None or rescue_artifact_sha256 is None)
        ):
            raise ValueError(
                "F7 relaxed artifact scoring requires a rescue artifact and its SHA-256"
            )
        cores, attachments = _validate_relaxed_artifact(
            artifact,
            family_artifact,
            family_artifact_sha256,
            rescue_artifact=rescue_artifact,
            rescue_artifact_sha256=rescue_artifact_sha256,
        )
        cores = {identifier: sorted(members) for identifier, members in cores.items()}
    else:
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
        attachments = artifact["attachments"]
    groups = [members for _, members in sorted(cores.items())]
    groups.extend(
        sorted(cores[item["family_id"]] + [item["member"]])
        for item in attachments
    )
    return groups


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _encode_json(value: Any) -> bytes:
    return (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _stage_bytes(path: Path, data: bytes) -> None:
    with path.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _reserve_sibling(path: Path, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=suffix, dir=str(path.parent)
    )
    os.close(descriptor)
    reserved = Path(name)
    reserved.unlink()
    return reserved


def _exists(path: Path) -> bool:
    return os.path.lexists(os.fspath(path))


def _same_output_path(first: Path, second: Path) -> bool:
    try:
        if first.resolve(strict=False) == second.resolve(strict=False):
            return True
    except (OSError, RuntimeError):
        if os.path.abspath(os.fspath(first)) == os.path.abspath(os.fspath(second)):
            return True
    if _exists(first) and _exists(second):
        try:
            return os.path.samefile(first, second)
        except OSError:
            return False
    return False


def _cleanup(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        # Cleanup is best effort after a failed transaction; the original
        # publish error is more useful than masking it with a second failure.
        pass


def _publish_json_files(entries: list[tuple[Path, bytes]]) -> None:
    """Publish one or more complete JSON files as one recoverable transaction."""
    paths = [Path(path) for path, _ in entries]
    if len(paths) != len(set(paths)):
        # This catches equal lexical paths before touching their parents.
        raise ValueError("relaxed output paths must be distinct")
    for index, path in enumerate(paths):
        if any(_same_output_path(path, other) for other in paths[index + 1:]):
            raise ValueError("relaxed output paths must not collide")
        path.parent.mkdir(parents=True, exist_ok=True)
    devices = {os.stat(path.parent).st_dev for path in paths}
    if len(devices) != 1:
        raise ValueError("relaxed output paths must share a filesystem")

    records = [
        {
            "target": path,
            "data": data,
            "stage": None,
            "backup": None,
            "old_exists": _exists(path),
            "backup_moved": False,
        }
        for path, data in entries
    ]
    try:
        # Stage every byte before moving an existing output or publishing any
        # new output. Each stage is a sibling, so os.replace cannot cross a
        # filesystem boundary.
        for record in records:
            stage = _reserve_sibling(record["target"], ".stage")
            record["stage"] = stage
            _stage_bytes(stage, record["data"])

        for record in records:
            target = record["target"]
            if record["old_exists"]:
                backup = _reserve_sibling(target, ".backup")
                record["backup"] = backup
                try:
                    os.replace(target, backup)
                except Exception:
                    # A replace shim can fail after moving its source; retain
                    # that backup only when the target is actually gone.
                    if not _exists(target) and _exists(backup):
                        record["backup_moved"] = True
                    raise
                record["backup_moved"] = True
            os.replace(record["stage"], target)
    except Exception:
        # Restore in reverse order. A backup is authoritative even if an
        # os.replace call raised after moving its source.
        for record in reversed(records):
            target = record["target"]
            backup = record["backup"]
            if record["backup_moved"] and backup is not None and _exists(backup):
                _cleanup(target)
                try:
                    os.replace(backup, target)
                except OSError:
                    pass
            elif not record["old_exists"] and _exists(target):
                _cleanup(target)
        raise
    finally:
        for record in records:
            _cleanup(record["stage"])
            _cleanup(record["backup"])


def write_json(path: Path, value: Any) -> str:
    encoded = _encode_json(value)
    _publish_json_files([(Path(path), encoded)])
    return _sha256(encoded)


def write_json_pair(
    first_path: Path,
    first_value: Any,
    second_path: Path,
    second_value: Any,
) -> tuple[str, str]:
    first_encoded = _encode_json(first_value)
    second_encoded = _encode_json(second_value)
    _publish_json_files([
        (Path(first_path), first_encoded),
        (Path(second_path), second_encoded),
    ])
    return _sha256(first_encoded), _sha256(second_encoded)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="a CallKin-Real run manifest")
    parser.add_argument(
        "--candidates",
        help=f"relaxed queue; defaults to the {RELAXED_QUEUE} file beside the run",
    )
    parser.add_argument("--families", help="strict F6 family artifact")
    parser.add_argument(
        "--rescue",
        help="optional F7 rescue artifact; writes the paired F7 relaxed output",
    )
    parser.add_argument(
        "--config",
        default=str(FORMAL_CONFIG),
        help="formal V1 pair policy; defaults to frozen_v1/configs/v1.formal.json",
    )
    parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument("--output", help="strict-core relaxed artifact path")
    parser.add_argument(
        "--rescue-output", help="F7-core relaxed artifact path (when rescue is supplied)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        run_path = Path(args.run)
        run = json.loads(run_path.read_text(encoding="utf-8"))
        source = load_from_run(run_path)
        family_path = (
            Path(args.families)
            if args.families
            else run_path.parent / f"{run_path.stem}.v1.families.strict.json"
        )
        family_raw = family_path.read_bytes()
        families = json.loads(family_raw.decode("utf-8"))
        family_sha = _sha256(family_raw)
        if run["binary"]["sha256"] != families["provenance"]["stripped_sha256"]:
            raise ValueError("run and strict families describe different binaries")
        candidate_path = (
            Path(args.candidates)
            if args.candidates
            else run_path.parent
            / f"{run_path.stem}.v1.{RELAXED_QUEUE}.k{args.top_k}.candidates.json"
        )
        candidate_raw = candidate_path.read_bytes()
        candidates = json.loads(candidate_raw.decode("utf-8"))
        candidate_sha = _sha256(candidate_raw)
        config_raw = Path(args.config).read_bytes()
        config_sha = _sha256(config_raw)
        config = PairPolicyConfig.from_file(args.config)

        rescue_path = None
        rescue = None
        rescue_sha = None
        if args.rescue:
            rescue_path = Path(args.rescue)
        else:
            default_rescue = run_path.parent / f"{run_path.stem}.v1.families.rescue.json"
            if default_rescue.is_file():
                rescue_path = default_rescue
        if rescue_path is not None:
            rescue_raw = rescue_path.read_bytes()
            rescue = json.loads(rescue_raw.decode("utf-8"))
            rescue_sha = _sha256(rescue_raw)

        strict_artifact, rescue_relaxed = build_relaxed_artifacts(
            families,
            candidates,
            source.bodies,
            config,
            family_artifact_sha256=family_sha,
            candidate_artifact_sha256=candidate_sha,
            rescue_artifact=rescue,
            rescue_artifact_sha256=rescue_sha,
        )
        output = (
            Path(args.output)
            if args.output
            else run_path.parent / f"{run_path.stem}.v1.families.relaxed.json"
        )
        rescue_output = None
        rescue_digest = None
        if rescue_relaxed is not None:
            rescue_output = (
                Path(args.rescue_output)
                if args.rescue_output
                else run_path.parent
                / f"{run_path.stem}.v1.families.rescue-relaxed.json"
            )
            strict_digest, rescue_digest = write_json_pair(
                output,
                strict_artifact,
                rescue_output,
                rescue_relaxed,
            )
        else:
            strict_digest = write_json(output, strict_artifact)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    report = {
        "output": str(output),
        "sha256": strict_digest,
        "artifact": ARTIFACT,
        "summary": strict_artifact["summary"],
        "binary_sha256": source.binary_sha256,
        "queue": {
            "path": str(candidate_path),
            "sha256": candidate_sha,
            "kind": RELAXED_QUEUE,
        },
        "config": {
            "path": str(args.config),
            "sha256": config_sha,
            "policy": config.to_dict(),
        },
        "families": {"path": str(family_path), "sha256": family_sha},
        "strict_families": {"path": str(family_path), "sha256": family_sha},
        "rescue": (
            {"path": str(rescue_path), "sha256": rescue_sha}
            if rescue_path is not None
            else None
        ),
        "artifacts": {
            "strict": {
                "path": str(output),
                "sha256": strict_digest,
                "partition": strict_artifact["partition"],
                "summary": strict_artifact["summary"],
            },
            "f7": (
                {
                    "path": str(rescue_output),
                    "sha256": rescue_digest,
                    "partition": rescue_relaxed["partition"],
                    "summary": rescue_relaxed["summary"],
                }
                if rescue_relaxed is not None
                else None
            ),
        },
    }
    if rescue_relaxed is not None:
        report["rescue_output"] = str(rescue_output)
        report["rescue_sha256"] = rescue_digest
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
