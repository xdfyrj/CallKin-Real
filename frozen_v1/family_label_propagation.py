"""GT-free propagation of direct Oxidizer FLIRT labels across F6/F7 families.

The grouping artifact is treated as an immutable partition.  This module only
overlays direct ``canonical_origin``/``owner`` labels after grouping has
finished; it never searches symbols, reads ground truth, or changes a family.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from family_rescue import RESCUE_RULE_VERSION, SHARED_PROVENANCE, rescued_clusters
from graph_projector import function_id
from oxidizer_adapter import validate_label_artifact


PROPAGATION_ARTIFACT = "v1-family-label-propagation"
PROPAGATION_SCHEMA_VERSION = 1
DEFAULT_ID_BIAS = 0x100000
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _sha256(value: str, *, where: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{where} must be a SHA-256 digest")
    return value


def _metadata(artifact: Mapping[str, Any], *, where: str) -> None:
    for key in ("case", "build", "profile", "scope"):
        value = artifact.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{where}.{key} must be a non-empty string")


def _provenance(artifact: Mapping[str, Any], *, where: str) -> Mapping[str, Any]:
    value = artifact.get("provenance")
    if not isinstance(value, Mapping):
        raise ValueError(f"{where}.provenance must be an object")
    stripped = value.get("stripped_sha256")
    _sha256(stripped, where=f"{where}.provenance.stripped_sha256")
    for key, digest in value.items():
        if key.endswith("_sha256"):
            _sha256(digest, where=f"{where}.provenance.{key}")
    return value


def _validate_family_artifact(artifact: Mapping[str, Any]) -> None:
    """Validate the relevant F6 schema and its status partition."""
    if not isinstance(artifact, Mapping):
        raise ValueError("family artifact must be an object")
    expected_fields = {
        "schema_version", "artifact", "case", "build", "profile", "scope",
        "config", "provenance", "universe", "clusters", "status_members",
        "abstain_reasons", "pair_decisions", "blocked_merges", "metrics",
    }
    if set(artifact) != expected_fields:
        raise ValueError("unsupported v1 family artifact schema")
    if artifact.get("schema_version") != 1 or artifact.get("artifact") != "v1-family-grouping":
        raise ValueError("unsupported v1 family artifact")
    _metadata(artifact, where="family artifact")
    _provenance(artifact, where="family artifact")
    for key in ("config", "metrics", "abstain_reasons"):
        if not isinstance(artifact[key], Mapping):
            raise ValueError(f"family artifact {key} must be an object")
    for key in ("pair_decisions", "blocked_merges"):
        if not isinstance(artifact[key], list):
            raise ValueError(f"family artifact {key} must be a list")
    universe = artifact.get("universe")
    if not isinstance(universe, Mapping) or set(universe) != {
        "target_count", "target_ids", "complete_body_count", "incomplete_ids",
    }:
        raise ValueError("family artifact universe must be an object")
    target_ids = universe.get("target_ids")
    if (
        not isinstance(target_ids, list)
        or any(not isinstance(member, str) or not member for member in target_ids)
        or len(set(target_ids)) != len(target_ids)
    ):
        raise ValueError("family artifact target_ids are invalid")
    incomplete_ids = universe["incomplete_ids"]
    if (
        not isinstance(incomplete_ids, list)
        or any(not isinstance(member, str) or not member for member in incomplete_ids)
        or len(set(incomplete_ids)) != len(incomplete_ids)
        or not set(incomplete_ids) <= set(target_ids)
        or universe["target_count"] != len(target_ids)
        or universe["complete_body_count"] != len(target_ids) - len(incomplete_ids)
    ):
        raise ValueError("family artifact universe counts are inconsistent")
    clusters = artifact.get("clusters")
    if not isinstance(clusters, list):
        raise ValueError("family artifact clusters must be a list")
    target_set = set(target_ids)
    cluster_ids: set[str] = set()
    all_members: set[str] = set()
    for index, cluster in enumerate(clusters):
        where = f"family artifact clusters[{index}]"
        if not isinstance(cluster, Mapping):
            raise ValueError(f"{where} must be an object")
        if set(cluster) != {"id", "status", "members"}:
            raise ValueError(f"{where} has an invalid field set")
        if not isinstance(cluster.get("id"), str) or not cluster["id"]:
            raise ValueError(f"{where}.id must be a non-empty string")
        if cluster["id"] in cluster_ids:
            raise ValueError(f"duplicate family cluster id: {cluster['id']!r}")
        cluster_ids.add(cluster["id"])
        if cluster.get("status") not in {"accepted", "provisional", "unresolved", "abstain"}:
            raise ValueError(f"{where}.status is invalid")
        members = cluster.get("members")
        if (
            not isinstance(members, list)
            or not members
            or any(not isinstance(member, str) or not member for member in members)
            or len(set(members)) != len(members)
        ):
            raise ValueError(f"{where}.members are invalid")
        outside = sorted(set(members) - target_set)
        if outside:
            raise ValueError(
                f"{where}.members contain IDs outside the target universe: {outside[0]!r}"
            )
        duplicate = sorted(all_members.intersection(members))
        if duplicate:
            raise ValueError(
                f"family member appears in more than one cluster: {duplicate[0]!r}"
            )
        all_members.update(members)

    statuses = artifact["status_members"]
    expected_statuses = {"accepted", "provisional", "unresolved", "abstain"}
    if not isinstance(statuses, Mapping) or set(statuses) != expected_statuses:
        raise ValueError("family artifact statuses are invalid")
    buckets: dict[str, set[str]] = {}
    for status in sorted(expected_statuses):
        members = statuses[status]
        if (
            not isinstance(members, list)
            or any(not isinstance(member, str) or not member for member in members)
            or len(set(members)) != len(members)
        ):
            raise ValueError(f"family artifact status bucket {status!r} is invalid")
        buckets[status] = set(members)
        if not buckets[status] <= target_set:
            raise ValueError(f"family artifact status bucket {status!r} escapes target universe")
    values = list(buckets.values())
    if any(left & right for index, left in enumerate(values) for right in values[index + 1:]):
        raise ValueError("family artifact status buckets overlap")
    if set().union(*values) != target_set:
        raise ValueError("family artifact statuses do not cover target_ids")
    for cluster in clusters:
        if not set(cluster["members"]) <= buckets[cluster["status"]]:
            raise ValueError("family cluster/status_members mismatch")
    if all_members != target_set - buckets["abstain"]:
        raise ValueError("family clusters do not match non-abstain status members")
    if set(artifact["abstain_reasons"]) != buckets["abstain"]:
        raise ValueError("family abstain reasons do not match status_members")
    if set(incomplete_ids) != buckets["abstain"]:
        raise ValueError("family incomplete_ids do not match abstain status")


def _common_identity(
    family_artifact: Mapping[str, Any], labels_artifact: Mapping[str, Any]
) -> None:
    for key in ("case", "build", "profile"):
        if family_artifact.get(key) != labels_artifact.get(key):
            raise ValueError(
                f"family and Oxidizer labels disagree on {key}: "
                f"{family_artifact.get(key)!r} != {labels_artifact.get(key)!r}"
            )
    family_provenance = _provenance(family_artifact, where="family artifact")
    label_provenance = _provenance(labels_artifact, where="Oxidizer labels")
    if family_provenance["stripped_sha256"] != labels_artifact.get("stripped_sha256"):
        raise ValueError("family/Oxidizer labels stripped hash mismatch")
    if label_provenance["stripped_sha256"] != labels_artifact.get("stripped_sha256"):
        raise ValueError("Oxidizer labels stripped hash does not match provenance")
    # BuildProvenance fields are repeated in both artifacts.  Additional F6
    # provenance fields are not present in the Oxidizer artifact, so compare
    # only fields both sides actually declare.
    for key in ("build_id", "source_sha256", "non_stripped_sha256"):
        if key in family_provenance and key in label_provenance:
            if family_provenance[key] != label_provenance[key]:
                raise ValueError(f"family/Oxidizer labels provenance mismatch on {key}")
    raw_graph = family_provenance.get("raw_graph_sha256")
    if raw_graph is not None and labels_artifact.get("raw_graph_sha256") != raw_graph:
        raise ValueError("family/Oxidizer labels raw graph hash mismatch")
    if "raw_graph_sha256" in labels_artifact:
        _sha256(labels_artifact["raw_graph_sha256"], where="Oxidizer labels.raw_graph_sha256")


def _selected_partition(
    family_artifact: Mapping[str, Any],
    rescue_artifact: Mapping[str, Any] | None,
    *,
    family_artifact_sha256: str,
) -> tuple[str, list[dict[str, Any]]]:
    clusters = family_artifact["clusters"]
    accepted = [
        {
            "id": item["id"],
            "members": sorted(item["members"]),
            "origin": "strict",
        }
        for item in clusters
        if item["status"] == "accepted"
    ]
    if rescue_artifact is None:
        return "strict", sorted(accepted, key=lambda item: (tuple(item["members"]), item["id"]))

    if not isinstance(rescue_artifact, Mapping):
        raise ValueError("rescue artifact must be an object")
    expected_fields = {
        "artifact", "schema_version", "rescue_rule_version", "case", "build",
        "profile", "scope", "ground_truth", "provenance", "verified_provenance",
        "budget", "summary", "strict_partition", "final_partition", "components",
    }
    if set(rescue_artifact) != expected_fields:
        raise ValueError("unsupported v1 family rescue artifact schema")
    if rescue_artifact.get("artifact") != "v1-family-rescue":
        raise ValueError("expected a v1-family-rescue artifact")
    if rescue_artifact.get("schema_version") != 1:
        raise ValueError("unsupported v1 family rescue artifact")
    if rescue_artifact.get("rescue_rule_version") != RESCUE_RULE_VERSION:
        raise ValueError("unsupported v1 family rescue rule version")
    _metadata(rescue_artifact, where="rescue artifact")
    for key in ("case", "build", "profile", "scope"):
        if rescue_artifact.get(key) != family_artifact.get(key):
            raise ValueError(f"family and rescue artifacts disagree on {key}")
    rescue_provenance = rescue_artifact.get("provenance")
    if not isinstance(rescue_provenance, Mapping) or set(rescue_provenance) != {
        "family_artifact_sha256", "candidate_artifact_sha256",
        "body_evidence_sha256", "raw_graph_sha256",
    }:
        raise ValueError("rescue artifact provenance must be an object")
    for key, digest in rescue_provenance.items():
        _sha256(digest, where=f"rescue artifact provenance.{key}")
    recorded = rescue_provenance.get("family_artifact_sha256")
    if recorded != family_artifact_sha256:
        raise ValueError(
            "rescue artifact was built from family artifact "
            f"{recorded}, not {family_artifact_sha256}"
        )
    declared_strict = rescue_artifact.get("strict_partition")
    if not isinstance(declared_strict, list):
        raise ValueError("rescue artifact strict_partition must be a list")
    strict_ids: set[str] = set()
    strict_members: set[str] = set()
    for index, item in enumerate(declared_strict):
        if not isinstance(item, Mapping):
            raise ValueError(f"rescue artifact strict_partition[{index}] is invalid")
        if set(item) != {"id", "members"}:
            raise ValueError(f"rescue artifact strict_partition[{index}] has invalid fields")
        identifier = item.get("id")
        members = item.get("members")
        if not isinstance(identifier, str) or not identifier or identifier in strict_ids:
            raise ValueError(f"rescue artifact strict_partition[{index}].id is invalid")
        if (
            not isinstance(members, list)
            or not members
            or any(not isinstance(member, str) or not member for member in members)
            or len(set(members)) != len(members)
            or strict_members.intersection(members)
        ):
            raise ValueError(f"rescue artifact strict_partition[{index}].members are invalid")
        strict_ids.add(identifier)
        strict_members.update(members)
    family_provenance = family_artifact["provenance"]
    verified = rescue_artifact["verified_provenance"]
    if not isinstance(verified, Mapping) or set(verified) != set(SHARED_PROVENANCE) | {"target_count"}:
        raise ValueError("rescue artifact verified_provenance has an invalid field set")
    for key in SHARED_PROVENANCE:
        if verified[key] != family_provenance.get(key):
            raise ValueError(f"family/rescue provenance mismatch on {key}")
    if verified["target_count"] != len(family_artifact["universe"]["target_ids"]):
        raise ValueError("family/rescue target_count mismatch")
    for key in ("body_evidence_sha256", "raw_graph_sha256"):
        if rescue_provenance[key] != verified[key]:
            raise ValueError(f"family/rescue provenance mismatch on {key}")
    if rescue_artifact["ground_truth"] != {"used_for": "not used"}:
        raise ValueError("rescue artifact ground_truth policy is invalid")
    if not isinstance(rescue_artifact["budget"], Mapping):
        raise ValueError("rescue artifact budget must be an object")
    if not isinstance(rescue_artifact["summary"], Mapping):
        raise ValueError("rescue artifact summary must be an object")
    if not isinstance(rescue_artifact["components"], list):
        raise ValueError("rescue artifact components must be a list")

    # rescued_clusters performs the strict-partition, duplicate, missing and
    # added-member checks required by F7.  Keep the IDs from final_partition
    # for auditability while taking membership from its validated result.
    validated = rescued_clusters(
        family_artifact,
        rescue_artifact,
        family_artifact_sha256=family_artifact_sha256,
    )
    final = rescue_artifact.get("final_partition")
    if not isinstance(final, list) or len(final) != len(validated):
        raise ValueError("rescue artifact final_partition is invalid")
    rows: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, (item, members) in enumerate(zip(final, validated)):
        if not isinstance(item, Mapping):
            raise ValueError(f"rescue artifact final_partition[{index}] is invalid")
        if set(item) != {"id", "members", "origin"}:
            raise ValueError(f"rescue artifact final_partition[{index}] has invalid fields")
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError(f"rescue artifact final_partition[{index}].id is invalid")
        if identifier in ids:
            raise ValueError(f"duplicate rescue family id: {identifier!r}")
        ids.add(identifier)
        declared = item.get("members")
        if not isinstance(declared, list) or sorted(declared) != members:
            raise ValueError(f"rescue artifact final_partition[{index}] membership drifted")
        origin = item.get("origin", "rescued")
        if origin not in {"strict", "rescued"}:
            raise ValueError(f"rescue artifact final_partition[{index}].origin is invalid")
        rows.append({"id": identifier, "members": members, "origin": origin})
    return "rescue", sorted(rows, key=lambda item: (tuple(item["members"]), item["id"]))


def _seed_reference(seed: Mapping[str, Any]) -> dict[str, Any]:
    """Copy label evidence without carrying the demangled symbol name."""
    return {
        "member": seed["member"],
        "address": seed["address"],
        "mapped_address": seed["mapped_address"],
        "canonical_origin": seed["canonical_origin"],
        "owner": seed["owner"],
        "evidence": "direct-flirt",
    }


def build_propagation_artifact(
    family_artifact: Mapping[str, Any],
    labels_artifact: Mapping[str, Any],
    rescue_artifact: Mapping[str, Any] | None = None,
    *,
    id_bias: int = DEFAULT_ID_BIAS,
    family_artifact_sha256: str,
    oxidizer_labels_sha256: str,
    rescue_artifact_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate raw artifacts, sanitize labels, then run GT-free propagation."""
    _validate_family_artifact(family_artifact)
    if not isinstance(id_bias, int) or isinstance(id_bias, bool) or id_bias < 0:
        raise ValueError("id_bias must be a non-negative integer")
    try:
        labels = validate_label_artifact(labels_artifact)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid Oxidizer labels: {exc}") from exc
    _common_identity(family_artifact, labels)
    family_provenance = family_artifact["provenance"]
    if family_provenance.get("id_bias") is not None and family_provenance["id_bias"] != id_bias:
        raise ValueError("family artifact id_bias does not match propagation id_bias")
    direct_matches = [
        {
            key: match[key]
            for key in ("address", "mapped_address", "canonical_origin", "owner")
        }
        for match in labels["matches"]
    ]
    return _build_propagation_core(
        family_artifact,
        direct_matches,
        rescue_artifact,
        id_bias=id_bias,
        family_artifact_sha256=family_artifact_sha256,
        oxidizer_labels_sha256=oxidizer_labels_sha256,
        rescue_artifact_sha256=rescue_artifact_sha256,
    )


def _build_propagation_core(
    family_artifact: Mapping[str, Any],
    direct_matches: list[dict[str, Any]],
    rescue_artifact: Mapping[str, Any] | None,
    *,
    id_bias: int,
    family_artifact_sha256: str,
    oxidizer_labels_sha256: str,
    rescue_artifact_sha256: str | None,
) -> dict[str, Any]:
    """Propagate sanitized labels; raw symbol names cannot cross this boundary."""
    family_provenance = family_artifact["provenance"]

    family_hash = _sha256(family_artifact_sha256, where="family_artifact_sha256")
    labels_hash = _sha256(oxidizer_labels_sha256, where="oxidizer_labels_sha256")
    if rescue_artifact is None:
        if rescue_artifact_sha256 is not None:
            raise ValueError("rescue_artifact_sha256 requires a rescue artifact")
        rescue_hash = None
    else:
        rescue_hash = _sha256(
            rescue_artifact_sha256, where="rescue_artifact_sha256"
        )
    method, partition = _selected_partition(
        family_artifact,
        rescue_artifact,
        family_artifact_sha256=family_hash,
    )
    target_ids = sorted(family_artifact["universe"]["target_ids"])
    target_set = set(target_ids)

    direct_labels: list[dict[str, Any]] = []
    direct_by_member: dict[str, dict[str, Any]] = {}
    for match in direct_matches:
        address = int(match["address"], 0)
        if address < 0:
            raise ValueError(f"direct seed address must be non-negative: {match['address']!r}")
        member = function_id(address, id_bias=id_bias)
        if member in direct_by_member:
            raise ValueError(f"duplicate direct seed member: {member!r}")
        item = {
            "member": member,
            "address": match["address"],
            "mapped_address": match["mapped_address"],
            "canonical_origin": match["canonical_origin"],
            "owner": match["owner"],
            "evidence": "direct-flirt",
            "in_universe": member in target_set,
        }
        direct_by_member[member] = item
        direct_labels.append(item)
    direct_labels.sort(key=lambda item: (item["member"], item["address"]))

    propagated_labels: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    family_rows: list[dict[str, Any]] = []
    artifact_provenance = {
        "family_artifact_sha256": family_hash,
        "rescue_artifact_sha256": rescue_hash,
        "oxidizer_labels_sha256": labels_hash,
        "stripped_sha256": family_provenance["stripped_sha256"],
        "id_bias": id_bias,
    }
    selected_members = {
        member for family in partition for member in family["members"]
    }
    for family in partition:
        members = sorted(family["members"])
        seeds = [direct_by_member[member] for member in members if member in direct_by_member]
        seed_members = sorted(seed["member"] for seed in seeds)
        signatures = {(seed["canonical_origin"], seed["owner"]) for seed in seeds}
        family_row: dict[str, Any] = {
            "id": family["id"],
            "members": members,
            "origin": family.get("origin", "strict"),
            "direct_seed_members": seed_members,
            "propagated_members": [],
        }
        if not seeds:
            family_row["status"] = "no-seed"
            family_rows.append(family_row)
            continue
        if len(signatures) != 1:
            family_row["status"] = "conflict"
            family_row["seed_labels"] = [_seed_reference(seed) for seed in sorted(seeds, key=lambda item: item["member"])]
            conflicts.append({
                "family": family["id"],
                "members": members,
                "seed_members": seed_members,
                "seed_labels": family_row["seed_labels"],
                "reason": "conflicting_direct_seed_labels",
                "provenance": artifact_provenance,
            })
            family_rows.append(family_row)
            continue

        canonical_origin, owner = next(iter(signatures))
        unlabeled_members = [member for member in members if member not in direct_by_member]
        family_row.update({
            "status": "eligible" if unlabeled_members else "fully-labeled",
            "canonical_origin": canonical_origin,
            "owner": owner,
            "seed_labels": [_seed_reference(seed) for seed in sorted(seeds, key=lambda item: item["member"])],
        })
        for member in unlabeled_members:
            item = {
                "member": member,
                "canonical_origin": canonical_origin,
                "owner": owner,
                "family": family["id"],
                "seed_members": seed_members,
                "provenance": artifact_provenance,
            }
            propagated_labels.append(item)
            family_row["propagated_members"].append(member)
        family_rows.append(family_row)

    propagated_labels.sort(key=lambda item: (item["member"], item["family"]))
    conflicts.sort(key=lambda item: (tuple(item["members"]), item["family"]))
    family_rows.sort(key=lambda item: (tuple(item["members"]), item["id"]))
    eligible_count = sum(item["status"] == "eligible" for item in family_rows)
    artifact = {
        "schema_version": PROPAGATION_SCHEMA_VERSION,
        "artifact": PROPAGATION_ARTIFACT,
        "case": family_artifact["case"],
        "build": family_artifact["build"],
        "profile": family_artifact["profile"],
        "scope": family_artifact["scope"],
        "method": method,
        "provenance": artifact_provenance,
        "opportunity": {
            "target_member_count": len(target_ids),
            "family_count": len(family_rows),
            "eligible_family_count": eligible_count,
            "conflict_family_count": len(conflicts),
            "direct_seed_count": len(direct_labels),
            "direct_seed_in_universe_count": sum(item["in_universe"] for item in direct_labels),
            "direct_seed_outside_universe_count": sum(not item["in_universe"] for item in direct_labels),
            "direct_seed_in_selected_partition_count": sum(
                item["member"] in selected_members for item in direct_labels
            ),
            "direct_seed_outside_selected_partition_count": sum(
                item["member"] not in selected_members for item in direct_labels
            ),
            "propagated_member_count": len(propagated_labels),
        },
        "direct_labels": direct_labels,
        "propagated_labels": propagated_labels,
        "families": family_rows,
        "conflicts": conflicts,
    }
    validate_propagation_artifact(artifact)
    return artifact


def validate_propagation_artifact(data: object) -> dict[str, Any]:
    """Validate output invariants before an artifact is written or scored."""
    if not isinstance(data, Mapping):
        raise ValueError("family label propagation artifact must be an object")
    expected_fields = {
        "schema_version", "artifact", "case", "build", "profile", "scope",
        "method", "provenance", "opportunity", "direct_labels",
        "propagated_labels", "families", "conflicts",
    }
    if set(data) != expected_fields:
        raise ValueError("family label propagation artifact has an invalid field set")
    if data["schema_version"] != PROPAGATION_SCHEMA_VERSION or data["artifact"] != PROPAGATION_ARTIFACT:
        raise ValueError("unsupported family label propagation artifact")
    _metadata(data, where="family label propagation artifact")
    if data["method"] not in {"strict", "rescue"}:
        raise ValueError("family label propagation method is invalid")
    provenance = data["provenance"]
    if not isinstance(provenance, Mapping) or set(provenance) != {
        "family_artifact_sha256", "rescue_artifact_sha256",
        "oxidizer_labels_sha256", "stripped_sha256", "id_bias",
    }:
        raise ValueError("family label propagation provenance has an invalid field set")
    for key in ("family_artifact_sha256", "oxidizer_labels_sha256", "stripped_sha256"):
        _sha256(provenance.get(key), where=f"propagation provenance.{key}")
    rescue_hash = provenance.get("rescue_artifact_sha256")
    if data["method"] == "strict" and rescue_hash is not None:
        raise ValueError("strict propagation must not record a rescue hash")
    if data["method"] == "rescue" and rescue_hash is None:
        raise ValueError("rescue propagation must record a rescue hash")
    if rescue_hash is not None:
        _sha256(rescue_hash, where="propagation provenance.rescue_artifact_sha256")
    id_bias = provenance.get("id_bias")
    if not isinstance(id_bias, int) or isinstance(id_bias, bool) or id_bias < 0:
        raise ValueError("propagation provenance.id_bias is invalid")

    direct = data["direct_labels"]
    propagated = data["propagated_labels"]
    if not isinstance(direct, list) or not isinstance(propagated, list):
        raise ValueError("propagation labels must be lists")
    if direct != sorted(direct, key=lambda item: (item.get("member", ""), item.get("address", "")) if isinstance(item, Mapping) else ("", "")):
        raise ValueError("propagation direct_labels ordering is invalid")
    direct_members: set[str] = set()
    direct_by_member: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(direct):
        if not isinstance(item, Mapping):
            raise ValueError(f"propagation direct_labels[{index}] is invalid")
        if set(item) != {
            "member", "address", "mapped_address", "canonical_origin", "owner",
            "evidence", "in_universe",
        }:
            raise ValueError(f"propagation direct_labels[{index}] has invalid fields")
        member = item["member"]
        if not isinstance(member, str) or not member or member in direct_members:
            raise ValueError(f"duplicate or invalid direct member: {member!r}")
        if any(not isinstance(item[key], str) or not item[key] for key in (
            "address", "mapped_address", "canonical_origin", "owner",
        )):
            raise ValueError(f"propagation direct_labels[{index}] has invalid values")
        if item["evidence"] != "direct-flirt" or not isinstance(item["in_universe"], bool):
            raise ValueError(f"propagation direct_labels[{index}] policy is invalid")
        direct_members.add(member)
        direct_by_member[member] = item

    if propagated != sorted(propagated, key=lambda item: (item.get("member", ""), item.get("family", "")) if isinstance(item, Mapping) else ("", "")):
        raise ValueError("propagation propagated_labels ordering is invalid")
    propagated_members: set[str] = set()
    propagated_by_member: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(propagated):
        if not isinstance(item, Mapping):
            raise ValueError(f"propagation propagated_labels[{index}] is invalid")
        if set(item) != {
            "member", "canonical_origin", "owner", "family", "seed_members", "provenance",
        }:
            raise ValueError(f"propagation propagated_labels[{index}] has invalid fields")
        member = item["member"]
        if not isinstance(member, str) or not member or member in propagated_members:
            raise ValueError(f"duplicate or invalid propagated member: {member!r}")
        if member in direct_members:
            raise ValueError(f"direct member is duplicated as propagated: {member!r}")
        seeds = item["seed_members"]
        if (
            not isinstance(seeds, list)
            or not seeds
            or any(not isinstance(seed, str) or seed not in direct_members for seed in seeds)
            or len(set(seeds)) != len(seeds)
            or seeds != sorted(seeds)
        ):
            raise ValueError(f"propagation propagated_labels[{index}].seed_members is invalid")
        if item["provenance"] != provenance:
            raise ValueError(f"propagated label provenance mismatch for {member!r}")
        propagated_members.add(member)
        propagated_by_member[member] = item

    families = data["families"]
    if not isinstance(families, list):
        raise ValueError("propagation families must be a list")
    if families != sorted(families, key=lambda item: (tuple(item.get("members", [])), item.get("id", "")) if isinstance(item, Mapping) else ((), "")):
        raise ValueError("propagation family ordering is invalid")
    family_ids: set[str] = set()
    selected_members: set[str] = set()
    expected_conflicts: list[dict[str, Any]] = []
    expected_propagated_members: set[str] = set()
    eligible_count = 0
    for index, family in enumerate(families):
        where = f"propagation families[{index}]"
        if not isinstance(family, Mapping):
            raise ValueError(f"{where} must be an object")
        identifier = family.get("id")
        members = family.get("members")
        status = family.get("status")
        base_fields = {
            "id", "members", "origin", "status", "direct_seed_members", "propagated_members",
        }
        expected_family_fields = (
            base_fields | {"seed_labels"}
            if status == "conflict"
            else base_fields | {"canonical_origin", "owner", "seed_labels"}
            if status in {"eligible", "fully-labeled"}
            else base_fields
        )
        if set(family) != expected_family_fields:
            raise ValueError(f"{where} has an invalid field set")
        if not isinstance(identifier, str) or not identifier or identifier in family_ids:
            raise ValueError(f"{where}.id is invalid or duplicated")
        if (
            not isinstance(members, list) or not members or members != sorted(members)
            or any(not isinstance(member, str) or not member for member in members)
            or len(set(members)) != len(members)
        ):
            raise ValueError(f"{where}.members are invalid")
        duplicate = sorted(selected_members.intersection(members))
        if duplicate:
            raise ValueError(f"propagation family members overlap: {duplicate[0]!r}")
        if family.get("origin") not in {"strict", "rescued"}:
            raise ValueError(f"{where}.origin is invalid")
        if status not in {"eligible", "fully-labeled", "conflict", "no-seed"}:
            raise ValueError(f"{where}.status is invalid")
        seed_members = sorted(set(members) & direct_members)
        if family["direct_seed_members"] != seed_members:
            raise ValueError(f"{where}.direct_seed_members is inconsistent")
        seeds = [direct_by_member[member] for member in seed_members]
        signatures = {(seed["canonical_origin"], seed["owner"]) for seed in seeds}
        unlabeled = [member for member in members if member not in direct_members]
        expected_status = (
            "no-seed" if not seeds else
            "conflict" if len(signatures) != 1 else
            "eligible" if unlabeled else
            "fully-labeled"
        )
        if status != expected_status:
            raise ValueError(f"{where}.status is inconsistent")
        seed_labels = [_seed_reference(seed) for seed in seeds]
        if status != "no-seed" and family["seed_labels"] != seed_labels:
            raise ValueError(f"{where}.seed_labels is inconsistent")
        expected_family_propagated = unlabeled if status == "eligible" else []
        if family["propagated_members"] != expected_family_propagated:
            raise ValueError(f"{where}.propagated_members is inconsistent")
        if status == "eligible":
            eligible_count += 1
            canonical_origin, owner = next(iter(signatures))
            if family["canonical_origin"] != canonical_origin or family["owner"] != owner:
                raise ValueError(f"{where} label is inconsistent")
            for member in unlabeled:
                item = propagated_by_member.get(member)
                if item is None or (
                    item["family"] != identifier
                    or item["seed_members"] != seed_members
                    or item["canonical_origin"] != canonical_origin
                    or item["owner"] != owner
                ):
                    raise ValueError(f"propagated label is inconsistent for {member!r}")
            expected_propagated_members.update(unlabeled)
        elif status == "fully-labeled":
            canonical_origin, owner = next(iter(signatures))
            if family["canonical_origin"] != canonical_origin or family["owner"] != owner:
                raise ValueError(f"{where} label is inconsistent")
        elif status == "conflict":
            expected_conflicts.append({
                "family": identifier,
                "members": members,
                "seed_members": seed_members,
                "seed_labels": seed_labels,
                "reason": "conflicting_direct_seed_labels",
                "provenance": provenance,
            })
        family_ids.add(identifier)
        selected_members.update(members)

    if propagated_members != expected_propagated_members:
        raise ValueError("propagated labels do not match eligible family members")
    if any(not direct_by_member[member]["in_universe"] for member in direct_members & selected_members):
        raise ValueError("selected-partition direct seed is outside the universe")

    conflicts = data["conflicts"]
    expected_conflicts.sort(key=lambda item: (tuple(item["members"]), item["family"]))
    if not isinstance(conflicts, list) or conflicts != expected_conflicts:
        raise ValueError("propagation conflicts are inconsistent")
    if conflicts != sorted(conflicts, key=lambda item: (tuple(item.get("members", [])), item.get("family", ""))):
        raise ValueError("propagation conflict ordering is invalid")
    for index, conflict in enumerate(conflicts):
        if set(conflict) != {
            "family", "members", "seed_members", "seed_labels", "reason", "provenance",
        }:
            raise ValueError(f"propagation conflicts[{index}] has invalid fields")

    opportunity = data["opportunity"]
    expected_opportunity_fields = {
        "target_member_count", "family_count", "eligible_family_count",
        "conflict_family_count", "direct_seed_count",
        "direct_seed_in_universe_count", "direct_seed_outside_universe_count",
        "direct_seed_in_selected_partition_count",
        "direct_seed_outside_selected_partition_count", "propagated_member_count",
    }
    if not isinstance(opportunity, Mapping) or set(opportunity) != expected_opportunity_fields:
        raise ValueError("propagation opportunity has an invalid field set")
    expected_counts = {
        "family_count": len(families),
        "eligible_family_count": eligible_count,
        "conflict_family_count": len(conflicts),
        "direct_seed_count": len(direct),
        "direct_seed_in_universe_count": sum(item["in_universe"] for item in direct),
        "direct_seed_outside_universe_count": sum(not item["in_universe"] for item in direct),
        "direct_seed_in_selected_partition_count": len(direct_members & selected_members),
        "direct_seed_outside_selected_partition_count": len(direct_members - selected_members),
        "propagated_member_count": len(propagated),
    }
    if any(opportunity[key] != value for key, value in expected_counts.items()):
        raise ValueError("propagation opportunity counts are inconsistent")
    if (
        not isinstance(opportunity["target_member_count"], int)
        or isinstance(opportunity["target_member_count"], bool)
        or opportunity["target_member_count"] < len(selected_members)
    ):
        raise ValueError("propagation opportunity target_member_count is invalid")

    return dict(data)


def build_propagation_files(
    family_path: str | Path,
    labels_path: str | Path,
    rescue_path: str | Path | None = None,
    *,
    id_bias: int = DEFAULT_ID_BIAS,
) -> dict[str, Any]:
    """Load files, bind byte hashes, and build one propagation artifact."""
    family_bytes = Path(family_path).read_bytes()
    labels_bytes = Path(labels_path).read_bytes()
    rescue_bytes = Path(rescue_path).read_bytes() if rescue_path is not None else None
    family = json.loads(family_bytes)
    labels = json.loads(labels_bytes)
    rescue = json.loads(rescue_bytes) if rescue_bytes is not None else None
    return build_propagation_artifact(
        family,
        labels,
        rescue,
        id_bias=id_bias,
        family_artifact_sha256=hashlib.sha256(family_bytes).hexdigest(),
        rescue_artifact_sha256=(
            None
            if rescue_bytes is None
            else hashlib.sha256(rescue_bytes).hexdigest()
        ),
        oxidizer_labels_sha256=hashlib.sha256(labels_bytes).hexdigest(),
    )


def write_propagation_artifact(data: Mapping[str, Any], path: str | Path) -> None:
    """Validate and write a deterministic propagation JSON artifact."""
    validate_propagation_artifact(data)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_propagation_artifact(path: str | Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"cannot read family label propagation artifact {path}: {exc}"
        ) from exc
    return validate_propagation_artifact(data)


__all__ = [
    "DEFAULT_ID_BIAS",
    "PROPAGATION_ARTIFACT",
    "PROPAGATION_SCHEMA_VERSION",
    "build_propagation_artifact",
    "build_propagation_files",
    "load_propagation_artifact",
    "validate_propagation_artifact",
    "write_propagation_artifact",
]
