"""R6: build `labels.direct.json` from an Oxidizer run.

Spec 7.6 keeps Oxidizer's stages apart, because only one of them may seed
propagation:

    matches               direct-flirt, usable as a seed
    propagated_wrappers   recorded, never a seed
    cleanup_heuristics    recorded, never a seed
    unmatched_addresses   results that did not join the discovery universe

The distinction is the whole point. Oxidizer's own wrapper propagation and
cleanup heuristics are inferences about the binary; treating them as seeds
would let F10 propagate an inference from an inference and report the result as
a direct observation.

`canonical_origin` and `owner` come from `rust_symbol_parser`, which reproduces
the frozen normalizer without importing `gt_extractor` -- spec 12.4 forbids that
import in the analysis path.

Oxidizer runs in its own Python environment. CallKin-Real receives JSON and
never imports Oxidizer's angr fork.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import callkin_real
from rust_symbol_parser import normalize_all_rust_origin, rust_symbol_owner

LABEL_ARTIFACT = "callkin-real-labels-direct"
LABEL_SCHEMA_VERSION = 1
DIRECT_FLIRT = "direct-flirt"
PROPAGATED_WRAPPER = "propagated-wrapper"
CLEANUP_HEURISTIC = "cleanup-heuristic"
# The buckets, and whether a member of each may seed propagation.
SEEDABLE = {DIRECT_FLIRT: True, PROPAGATED_WRAPPER: False, CLEANUP_HEURISTIC: False}


class LabelArtifactError(ValueError):
    """The Oxidizer output cannot be read as direct labels."""


def _address(value: object, *, where: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise LabelArtifactError(f"{where} is not an address: {value!r}") from exc
    raise LabelArtifactError(f"{where} is not an address: {value!r}")


def normalize_name(name: str) -> dict[str, str]:
    """Split a demangled symbol into the identity F10 compares seeds by.

    F10 propagates only when every seed in a family agrees on
    `(canonical_origin, owner)`, so this pair is what decides agreement. An
    owner that cannot be read is `unknown` rather than absent: two seeds whose
    owner is unreadable must not be treated as agreeing by omission.
    """
    return {
        "canonical_origin": normalize_all_rust_origin(name),
        "owner": rust_symbol_owner(name) or "unknown",
    }


def build_label_artifact(
    oxidizer_output: dict[str, Any],
    *,
    binary_sha256: str,
    discovery_addresses: set[int],
    id_bias: int = callkin_real.ID_BIAS,
) -> dict[str, Any]:
    """Sort one Oxidizer run into the four buckets, joined to discovery.

    A match whose address is not a discovered function goes to
    `unmatched_addresses` rather than being dropped or being forced into the
    universe: it is a real Oxidizer result about a place CallKin-Real found no
    function, and both halves of that are worth keeping.
    """
    buckets: dict[str, list[dict[str, Any]]] = {
        "matches": [], "propagated_wrappers": [], "cleanup_heuristics": [],
    }
    unmatched: list[dict[str, Any]] = []
    key_for = {
        DIRECT_FLIRT: "matches",
        PROPAGATED_WRAPPER: "propagated_wrappers",
        CLEANUP_HEURISTIC: "cleanup_heuristics",
    }

    seen: dict[tuple[str, int], str] = {}
    for index, item in enumerate(oxidizer_output.get("matches", [])):
        where = f"oxidizer.matches[{index}]"
        if not isinstance(item, dict):
            raise LabelArtifactError(f"{where} must be an object")
        evidence = item.get("evidence", DIRECT_FLIRT)
        if evidence not in SEEDABLE:
            raise LabelArtifactError(f"{where}.evidence is {evidence!r}")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise LabelArtifactError(f"{where}.name must be a non-empty string")
        address = _address(item.get("address"), where=f"{where}.address")
        if (evidence, address) in seen:
            raise LabelArtifactError(
                f"{where} repeats address 0x{address:x} for {evidence}"
            )
        seen[(evidence, address)] = name

        mapped_address = _address(
            item.get("mapped_address", address),
            where=f"{where}.mapped_address",
        )
        record = {
            "member": callkin_real.function_id(address),
            "address": callkin_real.hex_address(address),
            "mapped_address": callkin_real.hex_address(mapped_address),
            "evidence": evidence,
            "seedable": SEEDABLE[evidence],
            **normalize_name(name),
        }
        if address in discovery_addresses:
            buckets[key_for[evidence]].append(record)
        else:
            unmatched.append({**record, "reason": "no_discovered_function"})

    for values in (*buckets.values(), unmatched):
        values.sort(key=lambda record: (record["address"], record["evidence"]))

    return {
        "schema_version": LABEL_SCHEMA_VERSION,
        "artifact": LABEL_ARTIFACT,
        "binary": {"sha256": binary_sha256},
        "id_bias": id_bias,
        "policy": {
            "seed_policy": "direct-flirt-only",
            "normalizer": "rust_symbol_parser (no gt_extractor, no catalog)",
            "note": (
                "propagated_wrappers and cleanup_heuristics are Oxidizer "
                "inferences and are recorded but never used as seeds"
            ),
        },
        **buckets,
        "unmatched_addresses": unmatched,
        "summary": {
            "direct_match_count": len(buckets["matches"]),
            "propagated_wrapper_count": len(buckets["propagated_wrappers"]),
            "cleanup_heuristic_count": len(buckets["cleanup_heuristics"]),
            "unmatched_address_count": len(unmatched),
            "seedable_count": len(buckets["matches"]),
        },
    }


def validate_label_artifact(data: object) -> dict[str, Any]:
    """Refuse anything that is not this project's direct-label artifact."""
    if not isinstance(data, dict):
        raise LabelArtifactError("label artifact must be an object")
    required = {
        "schema_version", "artifact", "binary", "id_bias", "policy",
        "matches", "propagated_wrappers", "cleanup_heuristics",
        "unmatched_addresses", "summary",
    }
    if set(data) != required:
        raise LabelArtifactError(
            f"label artifact field set is wrong: {sorted(set(data) ^ required)}"
        )
    if data["schema_version"] != LABEL_SCHEMA_VERSION:
        raise LabelArtifactError("unsupported label artifact schema")
    if data["artifact"] != LABEL_ARTIFACT:
        raise LabelArtifactError(f"not a {LABEL_ARTIFACT} artifact")
    if data["policy"]["seed_policy"] != "direct-flirt-only":
        raise LabelArtifactError("label artifact seed policy is not direct-flirt-only")
    seen_evidence_addresses: set[tuple[str, int]] = set()
    for key, evidence in (
        ("matches", DIRECT_FLIRT),
        ("propagated_wrappers", PROPAGATED_WRAPPER),
        ("cleanup_heuristics", CLEANUP_HEURISTIC),
    ):
        if not isinstance(data[key], list):
            raise LabelArtifactError(f"{key} must be a list")
        for record in data[key]:
            if not isinstance(record, dict):
                raise LabelArtifactError(f"{key} records must be objects")
            if record["evidence"] != evidence:
                raise LabelArtifactError(f"{key} holds a {record['evidence']} record")
            if record["seedable"] is not SEEDABLE[evidence]:
                raise LabelArtifactError(f"{key} record has the wrong seedable flag")
            address = _address(record["address"], where=f"{key}.address")
            marker = (evidence, address)
            if marker in seen_evidence_addresses:
                raise LabelArtifactError(
                    f"duplicate label evidence at 0x{address:x}: {evidence}"
                )
            seen_evidence_addresses.add(marker)

    unmatched = data["unmatched_addresses"]
    if not isinstance(unmatched, list):
        raise LabelArtifactError("unmatched_addresses must be a list")
    expected_unmatched_fields = {
        "member", "address", "mapped_address", "evidence", "seedable",
        "canonical_origin", "owner", "reason",
    }
    for index, record in enumerate(unmatched):
        where = f"unmatched_addresses[{index}]"
        if not isinstance(record, dict) or set(record) != expected_unmatched_fields:
            raise LabelArtifactError(f"{where} has invalid fields")
        evidence = record["evidence"]
        if evidence not in SEEDABLE:
            raise LabelArtifactError(f"{where}.evidence is {evidence!r}")
        if record["seedable"] is not SEEDABLE[evidence]:
            raise LabelArtifactError(f"{where} has the wrong seedable flag")
        if record["reason"] != "no_discovered_function":
            raise LabelArtifactError(f"{where}.reason is invalid")
        if any(
            not isinstance(record[key], str) or not record[key]
            for key in ("member", "address", "mapped_address", "canonical_origin", "owner")
        ):
            raise LabelArtifactError(f"{where} has invalid values")
        address = _address(record["address"], where=f"{where}.address")
        _address(record["mapped_address"], where=f"{where}.mapped_address")
        marker = (evidence, address)
        if marker in seen_evidence_addresses:
            raise LabelArtifactError(
                f"duplicate label evidence at 0x{address:x}: {evidence}"
            )
        seen_evidence_addresses.add(marker)
    return data


def direct_seeds(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    """The seeds F10 may use: every direct-flirt observation.

    Joined matches and direct results that did not join the discovery universe
    are both direct evidence. Wrapper and cleanup inferences remain excluded,
    and the artifact is revalidated first so a schema-inconsistent edit cannot
    smuggle one in. Raw-file hashes bind valid artifacts at the consumer edge.
    """
    validate_label_artifact(artifact)
    records = [
        *artifact["matches"],
        *(
            record
            for record in artifact["unmatched_addresses"]
            if record.get("evidence") == DIRECT_FLIRT
        ),
    ]
    return [
        {
            "address": record["address"],
            "mapped_address": record["mapped_address"],
            "canonical_origin": record["canonical_origin"],
            "owner": record["owner"],
        }
        for record in records
    ]


def write_json(path: Path, value: Any) -> str:
    import hashlib

    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()
