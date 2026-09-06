"""Score a finished CallKin-Real F10 prediction against an all-Rust catalog.

This module is evaluation-only.  It deliberately has no dependency on the
legacy V0 scorer or on the analysis pipeline: callers hand it three immutable
artifacts (or paths to their JSON files), and it returns a new report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from flirt_labels import direct_seeds, validate_label_artifact

_FROZEN = Path(__file__).resolve().parent / "frozen_v1"
if str(_FROZEN) not in sys.path:
    sys.path.insert(0, str(_FROZEN))
from family_label_propagation import validate_propagation_artifact  # noqa: E402


SCHEMA_VERSION = 1
EVALUATION_ARTIFACT = "v1-family-label-propagation-evaluation"
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CATALOG_FIELDS = {
    "schema_version", "case", "build", "profile", "scope", "id_bias",
    "root_namespace", "provenance", "source", "origins", "symbols",
    "owners", "cross_origin_aliases",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, *, where: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{where} must be a SHA-256 digest")
    return value


def _resolve_digest_aliases(
    *values: str | None, where: str
) -> str | None:
    supplied = [value for value in values if value is not None]
    if not supplied:
        return None
    selected = supplied[0]
    if any(value != selected for value in supplied[1:]):
        raise ValueError(f"{where} has conflicting SHA-256 digest aliases")
    return selected


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _read_source(
    value: Mapping[str, Any] | str | Path | bytes,
    *,
    where: str,
    declared_sha256: str | None,
) -> tuple[dict[str, Any], str]:
    """Load JSON and bind raw bytes or canonical mapping content.

    Paths and byte strings are hashed exactly as supplied.  An in-memory
    mapping has no source bytes, so its digest is the deterministic canonical
    JSON encoding; a caller-provided digest must match that encoding.
    """
    if isinstance(value, (str, Path)):
        path = Path(value)
        try:
            raw = path.read_bytes()
            data = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read {where} {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{where} must contain a JSON object")
        digest = _sha256(raw)
        if declared_sha256 is not None and _digest(
            declared_sha256, where=f"{where}_sha256"
        ) != digest:
            raise ValueError(f"{where} raw SHA-256 mismatch")
        return data, digest
    if isinstance(value, bytes):
        try:
            data = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{where} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{where} must contain a JSON object")
        digest = _sha256(value)
        if declared_sha256 is not None and _digest(
            declared_sha256, where=f"{where}_sha256"
        ) != digest:
            raise ValueError(f"{where} raw SHA-256 mismatch")
        return data, digest
    if isinstance(value, Mapping):
        data = dict(value)
        try:
            digest = _sha256(_json_bytes(data))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{where} cannot be canonically encoded: {exc}") from exc
        if declared_sha256 is not None and _digest(
            declared_sha256, where=f"{where}_sha256"
        ) != digest:
            raise ValueError(f"{where} canonical SHA-256 mismatch")
        return data, digest
    raise ValueError(f"{where} must be a JSON path, bytes, or object")


def _int_address(value: object, *, where: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{where} is not an address: {value!r}")
    try:
        address = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{where} is not an address: {value!r}") from exc
    if address < 0:
        raise ValueError(f"{where} must be non-negative")
    return address


def _decode_member(member: object, *, id_bias: int, where: str) -> int:
    if not isinstance(member, str) or not re.fullmatch(r"FUN_[0-9A-Fa-f]+", member):
        raise ValueError(f"{where} is not a function ID: {member!r}")
    address = int(member[4:], 16) - id_bias
    if address < 0:
        raise ValueError(f"{where} decodes to a negative address")
    return address


def _encode_member(address: int, *, id_bias: int) -> str:
    """Return the canonical FUN member spelling for one decoded address."""
    return f"FUN_{address + id_bias:08x}"


def _validate_catalog(catalog: Mapping[str, Any]) -> dict[str, Any]:
    if set(catalog) - {"note"} != _CATALOG_FIELDS:
        raise ValueError("all-Rust catalog has an invalid field set")
    if catalog.get("schema_version") != 1 or catalog.get("scope") != "all-rust":
        raise ValueError("unsupported all-Rust catalog")
    for key in ("case", "build", "profile", "root_namespace", "source"):
        if not isinstance(catalog.get(key), str) or not catalog[key]:
            raise ValueError(f"all-Rust catalog {key} must be a non-empty string")
    bias = catalog.get("id_bias")
    if not isinstance(bias, int) or isinstance(bias, bool) or bias < 0:
        raise ValueError("all-Rust catalog id_bias must be a non-negative integer")
    provenance = catalog.get("provenance")
    if not isinstance(provenance, Mapping):
        raise ValueError("all-Rust catalog provenance must be an object")
    _digest(provenance.get("stripped_sha256"), where="catalog stripped_sha256")
    for key, value in provenance.items():
        if key.endswith("_sha256"):
            _digest(value, where=f"catalog provenance.{key}")
    origins = catalog.get("origins")
    if not isinstance(origins, list) or not origins:
        raise ValueError("all-Rust catalog origins must be a non-empty list")
    members: set[str] = set()
    origin_names: set[str] = set()
    origin_by_member: dict[str, str] = {}
    for index, group in enumerate(origins):
        if not isinstance(group, Mapping) or set(group) != {"origin", "members"}:
            raise ValueError(f"catalog origins[{index}] is invalid")
        origin = group.get("origin")
        values = group.get("members")
        if not isinstance(origin, str) or not origin or origin in origin_names:
            raise ValueError(f"catalog origins[{index}].origin is invalid")
        if (
            not isinstance(values, list) or not values
            or any(not isinstance(member, str) or not member for member in values)
            or len(set(values)) != len(values)
            or members.intersection(values)
        ):
            raise ValueError(f"catalog origins[{index}].members are invalid")
        members.update(values)
        origin_names.add(origin)
        origin_by_member.update({member: origin for member in values})
    for key in ("symbols", "owners"):
        values = catalog.get(key)
        if not isinstance(values, Mapping) or set(values) != members:
            raise ValueError(f"catalog {key} keys do not match origin members")
    for member, names in catalog["symbols"].items():
        if not isinstance(names, list) or not names or any(
            not isinstance(name, str) or not name for name in names
        ):
            raise ValueError(f"catalog symbols[{member!r}] is invalid")
    if any(not isinstance(owner, str) or not owner for owner in catalog["owners"].values()):
        raise ValueError("catalog owners must be non-empty strings")
    aliases = catalog.get("cross_origin_aliases")
    if not isinstance(aliases, list):
        raise ValueError("catalog cross_origin_aliases must be a list")
    alias_members: set[str] = set()
    for index, alias in enumerate(aliases):
        if not isinstance(alias, Mapping) or set(alias) != {"member", "origins"}:
            raise ValueError(f"catalog cross_origin_aliases[{index}] is invalid")
        member = alias.get("member")
        values = alias.get("origins")
        if (
            not isinstance(member, str)
            or not member
            or member not in members
            or member in alias_members
            or not isinstance(values, list)
            or any(not isinstance(origin, str) or not origin for origin in values)
            or len(values) < 2
            or len(set(values)) != len(values)
            or any(origin.startswith("shared-address@") for origin in values)
            or origin_by_member.get(member) != f"shared-address@{member}"
            or catalog["owners"].get(member) != "shared-address"
            or f"shared-address@{member}" in values
        ):
            raise ValueError(f"catalog cross_origin_aliases[{index}] is invalid")
        alias_members.add(member)
    synthetic_members = {
        member for member, origin in origin_by_member.items()
        if origin.startswith("shared-address@")
    }
    if synthetic_members != alias_members:
        raise ValueError("catalog synthetic shared-address origins and aliases disagree")
    return dict(catalog)


def _catalog_views(catalog: Mapping[str, Any]) -> tuple[
    dict[int, str], dict[int, str], dict[int, str], dict[str, int], set[int]
]:
    """Map decoded addresses to exact origin/owner and retain catalog IDs."""
    origins: dict[int, str] = {}
    owner_by_address: dict[int, str] = {}
    member_by_address: dict[int, str] = {}
    address_by_member: dict[str, int] = {}
    ambiguous_addresses: set[int] = set()
    alias_members = {alias["member"] for alias in catalog["cross_origin_aliases"]}
    bias = catalog["id_bias"]
    for group in catalog["origins"]:
        for member in group["members"]:
            address = _decode_member(member, id_bias=bias, where="catalog member")
            if address in origins:
                raise ValueError(f"catalog has duplicate decoded address 0x{address:x}")
            origins[address] = group["origin"]
            owner_by_address[address] = catalog["owners"][member]
            member_by_address[address] = member
            address_by_member[member] = address
            if member in alias_members:
                ambiguous_addresses.add(address)
    return origins, owner_by_address, member_by_address, address_by_member, ambiguous_addresses


def _prediction_members(
    prediction: Mapping[str, Any], key: str, *, id_bias: int
) -> dict[int, Mapping[str, Any]]:
    values = prediction.get(key)
    if not isinstance(values, list):
        raise ValueError(f"prediction {key} must be a list")
    result: dict[int, Mapping[str, Any]] = {}
    for index, item in enumerate(values):
        if not isinstance(item, Mapping) or not isinstance(item.get("member"), str):
            raise ValueError(f"prediction {key}[{index}] is invalid")
        address = _decode_member(item["member"], id_bias=id_bias, where=f"prediction {key}[{index}].member")
        if address in result:
            raise ValueError(f"prediction {key} has duplicate decoded address 0x{address:x}")
        result[address] = item
    return result


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _exact(
    item: Mapping[str, Any], address: int, origins: Mapping[int, str], owners: Mapping[int, str]
) -> bool:
    return item.get("canonical_origin") == origins[address] and item.get("owner") == owners[address]


def _upper_bound(
    catalog: Mapping[str, Any],
    direct_correct: set[int],
    direct_all: set[int],
    member_by_address: Mapping[int, str],
    ambiguous_addresses: set[int] | None = None,
) -> dict[str, Any]:
    rows = []
    ambiguous_addresses = ambiguous_addresses or set()
    for group in catalog["origins"]:
        addresses = {
            _decode_member(member, id_bias=catalog["id_bias"], where="catalog member")
            for member in group["members"]
        } - ambiguous_addresses
        known = sorted(addresses & direct_correct)
        unknown = sorted(addresses - direct_all - ambiguous_addresses)
        if not known or not unknown:
            continue
        rows.append({
            "origin": group["origin"],
            "known_direct_flirt_instances": len(known),
            "unknown_instances": len(unknown),
            "newly_propagatable_member_count": len(unknown),
            "cross_boundary_same_family_pair_count": len(known) * len(unknown),
            "known_members": [member_by_address[address] for address in known],
            "unknown_members": [member_by_address[address] for address in unknown],
        })
    return {
        "mixed_family_count": len(rows),
        "cross_boundary_member_count": sum(row["unknown_instances"] for row in rows),
        "newly_propagatable_member_count": sum(row["newly_propagatable_member_count"] for row in rows),
        "cross_boundary_same_family_pair_count": sum(
            row["cross_boundary_same_family_pair_count"] for row in rows
        ),
        "families": rows,
    }


def score_catalog_propagation(
    catalog: Mapping[str, Any] | str | Path | bytes,
    labels: Mapping[str, Any] | str | Path | bytes,
    prediction: Mapping[str, Any] | str | Path | bytes,
    *,
    catalog_sha256: str | None = None,
    labels_sha256: str | None = None,
    prediction_sha256: str | None = None,
    catalog_raw_sha256: str | None = None,
    labels_raw_sha256: str | None = None,
    prediction_raw_sha256: str | None = None,
    all_rust_catalog_sha256: str | None = None,
    oxidizer_labels_sha256: str | None = None,
    family_label_propagation_sha256: str | None = None,
) -> dict[str, Any]:
    """Return exact origin+owner metrics without changing any input artifact."""
    catalog_sha256 = _resolve_digest_aliases(
        catalog_sha256,
        catalog_raw_sha256,
        all_rust_catalog_sha256,
        where="catalog",
    )
    labels_sha256 = _resolve_digest_aliases(
        labels_sha256,
        labels_raw_sha256,
        oxidizer_labels_sha256,
        where="labels",
    )
    prediction_sha256 = _resolve_digest_aliases(
        prediction_sha256,
        prediction_raw_sha256,
        family_label_propagation_sha256,
        where="prediction",
    )
    catalog, catalog_hash = _read_source(
        catalog, where="catalog", declared_sha256=catalog_sha256
    )
    labels, labels_hash = _read_source(
        labels, where="labels", declared_sha256=labels_sha256
    )
    prediction, prediction_hash = _read_source(
        prediction, where="prediction", declared_sha256=prediction_sha256
    )
    catalog = _validate_catalog(catalog)
    try:
        labels = validate_label_artifact(labels)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid direct-label artifact: {exc}") from exc
    try:
        prediction = validate_propagation_artifact(prediction)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid propagation artifact: {exc}") from exc

    catalog_stripped = _digest(
        catalog["provenance"].get("stripped_sha256"),
        where="catalog provenance.stripped_sha256",
    )
    binary = labels.get("binary")
    binary_sha = binary.get("sha256") if isinstance(binary, Mapping) else None
    label_stripped = _digest(
        binary_sha or labels.get("stripped_sha256"), where="labels stripped_sha256"
    )
    prediction_provenance = prediction["provenance"]
    prediction_stripped = _digest(
        prediction_provenance.get("stripped_sha256"),
        where="prediction provenance.stripped_sha256",
    )
    label_bias = labels.get("id_bias")
    if not isinstance(label_bias, int) or isinstance(label_bias, bool) or label_bias < 0:
        raise ValueError("labels id_bias must be a non-negative integer")
    prediction_bias = prediction_provenance["id_bias"]
    if label_bias != prediction_bias:
        raise ValueError("labels and prediction id_bias mismatch")
    if not (catalog_stripped == label_stripped == prediction_stripped):
        raise ValueError("catalog, labels, and prediction stripped hash mismatch")
    if prediction_provenance.get("oxidizer_labels_sha256") != labels_hash:
        raise ValueError("prediction/raw labels SHA-256 mismatch")

    origins, owners, catalog_member, _, ambiguous_addresses = _catalog_views(catalog)
    catalog_addresses = set(origins)
    evaluable_addresses = catalog_addresses - ambiguous_addresses
    direct = _prediction_members(prediction, "direct_labels", id_bias=prediction_bias)
    propagated = _prediction_members(
        prediction, "propagated_labels", id_bias=prediction_bias
    )
    duplicate_addresses = set(direct) & set(propagated)
    if duplicate_addresses:
        address = min(duplicate_addresses)
        raise ValueError(
            f"direct and propagated members share decoded address 0x{address:x}"
        )

    # The complete direct baseline is the source of truth for direct labels.
    seeds = direct_seeds(labels)
    expected: dict[int, Mapping[str, Any]] = {}
    for index, seed in enumerate(seeds):
        address = _int_address(seed["address"], where=f"direct seed {index}.address")
        if address in expected:
            raise ValueError(f"duplicate direct seed address 0x{address:x}")
        expected[address] = seed
    expected_members: dict[int, str] = {}
    for record in (
        *labels["matches"],
        *(record for record in labels["unmatched_addresses"]
          if record.get("evidence") == "direct-flirt"),
    ):
        address = _int_address(record.get("address"), where="direct label address")
        member = record.get("member")
        canonical_member = _encode_member(address, id_bias=label_bias)
        if member != canonical_member:
            raise ValueError("direct label member is not canonical for its address")
        if address in expected_members:
            raise ValueError(f"duplicate direct label address 0x{address:x}")
        expected_members[address] = member
    if set(direct) != set(expected):
        raise ValueError("prediction direct baseline differs from direct_seeds()")
    for address, item in direct.items():
        expected_item = expected[address]
        if item.get("member") != expected_members.get(address):
            raise ValueError("prediction direct baseline member differs from labels")
        if _int_address(item.get("address"), where="prediction direct address") != address:
            raise ValueError("prediction direct baseline differs from direct_seeds()")
        for key in ("address", "mapped_address", "canonical_origin", "owner"):
            if item.get(key) != expected_item.get(key):
                raise ValueError("prediction direct baseline differs from direct_seeds()")
        if item.get("evidence") != "direct-flirt":
            raise ValueError("prediction direct baseline differs from direct_seeds()")

    unknown_propagated = sorted(set(propagated) - catalog_addresses)
    if unknown_propagated:
        raise ValueError(
            f"propagated member has no catalog address: 0x{unknown_propagated[0]:x}"
        )
    direct_ambiguous = set(direct) & ambiguous_addresses
    propagated_ambiguous = set(propagated) & ambiguous_addresses
    direct_known = set(direct) & evaluable_addresses
    propagated_known = set(propagated) & evaluable_addresses
    direct_correct = {address for address in direct_known if _exact(direct[address], address, origins, owners)}
    propagated_correct = {
        address for address in propagated_known
        if _exact(propagated[address], address, origins, owners)
    }
    propagated_wrong = propagated_known - propagated_correct
    wrong_families = {
        propagated[address].get("family")
        for address in propagated_wrong
        if propagated[address].get("family") is not None
    }
    wrong_member_rows = [
        {
            "family": propagated[address].get("family"),
            "prediction_member": propagated[address]["member"],
            "catalog_member": catalog_member[address],
            "address": f"0x{address:x}",
            "predicted": {
                "canonical_origin": propagated[address].get("canonical_origin"),
                "owner": propagated[address].get("owner"),
            },
            "expected": {
                "canonical_origin": origins[address],
                "owner": owners[address],
            },
        }
        for address in sorted(propagated_wrong)
    ]
    combined = set(direct) | set(propagated)
    combined_ambiguous = combined & ambiguous_addresses
    combined_known = combined & evaluable_addresses
    combined_correct = {
        address for address in combined_known
        if _exact(direct.get(address) or propagated[address], address, origins, owners)
    }
    catalog_raw_count = len(catalog_addresses)
    catalog_ambiguous_count = len(ambiguous_addresses)
    catalog_evaluable_count = len(evaluable_addresses)
    direct_precision = _ratio(len(direct_correct), len(direct_known))
    combined_precision = _ratio(len(combined_correct), len(combined_known))
    direct_coverage = _ratio(len(direct_correct), catalog_evaluable_count)
    combined_coverage = _ratio(len(combined_correct), catalog_evaluable_count)
    metrics = {
        "catalog_member_count": catalog_raw_count,
        "catalog_raw_member_count": catalog_raw_count,
        "catalog_evaluable_member_count": catalog_evaluable_count,
        "catalog_ambiguous_member_count": catalog_ambiguous_count,
        "direct_correct_count": len(direct_correct),
        "direct_incorrect_count": len(direct_known) - len(direct_correct),
        "direct_unknown_count": len(set(direct) - catalog_addresses),
        "direct_ambiguous_count": len(direct_ambiguous),
        "propagated_correct_count": len(propagated_correct),
        "propagated_incorrect_count": len(propagated_wrong),
        "propagated_ambiguous_count": len(propagated_ambiguous),
        "combined_ambiguous_count": len(combined_ambiguous),
        "newly_correct_member_count": len(propagated_correct - direct_correct),
        "wrongly_propagated_member_count": len(propagated_wrong),
        "wrongly_propagated_family_count": len(wrong_families),
        "conflict_family_count": len(prediction.get("conflicts", [])),
        "eligible_family_count": sum(
            isinstance(item, Mapping) and item.get("status") == "eligible"
            for item in prediction.get("families", [])
        ),
        "direct_catalog_coverage": direct_coverage,
        "combined_catalog_coverage": combined_coverage,
        "direct_precision": direct_precision,
        "combined_precision": combined_precision,
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "artifact": EVALUATION_ARTIFACT,
        "case": catalog["case"],
        "build": catalog["build"],
        "profile": catalog["profile"],
        "provenance": {
            # These bind raw path/byte inputs or canonical in-memory mappings.
            "all_rust_catalog_sha256": catalog_hash,
            "oxidizer_labels_sha256": labels_hash,
            "family_label_propagation_sha256": prediction_hash,
            "propagation_stripped_sha256": catalog_stripped,
            "stripped_sha256": catalog_stripped,
            "catalog_id_bias": catalog["id_bias"],
            "labels_id_bias": label_bias,
            "prediction_id_bias": prediction_bias,
            "identity_binding": "stripped_sha256",
            "address_join": "decoded FUN_ address",
            "family_artifact_sha256": prediction_provenance["family_artifact_sha256"],
            "rescue_artifact_sha256": prediction_provenance["rescue_artifact_sha256"],
            "prediction_oxidizer_labels_sha256": prediction_provenance["oxidizer_labels_sha256"],
            "method": prediction["method"],
        },
        "direct": {
            "predicted_member_count": len(direct),
            "catalog_member_count": len(direct_known),
            "catalog_raw_member_count": catalog_raw_count,
            "catalog_evaluable_member_count": catalog_evaluable_count,
            "catalog_ambiguous_member_count": catalog_ambiguous_count,
            "evaluable_count": len(direct_known),
            "ambiguous_count": len(direct_ambiguous),
            "correct_count": len(direct_correct),
            "incorrect_count": len(direct_known) - len(direct_correct),
            "unknown_count": len(set(direct) - catalog_addresses),
            "precision": direct_precision,
            "catalog_coverage": direct_coverage,
            "correct_members": sorted(catalog_member[address] for address in direct_correct),
        },
        "propagated": {
            "predicted_member_count": len(propagated),
            "catalog_member_count": len(propagated_known),
            "catalog_raw_member_count": catalog_raw_count,
            "catalog_evaluable_member_count": catalog_evaluable_count,
            "catalog_ambiguous_member_count": catalog_ambiguous_count,
            "evaluable_count": len(propagated_known),
            "ambiguous_count": len(propagated_ambiguous),
            "correct_count": len(propagated_correct),
            "incorrect_count": len(propagated_wrong),
            "precision": _ratio(len(propagated_correct), len(propagated_known)),
            "correct_members": sorted(catalog_member[address] for address in propagated_correct),
            "wrong_family_members": sorted(catalog_member[address] for address in propagated_wrong),
            "wrong_members": wrong_member_rows,
        },
        "combined": {
            "predicted_member_count": len(combined),
            "catalog_member_count": len(combined_known),
            "catalog_raw_member_count": catalog_raw_count,
            "catalog_evaluable_member_count": catalog_evaluable_count,
            "catalog_ambiguous_member_count": catalog_ambiguous_count,
            "evaluable_count": len(combined_known),
            "ambiguous_count": len(combined_ambiguous),
            "correct_count": len(combined_correct),
            "incorrect_count": len(combined_known) - len(combined_correct),
            "precision": combined_precision,
            "catalog_coverage": combined_coverage,
            "newly_correct_member_count": len(propagated_correct - direct_correct),
        },
        "metrics": metrics,
        "gt_upper_bound": _upper_bound(
            catalog,
            direct_correct,
            set(direct),
            catalog_member,
            ambiguous_addresses,
        ),
    }
    return report


def evaluate_f10_catalog_files(
    catalog_path: str | Path,
    labels_path: str | Path,
    prediction_path: str | Path,
) -> dict[str, Any]:
    """Score three on-disk files, binding each file's raw bytes."""
    return score_catalog_propagation(catalog_path, labels_path, prediction_path)


def score_callkin_f10_catalog(
    catalog: Mapping[str, Any],
    labels: Mapping[str, Any],
    prediction: Mapping[str, Any],
    *,
    catalog_sha256: str,
    labels_sha256: str,
    prediction_sha256: str,
) -> dict[str, Any]:
    """Score mappings whose hashes bind their canonical JSON content.

    Use :func:`score_catalog_propagation` with paths or bytes when raw source
    bytes, rather than canonical mapping content, must be bound.
    """
    return score_catalog_propagation(
        catalog,
        labels,
        prediction,
        catalog_sha256=catalog_sha256,
        labels_sha256=labels_sha256,
        prediction_sha256=prediction_sha256,
    )


def write_json(path: str | Path, value: Mapping[str, Any]) -> str:
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(raw)
    return _sha256(raw)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog_pos", nargs="?", help="all-Rust catalog JSON")
    parser.add_argument("labels_pos", nargs="?", help="labels.direct.json")
    parser.add_argument("prediction_pos", nargs="?", help="strict or rescue F10 prediction JSON")
    parser.add_argument("--catalog", dest="catalog_opt", help="all-Rust catalog JSON")
    parser.add_argument("--labels", dest="labels_opt", help="labels.direct.json")
    parser.add_argument("--prediction", dest="prediction_opt", help="strict or rescue F10 prediction JSON")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        catalog = args.catalog_opt or args.catalog_pos
        labels = args.labels_opt or args.labels_pos
        prediction = args.prediction_opt or args.prediction_pos
        if not all((catalog, labels, prediction)):
            raise ValueError("catalog, labels, and prediction inputs are required")
        report = score_catalog_propagation(catalog, labels, prediction)
        if args.output:
            write_json(args.output, report)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
