"""Attach uncertain singleton fragments to strict F6 cores, provisionally.

This is deliberately a post-processing experiment.  It never changes the
strict family artifact and its output is not accepted by label propagation.
One consensus3 candidate MATCH supplies positive evidence; UNKNOWN and
ABSTAIN do not veto it, while REJECT does.  A member compatible with more than
one strict core stays ambiguous.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping


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
    return cores, sorted(buckets["provisional"]), decisions


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
            "input_provisional_member_count": len(provisional),
            "attached_member_count": len(attachments),
            "ambiguous_member_count": len(ambiguous),
            "vetoed_hypothesis_count": len(vetoed),
            "unassigned_member_count": len(unassigned),
        },
    }


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
