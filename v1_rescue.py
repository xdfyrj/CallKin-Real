"""R5: run the frozen F7 fragment rescue over a strict F6 partition.

Ground truth is not an input, and neither is a FLIRT label. The rescue rule
reads the strict partition, the 2-view consensus queue, the bodies and the
transfers, and nothing that names an origin.

The six conditions are the frozen ones, unchanged, because `family_rescue.py`,
`family_template.py` and `slot_overlay.py` in `frozen_v1/` are byte-identical
copies:

    a verified strict partition
    a relation bridge between fragments
    a unique independent axis basis
    complete Cartesian coverage
    a bijective tuple
    internal fragment support on each axis

Two joins are needed and neither touches the frozen code. The frozen raw graph
keyed transfers by hex address while CallKin-Real's discovery keys them by
function id, so `raw_graph_view` renames the fields. And `check_inputs_agree`
cross-checks seven provenance fields, five of which name oracle artifacts; F5
fills them with their CallKin-Real counterparts, so the check runs rather than
being skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import callkin_real
from real_v1_adapter import RealV1Input, load_from_run

_FROZEN = Path(__file__).resolve().parent / "frozen_v1"
for _entry in (_FROZEN, _FROZEN / "analysis"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from family_rescue import (  # noqa: E402
    ACCEPTED,
    BUDGET_BLOCKED,
    REJECTED,
    RESCUE_RULE_VERSION,
    RescueBudget,
    accepted_fragments,
    check_inputs_agree,
    final_partition,
    rescue_families,
)
from slot_overlay import transfers_by_source  # noqa: E402

RESCUE_ARTIFACT = "v1-family-rescue"
RESCUE_SCHEMA_VERSION = 1
# Spec 10.6: the rescue queue is the two-view consensus, not the three-view one
# F6 grouped from. Rescue exists to reconsider what strict grouping split.
RESCUE_QUEUE = "consensus2"


def raw_graph_view(discovery_payload: dict[str, Any]) -> dict[str, Any]:
    """Present CallKin-Real transfers the way the frozen F7 reads them.

    The frozen raw graph put hex addresses in `source`, `callsite` and
    `target`; CallKin-Real's discovery puts function ids in `source` and
    `target` and keeps the addresses beside them. `slot_overlay` parses those
    fields with `int(..., 16)` and uses `target` as a slot value, so the
    addresses are what must be handed over -- a function id would raise on the
    first transfer.

    `status` is passed through unchanged. CallKin-Real's `unmapped` means the
    target address is known but no function was discovered there, which the
    frozen rules score as unresolved: the slot contributes nothing rather than
    contributing an address the frozen vocabulary never had. That is the
    conservative reading, and `unmapped_transfer_count` records how much
    evidence it sets aside.
    """
    transfers = []
    for transfer in discovery_payload["transfers"]:
        transfers.append({
            "source": transfer["source_address"],
            "callsite": transfer["callsite"],
            "target": transfer["target_address"],
            "status": transfer["status"],
            "kind": transfer["kind"],
            "operand_kind": transfer["operand_kind"],
            "instruction": transfer["instruction"],
            "resolver": transfer["resolver"],
            "confidence": transfer["confidence"],
            "angr_status": transfer["angr_status"],
            # Only the count is read, but addresses keep the value space of
            # every other field in this record.
            "angr_targets": [
                callkin_real.hex_address(
                    callkin_real.address_from_function_id(value)
                )
                for value in transfer["angr_targets"]
            ],
            # CallKin-Real filters nothing at this stage; the frozen reader
            # treats a missing key and a null the same way.
            "filter_reason": None,
        })
    return {"transfers": transfers}


def build_rescue_artifact(
    family_artifact: dict[str, Any],
    candidate_artifact: dict[str, Any],
    discovery_payload: dict[str, Any],
    source: RealV1Input,
    *,
    budget: RescueBudget,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    """The frozen F7 artifact, built from CallKin-Real inputs."""
    verified = check_inputs_agree(family_artifact, candidate_artifact)
    bodies = dict(source.bodies)
    raw_graph = raw_graph_view(discovery_payload)
    transfers = transfers_by_source(raw_graph)
    address_of = {
        member: callkin_real.address_from_function_id(member) for member in bodies
    }

    components, used = rescue_families(
        family_artifact, candidate_artifact, bodies, transfers, address_of,
        budget=budget,
    )
    strict = accepted_fragments(family_artifact)
    final = final_partition(family_artifact, components)
    statuses = Counter(component.status for component in components)
    reasons = Counter(
        component.reason for component in components if component.reason
    )
    unmapped = sum(
        1 for item in raw_graph["transfers"] if item["status"] == "unmapped"
    )

    return {
        "artifact": RESCUE_ARTIFACT,
        "schema_version": RESCUE_SCHEMA_VERSION,
        "rescue_rule_version": RESCUE_RULE_VERSION,
        "case": family_artifact.get("case"),
        "build": family_artifact.get("build"),
        "profile": family_artifact.get("profile"),
        "scope": family_artifact.get("scope"),
        "ground_truth": {"used_for": "not used"},
        "provenance": provenance,
        "verified_provenance": verified,
        "budget": budget.to_dict(),
        "summary": {
            "strict_accepted_fragment_count": len(strict),
            "strict_accepted_member_count": sum(len(v) for v in strict.values()),
            "component_count": len(components),
            "accepted_component_count": statuses.get(ACCEPTED, 0),
            "rejected_component_count": statuses.get(REJECTED, 0),
            "budget_blocked_component_count": statuses.get(BUDGET_BLOCKED, 0),
            "rejection_reasons": dict(sorted(reasons.items())),
            "reserved_comparisons": used["reserved_comparisons"],
            "reserved_alignment_cells": used["reserved_alignment_cells"],
            "final_family_count": len(final),
            "rescued_family_count": sum(
                1 for item in final if item["origin"] == "rescued"
            ),
            # Slot evidence the conservative status reading sets aside.
            "unmapped_transfer_count": unmapped,
            "transfer_count": len(raw_graph["transfers"]),
        },
        "strict_partition": [
            {"id": name, "members": list(members)}
            for name, members in sorted(strict.items())
        ],
        "final_partition": final,
        "components": [component.to_dict() for component in components],
    }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> str:
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return _sha256_bytes(encoded)


def discovery_payload_for(run_path: Path) -> dict[str, Any]:
    run = json.loads(run_path.read_text(encoding="utf-8"))
    path = run_path.parent / run["artifacts"]["discovery"]["path"]
    raw = path.read_bytes()
    digest = _sha256_bytes(raw)
    if digest != run["stage_sha256"]["discovery"]:
        raise ValueError("discovery on disk is not the discovery this run recorded")
    artifact = json.loads(raw.decode("utf-8"))
    if artifact.get("artifact") != "callkin-real-discovery":
        raise ValueError(f"{path.name} is not a discovery artifact")
    return artifact["payload"]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="a callkin-real run manifest (run.json)")
    parser.add_argument("--families", help="F6 strict families artifact")
    parser.add_argument(
        "--candidates",
        help=f"rescue queue; defaults to the {RESCUE_QUEUE} file beside the run",
    )
    parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument("--max-component-members", type=int, default=None)
    parser.add_argument("--max-comparisons", type=int, default=None)
    parser.add_argument("--max-alignment-cells", type=int, default=None)
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    defaults = RescueBudget()
    budget = RescueBudget(
        max_component_members=(
            args.max_component_members if args.max_component_members is not None
            else defaults.max_component_members
        ),
        max_comparisons=(
            args.max_comparisons if args.max_comparisons is not None
            else defaults.max_comparisons
        ),
        max_alignment_cells=(
            args.max_alignment_cells if args.max_alignment_cells is not None
            else defaults.max_alignment_cells
        ),
    )
    try:
        run_path = Path(args.run)
        source = load_from_run(run_path)
        family_path = (
            Path(args.families) if args.families
            else run_path.parent / f"{run_path.stem}.v1.families.strict.json"
        )
        candidate_path = (
            Path(args.candidates) if args.candidates
            else run_path.parent
            / f"{run_path.stem}.v1.{RESCUE_QUEUE}.k{args.top_k}.candidates.json"
        )
        family_raw = family_path.read_bytes()
        candidate_raw = candidate_path.read_bytes()
        report = build_rescue_artifact(
            json.loads(family_raw.decode("utf-8")),
            json.loads(candidate_raw.decode("utf-8")),
            discovery_payload_for(run_path),
            source,
            budget=budget,
            # Exactly these four keys. The frozen F10 closes this field set,
            # and the rest is not lost: `verified_provenance` already carries
            # the binary, the universe, the projection rules and the policies,
            # because `check_inputs_agree` put them there.
            provenance={
                "family_artifact_sha256": _sha256_bytes(family_raw),
                "candidate_artifact_sha256": _sha256_bytes(candidate_raw),
                "body_evidence_sha256": source.stage_sha256["body"],
                "raw_graph_sha256": source.stage_sha256["discovery"],
            },
        )
        output = (
            Path(args.output) if args.output
            else run_path.parent / f"{run_path.stem}.v1.families.rescue.json"
        )
        digest = write_json(output, report)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = report["summary"]
    print(json.dumps({
        "output": str(output),
        "sha256": digest,
        "rescue_rule_version": report["rescue_rule_version"],
        "queue": {"path": str(candidate_path), "kind": RESCUE_QUEUE},
        "budget": report["budget"],
        "summary": summary,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
