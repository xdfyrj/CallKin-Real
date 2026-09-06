"""Select whole F5 candidate-graph components within the frozen F6 budget."""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path
from typing import Any, Mapping

from real_v1_adapter import RealV1Input

_FROZEN = Path(__file__).resolve().parent / "frozen_v1"
if str(_FROZEN) not in sys.path:
    sys.path.insert(0, str(_FROZEN))

from v1_candidates import PairKey, validate_candidate_artifact  # noqa: E402
from v1_engine import PairPolicyConfig  # noqa: E402


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == hashlib.sha256().digest_size * 2
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _component_records(
    candidate_artifact: Mapping[str, Any],
    source: RealV1Input,
    config: PairPolicyConfig,
) -> list[dict[str, Any]]:
    target_ids = list(candidate_artifact["universe"]["target_ids"])
    adjacency: dict[str, set[str]] = {member: set() for member in target_ids}
    for record in candidate_artifact["pairs"]:
        pair = PairKey.make(record["first"], record["second"])
        adjacency[pair.left].add(pair.right)
        adjacency[pair.right].add(pair.left)

    comparable = set(source.comparable)
    records: list[dict[str, Any]] = []
    unseen = set(target_ids)
    for root in target_ids:
        if root not in unseen:
            continue
        stack = [root]
        unseen.remove(root)
        members: list[str] = []
        while stack:
            member = stack.pop()
            members.append(member)
            for neighbor in sorted(adjacency[member], reverse=True):
                if neighbor in unseen:
                    unseen.remove(neighbor)
                    stack.append(neighbor)
        members.sort()

        lengths: list[int] = []
        for member in members:
            body = source.bodies.get(member)
            if member not in comparable or body is None or not body.complete:
                continue
            if (
                config.abstain_on_opaque_indirect
                and int(body.quality.get("opaque_indirect_jumps", 0)) > 0
            ):
                continue
            lengths.append(len(body.instructions))

        total = sum(lengths)
        squared = sum(length * length for length in lengths)
        records.append({
            "members": members,
            "member_count": len(members),
            "comparable_member_count": len(lengths),
            "comparisons": len(lengths) * (len(lengths) - 1) // 2,
            "alignment_cells": (total * total - squared) // 2,
        })

    return sorted(
        records,
        key=lambda item: (
            item["alignment_cells"],
            item["comparisons"],
            tuple(item["members"]),
        ),
    )


def build_budgeted_candidate_artifact(
    candidate_artifact: Mapping[str, Any],
    source: RealV1Input,
    config: PairPolicyConfig,
    source_candidate_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive a queue whose selected F5 components fit both F6 ceilings."""

    if not _is_sha256(source_candidate_sha256):
        raise ValueError("source candidate SHA-256 must be a 64-character hex digest")
    validate_candidate_artifact(candidate_artifact)

    records = _component_records(candidate_artifact, source, config)
    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    selected_comparisons = 0
    selected_cells = 0
    for record in records:
        next_comparisons = selected_comparisons + record["comparisons"]
        next_cells = selected_cells + record["alignment_cells"]
        fits_comparisons = (
            config.max_comparison_count is None
            or next_comparisons <= config.max_comparison_count
        )
        fits_cells = (
            config.max_alignment_cell_budget is None
            or next_cells <= config.max_alignment_cell_budget
        )
        if fits_comparisons and fits_cells:
            selected.append(record)
            selected_comparisons = next_comparisons
            selected_cells = next_cells
        else:
            deferred.append(record)

    derived = copy.deepcopy(dict(candidate_artifact))
    selected_members = set().union(*(item["members"] for item in selected)) if selected else set()
    derived["pairs"] = [
        pair
        for pair in derived["pairs"]
        if pair["first"] in selected_members and pair["second"] in selected_members
    ]

    deferred_comparisons = sum(item["comparisons"] for item in deferred)
    deferred_cells = sum(item["alignment_cells"] for item in deferred)
    component_report: dict[str, Any] = {
        "component_count": len(records),
        "selected_component_count": len(selected),
        "deferred_component_count": len(deferred),
        "selected_member_count": sum(item["member_count"] for item in selected),
        "deferred_member_count": sum(item["member_count"] for item in deferred),
        "selected_upper_bound_comparisons": selected_comparisons,
        "selected_upper_bound_alignment_cells": selected_cells,
        "deferred_upper_bound_comparisons": deferred_comparisons,
        "deferred_upper_bound_alignment_cells": deferred_cells,
        "max_comparison_count": config.max_comparison_count,
        "max_alignment_cell_budget": config.max_alignment_cell_budget,
        "within_budget": (
            config.max_comparison_count is None
            or selected_comparisons <= config.max_comparison_count
        ) and (
            config.max_alignment_cell_budget is None
            or selected_cells <= config.max_alignment_cell_budget
        ),
        "components": records,
        "selected_components": selected,
        "deferred_components": deferred,
    }
    derivation = {
        "kind": "whole-component-budget",
        "source_candidate_sha256": source_candidate_sha256,
        "policy": config.to_dict(),
        **component_report,
    }
    derived["provenance"] = {
        **dict(derived["provenance"]),
        "component_budget_derivation": derivation,
    }
    validate_candidate_artifact(derived)
    return derived, component_report
