"""R3: score a pair of CallKin-Real bodies with the frozen V1 comparator.

`body_similarity.py` is byte-identical to v0-engine-py-f10@0abd091, so the
thirteen numbers a pair gets here are the numbers the formal V1 results were
scored on. Nothing in this module may change one of them; the 556-pair golden
in `tests/fixtures/f4_golden` fails on a single least-significant bit.

Two of the thirteen live in the frozen `analysis/v1_feasibility.py` rather than
in the comparator, and that module needs an oracle to run. They are reproduced
here, and the golden proves the reproduction is exact.

What this module adds is the join: R2 writes bodies inside a stage envelope,
and F4 wants the function records.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from body_similarity import (
    FunctionBody,
    _multiset_jaccard,
    compare_bodies,
    parse_body,
)


# The thirteen numeric fields, and the four quality fields, that the golden
# pins. Ordering is the golden's: sorted by name.
METRIC_NAMES = (
    "aligned_block_ratio",
    "aligned_instruction_ratio",
    "call_slot_shape_consistency",
    "constant_slot_consistency",
    "edge_consistency",
    "evidence_slot_consistency",
    "instruction_count_ratio",
    "mnemonic_multiset_jaccard",
    "mnemonic_ngram_jaccard",
    "opaque_cfg_penalty",
    "sequence_ratio",
    "size_ratio",
    "slot_adjusted_aligned_instruction_ratio",
)
QUALITY_NAMES = (
    "both_complete",
    "candidate_block_pair_count",
    "matched_block_count",
    "opaque_indirect_jumps",
)


def evidence_slots(body: FunctionBody) -> Counter[tuple[Any, ...]]:
    """Local slot evidence, verbatim from the frozen v1_feasibility."""
    values: Counter[tuple[Any, ...]] = Counter()
    for instruction in body.instructions:
        for slot in instruction.get("slots", []):
            # Local-only comparison excludes call identity/status/resolver.
            if slot.get("kind") == "call":
                continue
            values[(
                slot.get("kind"),
                slot.get("value"),
                slot.get("status"),
                slot.get("resolver"),
            )] += 1
    return values


def score_pair(
    first: FunctionBody,
    second: FunctionBody,
) -> tuple[dict[str, float], dict[str, bool | int]]:
    """Every numeric field the frozen V1 records for a pair.

    Eleven come from `compare_bodies`. `evidence_slot_consistency` and
    `slot_adjusted_aligned_instruction_ratio` are computed the way
    v1_feasibility computes them, including the division by 3.0 -- the order of
    those three additions decides the last bit, so it is not rearranged.
    """
    comparison = compare_bodies(first, second).to_dict()
    comparison.pop("pair")
    quality = comparison.pop("quality")
    evidence_slot_consistency = _multiset_jaccard(
        evidence_slots(first), evidence_slots(second)
    )
    variation_support = (
        comparison["constant_slot_consistency"]
        + comparison["call_slot_shape_consistency"]
        + evidence_slot_consistency
    ) / 3.0
    comparison["evidence_slot_consistency"] = evidence_slot_consistency
    comparison["slot_adjusted_aligned_instruction_ratio"] = min(
        comparison["aligned_instruction_ratio"], variation_support
    )
    return comparison, quality


def body_records(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    """The function records, from a stage envelope or a bare body artifact.

    R2 wraps the body artifact in an envelope carrying the binary hash and the
    hash of the discovery it came from. The frozen V1 wrote the artifact
    directly. Both are accepted so a frozen body evidence file can be scored
    against a CallKin-Real one without converting either.
    """
    if artifact.get("artifact") == "callkin-real-body" and "payload" in artifact:
        return list(artifact["payload"]["functions"])
    return list(artifact["functions"])


def load_bodies(source: str | Path | dict[str, Any]) -> dict[str, FunctionBody]:
    """Parse every function record into a comparable body.

    A record that fails `parse_body` is a schema break, not a bad function:
    the frozen V1 refuses it, and so does this.
    """
    artifact = (
        source if isinstance(source, dict)
        else json.loads(Path(source).read_text(encoding="utf-8"))
    )
    bodies: dict[str, FunctionBody] = {}
    for record in body_records(artifact):
        body = parse_body(record)
        if body.id in bodies:
            raise ValueError(f"duplicate body function id: {body.id}")
        bodies[body.id] = body
    return bodies


def comparable_bodies(source: str | Path | dict[str, Any]) -> dict[str, FunctionBody]:
    """Only the bodies F4 may score: the ones that decoded completely.

    An incomplete body still parses, and every metric would still return a
    number. The number would be about the bytes that happened to decode, which
    is exactly the inference R2 exists to refuse.
    """
    return {
        function_id: body
        for function_id, body in load_bodies(source).items()
        if body.complete
    }
