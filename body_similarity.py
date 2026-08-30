from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


METRICS = (
    "size_ratio",
    "instruction_count_ratio",
    "mnemonic_multiset_jaccard",
    "mnemonic_ngram_jaccard",
    "sequence_ratio",
    "aligned_block_ratio",
    "aligned_instruction_ratio",
    "edge_consistency",
    "call_slot_shape_consistency",
    "constant_slot_consistency",
    "opaque_cfg_penalty",
)


@dataclass(frozen=True)
class FunctionBody:
    id: str
    size: int
    instructions: tuple[dict[str, Any], ...]
    edges: tuple[dict[str, Any], ...]
    blocks: tuple[dict[str, Any], ...]
    quality: dict[str, Any]

    @property
    def complete(self) -> bool:
        return bool(self.quality.get("complete_decode"))


@dataclass(frozen=True)
class BodyAlignment:
    """Correspondence between two bodies.

    `block_pairs` and `candidate_block_pair_count` are what F4 scores from.
    `instruction_pairs` is additional detail for F7 template building and is
    deliberately excluded from every F4 metric.
    """

    block_pairs: tuple[tuple[str, str], ...]
    candidate_block_pair_count: int
    instruction_pairs: tuple[tuple[int, int], ...]
    unmatched_reference: tuple[int, ...]
    unmatched_target: tuple[int, ...]


@dataclass(frozen=True)
class BodyPairEvidence:
    first_id: str
    second_id: str
    size_ratio: float
    instruction_count_ratio: float
    mnemonic_multiset_jaccard: float
    mnemonic_ngram_jaccard: float
    sequence_ratio: float
    aligned_block_ratio: float
    aligned_instruction_ratio: float
    edge_consistency: float
    call_slot_shape_consistency: float
    constant_slot_consistency: float
    opaque_cfg_penalty: float
    quality: dict[str, bool | int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair": [self.first_id, self.second_id],
            **{
                key: value
                for key, value in self.__dict__.items()
                if key not in {"first_id", "second_id"}
            },
        }


def parse_body(data: dict[str, Any]) -> FunctionBody:
    required = {
        "id", "size", "instructions", "normalized_instructions",
        "cfg_edges", "blocks", "quality",
    }
    if set(data) - {"address", "byte_sha256", "summary"} != required:
        raise ValueError("body function record does not satisfy schema v2")
    return FunctionBody(
        id=data["id"],
        size=data["size"],
        instructions=tuple(data["normalized_instructions"]),
        edges=tuple(data["cfg_edges"]),
        blocks=tuple(data["blocks"]),
        quality=dict(data["quality"]),
    )


def load_body_evidence(
    source: str | Path | dict[str, Any],
) -> dict[str, FunctionBody]:
    if isinstance(source, dict):
        artifact = source
    else:
        artifact = json.loads(Path(source).read_text(encoding="utf-8"))
    bodies: dict[str, FunctionBody] = {}
    for item in artifact["functions"]:
        body = parse_body(item)
        if body.id in bodies:
            raise ValueError(f"duplicate body function id: {body.id}")
        bodies[body.id] = body
    return bodies


def body_evidence_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compare_bodies(first: FunctionBody, second: FunctionBody) -> BodyPairEvidence:
    first_tokens = [_instruction_token(item) for item in first.instructions]
    second_tokens = [_instruction_token(item) for item in second.instructions]

    # F4 reads only the block level; instruction pairs would cost an LCS per
    # block pair and must not influence any score.
    alignment = align_function_bodies(first, second, with_instructions=False)
    matched_pairs = list(alignment.block_pairs)
    candidate_pair_count = alignment.candidate_block_pair_count
    aligned_instruction_numerator = sum(
        min(
            _block_instruction_count(first, label_a),
            _block_instruction_count(second, label_b),
        )
        * max(
            _sequence_ratio(
                _block_sequence(first, label_a),
                _block_sequence(second, label_b),
            ),
            _ngram_jaccard(
                _block_sequence(first, label_a),
                _block_sequence(second, label_b),
            ),
        )
        for label_a, label_b in matched_pairs
    )
    aligned_instruction_denominator = max(len(first.instructions), len(second.instructions), 1)

    edge_consistency = _edge_consistency(first, second, matched_pairs)
    call_shapes_a = Counter(
        tuple(item.get("operands", []))
        for item in first.instructions
        if item.get("control_flow") == "call"
    )
    call_shapes_b = Counter(
        tuple(item.get("operands", []))
        for item in second.instructions
        if item.get("control_flow") == "call"
    )
    constants_a = Counter(
        int(value)
        for item in first.instructions
        for value in item.get("constants", [])
    )
    constants_b = Counter(
        int(value)
        for item in second.instructions
        for value in item.get("constants", [])
    )
    opaque_jumps = max(
        int(first.quality.get("opaque_indirect_jumps", 0)),
        int(second.quality.get("opaque_indirect_jumps", 0)),
    )

    return BodyPairEvidence(
        first_id=first.id,
        second_id=second.id,
        size_ratio=_count_ratio(first.size, second.size),
        instruction_count_ratio=_count_ratio(
            len(first.instructions), len(second.instructions)
        ),
        mnemonic_multiset_jaccard=_multiset_jaccard(
            Counter(token.split()[0] for token in first_tokens),
            Counter(token.split()[0] for token in second_tokens),
        ),
        mnemonic_ngram_jaccard=_ngram_jaccard(first_tokens, second_tokens),
        sequence_ratio=_sequence_ratio(first_tokens, second_tokens),
        aligned_block_ratio=(
            len(matched_pairs) / candidate_pair_count
            if candidate_pair_count
            else 1.0
        ),
        aligned_instruction_ratio=(
            aligned_instruction_numerator / aligned_instruction_denominator
        ),
        edge_consistency=edge_consistency,
        call_slot_shape_consistency=_multiset_jaccard(call_shapes_a, call_shapes_b),
        constant_slot_consistency=_multiset_jaccard(constants_a, constants_b),
        opaque_cfg_penalty=(
            opaque_jumps / aligned_instruction_denominator
        ),
        quality={
            "both_complete": first.complete and second.complete,
            "matched_block_count": len(matched_pairs),
            "candidate_block_pair_count": candidate_pair_count,
            "opaque_indirect_jumps": opaque_jumps,
        },
    )


def align_function_bodies(
    reference: FunctionBody,
    target: FunctionBody,
    *,
    with_instructions: bool = True,
) -> BodyAlignment:
    """Align two bodies at block level, and optionally at instruction level.

    Instruction pairs are produced only inside an aligned block pair, so two
    instructions from unrelated blocks are never linked. Pass
    `with_instructions=False` to skip the per-block LCS when only the block
    alignment is needed.
    """
    block_pairs, candidate_block_pair_count = _align_blocks(reference, target)
    if not with_instructions:
        return BodyAlignment(
            block_pairs=tuple(block_pairs),
            candidate_block_pair_count=candidate_block_pair_count,
            instruction_pairs=(),
            unmatched_reference=(),
            unmatched_target=(),
        )

    instruction_pairs: list[tuple[int, int]] = []
    for label_a, label_b in block_pairs:
        items_a = _block_instruction_items(reference, label_a)
        items_b = _block_instruction_items(target, label_b)
        instruction_pairs.extend(
            (items_a[index_a][0], items_b[index_b][0])
            for index_a, index_b in _lcs_pairs(
                [token for _offset, token in items_a],
                [token for _offset, token in items_b],
            )
        )
    instruction_pairs.sort()

    matched_reference = {offset for offset, _ in instruction_pairs}
    matched_target = {offset for _, offset in instruction_pairs}
    return BodyAlignment(
        block_pairs=tuple(block_pairs),
        candidate_block_pair_count=candidate_block_pair_count,
        instruction_pairs=tuple(instruction_pairs),
        unmatched_reference=tuple(
            sorted(
                item["offset"]
                for item in reference.instructions
                if item["offset"] not in matched_reference
            )
        ),
        unmatched_target=tuple(
            sorted(
                item["offset"]
                for item in target.instructions
                if item["offset"] not in matched_target
            )
        ),
    )


def _instruction_token(item: dict[str, Any]) -> str:
    return " ".join((item["mnemonic_class"], *item.get("operands", [])))


def _count_ratio(left: int, right: int) -> float:
    denominator = max(left, right)
    return min(left, right) / denominator if denominator else 1.0


def _multiset_jaccard(left: Counter[Any], right: Counter[Any]) -> float:
    union = sum((left | right).values())
    return sum((left & right).values()) / union if union else 1.0


def _ngrams(tokens: list[str], size: int = 3) -> list[tuple[str, ...]]:
    if len(tokens) < size:
        return [tuple(tokens)] if tokens else []
    return [tuple(tokens[index:index + size]) for index in range(len(tokens) - size + 1)]


def _ngram_jaccard(left: list[str], right: list[str]) -> float:
    return _multiset_jaccard(Counter(_ngrams(left)), Counter(_ngrams(right)))


def _sequence_ratio(left: list[str], right: list[str]) -> float:
    common = _lcs_length(left, right)
    denominator = max(len(left), len(right))
    return common / denominator if denominator else 1.0


def _lcs_length(left: list[str], right: list[str]) -> int:
    if not left or not right:
        return 0
    previous = [0] * (len(right) + 1)
    for left_item in left:
        current = [0]
        for index, right_item in enumerate(right, 1):
            if left_item == right_item:
                current.append(previous[index - 1] + 1)
            else:
                current.append(max(previous[index], current[-1]))
        previous = current
    return previous[-1]


def _lcs_pairs(left: list[str], right: list[str]) -> list[tuple[int, int]]:
    """Index pairs of one longest common subsequence.

    The traceback is fully determined, so equal tokens repeated inside a block
    always produce the same correspondence.
    """
    rows, columns = len(left), len(right)
    if not rows or not columns:
        return []

    table = [[0] * (columns + 1) for _ in range(rows + 1)]
    for row_index in range(rows - 1, -1, -1):
        row = table[row_index]
        following = table[row_index + 1]
        for column_index in range(columns - 1, -1, -1):
            if left[row_index] == right[column_index]:
                row[column_index] = following[column_index + 1] + 1
            else:
                row[column_index] = max(
                    following[column_index], row[column_index + 1]
                )

    pairs: list[tuple[int, int]] = []
    row_index = column_index = 0
    while row_index < rows and column_index < columns:
        if left[row_index] == right[column_index]:
            pairs.append((row_index, column_index))
            row_index += 1
            column_index += 1
        elif table[row_index + 1][column_index] >= table[row_index][column_index + 1]:
            row_index += 1
        else:
            column_index += 1
    return pairs


def _block_by_label(body: FunctionBody) -> dict[str, dict[str, Any]]:
    return {item["label"]: item for item in body.blocks}


def _block_instruction_items(
    body: FunctionBody,
    label: str,
) -> list[tuple[int, str]]:
    instructions = {item["offset"]: item for item in body.instructions}
    block = _block_by_label(body)[label]
    return [
        (offset, _instruction_token(instructions[offset]))
        for offset in block.get("instruction_offsets", [])
        if offset in instructions
    ]


def _block_sequence(body: FunctionBody, label: str) -> list[str]:
    return [token for _offset, token in _block_instruction_items(body, label)]


def _degrees(body: FunctionBody) -> tuple[Counter[str], Counter[str]]:
    outgoing: Counter[str] = Counter()
    incoming: Counter[str] = Counter()
    for edge in body.edges:
        if edge.get("kind") == "external_exit":
            continue
        outgoing[edge["source"]] += 1
        incoming[edge["target"]] += 1
    return outgoing, incoming


def _align_blocks(
    first: FunctionBody,
    second: FunctionBody,
) -> tuple[list[tuple[str, str]], int]:
    first_blocks = _block_by_label(first)
    second_blocks = _block_by_label(second)
    candidates: list[tuple[float, str, str]] = []
    first_out, first_in = _degrees(first)
    second_out, second_in = _degrees(second)
    first_terminals = _terminals(first)
    second_terminals = _terminals(second)

    for label_a, block_a in first_blocks.items():
        sequence_a = _block_sequence(first, label_a)
        for label_b, block_b in second_blocks.items():
            out_difference = abs(first_out[label_a] - second_out[label_b])
            in_difference = abs(first_in[label_a] - second_in[label_b])
            if out_difference > 1 or in_difference > 1:
                continue
            if bool(label_a in first_terminals) != bool(label_b in second_terminals):
                continue
            sequence_b = _block_sequence(second, label_b)
            score = max(
                _sequence_ratio(sequence_a, sequence_b),
                _ngram_jaccard(sequence_a, sequence_b),
            )
            candidates.append((score, label_a, label_b))

    entry_pair = ("B0", "B0") if "B0" in first_blocks and "B0" in second_blocks else None
    selected_set: set[tuple[str, str]] = {entry_pair} if entry_pair else set()
    used_a = {label for label, _ in selected_set}
    used_b = {label for _, label in selected_set}
    for score, label_a, label_b in sorted(candidates, reverse=True):
        if label_a in used_a or label_b in used_b:
            continue
        selected_set.add((label_a, label_b))
        used_a.add(label_a)
        used_b.add(label_b)

    total_blocks = max(len(first_blocks), len(second_blocks))
    return sorted(selected_set), total_blocks


def _block_instruction_count(body: FunctionBody, label: str) -> int:
    offsets = {
        item["offset"] for item in body.instructions
    }
    block = _block_by_label(body)[label]
    return sum(offset in offsets for offset in block.get("instruction_offsets", []))


def _terminals(body: FunctionBody) -> set[str]:
    instructions = {item["offset"]: item for item in body.instructions}
    terminal_labels = {
        block["label"]
        for block in body.blocks
        if block.get("instruction_offsets")
        and instructions.get(block["instruction_offsets"][-1], {}).get(
            "control_flow"
        ) == "return"
    }
    return {
        label
        for label in terminal_labels
        if any(edge["source"] == label for edge in body.edges) is False
    }


def _edge_consistency(
    first: FunctionBody,
    second: FunctionBody,
    matches: list[tuple[str, str]],
) -> float:
    mapping = dict(matches)
    reverse = {value: key for key, value in matches}
    first_edges = first.edges
    second_edges = second.edges
    scores = []
    for label_a, label_b in matches:
        targets_a = {
            (
                _edge_target_in_b_space(
                    edge["target"], mapping, reverse, source="a"
                ),
                edge["kind"],
            )
            for edge in first_edges
            if edge["source"] == label_a
        }
        targets_b = {
            (
                _edge_target_in_b_space(
                    edge["target"], mapping, reverse, source="b"
                ),
                edge["kind"],
            )
            for edge in second_edges
            if edge["source"] == label_b
        }
        union = targets_a | targets_b
        scores.append(len(targets_a & targets_b) / len(union) if union else 1.0)
    return sum(scores) / len(scores) if scores else 1.0


def _edge_target_in_b_space(
    target: str,
    mapping: dict[str, str],
    reverse: dict[str, str],
    *,
    source: str,
) -> str:
    if target in {"EXIT", "OPAQUE"}:
        return target
    if source == "a":
        return mapping.get(target, f"A-UNMATCHED:{target}")
    return target if target in reverse else f"B-UNMATCHED:{target}"
