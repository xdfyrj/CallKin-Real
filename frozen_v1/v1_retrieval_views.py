"""Independent retrieval views for F5.2.

Each view describes one kind of observable evidence.  The module deliberately
does not import ground truth or the candidate generator: profiles and scores
can therefore be computed for a stripped binary without source labels.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Iterable, Mapping, Sequence

from body_similarity import FunctionBody


VIEW_NAMES = ("composite", "token", "cfg", "relation")
# ``composite`` is retained as an explicit baseline.  The proposed multi-view
# retrieval deliberately unions only independent token/CFG/relation evidence.
MULTI_VIEW_NAMES = ("token", "cfg", "relation")
VIEW_PROFILE_VERSIONS = {
    "composite": "cheap-body-v1",
    "token": "token-v2-no-sequence",
    "cfg": "cfg-v2-digested-topology",
    "relation": "relation-v3-anchor-class-context",
}


@dataclass(frozen=True)
class TokenProfile:
    function_id: str
    instruction_tokens: tuple[str, ...]
    mnemonic_counts: tuple[tuple[str, int], ...]
    mnemonic_ngrams: frozenset[tuple[str, ...]]
    operand_counts: tuple[tuple[tuple[str, ...], int], ...]
    constant_counts: tuple[tuple[str, int], ...]
    exact_token_hash: str

    @property
    def signature(self) -> tuple[Any, ...]:
        return (
            self.mnemonic_counts,
            tuple(sorted(self.mnemonic_ngrams)),
            self.operand_counts,
            self.constant_counts,
        )

    @property
    def has_evidence(self) -> bool:
        return bool(self.instruction_tokens)


@dataclass(frozen=True)
class CFGProfile:
    function_id: str
    block_count: int
    edge_count: int
    block_roles: tuple[tuple[Any, ...], ...]
    edge_kinds: tuple[tuple[str, int], ...]
    degree_pairs: tuple[tuple[tuple[int, int], int], ...]
    topology_labels: tuple[str, ...]
    block_role_counts: tuple[tuple[tuple[Any, ...], int], ...]
    topology_label_counts: tuple[tuple[str, int], ...]

    @property
    def signature(self) -> tuple[Any, ...]:
        return (
            self.block_count,
            self.edge_count,
            self.block_roles,
            self.edge_kinds,
            self.degree_pairs,
            self.block_role_counts,
            self.topology_label_counts,
        )

    @property
    def has_evidence(self) -> bool:
        return bool(
            self.edge_count
            or any(role and int(role[0]) > 0 for role in self.block_roles)
        )


@dataclass(frozen=True)
class RelationProfile:
    function_id: str
    history: tuple[tuple[int, int, int], ...]
    final_group: tuple[int, int] | None
    group_size_history: tuple[int, ...]
    out_signature: tuple[tuple[Any, int], ...]
    in_signature: tuple[tuple[Any, int], ...]

    @property
    def signature(self) -> tuple[Any, ...]:
        return (
            self.history,
            self.final_group,
            self.group_size_history,
            self.out_signature,
            self.in_signature,
        )

    @property
    def has_evidence(self) -> bool:
        return bool(
            any(group_index >= 0 for _round, group_index, _size in self.history)
            or self.final_group is not None
            or any(size > 0 for size in self.group_size_history)
            or self.out_signature
            or self.in_signature
        )


def build_token_profiles(
    bodies: Mapping[str, FunctionBody],
) -> dict[str, TokenProfile]:
    profiles: dict[str, TokenProfile] = {}
    for function_id in sorted(bodies):
        body = bodies[function_id]
        tokens: list[str] = []
        mnemonics: list[str] = []
        operands: list[tuple[str, ...]] = []
        constants: list[str] = []
        for instruction in body.instructions:
            mnemonic = str(instruction.get("mnemonic_class", "UNKNOWN")).upper()
            operand_shapes = tuple(
                _operand_shape(value)
                for value in instruction.get("operands", ())
            )
            constant_shapes = tuple(
                _constant_shape(value)
                for value in instruction.get("constants", ())
            )
            control_flow = _control_flow_shape(instruction.get("control_flow"))
            tokens.append(_instruction_token(
                mnemonic,
                operand_shapes,
                constant_shapes,
                control_flow,
            ))
            mnemonics.append(mnemonic)
            operands.append(operand_shapes)
            constants.extend(constant_shapes)
        encoded = json.dumps(tokens, ensure_ascii=True, separators=(",", ":"))
        profiles[function_id] = TokenProfile(
            function_id=function_id,
            instruction_tokens=tuple(tokens),
            mnemonic_counts=_counter_tuple(mnemonics),
            mnemonic_ngrams=frozenset(_ngrams(mnemonics)),
            operand_counts=_counter_tuple(operands),
            constant_counts=_counter_tuple(constants),
            exact_token_hash=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        )
    return profiles


def token_similarity(first: TokenProfile, second: TokenProfile) -> float:
    """Compare mnemonic, operand-shape, and constant-shape evidence only."""

    if not first.has_evidence or not second.has_evidence:
        return 0.0
    # The token view intentionally uses local token evidence only.  Sequence
    # alignment is an F4 detailed metric; running it for every retrieval pair
    # makes a large binary quadratic in the length of both functions.  The
    # mnemonic n-gram Jaccard below is the bounded sequence-shape proxy.
    values = (
        _counter_jaccard(first.mnemonic_counts, second.mnemonic_counts),
        _set_jaccard(first.mnemonic_ngrams, second.mnemonic_ngrams),
        _counter_jaccard(first.operand_counts, second.operand_counts),
        _counter_jaccard(first.constant_counts, second.constant_counts),
    )
    return sum(values) / len(values)


def build_cfg_profiles(
    bodies: Mapping[str, FunctionBody],
) -> dict[str, CFGProfile]:
    profiles: dict[str, CFGProfile] = {}
    for function_id in sorted(bodies):
        body = bodies[function_id]
        block_map = {
            str(block.get("label")): block
            for block in body.blocks
        }
        incoming: Counter[str] = Counter()
        outgoing: Counter[str] = Counter()
        edge_kinds: Counter[str] = Counter()
        edge_records: list[tuple[str, str, str]] = []
        for edge in body.edges:
            source = str(edge.get("source"))
            target = str(edge.get("target"))
            kind = _edge_kind(edge.get("kind"))
            edge_records.append((source, target, kind))
            edge_kinds[kind] += 1
            if source in block_map and target in block_map:
                outgoing[source] += 1
                incoming[target] += 1

        instruction_map = {
            int(instruction.get("offset", 0)): instruction
            for instruction in body.instructions
        }
        block_roles: dict[str, tuple[Any, ...]] = {}
        degree_pairs: list[tuple[int, int]] = []
        for label, block in block_map.items():
            offsets = [int(offset) for offset in block.get("instruction_offsets", ())]
            last_instruction = instruction_map.get(offsets[-1]) if offsets else None
            terminal = _terminal_role(
                last_instruction.get("control_flow") if last_instruction else None
            )
            indegree = int(incoming[label])
            outdegree = int(outgoing[label])
            role = (
                len(offsets),
                indegree,
                outdegree,
                terminal,
                indegree == 0,
                outdegree == 0,
            )
            block_roles[label] = role
            degree_pairs.append((indegree, outdegree))

        topology_labels = _refine_block_topology(
            block_map,
            block_roles,
            edge_records,
        )
        profiles[function_id] = CFGProfile(
            function_id=function_id,
            block_count=len(block_map),
            edge_count=sum(
                source in block_map and target in block_map
                for source, target, _kind in edge_records
            ),
            block_roles=tuple(sorted(block_roles.values(), key=repr)),
            edge_kinds=tuple(sorted(edge_kinds.items())),
            degree_pairs=_counter_tuple(degree_pairs),
            topology_labels=tuple(sorted(topology_labels.values())),
            block_role_counts=_counter_tuple(block_roles.values()),
            topology_label_counts=_counter_tuple(topology_labels.values()),
        )
    return profiles


def cfg_similarity(first: CFGProfile, second: CFGProfile) -> float:
    """Compare CFG block roles and topology without instruction tokens."""

    if not first.has_evidence or not second.has_evidence:
        return 0.0
    values = (
        _ratio(first.block_count, second.block_count),
        _ratio(first.edge_count, second.edge_count),
        _counter_jaccard(first.block_role_counts, second.block_role_counts),
        _counter_jaccard(first.edge_kinds, second.edge_kinds),
        _counter_jaccard(first.degree_pairs, second.degree_pairs),
        _counter_jaccard(first.topology_label_counts, second.topology_label_counts),
    )
    return sum(values) / len(values)


def build_relation_profiles(
    function_ids: Iterable[str],
    *,
    final_groups: Iterable[Iterable[str]] | None = None,
    prior_round_groups: Iterable[tuple[int, Iterable[Iterable[str]]]] | None = None,
    final_round: int | None = None,
    out_signatures: Mapping[str, Any] | None = None,
    in_signatures: Mapping[str, Any] | None = None,
    anchor_classes: Mapping[str, str] | None = None,
) -> dict[str, RelationProfile]:
    ids = sorted(set(function_ids))
    prior = sorted(
        (
            int(round_index),
            _group_membership(groups),
        )
        for round_index, groups in (prior_round_groups or ())
    )
    final_membership = _group_membership(final_groups or ())
    rounds: list[tuple[int, dict[str, tuple[int, int]]]] = list(prior)
    if final_groups is not None:
        rounds.append((
            int(final_round if final_round is not None else (prior[-1][0] + 1 if prior else 0)),
            final_membership,
        ))

    def transformed_signature(
        mapping: Mapping[str, Any] | None,
        function_id: str,
    ) -> tuple[tuple[Any, int], ...]:
        values = []
        for target, count in (mapping or {}).get(function_id, ()):
            target_id = str(target)
            if target_id in final_membership:
                group_index, group_size = final_membership[target_id]
                descriptor = (
                    "candidate_group",
                    group_index,
                    group_size,
                )
            elif target_id in (anchor_classes or {}):
                descriptor = (
                    "anchor_class",
                    anchor_classes[target_id],
                )
            else:
                descriptor = ("external_unknown",)
            values.append((descriptor, int(count)))
        return tuple(sorted(values, key=repr))

    result: dict[str, RelationProfile] = {}
    for function_id in ids:
        history: list[tuple[int, int, int]] = []
        group_sizes: list[int] = []
        for round_index, membership in rounds:
            group = membership.get(function_id)
            if group is None:
                history.append((round_index, -1, 0))
                group_sizes.append(0)
            else:
                group_index, group_size = group
                history.append((round_index, group_index, group_size))
                group_sizes.append(group_size)
        result[function_id] = RelationProfile(
            function_id=function_id,
            history=tuple(history),
            final_group=final_membership.get(function_id),
            group_size_history=tuple(group_sizes),
            out_signature=transformed_signature(out_signatures, function_id),
            in_signature=transformed_signature(in_signatures, function_id),
        )
    return result


def relation_similarity(first: RelationProfile, second: RelationProfile) -> float:
    """Compare WL history and call context; no body feature is consulted."""

    if not first.has_evidence or not second.has_evidence:
        return 0.0
    history = _sequence_ratio(first.history, second.history)
    final = _same_or_unknown(first.final_group, second.final_group)
    sizes = _sequence_ratio(first.group_size_history, second.group_size_history)
    values = [history, final, sizes]
    if first.out_signature or second.out_signature:
        values.append(_counter_jaccard(
            _counter_from_values(first.out_signature),
            _counter_from_values(second.out_signature),
        ))
    if first.in_signature or second.in_signature:
        values.append(_counter_jaccard(
            _counter_from_values(first.in_signature),
            _counter_from_values(second.in_signature),
        ))
    return sum(values) / len(values)


def _group_membership(
    groups: Iterable[Iterable[str]],
) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    normalized = sorted(
        (sorted(set(group)) for group in groups),
        key=lambda group: tuple(group),
    )
    for index, group in enumerate(normalized):
        for member in group:
            if member in result:
                raise ValueError(f"function appears in multiple relation groups: {member}")
            result[member] = (index, len(group))
    return result


def _refine_block_topology(
    block_map: Mapping[str, Mapping[str, Any]],
    roles: Mapping[str, tuple[Any, ...]],
    edges: Sequence[tuple[str, str, str]],
) -> dict[str, str]:
    labels = {label: _stable_label(roles[label]) for label in block_map}
    for _ in range(2):
        outgoing: defaultdict[str, list[tuple[str, str]]] = defaultdict(list)
        incoming: defaultdict[str, list[tuple[str, str]]] = defaultdict(list)
        for source, target, kind in edges:
            if source in labels and target in labels:
                outgoing[source].append((kind, labels[target]))
                incoming[target].append((kind, labels[source]))
        labels = {
            label: _stable_label((
                labels[label],
                tuple(sorted(outgoing[label])),
                tuple(sorted(incoming[label])),
            ))
            for label in labels
        }
    return labels


def _stable_label(value: Any) -> str:
    encoded = repr(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _instruction_token(
    mnemonic: str,
    operands: tuple[str, ...],
    constants: tuple[str, ...],
    control_flow: str,
) -> str:
    return "|".join((
        mnemonic,
        ",".join(operands) or "-",
        ",".join(constants) or "-",
        control_flow,
    ))


def _operand_shape(value: Any) -> str:
    if isinstance(value, Mapping):
        kind = str(value.get("kind", value.get("type", "operand"))).lower()
        width = value.get("width")
        return f"{kind}:{width}" if width is not None else kind
    text = str(value).strip().lower()
    if not text:
        return "unknown"
    if re.fullmatch(r"(?:r|e)?(?:ax|bx|cx|dx|si|di|sp|bp|ip)|r(?:1[0-5]|[0-9])|[abcd]l|[abcd]h", text):
        return "reg"
    if text.startswith("reg") or text.startswith("xmm") or text.startswith("ymm"):
        return text
    if text.startswith("mem") or "[" in text or " ptr " in text:
        width = re.search(r"(8|16|32|64|128|256)", text)
        return f"mem{width.group(1)}" if width else "mem"
    if text.startswith("imm") or text.startswith("const"):
        return text
    if text.startswith("call_") or text in {"call_target", "branch_target"}:
        return "target"
    if re.fullmatch(r"[-+]?0x[0-9a-f]+|[-+]?\d+", text):
        return "imm"
    return text


def _constant_shape(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        if value == 0:
            return "int:zero"
        if value == 1:
            return "int:one"
        return "int:small" if abs(value) < 256 else "int:large"
    if isinstance(value, float):
        return "float"
    if isinstance(value, bytes):
        return f"bytes:{_length_bucket(len(value))}"
    text = str(value).strip().lower()
    if re.fullmatch(r"[-+]?0x[0-9a-f]+|[-+]?\d+", text):
        try:
            return _constant_shape(int(text, 0))
        except ValueError:
            return "number"
    return f"str:{_length_bucket(len(text))}"


def _control_flow_shape(value: Any) -> str:
    text = str(value or "other").lower()
    if "return" in text or text in {"ret", "terminal"}:
        return "return"
    if "conditional" in text or "branch" in text:
        return "conditional"
    if "jump" in text:
        return "jump"
    if "call" in text:
        return "call"
    return "fallthrough"


def _terminal_role(value: Any) -> str:
    return _control_flow_shape(value)


def _edge_kind(value: Any) -> str:
    return str(value or "unknown").lower()


def _counter_tuple(values: Iterable[Any]) -> tuple[tuple[Any, int], ...]:
    counts = Counter(values)
    return tuple(sorted(counts.items(), key=lambda item: repr(item[0])))


def _counter_from_values(values: Iterable[Any]) -> tuple[tuple[Any, int], ...]:
    return _counter_tuple(values)


def _counter_jaccard(
    first: Iterable[tuple[Any, int]],
    second: Iterable[tuple[Any, int]],
) -> float:
    left, right = dict(first), dict(second)
    keys = left.keys() | right.keys()
    union = sum(max(left.get(key, 0), right.get(key, 0)) for key in keys)
    intersection = sum(min(left.get(key, 0), right.get(key, 0)) for key in keys)
    return intersection / union if union else 1.0


def _set_jaccard(first: Iterable[Any], second: Iterable[Any]) -> float:
    left, right = set(first), set(second)
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _sequence_ratio(first: Sequence[Any], second: Sequence[Any]) -> float:
    if not first and not second:
        return 1.0
    return SequenceMatcher(a=list(first), b=list(second), autojunk=False).ratio()


def _same_or_unknown(
    first: tuple[int, int] | None,
    second: tuple[int, int] | None,
) -> float:
    if first is None or second is None:
        return 0.0
    return 1.0 if first == second else 0.0


def _ratio(first: int, second: int) -> float:
    denominator = max(first, second)
    return min(first, second) / denominator if denominator else 1.0


def _length_bucket(length: int) -> str:
    if length == 0:
        return "0"
    if length <= 4:
        return "1-4"
    if length <= 16:
        return "5-16"
    if length <= 64:
        return "17-64"
    return "65+"


def _ngrams(values: Sequence[str], size: int = 3) -> list[tuple[str, ...]]:
    if not values:
        return []
    if len(values) < size:
        return [tuple(values)]
    return [tuple(values[index:index + size]) for index in range(len(values) - size + 1)]
