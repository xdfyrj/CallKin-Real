"""F7 family templates.

F7.1 picks a medoid: the member that actually exists in the binary and matches
the rest of the family best. No averaged body is synthesised, because averaging
would erase exactly the information F7 is looking for, namely which positions
are common and which vary with the concrete types.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
from typing import Any, Callable, Mapping, Sequence

from body_similarity import BodyAlignment, FunctionBody, align_function_bodies, compare_bodies
from slot_overlay import MISSING, RESOLVED, SlotObservation


@dataclass(frozen=True)
class FamilyMedoid:
    medoid: str
    members: tuple[str, ...]
    mean_similarity: dict[str, float]

    @property
    def score(self) -> float:
        return self.mean_similarity[self.medoid]

    def to_dict(self) -> dict[str, object]:
        return {
            "medoid": self.medoid,
            "members": list(self.members),
            "mean_similarity": dict(sorted(self.mean_similarity.items())),
            "score": self.score,
        }


def structure_similarity(first: FunctionBody, second: FunctionBody) -> float:
    """The scalar F6 accepts pairs on, reused so F7 centres on the same notion.

    `min` of the three structural ratios, matching
    `v1_engine._pair_features().structure_score`.
    """
    evidence = compare_bodies(first, second)
    return min(
        float(evidence.aligned_instruction_ratio),
        float(evidence.sequence_ratio),
        float(evidence.mnemonic_multiset_jaccard),
    )


def select_medoid(
    bodies: Mapping[str, FunctionBody],
    members: Sequence[str],
    *,
    similarity: Callable[[FunctionBody, FunctionBody], float] = structure_similarity,
) -> FamilyMedoid:
    """Choose the member with the highest mean similarity to the others.

    Costs one comparison per unordered pair, so a family of `m` members costs
    `m * (m - 1) / 2`. Callers that group very large clusters should bound the
    family size before calling.
    """
    unique = sorted(set(members))
    if len(unique) != len(members):
        raise ValueError("family members must be unique")
    if len(unique) < 2:
        raise ValueError("a medoid needs at least two members")
    missing = [member for member in unique if member not in bodies]
    if missing:
        raise ValueError(f"no body for family member {missing[0]!r}")

    totals = {member: 0.0 for member in unique}
    for first, second in combinations(unique, 2):
        score = similarity(bodies[first], bodies[second])
        totals[first] += score
        totals[second] += score

    divisor = len(unique) - 1
    mean_similarity = {member: total / divisor for member, total in totals.items()}
    # Highest mean wins; the lexicographically first id breaks ties so the
    # medoid never depends on iteration order.
    medoid = min(unique, key=lambda member: (-mean_similarity[member], member))
    return FamilyMedoid(
        medoid=medoid,
        members=tuple(unique),
        mean_similarity=mean_similarity,
    )


def align_members_to_medoid(
    bodies: Mapping[str, FunctionBody],
    selection: FamilyMedoid,
) -> dict[str, BodyAlignment]:
    """Align every other member onto the medoid, medoid first in each pair."""
    reference = bodies[selection.medoid]
    return {
        member: align_function_bodies(reference, bodies[member])
        for member in selection.members
        if member != selection.medoid
    }


COMMON = "common"
OPTIONAL = "optional"


@dataclass(frozen=True)
class TemplateSlot:
    """One medoid position, observed across every member."""

    block: str
    offset: int
    index: int
    kind: str
    values_by_member: dict[str, Any]
    states_by_member: dict[str, str]

    @property
    def resolved_values(self) -> tuple[Any, ...]:
        values = {
            self.values_by_member[member]
            for member, state in self.states_by_member.items()
            if state == RESOLVED
        }
        return tuple(sorted(values, key=repr))

    @property
    def observed_by_all(self) -> bool:
        return all(state == RESOLVED for state in self.states_by_member.values())

    @property
    def varies(self) -> bool:
        return len(self.resolved_values) > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "block": self.block,
            "offset": self.offset,
            "index": self.index,
            "kind": self.kind,
            "values_by_member": dict(sorted(self.values_by_member.items())),
            "states_by_member": dict(sorted(self.states_by_member.items())),
            "variant_count": len(self.resolved_values),
            "varies": self.varies,
        }


@dataclass(frozen=True)
class FamilyTemplate:
    medoid: str
    members: tuple[str, ...]
    block_roles: dict[str, str]
    member_specific_blocks: dict[str, tuple[str, ...]]
    slots: tuple[TemplateSlot, ...]

    @property
    def variation_slots(self) -> tuple[TemplateSlot, ...]:
        return tuple(slot for slot in self.slots if slot.varies)

    def to_dict(self) -> dict[str, Any]:
        return {
            "medoid": self.medoid,
            "members": list(self.members),
            "block_roles": dict(sorted(self.block_roles.items())),
            "member_specific_blocks": {
                member: list(blocks)
                for member, blocks in sorted(self.member_specific_blocks.items())
            },
            "slots": [slot.to_dict() for slot in self.slots],
            "variation_slot_count": len(self.variation_slots),
        }


@dataclass(frozen=True)
class VariationAxis:
    """An anonymous axis: one way the family's members get split.

    Two slots belong to the same axis when they split the members identically,
    however different their actual values are. The axis carries no claim about
    which source type parameter caused it.
    """

    id: str
    partition: tuple[tuple[str, ...], ...]
    slots: tuple[tuple[int, int, str], ...]
    labels: dict[str, int]

    @property
    def variant_count(self) -> int:
        return len(self.partition)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "variant_count": self.variant_count,
            "partition": [list(group) for group in self.partition],
            "slots": [
                {"offset": offset, "index": index, "kind": kind}
                for offset, index, kind in self.slots
            ],
            "labels": dict(sorted(self.labels.items())),
        }


@dataclass(frozen=True)
class AxisPairCoverage:
    first: str
    second: str
    expected_combinations: int
    observed_combinations: int
    tuple_counts: dict[tuple[int, int], int]

    @property
    def coverage(self) -> float:
        return self.observed_combinations / self.expected_combinations

    @property
    def complete(self) -> bool:
        return self.observed_combinations == self.expected_combinations

    @property
    def bijective(self) -> bool:
        return self.complete and set(self.tuple_counts.values()) == {1}

    def to_dict(self) -> dict[str, Any]:
        return {
            "first": self.first,
            "second": self.second,
            "expected_combinations": self.expected_combinations,
            "observed_combinations": self.observed_combinations,
            "coverage": self.coverage,
            "complete": self.complete,
            "bijective": self.bijective,
            "tuple_counts": {
                f"{left},{right}": count
                for (left, right), count in sorted(self.tuple_counts.items())
            },
        }


def _slot_partition(slot: TemplateSlot) -> tuple[tuple[str, ...], ...]:
    groups: dict[Any, list[str]] = {}
    for member, value in slot.values_by_member.items():
        groups.setdefault(value, []).append(member)
    return tuple(sorted(tuple(sorted(members)) for members in groups.values()))


def infer_variation_axes(template: FamilyTemplate) -> tuple[VariationAxis, ...]:
    """Group the family's varying slots into anonymous axes.

    A slot qualifies only when every member resolved it. A slot that is
    unresolved, filtered, ambiguous or missing for even one member cannot say
    how that member is grouped, so it is left out rather than guessed at.
    """
    by_partition: dict[tuple[tuple[str, ...], ...], list[TemplateSlot]] = {}
    for slot in template.slots:
        if not slot.observed_by_all or not slot.varies:
            continue
        by_partition.setdefault(_slot_partition(slot), []).append(slot)

    ordered = sorted(
        by_partition.items(),
        key=lambda item: min((slot.offset, slot.index) for slot in item[1]),
    )
    axes: list[VariationAxis] = []
    for number, (partition, slots) in enumerate(ordered, start=1):
        labels = {
            member: index
            for index, group in enumerate(partition)
            for member in group
        }
        axes.append(
            VariationAxis(
                id=f"AXIS_{number}",
                partition=partition,
                slots=tuple(
                    sorted((slot.offset, slot.index, slot.kind) for slot in slots)
                ),
                labels=labels,
            )
        )
    return tuple(axes)


def axis_pair_coverage(
    axes: Sequence[VariationAxis],
    members: Sequence[str],
) -> tuple[AxisPairCoverage, ...]:
    """Check whether each pair of axes spans a full Cartesian product."""
    results: list[AxisPairCoverage] = []
    for first, second in combinations(axes, 2):
        counts: dict[tuple[int, int], int] = {}
        for member in members:
            key = (first.labels[member], second.labels[member])
            counts[key] = counts.get(key, 0) + 1
        results.append(
            AxisPairCoverage(
                first=first.id,
                second=second.id,
                expected_combinations=first.variant_count * second.variant_count,
                observed_combinations=len(counts),
                tuple_counts=counts,
            )
        )
    return tuple(results)


def refines(fine: VariationAxis, coarse: VariationAxis) -> bool:
    """True when every group of `fine` sits inside one group of `coarse`.

    Distinct axes always have distinct partitions, since identical partitions
    were merged into one axis, so this relation cannot hold both ways.
    """
    return all(
        len({coarse.labels[member] for member in group}) == 1
        for group in fine.partition
    )


def coarsening_relations(
    axes: Sequence[VariationAxis],
) -> tuple[dict[str, str], ...]:
    return tuple(
        {"coarse": coarse.id, "fine": fine.id}
        for coarse in axes
        for fine in axes
        if fine.id != coarse.id and refines(fine, coarse)
    )


def maximal_axes(axes: Sequence[VariationAxis]) -> tuple[VariationAxis, ...]:
    """The finest axes: those no other axis refines."""
    return tuple(
        axis
        for axis in axes
        if not any(
            other.id != axis.id and refines(other, axis) for other in axes
        )
    )


def select_basis(
    axes: Sequence[VariationAxis],
    members: Sequence[str],
) -> tuple[list[str] | None, str, tuple[AxisPairCoverage, ...]]:
    """Find the one axis pair that explains the family, if there is exactly one.

    A basis is a pair of maximal axes spanning a bijective Cartesian product
    such that every remaining axis equals or coarsens one of the two.

    Two candidate pairs would report `ambiguous` rather than a choice being
    made, though drawing pairs from the maximal axes alone should rule that
    out: for `(X, Y)` and `(X, Z)` to both qualify, `Z` would have to coarsen
    `X` or `Y`, and a coarsening is never maximal.
    """
    maximal = maximal_axes(axes)
    bijective = tuple(
        pair for pair in axis_pair_coverage(maximal, members) if pair.bijective
    )
    by_id = {axis.id: axis for axis in axes}

    candidates: list[list[str]] = []
    for pair in bijective:
        first, second = by_id[pair.first], by_id[pair.second]
        others = [axis for axis in axes if axis.id not in (first.id, second.id)]
        if all(
            refines(first, other) or refines(second, other) for other in others
        ):
            candidates.append([first.id, second.id])

    if not candidates:
        return None, "none" if not bijective else "no_pair_explains_every_axis", bijective
    if len(candidates) > 1:
        return None, "ambiguous", bijective
    return candidates[0], "unique", bijective


def axis_report(template: FamilyTemplate) -> dict[str, Any]:
    """Everything a probe should record, including why slots were excluded."""
    excluded: list[dict[str, Any]] = []
    for slot in template.slots:
        if slot.observed_by_all and slot.varies:
            continue
        reason = (
            "invariant"
            if slot.observed_by_all
            else "not_resolved_for_every_member"
        )
        excluded.append({
            "offset": slot.offset,
            "index": slot.index,
            "kind": slot.kind,
            "reason": reason,
            "states": sorted(set(slot.states_by_member.values())),
        })

    axes = infer_variation_axes(template)
    pairs = axis_pair_coverage(axes, template.members)
    maximal = maximal_axes(axes)
    basis, basis_status, bijective = select_basis(axes, template.members)
    kinds: dict[str, int] = {}
    for slot in template.slots:
        kinds[slot.kind] = kinds.get(slot.kind, 0) + 1
    return {
        "medoid": template.medoid,
        "member_count": len(template.members),
        "slot_count": len(template.slots),
        "slot_count_by_kind": dict(sorted(kinds.items())),
        "observed_by_all_slot_count": sum(
            1 for slot in template.slots if slot.observed_by_all
        ),
        "varying_slot_count": len(template.variation_slots),
        "axis_count": len(axes),
        "axes": [axis.to_dict() for axis in axes],
        "axis_pairs": [pair.to_dict() for pair in pairs],
        "coarsening_relations": [dict(item) for item in coarsening_relations(axes)],
        "maximal_axes": [axis.id for axis in maximal],
        "independent_axis_count": len(maximal),
        "bijective_bases": [[pair.first, pair.second] for pair in bijective],
        "selected_basis": basis,
        "selected_basis_status": basis_status,
        "excluded_slots": excluded,
    }


def _medoid_block_of_offset(body: FunctionBody) -> dict[int, str]:
    return {
        offset: block["label"]
        for block in body.blocks
        for offset in block.get("instruction_offsets", ())
    }


def build_family_template(
    bodies: Mapping[str, FunctionBody],
    selection: FamilyMedoid,
    observations: Mapping[str, Sequence[SlotObservation]],
    *,
    alignments: Mapping[str, BodyAlignment] | None = None,
) -> FamilyTemplate:
    """Describe a family as medoid positions plus what each member puts there.

    Positions are anchored on the medoid, so the medoid observes itself through
    an identity mapping. Only `CALL_TARGET`, `DATA_REFERENCE` and
    `IMMEDIATE_CONSTANT` are handled: operand width and memory shape change the
    instruction token itself, so the current LCS leaves them unmatched rather
    than pairing them, and reading them here would invent correspondences.
    """
    missing = [member for member in selection.members if member not in observations]
    if missing:
        raise ValueError(f"no slot observations for member {missing[0]!r}")
    if alignments is None:
        alignments = align_members_to_medoid(bodies, selection)

    medoid = selection.medoid
    medoid_body = bodies[medoid]
    block_of_offset = _medoid_block_of_offset(medoid_body)

    # Medoid offset -> member offset. The medoid maps onto itself.
    offset_maps: dict[str, dict[int, int]] = {
        medoid: {offset: offset for offset in block_of_offset}
    }
    for member in selection.members:
        if member == medoid:
            continue
        offset_maps[member] = dict(alignments[member].instruction_pairs)

    observed = {
        member: {item.position: item for item in observations[member]}
        for member in selection.members
    }

    slots: list[TemplateSlot] = []
    for anchor in observations[medoid]:
        values: dict[str, Any] = {}
        states: dict[str, str] = {}
        for member in selection.members:
            member_offset = offset_maps[member].get(anchor.offset)
            found = (
                None
                if member_offset is None
                else observed[member].get((member_offset, anchor.index, anchor.kind))
            )
            values[member] = None if found is None else found.value
            states[member] = MISSING if found is None else found.state
        slots.append(
            TemplateSlot(
                block=block_of_offset.get(anchor.offset, ""),
                offset=anchor.offset,
                index=anchor.index,
                kind=anchor.kind,
                values_by_member=values,
                states_by_member=states,
            )
        )

    block_roles: dict[str, str] = {}
    medoid_labels = {block["label"] for block in medoid_body.blocks}
    for label in sorted(medoid_labels):
        matched = sum(
            1
            for member in selection.members
            if member == medoid
            or any(left == label for left, _ in alignments[member].block_pairs)
        )
        block_roles[label] = COMMON if matched == len(selection.members) else OPTIONAL

    # A block a member owns alone stays that member's own. Two members' orphan
    # blocks are never merged into one optional region: that would need its own
    # alignment between members, which this stage does not attempt.
    member_specific: dict[str, tuple[str, ...]] = {}
    for member in selection.members:
        if member == medoid:
            continue
        paired = {right for _, right in alignments[member].block_pairs}
        orphans = sorted(
            block["label"]
            for block in bodies[member].blocks
            if block["label"] not in paired
        )
        if orphans:
            member_specific[member] = tuple(orphans)

    return FamilyTemplate(
        medoid=medoid,
        members=selection.members,
        block_roles=block_roles,
        member_specific_blocks=member_specific,
        slots=tuple(slots),
    )
