"""F7 family-fragment rescue.

Strict F6 keeps precision high by splitting one family into several accepted
fragments: ReadByLine's 30 functions survive as 10, 5, 10 and 5. This stage asks
whether a group of fragments is the Cartesian product of repeated variation
axes, and merges only when it is.

It lives outside `v1_engine.py` on purpose, so the strict partition and the
rescued one stay separately auditable, and it never reads ground truth, origin
names or symbols.

A complete Cartesian is not enough on its own. `StandardSink::context` and
`matched` are two different source origins whose method identity read as one
axis and whose generic variants read as another, producing a perfect 2 x 2. Two
further conditions rule that out: the fragments must already be joined by a V0
relation bridge, and every axis used must vary *inside* some fragment rather
than only telling fragments apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Iterable, Mapping, Sequence

from body_similarity import FunctionBody
from family_template import (
    axis_report,
    build_family_template,
    infer_variation_axes,
    select_medoid,
)
from slot_overlay import collect_slot_observations


RESCUE_RULE_VERSION = "f7-rescue-v1"

ACCEPTED = "accepted"
REJECTED = "rejected"
BUDGET_BLOCKED = "budget-blocked"

# Rejection reasons, one per acceptance condition.
NO_RELATION_BRIDGE = "no_relation_bridge"
BASIS_NOT_UNIQUE = "basis_not_unique"
TOO_FEW_INDEPENDENT_AXES = "too_few_independent_axes"
BASIS_NOT_COMPLETE = "basis_not_complete"
BASIS_NOT_BIJECTIVE = "basis_not_bijective"
NO_INTERNAL_SUPPORT = "axis_without_internal_fragment_support"
OVER_BUDGET = "comparison_budget"
TOO_MANY_MEMBERS = "component_too_large"

DEFAULT_MAX_COMPONENT_MEMBERS = 64
DEFAULT_MAX_COMPARISONS = 4096
DEFAULT_MAX_ALIGNMENT_CELLS = 500_000_000


@dataclass(frozen=True)
class RescueBudget:
    max_component_members: int = DEFAULT_MAX_COMPONENT_MEMBERS
    max_comparisons: int = DEFAULT_MAX_COMPARISONS
    max_alignment_cells: int = DEFAULT_MAX_ALIGNMENT_CELLS

    def to_dict(self) -> dict[str, int]:
        return {
            "max_component_members": self.max_component_members,
            "max_comparisons": self.max_comparisons,
            "max_alignment_cells": self.max_alignment_cells,
        }


@dataclass
class Component:
    """One rescue hypothesis: accepted fragments joined by 2-view candidates."""

    fragments: tuple[str, ...]
    members: tuple[str, ...]
    bridge_pairs: tuple[tuple[str, str], ...] = ()
    status: str = REJECTED
    reason: str | None = None
    reserved_comparisons: int = 0
    reserved_alignment_cells: int = 0
    report: dict[str, Any] | None = None
    internal_support: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fragments": list(self.fragments),
            "members": list(self.members),
            "member_count": len(self.members),
            "relation_bridge_pair_count": len(self.bridge_pairs),
            "relation_bridge_pairs": [list(pair) for pair in self.bridge_pairs],
            "status": self.status,
            "reason": self.reason,
            "reserved_comparisons": self.reserved_comparisons,
            "reserved_alignment_cells": self.reserved_alignment_cells,
            "internal_fragment_support": dict(sorted(self.internal_support.items())),
            "axis_report": self.report,
        }


# Every input that would change what either side is looking at.
SHARED_PROVENANCE = (
    "stripped_sha256",
    "body_evidence_sha256",
    "raw_graph_sha256",
    "candidate_selection_sha256",
    "projection_config_sha256",
    "anchor_policy",
    "edge_policy",
)


def check_inputs_agree(
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Refuse a strict partition and a rescue queue built from different runs."""
    for field_name in ("case", "build", "profile", "scope"):
        left = family_artifact.get(field_name)
        right = candidate_artifact.get(field_name)
        if left != right:
            raise ValueError(
                f"family and candidate artifacts disagree on {field_name}: "
                f"{left!r} vs {right!r}"
            )

    family_provenance = family_artifact.get("provenance") or {}
    candidate_provenance = candidate_artifact.get("provenance") or {}
    verified: dict[str, Any] = {}
    for field_name in SHARED_PROVENANCE:
        left = family_provenance.get(field_name)
        right = candidate_provenance.get(field_name)
        if left is None or left != right:
            raise ValueError(
                f"family and candidate artifacts disagree on {field_name}: "
                f"{left!r} vs {right!r}"
            )
        verified[field_name] = left

    family_universe = sorted(family_artifact["universe"]["target_ids"])
    candidate_universe = sorted(candidate_artifact["universe"]["target_ids"])
    if family_universe != candidate_universe:
        only_family = sorted(set(family_universe) - set(candidate_universe))
        only_candidate = sorted(set(candidate_universe) - set(family_universe))
        raise ValueError(
            "family and candidate target universes differ: "
            f"{len(only_family)} only in the family artifact, "
            f"{len(only_candidate)} only in the candidate artifact"
        )
    verified["target_count"] = len(family_universe)
    return verified


def accepted_fragments(
    family_artifact: Mapping[str, Any],
) -> dict[str, tuple[str, ...]]:
    """Only `accepted` clusters take part; the other statuses are not families."""
    return {
        cluster["id"]: tuple(sorted(cluster["members"]))
        for cluster in family_artifact["clusters"]
        if cluster["status"] == ACCEPTED
    }


def build_components(
    fragments: Mapping[str, Sequence[str]],
    candidate_pairs: Iterable[Mapping[str, Any]],
) -> list[Component]:
    """Join fragments that a 2-view candidate pair crosses.

    Components are built over *fragments*, never over functions. A function-level
    candidate graph collapses: on ripgrep its largest component reached 1,565
    functions across 1,133 origins.
    """
    fragment_of: dict[str, str] = {}
    for name, members in fragments.items():
        for member in members:
            fragment_of[member] = name

    parent = {name: name for name in fragments}

    def find(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    crossings: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for record in candidate_pairs:
        left, right = record["pair"]
        left_fragment = fragment_of.get(left)
        right_fragment = fragment_of.get(right)
        if left_fragment is None or right_fragment is None:
            continue
        if left_fragment == right_fragment:
            continue
        key = tuple(sorted((left_fragment, right_fragment)))
        if record.get("same_prior_color"):
            crossings.setdefault(key, []).append(tuple(sorted((left, right))))
        else:
            crossings.setdefault(key, [])
        first, second = find(key[0]), find(key[1])
        if first != second:
            parent[first] = second

    grouped: dict[str, list[str]] = {}
    for name in fragments:
        grouped.setdefault(find(name), []).append(name)

    components: list[Component] = []
    for names in grouped.values():
        if len(names) < 2:
            continue
        names = tuple(sorted(names))
        inside = set(names)
        bridges = tuple(sorted(
            pair
            for key, pairs in crossings.items()
            if key[0] in inside and key[1] in inside
            for pair in pairs
        ))
        members = tuple(sorted(
            member for name in names for member in fragments[name]
        ))
        components.append(
            Component(fragments=names, members=members, bridge_pairs=bridges)
        )
    components.sort(key=lambda item: item.fragments)
    return components


def reserve_cost(
    members: Sequence[str],
    bodies: Mapping[str, FunctionBody],
) -> tuple[int, int]:
    """Price a component before running any of it.

    Medoid selection compares every unordered pair, then the chosen medoid is
    aligned against the rest. The medoid is not known yet, so the worst possible
    choice is reserved.
    """
    count = len(members)
    sizes = [len(bodies[member].instructions) for member in members]
    comparisons = count * (count - 1) // 2 + (count - 1)
    pairwise = sum(
        sizes[left] * sizes[right]
        for left, right in combinations(range(count), 2)
    )
    worst_medoid = max(
        (
            sum(sizes[index] * sizes[other] for other in range(count) if other != index)
            for index in range(count)
        ),
        default=0,
    )
    return comparisons, pairwise + worst_medoid


def internal_fragment_support(
    axes: Sequence[Any],
    fragments: Mapping[str, Sequence[str]],
    names: Sequence[str],
) -> dict[str, bool]:
    """Does each axis vary *inside* a fragment, or only between fragments?

    An axis that only separates the fragments may be their identity rather than
    a type parameter, which is exactly how a false 2 x 2 arises.
    """
    support: dict[str, bool] = {}
    for axis in axes:
        support[axis.id] = any(
            len({axis.labels[member] for member in fragments[name]
                 if member in axis.labels}) >= 2
            for name in names
        )
    return support


def evaluate_component(
    component: Component,
    fragments: Mapping[str, Sequence[str]],
    bodies: Mapping[str, FunctionBody],
    observations: Mapping[str, Sequence[Any]],
) -> Component:
    """Apply the six acceptance conditions in order."""
    if not component.bridge_pairs:
        component.status, component.reason = REJECTED, NO_RELATION_BRIDGE
        return component

    selected = {member: bodies[member] for member in component.members}
    selection = select_medoid(selected, list(component.members))
    template = build_family_template(
        selected,
        selection,
        {member: observations[member] for member in component.members},
    )
    report = axis_report(template)
    component.report = report

    if report["independent_axis_count"] < 2:
        component.status, component.reason = REJECTED, TOO_FEW_INDEPENDENT_AXES
        return component
    if report["selected_basis"] is None:
        # Name the condition that actually failed. "No basis" alone would hide
        # whether the product was incomplete, merely not bijective, or genuinely
        # ambiguous, and that difference is what this stage is for.
        maximal = set(report["maximal_axes"])
        pairs = [
            item for item in report["axis_pairs"]
            if {item["first"], item["second"]} <= maximal
        ]
        if not any(item["complete"] for item in pairs):
            reason = BASIS_NOT_COMPLETE
        elif not any(item["bijective"] for item in pairs):
            reason = BASIS_NOT_BIJECTIVE
        else:
            reason = BASIS_NOT_UNIQUE
        component.status, component.reason = REJECTED, reason
        return component

    basis = set(report["selected_basis"])
    pair = next(
        item for item in report["axis_pairs"]
        if {item["first"], item["second"]} == basis
    )
    axes = [axis for axis in infer_variation_axes(template) if axis.id in basis]
    component.internal_support = internal_fragment_support(
        axes, fragments, component.fragments
    )
    if not all(component.internal_support.values()):
        component.status, component.reason = REJECTED, NO_INTERNAL_SUPPORT
        return component

    component.status, component.reason = ACCEPTED, None
    return component


def rescue_families(
    family_artifact: Mapping[str, Any],
    candidate_artifact: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    transfers: Mapping[int, Mapping[int, Mapping[str, Any]]],
    address_of: Mapping[str, int],
    *,
    budget: RescueBudget | None = None,
) -> tuple[list[Component], dict[str, int]]:
    budget = budget or RescueBudget()
    check_inputs_agree(family_artifact, candidate_artifact)
    fragments = accepted_fragments(family_artifact)
    components = build_components(fragments, candidate_artifact["pairs"])

    used_comparisons = used_cells = 0
    for component in components:
        if len(component.members) > budget.max_component_members:
            component.status, component.reason = BUDGET_BLOCKED, TOO_MANY_MEMBERS
            continue
        comparisons, cells = reserve_cost(component.members, bodies)
        component.reserved_comparisons = comparisons
        component.reserved_alignment_cells = cells
        # A component runs whole or not at all: comparing part of one and then
        # giving up would make the outcome depend on the order components were
        # tried.
        if (
            used_comparisons + comparisons > budget.max_comparisons
            or used_cells + cells > budget.max_alignment_cells
        ):
            component.status, component.reason = BUDGET_BLOCKED, OVER_BUDGET
            continue
        used_comparisons += comparisons
        used_cells += cells

        observations = {
            member: collect_slot_observations(
                bodies[member], address_of[member],
                transfers.get(address_of[member], {}),
            )
            for member in component.members
        }
        evaluate_component(component, fragments, bodies, observations)

    return components, {
        "reserved_comparisons": used_comparisons,
        "reserved_alignment_cells": used_cells,
    }


def final_partition(
    family_artifact: Mapping[str, Any],
    components: Sequence[Component],
) -> list[dict[str, Any]]:
    """Accepted components merge; everything else keeps its strict fragments."""
    merged = {
        name: component
        for component in components
        if component.status == ACCEPTED
        for name in component.fragments
    }
    partition: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for cluster in family_artifact["clusters"]:
        if cluster["status"] != ACCEPTED:
            continue
        component = merged.get(cluster["id"])
        if component is None:
            partition.append({
                "id": cluster["id"],
                "members": sorted(cluster["members"]),
                "origin": "strict",
            })
            continue
        if component.fragments in seen:
            continue
        seen.add(component.fragments)
        partition.append({
            "id": "+".join(component.fragments),
            "members": list(component.members),
            "origin": "rescued",
        })
    return partition


def rescued_clusters(
    family_artifact: Mapping[str, Any],
    rescue_artifact: Mapping[str, Any],
    *,
    family_artifact_sha256: str,
) -> list[list[str]]:
    """Validate a rescue artifact against its strict partition, return the final one.

    The rescue stage may only regroup what strict F6 accepted. It may not add a
    function, drop one, or place one in two families, so the member multiset is
    checked rather than trusted.
    """
    if rescue_artifact.get("artifact") != "v1-family-rescue":
        raise ValueError("expected a v1-family-rescue artifact")
    for field_name in ("case", "build", "profile", "scope"):
        left = family_artifact.get(field_name)
        right = rescue_artifact.get(field_name)
        if left != right:
            raise ValueError(
                f"family and rescue artifacts disagree on {field_name}: "
                f"{left!r} vs {right!r}"
            )

    recorded = (rescue_artifact.get("provenance") or {}).get("family_artifact_sha256")
    if not recorded:
        raise ValueError("rescue artifact does not record a family_artifact_sha256")
    if recorded != family_artifact_sha256:
        raise ValueError(
            "rescue artifact was built from family artifact "
            f"{recorded}, not {family_artifact_sha256}"
        )

    strict = accepted_fragments(family_artifact)
    declared = {
        item["id"]: tuple(sorted(item["members"]))
        for item in rescue_artifact["strict_partition"]
    }
    if declared != {name: tuple(sorted(members)) for name, members in strict.items()}:
        raise ValueError(
            "rescue artifact's strict partition does not match the family artifact"
        )

    clusters = [sorted(item["members"]) for item in rescue_artifact["final_partition"]]
    flattened = [member for cluster in clusters for member in cluster]
    duplicates = sorted({m for m in flattened if flattened.count(m) > 1})
    if duplicates:
        raise ValueError(
            f"{len(duplicates)} member(s) appear in more than one rescued family, "
            f"first is {duplicates[0]!r}"
        )
    expected = {member for members in strict.values() for member in members}
    seen = set(flattened)
    missing = sorted(expected - seen)
    added = sorted(seen - expected)
    if missing:
        raise ValueError(
            f"{len(missing)} strict accepted member(s) are absent from the rescued "
            f"partition, first is {missing[0]!r}"
        )
    if added:
        raise ValueError(
            f"{len(added)} member(s) were added by the rescued partition, "
            f"first is {added[0]!r}"
        )
    return clusters
