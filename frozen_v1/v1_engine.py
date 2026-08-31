"""F6: conservative tri-state body-evidence family builder.

This module is intentionally independent of ground truth.  It consumes the
bounded F5 candidate artifact, compares pairs lazily through a cache, and
only accepts complete-link families whose every cross-pair is a strong match.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from body_similarity import FunctionBody, compare_bodies, load_body_evidence  # noqa: E402
from v1_candidates import (  # noqa: E402
    CandidatePair,
    PairKey,
    validate_candidate_artifact,
)


MATCH = "match"
REJECT = "reject"
UNKNOWN = "unknown"
ABSTAIN = "abstain"
DECISIONS = (MATCH, REJECT, UNKNOWN, ABSTAIN)


@dataclass(frozen=True)
class PairFeatures:
    pair: PairKey
    structure_score: float
    aligned_instruction_ratio: float
    sequence_ratio: float
    mnemonic_multiset_jaccard: float
    constant_similarity: float | None
    call_shape_similarity: float | None
    data_reference_similarity: float | None
    same_final_color: bool | None
    same_prior_color: bool | None
    same_out_signature: bool | None
    same_in_signature: bool | None
    both_complete: bool
    opaque_indirect_jumps: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair": self.pair.to_list(),
            "structure_score": self.structure_score,
            "aligned_instruction_ratio": self.aligned_instruction_ratio,
            "sequence_ratio": self.sequence_ratio,
            "mnemonic_multiset_jaccard": self.mnemonic_multiset_jaccard,
            "constant_similarity": self.constant_similarity,
            "call_shape_similarity": self.call_shape_similarity,
            "data_reference_similarity": self.data_reference_similarity,
            "same_final_color": self.same_final_color,
            "same_prior_color": self.same_prior_color,
            "same_out_signature": self.same_out_signature,
            "same_in_signature": self.same_in_signature,
            "both_complete": self.both_complete,
            "opaque_indirect_jumps": self.opaque_indirect_jumps,
        }


@dataclass(frozen=True)
class PairPolicyConfig:
    structure_match_threshold: float
    slot_match_threshold: float
    structure_reject_threshold: float | None = None
    require_informative_slot: bool = True
    abstain_on_opaque_indirect: bool = True
    # Cost ceilings for F4 work. One alignment cell is one left normalized
    # instruction paired with one right one, a deterministic proxy for the
    # O(Ia * Ib) LCS work a comparison actually does.
    max_comparison_count: int | None = None
    max_alignment_cell_budget: int | None = None
    version: str = "v1"

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PairPolicyConfig":
        policy = value.get("policy", value)
        if not isinstance(policy, Mapping):
            raise ValueError("F6 policy must be an object")
        required = {"structure_match_threshold", "slot_match_threshold"}
        missing = required - set(policy)
        if missing:
            raise ValueError(f"F6 policy missing field(s): {sorted(missing)}")
        informative_flag = policy.get("require_informative_slot", True)
        if not isinstance(informative_flag, bool):
            raise ValueError("require_informative_slot must be boolean")
        opaque_flag = policy.get("abstain_on_opaque_indirect", True)
        if not isinstance(opaque_flag, bool):
            raise ValueError("abstain_on_opaque_indirect must be boolean")
        limits = {}
        for name in ("max_comparison_count", "max_alignment_cell_budget"):
            limit = policy.get(name)
            if limit is not None and (
                not isinstance(limit, int) or isinstance(limit, bool) or limit < 0
            ):
                raise ValueError(f"{name} must be a non-negative integer or null")
            limits[name] = limit
        config = cls(
            structure_match_threshold=_threshold(
                policy["structure_match_threshold"], "structure_match_threshold"
            ),
            slot_match_threshold=_threshold(
                policy["slot_match_threshold"], "slot_match_threshold"
            ),
            structure_reject_threshold=(
                None
                if policy.get("structure_reject_threshold") is None
                else _threshold(
                    policy["structure_reject_threshold"],
                    "structure_reject_threshold",
                )
            ),
            require_informative_slot=informative_flag,
            abstain_on_opaque_indirect=opaque_flag,
            max_comparison_count=limits["max_comparison_count"],
            max_alignment_cell_budget=limits["max_alignment_cell_budget"],
            version=str(value.get("version", "v1")),
        )
        return config

    @classmethod
    def from_file(cls, path: str | Path) -> "PairPolicyConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError("F6 config root must be an object")
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "structure_match_threshold": self.structure_match_threshold,
            "slot_match_threshold": self.slot_match_threshold,
            "structure_reject_threshold": self.structure_reject_threshold,
            "require_informative_slot": self.require_informative_slot,
            "abstain_on_opaque_indirect": self.abstain_on_opaque_indirect,
            "max_comparison_count": self.max_comparison_count,
            "max_alignment_cell_budget": self.max_alignment_cell_budget,
        }


@dataclass(frozen=True)
class PairEvaluation:
    pair: PairKey
    decision: str
    features: PairFeatures
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair": self.pair.to_list(),
            "decision": self.decision,
            "source": self.source,
            "features": self.features.to_dict(),
        }


def pair_features_from_bodies(
    first: FunctionBody,
    second: FunctionBody,
    candidate_record: CandidatePair | Mapping[str, Any] | None = None,
) -> PairFeatures:
    """Compute F6 evidence from local bodies only.

    Candidate metadata contributes relation annotations only; it never changes
    the body scores or the tri-state decision.
    """

    pair = PairKey.make(first.id, second.id)
    same_final, same_prior, same_out, same_in = _candidate_flags(candidate_record)
    both_complete = first.complete and second.complete
    if not both_complete:
        return PairFeatures(
            pair=pair,
            structure_score=0.0,
            aligned_instruction_ratio=0.0,
            sequence_ratio=0.0,
            mnemonic_multiset_jaccard=0.0,
            constant_similarity=None,
            call_shape_similarity=None,
            data_reference_similarity=None,
            same_final_color=same_final,
            same_prior_color=same_prior,
            same_out_signature=same_out,
            same_in_signature=same_in,
            both_complete=False,
            opaque_indirect_jumps=max(
                int(first.quality.get("opaque_indirect_jumps", 0)),
                int(second.quality.get("opaque_indirect_jumps", 0)),
            ),
        )

    evidence = compare_bodies(first, second)
    structure_values = (
        float(evidence.aligned_instruction_ratio),
        float(evidence.sequence_ratio),
        float(evidence.mnemonic_multiset_jaccard),
    )
    return PairFeatures(
        pair=pair,
        structure_score=min(structure_values),
        aligned_instruction_ratio=float(evidence.aligned_instruction_ratio),
        sequence_ratio=float(evidence.sequence_ratio),
        mnemonic_multiset_jaccard=float(evidence.mnemonic_multiset_jaccard),
        constant_similarity=_slot_similarity(
            _constant_slots(first), _constant_slots(second)
        ),
        call_shape_similarity=_slot_similarity(
            _call_shape_slots(first), _call_shape_slots(second)
        ),
        data_reference_similarity=_slot_similarity(
            _data_reference_slots(first), _data_reference_slots(second)
        ),
        same_final_color=same_final,
        same_prior_color=same_prior,
        same_out_signature=same_out,
        same_in_signature=same_in,
        both_complete=True,
        opaque_indirect_jumps=max(
            int(first.quality.get("opaque_indirect_jumps", 0)),
            int(second.quality.get("opaque_indirect_jumps", 0)),
        ),
    )


def classify_pair(
    features: PairFeatures,
    config: PairPolicyConfig,
) -> str:
    """Classify one pair without forcing uncertain evidence into a label."""

    if not features.both_complete:
        return ABSTAIN

    # An opaque indirect jump means the body CFG is not fully observed.  It
    # may still be useful for diagnostics, but it must not create a family
    # edge whose primary evidence depends on an incomplete control-flow view.
    if config.abstain_on_opaque_indirect and features.opaque_indirect_jumps > 0:
        return ABSTAIN

    reject_threshold = config.structure_reject_threshold
    if reject_threshold is not None and features.structure_score <= reject_threshold:
        return REJECT

    informative = [
        value
        for value in (
            features.constant_similarity,
            features.data_reference_similarity,
        )
        if value is not None
    ]
    if (
        features.structure_score >= config.structure_match_threshold
        and (
            informative
            if config.require_informative_slot
            else True
        )
        and all(value >= config.slot_match_threshold for value in informative)
    ):
        return MATCH
    return UNKNOWN


class PairEvidenceCache:
    """Memoize candidate and complete-link on-demand comparisons."""

    def __init__(
        self,
        bodies: Mapping[str, FunctionBody],
        candidate_pairs: Iterable[CandidatePair | Mapping[str, Any]],
        config: PairPolicyConfig,
        feature_provider: Callable[[PairKey], PairFeatures] | None = None,
    ) -> None:
        self.bodies = bodies
        self.config = config
        self.feature_provider = feature_provider
        self._candidate_records: dict[PairKey, CandidatePair | Mapping[str, Any]] = {}
        for item in candidate_pairs:
            pair = _pair_from_record(item)
            if pair in self._candidate_records:
                raise ValueError(f"duplicate candidate pair: {pair.to_list()}")
            self._candidate_records[pair] = item
        self._entries: dict[PairKey, PairEvaluation] = {}
        self.candidate_comparisons = 0
        self.on_demand_comparisons = 0
        self.candidate_alignment_cells = 0
        self.on_demand_alignment_cells = 0
        self.abstain_comparisons = 0
        self.cache_hits = 0

    @property
    def entries(self) -> dict[PairKey, PairEvaluation]:
        return dict(self._entries)

    @property
    def total_comparisons(self) -> int:
        return self.candidate_comparisons + self.on_demand_comparisons

    @property
    def total_alignment_cells(self) -> int:
        return self.candidate_alignment_cells + self.on_demand_alignment_cells

    def alignment_cells(self, pair: PairKey) -> int:
        left = self.bodies.get(pair.left)
        right = self.bodies.get(pair.right)
        if left is None or right is None:
            return 0
        return len(left.instructions) * len(right.instructions)

    def would_compare(self, pair: PairKey) -> bool:
        """True when evaluating this pair would actually run F4.

        Cache hits, absent or incomplete bodies and opaque-jump abstains cost
        no alignment work, so they are not charged to the budget.
        """
        if pair in self._entries:
            return False
        left = self.bodies.get(pair.left)
        right = self.bodies.get(pair.right)
        if left is None or right is None or not left.complete or not right.complete:
            return False
        if self.config.abstain_on_opaque_indirect and max(
            int(left.quality.get("opaque_indirect_jumps", 0)),
            int(right.quality.get("opaque_indirect_jumps", 0)),
        ) > 0:
            return False
        return True

    def demand(self, pairs: Iterable[PairKey]) -> tuple[int, int]:
        """How many comparisons and cells running these pairs would cost."""
        required = [pair for pair in pairs if self.would_compare(pair)]
        return len(required), sum(self.alignment_cells(pair) for pair in required)

    def within_budget(self, count: int, cells: int) -> bool:
        limit_count = self.config.max_comparison_count
        limit_cells = self.config.max_alignment_cell_budget
        if limit_count is not None and self.total_comparisons + count > limit_count:
            return False
        if limit_cells is not None and self.total_alignment_cells + cells > limit_cells:
            return False
        return True

    def remaining(self) -> dict[str, int | None]:
        limit_count = self.config.max_comparison_count
        limit_cells = self.config.max_alignment_cell_budget
        return {
            "remaining_comparisons": (
                None if limit_count is None
                else max(0, limit_count - self.total_comparisons)
            ),
            "remaining_alignment_cells": (
                None if limit_cells is None
                else max(0, limit_cells - self.total_alignment_cells)
            ),
        }

    def get_or_compare(self, first: str, second: str) -> str:
        return self.get_evaluation(first, second).decision

    def get_evaluation(self, first: str | PairKey, second: str | None = None) -> PairEvaluation:
        pair = first if isinstance(first, PairKey) else PairKey.make(first, second or "")
        cached = self._entries.get(pair)
        if cached is not None:
            self.cache_hits += 1
            return cached
        candidate_record = self._candidate_records.get(pair)
        source = "candidate" if candidate_record is not None else "on-demand"
        body_a = self.bodies.get(pair.left)
        body_b = self.bodies.get(pair.right)
        bodies_complete = (
            body_a is not None
            and body_b is not None
            and body_a.complete
            and body_b.complete
        )
        opaque_jumps = max(
            int(body_a.quality.get("opaque_indirect_jumps", 0)) if body_a else 0,
            int(body_b.quality.get("opaque_indirect_jumps", 0)) if body_b else 0,
        )
        opaque_abstain = (
            bodies_complete
            and self.config.abstain_on_opaque_indirect
            and opaque_jumps > 0
        )
        if not bodies_complete or opaque_abstain:
            self.abstain_comparisons += 1
            features = _abstain_features(pair, body_a, body_b, candidate_record)
            decision = ABSTAIN
        else:
            cells = self.alignment_cells(pair)
            if source == "candidate":
                self.candidate_comparisons += 1
                self.candidate_alignment_cells += cells
            else:
                self.on_demand_comparisons += 1
                self.on_demand_alignment_cells += cells
        if (
            bodies_complete
            and not opaque_abstain
            and self.feature_provider is not None
        ):
            features = self.feature_provider(pair)
            if features.pair != pair:
                raise ValueError("feature provider returned a non-canonical pair")
            decision = classify_pair(features, self.config)
        elif (
            bodies_complete
            and not opaque_abstain
        ):
            features = pair_features_from_bodies(body_a, body_b, candidate_record)
            decision = classify_pair(features, self.config)
        evaluation = PairEvaluation(
            pair=pair,
            decision=decision,
            features=features,
            source=source,
        )
        self._entries[pair] = evaluation
        return evaluation


def family_id_for_members(members: Iterable[str]) -> str:
    canonical = _canonical_members(members)
    encoded = json.dumps(
        list(canonical), ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    return "family_" + hashlib.sha256(encoded).hexdigest()


def build_family_artifact(
    *,
    candidate_artifact: Mapping[str, Any],
    bodies: Mapping[str, FunctionBody],
    config: PairPolicyConfig,
    feature_provider: Callable[[PairKey], PairFeatures] | None = None,
    body_sha256: str | None = None,
    body_provenance: Mapping[str, Any] | None = None,
    candidate_sha256: str | None = None,
) -> dict[str, Any]:
    """Build accepted/provisional/unresolved/abstain families."""

    validate_candidate_artifact(candidate_artifact)
    target_ids = list(candidate_artifact["universe"]["target_ids"])
    target_set = set(target_ids)
    candidate_provenance = candidate_artifact.get("provenance", {})
    if body_sha256 is not None:
        expected = candidate_provenance.get("body_evidence_sha256")
        if expected != body_sha256:
            raise ValueError("candidate/body evidence SHA-256 mismatch")
    if body_provenance is not None:
        if not isinstance(body_provenance, Mapping):
            raise ValueError("body provenance must be an object")
        for key in (
            "stripped_sha256",
            "candidate_selection_sha256",
            "raw_graph_sha256",
        ):
            expected = candidate_provenance.get(key)
            actual = body_provenance.get(key)
            if expected != actual:
                raise ValueError(f"candidate/body {key} mismatch")

    bodies_for_targets = {
        function_id: bodies[function_id]
        for function_id in target_ids
        if function_id in bodies
    }
    declared_incomplete = set(
        candidate_artifact["universe"]["incomplete_ids"]
    )
    observed_incomplete = {
        function_id
        for function_id, body in bodies_for_targets.items()
        if not body.complete
    }
    if set(bodies_for_targets) == target_set and declared_incomplete != observed_incomplete:
        raise ValueError("candidate/body incomplete-body set mismatch")
    candidate_records = candidate_artifact["pairs"]
    cache = PairEvidenceCache(
        bodies_for_targets,
        candidate_records,
        config,
        feature_provider=feature_provider,
    )
    # Candidates are stored in function-id order, so spending the budget as we
    # walk them would silently pick an arbitrary prefix of the binary. Price
    # the whole artifact first and refuse it outright if it does not fit: the
    # fix belongs in F5, which should produce a smaller artifact.
    candidate_pairs = [_pair_from_record(item) for item in candidate_records]
    candidate_required_count, candidate_required_cells = cache.demand(candidate_pairs)
    if not cache.within_budget(candidate_required_count, candidate_required_cells):
        raise ValueError(
            "candidate artifact exceeds F6 comparison budget: "
            f"{candidate_required_count} comparisons and "
            f"{candidate_required_cells} alignment cells required, limits are "
            f"{config.max_comparison_count} and {config.max_alignment_cell_budget}"
        )
    candidate_evaluations = [cache.get_evaluation(pair) for pair in candidate_pairs]
    match_evaluations = sorted(
        (item for item in candidate_evaluations if item.decision == MATCH),
        key=lambda item: (
            -_match_margin(item.features, config),
            -item.features.structure_score,
            item.pair.left,
            item.pair.right,
        ),
    )

    clusters: dict[str, set[str]] = {function_id: {function_id} for function_id in target_ids}
    blocked_merges: list[dict[str, Any]] = []
    budget_blocked_merges = 0
    for evaluation in match_evaluations:
        left_cluster = _cluster_for(clusters, evaluation.pair.left)
        right_cluster = _cluster_for(clusters, evaluation.pair.right)
        if left_cluster is right_cluster:
            continue
        left_members = sorted(left_cluster)
        right_members = sorted(right_cluster)
        pending = [
            PairKey.make(first, second)
            for first in left_members
            for second in right_members
        ]
        # A merge is allowed or blocked whole. Comparing part of a cross
        # product and then giving up would make the outcome depend on the
        # order merges happen to be tried.
        required_count, required_cells = cache.demand(pending)
        if not cache.within_budget(required_count, required_cells):
            blocked_merges.append({
                "edge": evaluation.pair.to_list(),
                "reason": "comparison_budget",
                "left_members": left_members,
                "right_members": right_members,
                "required_comparisons": required_count,
                "required_alignment_cells": required_cells,
                **cache.remaining(),
            })
            budget_blocked_merges += 1
            continue
        cross_evaluations = [
            cache.get_evaluation(first, second)
            for first in left_members
            for second in right_members
        ]
        if all(item.decision == MATCH for item in cross_evaluations):
            merged = left_cluster | right_cluster
            # Deterministic representative: the lexicographically first
            # member owns the set object after the merge.
            representative = min(merged)
            for member in merged:
                clusters[member] = merged
            clusters[representative] = merged
        else:
            blocked_merges.append({
                "edge": evaluation.pair.to_list(),
                "reason": "cross_pair_mismatch",
                "left_members": left_members,
                "right_members": right_members,
                "blocking_pairs": [
                    {
                        "pair": item.pair.to_list(),
                        "decision": item.decision,
                    }
                    for item in cross_evaluations
                    if item.decision != MATCH
                ],
            })

    final_sets: dict[tuple[str, ...], set[str]] = {}
    for member_set in clusters.values():
        key = tuple(sorted(member_set))
        final_sets[key] = member_set

    accepted_sets = [members for members in final_sets.values() if len(members) >= 2]
    accepted_sets.sort(key=lambda members: tuple(sorted(members)))
    accepted_ids = set().union(*accepted_sets) if accepted_sets else set()
    abstain_reasons: dict[str, str] = {}
    for function_id in target_ids:
        body = bodies_for_targets.get(function_id)
        if body is None:
            abstain_reasons[function_id] = "missing_body"
        elif not body.complete:
            abstain_reasons[function_id] = "incomplete_decode"
        elif (
            config.abstain_on_opaque_indirect
            and int(body.quality.get("opaque_indirect_jumps", 0)) > 0
        ):
            abstain_reasons[function_id] = "opaque_indirect_jump"
    abstain_ids = sorted(abstain_reasons)
    abstain_set = set(abstain_ids)
    usable_ids = target_set - abstain_set
    match_neighbors: dict[str, set[str]] = {function_id: set() for function_id in target_ids}
    for evaluation in cache.entries.values():
        if evaluation.decision != MATCH:
            continue
        left, right = evaluation.pair.left, evaluation.pair.right
        match_neighbors.setdefault(left, set()).add(right)
        match_neighbors.setdefault(right, set()).add(left)
    provisional_ids = sorted(
        function_id
        for function_id in usable_ids - accepted_ids
        if match_neighbors.get(function_id)
    )
    provisional_set = set(provisional_ids)
    unresolved_ids = sorted(usable_ids - accepted_ids - provisional_set)

    cluster_records: list[dict[str, Any]] = []
    for members in accepted_sets:
        ordered = sorted(members)
        cluster_records.append({
            "id": family_id_for_members(ordered),
            "status": "accepted",
            "members": ordered,
        })
    for status, ids in (
        ("provisional", provisional_ids),
        ("unresolved", unresolved_ids),
    ):
        for function_id in ids:
            cluster_records.append({
                "id": family_id_for_members([function_id]),
                "status": status,
                "members": [function_id],
            })
    cluster_records.sort(key=lambda item: item["members"])

    result_provenance = dict(candidate_provenance)
    if body_sha256 is not None:
        result_provenance["body_evidence_sha256"] = body_sha256
    if candidate_sha256 is not None:
        result_provenance["candidate_artifact_sha256"] = candidate_sha256
    output = {
        "schema_version": 1,
        "artifact": "v1-family-grouping",
        "case": candidate_artifact["case"],
        "build": candidate_artifact["build"],
        "profile": candidate_artifact["profile"],
        "scope": candidate_artifact["scope"],
        "config": config.to_dict(),
        "provenance": result_provenance,
        "universe": {
            "target_count": len(target_ids),
            "target_ids": sorted(target_ids),
            "complete_body_count": len(usable_ids),
            "incomplete_ids": sorted(abstain_set),
        },
        "clusters": cluster_records,
        "status_members": {
            "accepted": sorted(accepted_ids),
            "provisional": provisional_ids,
            "unresolved": unresolved_ids,
            "abstain": abstain_ids,
        },
        "abstain_reasons": abstain_reasons,
        "pair_decisions": [
            cache.entries[pair].to_dict()
            for pair in sorted(cache.entries)
        ],
        "blocked_merges": blocked_merges,
        "metrics": {
            "candidate_detailed_comparison_count": cache.candidate_comparisons,
            "on_demand_comparison_count": cache.on_demand_comparisons,
            "cache_hit_count": cache.cache_hits,
            "abstain_comparison_count": cache.abstain_comparisons,
            "total_detailed_comparisons": cache.total_comparisons,
            "candidate_alignment_cells": cache.candidate_alignment_cells,
            "on_demand_alignment_cells": cache.on_demand_alignment_cells,
            "total_alignment_cells": cache.total_alignment_cells,
            "budget_blocked_merge_count": budget_blocked_merges,
            "budget_limited": budget_blocked_merges > 0,
            **cache.remaining(),
        },
    }
    _validate_family_statuses(output)
    return output


def write_family_artifact(path: str | Path, artifact: Mapping[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _candidate_flags(
    record: CandidatePair | Mapping[str, Any] | None,
) -> tuple[bool | None, bool | None, bool | None, bool | None]:
    if record is None:
        return None, None, None, None
    if isinstance(record, CandidatePair):
        return (
            record.same_final_color,
            record.same_prior_color,
            record.same_out_signature,
            record.same_in_signature,
        )
    return tuple(record.get(key) for key in (
        "same_final_color",
        "same_prior_color",
        "same_out_signature",
        "same_in_signature",
    ))  # type: ignore[return-value]


def _pair_from_record(
    record: CandidatePair | Mapping[str, Any] | PairKey,
) -> PairKey:
    if isinstance(record, PairKey):
        return record
    if isinstance(record, CandidatePair):
        return record.pair
    if "first" in record and "second" in record:
        pair = PairKey.make(record["first"], record["second"])
    else:
        values = record.get("pair")
        if not isinstance(values, (list, tuple)) or len(values) != 2:
            raise ValueError("candidate pair record has no pair identity")
        pair = PairKey.make(values[0], values[1])
    return pair


def _abstain_features(
    pair: PairKey,
    first: FunctionBody | None,
    second: FunctionBody | None,
    record: CandidatePair | Mapping[str, Any] | None,
) -> PairFeatures:
    same_final, same_prior, same_out, same_in = _candidate_flags(record)
    return PairFeatures(
        pair=pair,
        structure_score=0.0,
        aligned_instruction_ratio=0.0,
        sequence_ratio=0.0,
        mnemonic_multiset_jaccard=0.0,
        constant_similarity=None,
        call_shape_similarity=None,
        data_reference_similarity=None,
        same_final_color=same_final,
        same_prior_color=same_prior,
        same_out_signature=same_out,
        same_in_signature=same_in,
        both_complete=(first is not None and second is not None and first.complete and second.complete),
        opaque_indirect_jumps=max(
            int(first.quality.get("opaque_indirect_jumps", 0)) if first else 0,
            int(second.quality.get("opaque_indirect_jumps", 0)) if second else 0,
        ),
    )


def _constant_slots(body: FunctionBody) -> Counter[Any]:
    return Counter(
        _freeze(value)
        for instruction in body.instructions
        for value in instruction.get("constants", ())
    )


def _call_shape_slots(body: FunctionBody) -> Counter[Any]:
    return Counter(
        tuple(instruction.get("operands", ()))
        for instruction in body.instructions
        if instruction.get("control_flow") == "call"
    )


def _data_reference_slots(body: FunctionBody) -> Counter[Any]:
    return Counter(
        (
            slot.get("kind"),
            slot.get("status"),
            _freeze(slot.get("value")),
            _freeze(slot.get("resolver")),
        )
        for instruction in body.instructions
        for slot in instruction.get("slots", ())
        if slot.get("kind") == "data"
    )


def _slot_similarity(first: Counter[Any], second: Counter[Any]) -> float | None:
    if not first and not second:
        return None
    if not first or not second:
        return 0.0
    union = sum((first | second).values())
    return sum((first & second).values()) / union if union else 1.0


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), _freeze(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set):
        return tuple(sorted((_freeze(item) for item in value), key=repr))
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value


def _match_margin(features: PairFeatures, config: PairPolicyConfig) -> float:
    values = [
        features.structure_score - config.structure_match_threshold,
    ]
    informative = [
        value
        for value in (
            features.constant_similarity,
            features.data_reference_similarity,
        )
        if value is not None
    ]
    if config.require_informative_slot and not informative:
        return float("-inf")
    values.extend(value - config.slot_match_threshold for value in informative)
    return min(values)


def _cluster_for(clusters: Mapping[str, set[str]], member: str) -> set[str]:
    return clusters[member]


def _canonical_members(members: Iterable[str]) -> tuple[str, ...]:
    values = list(members)
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise ValueError("family members must be non-empty strings")
    if len(set(values)) != len(values):
        raise ValueError("family members must be unique")
    return tuple(sorted(values))


def _validate_family_statuses(artifact: Mapping[str, Any]) -> None:
    statuses = artifact["status_members"]
    target_ids = set(artifact["universe"]["target_ids"])
    buckets = [set(statuses[name]) for name in ("accepted", "provisional", "unresolved", "abstain")]
    if any(left & right for index, left in enumerate(buckets) for right in buckets[index + 1:]):
        raise ValueError("family status buckets overlap")
    if set().union(*buckets) != target_ids:
        raise ValueError("family status buckets do not cover the target universe")


def _threshold(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    value = float(value)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be between 0 and 1")
    return value


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="F6: conservatively build family groups from an F5 artifact."
    )
    parser.add_argument("candidate_artifact")
    parser.add_argument("--body-evidence", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        candidate = json.loads(Path(args.candidate_artifact).read_text(encoding="utf-8"))
        body_artifact = json.loads(Path(args.body_evidence).read_text(encoding="utf-8"))
        bodies = load_body_evidence(body_artifact)
        for key in ("case", "build", "profile", "scope"):
            if body_artifact.get(key) != candidate.get(key):
                raise ValueError(f"candidate/body {key} mismatch")
        config = PairPolicyConfig.from_file(args.config)
        body_sha256 = hashlib.sha256(Path(args.body_evidence).read_bytes()).hexdigest()
        report = build_family_artifact(
            candidate_artifact=candidate,
            bodies=bodies,
            config=config,
            body_sha256=body_sha256,
            body_provenance=body_artifact.get("provenance"),
            candidate_sha256=hashlib.sha256(
                Path(args.candidate_artifact).read_bytes()
            ).hexdigest(),
        )
        write_family_artifact(args.output, report)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.output}")
    print(f"accepted_families={sum(item['status'] == 'accepted' for item in report['clusters'])}")
    print(f"total_comparisons={report['metrics']['total_detailed_comparisons']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
