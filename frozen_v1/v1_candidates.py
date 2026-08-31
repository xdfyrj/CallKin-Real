"""F5: retrieve a small, deterministic set of body-comparison candidates.

F5 is deliberately a retrieval step, not a family classifier.  It knows
about function bodies and the V0 relation partition, but it never reads
ground truth and it never decides that a pair has the same origin.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from body_similarity import FunctionBody, load_body_evidence  # noqa: E402
from engine import CGWLMode, CG_WL_MODES, CGWLResult, run_cg_wl  # noqa: E402
from loader import load_case  # noqa: E402
from paths import (  # noqa: E402
    ANALYSIS_TRACKS,
    ANCHOR_POLICIES,
    CANDIDATE_SCOPES,
    DEFAULT_BUILD,
    DEFAULT_PROFILE,
    body_evidence_for,
    normalize_build,
    normalize_anchor_policy,
    normalize_candidate_scope,
    normalize_profile,
    normalize_track,
    resolve_fixture_json,
)
from v1_retrieval_views import (  # noqa: E402
    MULTI_VIEW_NAMES,
    VIEW_NAMES,
    VIEW_PROFILE_VERSIONS,
    build_cfg_profiles,
    build_relation_profiles,
    build_token_profiles,
    cfg_similarity,
    relation_similarity,
    token_similarity,
)


ARTIFACT_SCHEMA_VERSION = 1
ARTIFACT_NAME = "v1-candidate-pairs"
MULTIVIEW_ARTIFACT_SCHEMA_VERSION = 2
MULTIVIEW_ARTIFACT_NAME = "v1-multiview-candidate-pairs"
NGRAM_SIZE = 3


@dataclass(frozen=True, order=True)
class PairKey:
    """Canonical undirected pair identity."""

    left: str
    right: str

    @staticmethod
    def make(first: str, second: str) -> "PairKey":
        if not isinstance(first, str) or not first:
            raise ValueError("pair member must be a non-empty string")
        if not isinstance(second, str) or not second:
            raise ValueError("pair member must be a non-empty string")
        if first == second:
            raise ValueError("self pair")
        return PairKey(*sorted((first, second)))

    def to_list(self) -> list[str]:
        return [self.left, self.right]


@dataclass(frozen=True)
class CheapBodyProfile:
    function_id: str
    size: int
    instruction_count: int
    block_count: int
    mnemonic_counts: tuple[tuple[str, int], ...]
    mnemonic_ngrams: frozenset[tuple[str, ...]]
    exact_mnemonic_hash: str

    @property
    def signature(self) -> tuple[Any, ...]:
        return (
            self.size,
            self.instruction_count,
            self.block_count,
            self.mnemonic_counts,
            self.mnemonic_ngrams,
        )

    @property
    def has_evidence(self) -> bool:
        """Whether this body has any instruction-level retrieval evidence."""

        return self.instruction_count > 0


@dataclass
class CandidatePair:
    pair: PairKey
    reasons: set[str] = field(default_factory=set)
    cheap_score: float = 0.0
    body_rank: int | None = None
    relation_rank: int | None = None
    last_shared_round: int | None = None
    same_out_signature: bool | None = None
    same_in_signature: bool | None = None
    same_final_color: bool | None = None
    same_prior_color: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair": self.pair.to_list(),
            "first": self.pair.left,
            "second": self.pair.right,
            "reasons": sorted(self.reasons),
            "cheap_score": self.cheap_score,
            "body_rank": self.body_rank,
            "relation_rank": self.relation_rank,
            "last_shared_round": self.last_shared_round,
            "same_out_signature": self.same_out_signature,
            "same_in_signature": self.same_in_signature,
            "same_final_color": self.same_final_color,
            "same_prior_color": self.same_prior_color,
        }


@dataclass
class MultiViewCandidatePair:
    """A candidate annotated with the independent views that selected it."""

    pair: PairKey
    views: dict[str, dict[str, float | int] | None]
    reasons: set[str] = field(default_factory=set)
    last_shared_round: int | None = None
    same_out_signature: bool | None = None
    same_in_signature: bool | None = None
    same_final_color: bool | None = None
    same_prior_color: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pair": self.pair.to_list(),
            "first": self.pair.left,
            "second": self.pair.right,
            "reasons": sorted(self.reasons),
            "views": {
                name: self.views[name]
                for name in sorted(self.views)
            },
            "last_shared_round": self.last_shared_round,
            "same_out_signature": self.same_out_signature,
            "same_in_signature": self.same_in_signature,
            "same_final_color": self.same_final_color,
            "same_prior_color": self.same_prior_color,
        }


def build_cheap_profiles(
    bodies: Mapping[str, FunctionBody],
) -> dict[str, CheapBodyProfile]:
    """Compute the retrieval-only profile once per body."""

    profiles: dict[str, CheapBodyProfile] = {}
    for function_id in sorted(bodies):
        body = bodies[function_id]
        mnemonics = tuple(
            str(item.get("mnemonic_class", "UNKNOWN"))
            for item in body.instructions
        )
        counts = Counter(mnemonics)
        encoded = json.dumps(
            list(mnemonics), ensure_ascii=True, separators=(",", ":")
        ).encode("utf-8")
        profiles[function_id] = CheapBodyProfile(
            function_id=function_id,
            size=int(body.size),
            instruction_count=len(body.instructions),
            block_count=len(body.blocks),
            mnemonic_counts=tuple(sorted(counts.items())),
            mnemonic_ngrams=frozenset(_ngrams(mnemonics)),
            exact_mnemonic_hash=hashlib.sha256(encoded).hexdigest(),
        )
    return profiles


def cheap_body_similarity(
    first: CheapBodyProfile,
    second: CheapBodyProfile,
) -> float:
    """Return the untrained retrieval score in [0, 1]."""

    values = (
        _ratio(first.size, second.size),
        _ratio(first.instruction_count, second.instruction_count),
        _ratio(first.block_count, second.block_count),
        _tuple_counter_jaccard(first.mnemonic_counts, second.mnemonic_counts),
        _set_jaccard(first.mnemonic_ngrams, second.mnemonic_ngrams),
    )
    return sum(values) / len(values)


def generate_candidate_pairs(
    bodies: Mapping[str, FunctionBody],
    *,
    top_k: int,
    final_groups: Iterable[Iterable[str]] | None = None,
    prior_round_groups: Iterable[tuple[int, Iterable[Iterable[str]]]] | None = None,
    final_round: int | None = None,
    out_signatures: Mapping[str, Any] | None = None,
    in_signatures: Mapping[str, Any] | None = None,
) -> list[CandidatePair]:
    """Generate the union of body and relation top-k retrieval results.

    The function intentionally never expands a whole color group into its
    Cartesian product.  Every source contributes at most ``top_k`` targets
    per retrieval source, and records from the different sources are merged
    by their canonical :class:`PairKey`.
    """

    _validate_top_k(top_k)
    profiles = build_cheap_profiles(bodies)
    complete_ids = sorted(
        function_id
        for function_id in profiles
        if bodies[function_id].complete
    )
    profile_signatures = {
        function_id: _cheap_profile_signature(profile)
        for function_id, profile in profiles.items()
    }
    score_cache: dict[frozenset[Any], float] = {}

    def score_pair(first: str, second: str) -> float:
        # IDs do not affect the cheap profile.  Reusing scores for identical
        # profile signatures is important in real binaries where many
        # monomorphized siblings have the same local shape.
        key = frozenset((profile_signatures[first], profile_signatures[second]))
        value = score_cache.get(key)
        if value is None:
            value = cheap_body_similarity(profiles[first], profiles[second])
        score_cache[key] = value
        return value

    records: dict[PairKey, CandidatePair] = {}

    def add(
        first: str,
        second: str,
        *,
        reason: str,
        score: float,
        body_rank: int | None = None,
        relation_rank: int | None = None,
        shared_round: int | None = None,
    ) -> None:
        pair = PairKey.make(first, second)
        record = records.get(pair)
        if record is None:
            record = CandidatePair(pair=pair, cheap_score=float(score))
            records[pair] = record
        record.reasons.add(reason)
        record.cheap_score = max(record.cheap_score, float(score))
        record.body_rank = _minimum_rank(record.body_rank, body_rank)
        record.relation_rank = _minimum_rank(record.relation_rank, relation_rank)
        if shared_round is not None:
            record.last_shared_round = _maximum_round(
                record.last_shared_round, shared_round
            )

    # Retrieval source 1: each complete body receives its nearest complete
    # neighbors.  The score is symmetric, so each unordered pair is scored
    # once and contributes to both endpoint heaps.  This is independent of
    # the V0 partition, so a family split into different colors can still meet.
    for source, ranked in _symmetric_top_k(
        complete_ids,
        top_k=top_k,
        score=score_pair,
        group_key=lambda member: profile_signatures[member],
    ).items():
        for rank, (pair_score, target) in enumerate(ranked, start=1):
            add(
                source,
                target,
                reason="body_top_k",
                score=pair_score,
                body_rank=rank,
            )

    final_membership = _membership(final_groups)
    if final_groups is not None:
        _add_relation_top_k(
            profiles,
            bodies,
            final_membership,
            top_k=top_k,
            reason="same_final_color",
            add=add,
            shared_round=final_round,
            score_fn=score_pair,
        )

    prior_memberships: list[tuple[int, dict[str, int]]] = []
    if prior_round_groups is not None:
        for round_index, groups in prior_round_groups:
            membership = _membership(groups)
            prior_memberships.append((int(round_index), membership))
            _add_relation_top_k(
                profiles,
                bodies,
                membership,
                top_k=top_k,
                reason="same_prior_round_color",
                add=add,
                shared_round=int(round_index),
                score_fn=score_pair,
            )

    # Exact mnemonic equality is an annotation on an already selected pair,
    # never an instruction to generate every pair in a large hash bucket.
    for record in records.values():
        if (
            profiles[record.pair.left].exact_mnemonic_hash
            == profiles[record.pair.right].exact_mnemonic_hash
        ):
            record.reasons.add("same_exact_mnemonic_hash")

    for record in records.values():
        record.same_final_color = _same_membership(
            final_membership, record.pair.left, record.pair.right
        )
        record.same_prior_color = _same_prior_membership(
            prior_memberships, record.pair.left, record.pair.right
        )
        record.same_out_signature = _same_mapping_value(
            out_signatures, record.pair.left, record.pair.right
        )
        record.same_in_signature = _same_mapping_value(
            in_signatures, record.pair.left, record.pair.right
        )

    return sorted(
        records.values(),
        key=lambda item: (item.pair.left, item.pair.right),
    )


def generate_multiview_candidate_pairs(
    bodies: Mapping[str, FunctionBody],
    *,
    top_k: int,
    views: Iterable[str] = MULTI_VIEW_NAMES,
    final_groups: Iterable[Iterable[str]] | None = None,
    prior_round_groups: Iterable[tuple[int, Iterable[Iterable[str]]]] | None = None,
    final_round: int | None = None,
    out_signatures: Mapping[str, Any] | None = None,
    in_signatures: Mapping[str, Any] | None = None,
    anchor_classes: Mapping[str, str] | None = None,
) -> list[MultiViewCandidatePair]:
    """Retrieve candidates through independent view-specific top-k searches.

    A view ranks pairs using only its own profile.  The returned records are
    the union of those bounded searches; no view is allowed to re-rank another
    view's candidates.
    """

    _validate_top_k(top_k)
    active_views = _normalize_views(views)
    final_groups = (
        [list(group) for group in final_groups]
        if final_groups is not None
        else None
    )
    prior_round_groups = (
        [
            (int(round_index), [list(group) for group in groups])
            for round_index, groups in prior_round_groups
        ]
        if prior_round_groups is not None
        else None
    )
    profiles = build_cheap_profiles(bodies) if "composite" in active_views else {}
    token_profiles = build_token_profiles(bodies) if "token" in active_views else {}
    cfg_profiles = build_cfg_profiles(bodies) if "cfg" in active_views else {}
    relation_profiles = (
        build_relation_profiles(
            bodies.keys(),
            final_groups=final_groups,
            prior_round_groups=prior_round_groups,
            final_round=final_round,
            out_signatures=out_signatures,
            in_signatures=in_signatures,
            anchor_classes=anchor_classes,
        )
        if "relation" in active_views
        else {}
    )
    profile_maps: dict[str, Mapping[str, Any]] = {
        "composite": profiles,
        "token": token_profiles,
        "cfg": cfg_profiles,
        "relation": relation_profiles,
    }
    score_functions: dict[str, Any] = {
        "composite": cheap_body_similarity,
        "token": token_similarity,
        "cfg": cfg_similarity,
        "relation": relation_similarity,
    }
    complete_ids = sorted(
        function_id
        for function_id, body in bodies.items()
        if body.complete
    )
    records: dict[PairKey, MultiViewCandidatePair] = {}

    final_membership = _membership(final_groups)
    prior_memberships = []
    if prior_round_groups is not None:
        prior_memberships = [
            (int(round_index), _membership(groups))
            for round_index, groups in prior_round_groups
        ]

    def add(
        first: str,
        second: str,
        *,
        view: str,
        score: float,
        rank: int,
    ) -> None:
        pair = PairKey.make(first, second)
        record = records.get(pair)
        if record is None:
            record = MultiViewCandidatePair(
                pair=pair,
                views={name: None for name in active_views},
            )
            records[pair] = record
        previous = record.views[view]
        if previous is None:
            record.views[view] = {"score": float(score), "rank": int(rank)}
        else:
            previous["score"] = max(float(previous["score"]), float(score))
            previous["rank"] = min(int(previous["rank"]), int(rank))
        record.reasons.add(f"{view}_top_k")

    for view in active_views:
        view_profiles = profile_maps[view]
        score_fn = score_functions[view]
        eligible_ids = [
            function_id
            for function_id in complete_ids
            if view_profiles[function_id].has_evidence
        ]
        if len(eligible_ids) < 2:
            continue
        signatures = {
            function_id: _view_profile_signature(view_profiles[function_id])
            for function_id in eligible_ids
        }

        def score_pair(first: str, second: str, *, _fn=score_fn, _profiles=view_profiles) -> float:
            return float(_fn(_profiles[first], _profiles[second]))

        ranked_by_source = _symmetric_top_k(
            eligible_ids,
            top_k=top_k,
            score=score_pair,
            group_key=lambda member, _signatures=signatures: _signatures[member],
        )
        selected_rank_by_source: dict[str, int] = defaultdict(int)
        for source, ranked in ranked_by_source.items():
            for score, target in ranked:
                if score <= 0.0:
                    continue
                selected_rank_by_source[source] += 1
                add(
                    source,
                    target,
                    view=view,
                    score=score,
                    rank=selected_rank_by_source[source],
                )

    for record in records.values():
        record.same_final_color = _same_membership(
            final_membership,
            record.pair.left,
            record.pair.right,
        )
        record.same_prior_color = _same_prior_membership(
            prior_memberships,
            record.pair.left,
            record.pair.right,
        )
        record.same_out_signature = _same_mapping_value(
            out_signatures,
            record.pair.left,
            record.pair.right,
        )
        record.same_in_signature = _same_mapping_value(
            in_signatures,
            record.pair.left,
            record.pair.right,
        )
        record.last_shared_round = _last_shared_round(
            record.pair.left,
            record.pair.right,
            final_membership,
            prior_memberships,
            final_round,
        )

    return sorted(
        records.values(),
        key=lambda item: (item.pair.left, item.pair.right),
    )


def relation_context_from_cgwl(
    case: Any,
    result: CGWLResult,
) -> dict[str, Any]:
    """Extract deterministic relation groups/signatures from one V0 run."""

    final_groups = [list(group) for group in result.clusters]
    trace = list(result.trace)
    final_round = trace[-1].round_index if trace else result.rounds
    prior_round_groups = [
        (step.round_index, [list(group) for group in step.clusters])
        for step in trace[:-1]
    ]

    out_signatures: dict[str, tuple[tuple[str, int], ...]] = {}
    in_values: defaultdict[str, list[tuple[str, int]]] = defaultdict(list)
    for node in case.nodes:
        outgoing = tuple(sorted((call.target, int(call.count)) for call in node.calls))
        out_signatures[node.id] = outgoing
        for call in node.calls:
            in_values[call.target].append((node.id, int(call.count)))
    in_signatures = {
        node_id: tuple(sorted(in_values.get(node_id, [])))
        for node_id in out_signatures
    }
    anchor_classes = {
        node.id: node.color_class
        for node in case.nodes
        if node.type == "anchor" and node.color_class is not None
    }
    return {
        "final_groups": final_groups,
        "prior_round_groups": prior_round_groups,
        "final_round": final_round,
        "out_signatures": out_signatures,
        "in_signatures": in_signatures,
        "anchor_classes": anchor_classes,
        "mode": result.mode,
        "rounds": result.rounds,
    }


def build_candidate_artifact(
    *,
    case: str,
    build: str,
    profile: str,
    scope: str,
    bodies: Mapping[str, FunctionBody],
    pairs: Iterable[CandidatePair],
    top_k: int,
    provenance: Mapping[str, Any],
    relation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_top_k(top_k)
    normalized_build = normalize_build(build)
    normalized_profile = normalize_profile(profile)
    normalized_scope = normalize_candidate_scope(scope)
    pair_records = sorted(
        (item.to_dict() for item in pairs),
        key=lambda item: (item["first"], item["second"]),
    )
    target_ids = sorted(bodies)
    incomplete_ids = sorted(
        function_id for function_id in target_ids if not bodies[function_id].complete
    )
    result: dict[str, Any] = {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "artifact": ARTIFACT_NAME,
        "case": case,
        "build": normalized_build,
        "profile": normalized_profile,
        "scope": normalized_scope,
        "config": {
            "top_k": top_k,
            "body_profile": "mnemonic+size+block",
            "ngram_size": NGRAM_SIZE,
        },
        "provenance": dict(provenance),
        "universe": {
            "target_count": len(target_ids),
            "complete_body_count": len(target_ids) - len(incomplete_ids),
            "incomplete_ids": incomplete_ids,
            "target_ids": target_ids,
        },
        "pairs": pair_records,
    }
    if relation is not None:
        result["relation"] = _json_safe_relation_metadata(relation)
    return result


def build_multiview_candidate_artifact(
    *,
    case: str,
    build: str,
    profile: str,
    scope: str,
    bodies: Mapping[str, FunctionBody],
    pairs: Iterable[MultiViewCandidatePair],
    top_k: int,
    views: Iterable[str],
    provenance: Mapping[str, Any],
    relation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the schema-2 artifact consumed by the existing F6 engine."""

    _validate_top_k(top_k)
    active_views = _normalize_views(views)
    normalized_build = normalize_build(build)
    normalized_profile = normalize_profile(profile)
    normalized_scope = normalize_candidate_scope(scope)
    pair_records = sorted(
        (item.to_dict() for item in pairs),
        key=lambda item: (item["first"], item["second"]),
    )
    target_ids = sorted(bodies)
    incomplete_ids = sorted(
        function_id
        for function_id in target_ids
        if not bodies[function_id].complete
    )
    result: dict[str, Any] = {
        "schema_version": MULTIVIEW_ARTIFACT_SCHEMA_VERSION,
        "artifact": MULTIVIEW_ARTIFACT_NAME,
        "case": case,
        "build": normalized_build,
        "profile": normalized_profile,
        "scope": normalized_scope,
        "config": {
            "top_k": top_k,
            "view_top_k": {name: top_k for name in active_views},
            "views": list(active_views),
            "view_profiles": {
                name: VIEW_PROFILE_VERSIONS[name]
                for name in active_views
            },
        },
        "provenance": dict(provenance),
        "universe": {
            "target_count": len(target_ids),
            "complete_body_count": len(target_ids) - len(incomplete_ids),
            "incomplete_ids": incomplete_ids,
            "target_ids": target_ids,
        },
        "pairs": pair_records,
    }
    if relation is not None:
        result["relation"] = _json_safe_relation_metadata(relation)
    validate_candidate_artifact(result)
    return result


def validate_candidate_artifact(artifact: Mapping[str, Any]) -> None:
    """Validate the stable F5 interchange format before F6 consumes it."""

    required = {
        "schema_version", "artifact", "case", "build", "profile", "scope",
        "config", "provenance", "universe", "pairs",
    }
    optional = {"relation"}
    if not isinstance(artifact, Mapping):
        raise ValueError("candidate artifact must be an object")
    missing = required - set(artifact)
    unknown = set(artifact) - required - optional
    if missing:
        raise ValueError(f"candidate artifact missing field(s): {sorted(missing)}")
    if unknown:
        raise ValueError(f"candidate artifact has unknown field(s): {sorted(unknown)}")
    is_multiview = (
        artifact["schema_version"] == MULTIVIEW_ARTIFACT_SCHEMA_VERSION
        and artifact["artifact"] == MULTIVIEW_ARTIFACT_NAME
    )
    is_legacy = (
        artifact["schema_version"] == ARTIFACT_SCHEMA_VERSION
        and artifact["artifact"] == ARTIFACT_NAME
    )
    if not is_multiview and not is_legacy:
        raise ValueError("unsupported candidate artifact schema/name")
    if not isinstance(artifact["case"], str) or not artifact["case"]:
        raise ValueError("candidate artifact case must be non-empty")
    normalize_build(artifact["build"])
    normalize_profile(artifact["profile"])
    normalize_candidate_scope(artifact["scope"])

    config = artifact["config"]
    if is_multiview:
        active_views = _validate_multiview_config(config)
    else:
        active_views = ()
        if not isinstance(config, Mapping) or set(config) != {
            "top_k", "body_profile", "ngram_size"
        }:
            raise ValueError("candidate artifact config has an invalid schema")
        _validate_top_k(config["top_k"])
        if config["body_profile"] != "mnemonic+size+block":
            raise ValueError("unsupported candidate body profile")
        if config["ngram_size"] != NGRAM_SIZE:
            raise ValueError("unsupported candidate ngram size")
    if not isinstance(artifact["provenance"], Mapping):
        raise ValueError("candidate artifact provenance must be an object")

    universe = artifact["universe"]
    if not isinstance(universe, Mapping) or set(universe) != {
        "target_count", "complete_body_count", "incomplete_ids", "target_ids"
    }:
        raise ValueError("candidate artifact universe has an invalid schema")
    target_ids = universe["target_ids"]
    if (
        not isinstance(target_ids, list)
        or target_ids != sorted(target_ids)
        or len(set(target_ids)) != len(target_ids)
        or any(not isinstance(item, str) or not item for item in target_ids)
    ):
        raise ValueError("candidate artifact target_ids must be sorted and unique")
    incomplete_ids = universe["incomplete_ids"]
    if (
        not isinstance(incomplete_ids, list)
        or incomplete_ids != sorted(incomplete_ids)
        or len(set(incomplete_ids)) != len(incomplete_ids)
        or not set(incomplete_ids).issubset(target_ids)
    ):
        raise ValueError("candidate artifact incomplete_ids are invalid")
    if universe["target_count"] != len(target_ids):
        raise ValueError("candidate artifact target_count mismatch")
    if universe["complete_body_count"] != len(target_ids) - len(incomplete_ids):
        raise ValueError("candidate artifact complete_body_count mismatch")

    pairs = artifact["pairs"]
    if not isinstance(pairs, list):
        raise ValueError("candidate artifact pairs must be a list")
    previous: tuple[str, str] | None = None
    for index, item in enumerate(pairs):
        if not isinstance(item, Mapping):
            raise ValueError(f"pairs[{index}] must be an object")
        required_pair_keys = (
            {
                "pair", "first", "second", "reasons", "views",
                "last_shared_round", "same_out_signature", "same_in_signature",
                "same_final_color", "same_prior_color",
            }
            if is_multiview
            else {
                "pair", "first", "second", "reasons", "cheap_score", "body_rank",
                "relation_rank", "last_shared_round", "same_out_signature",
                "same_in_signature", "same_final_color", "same_prior_color",
            }
        )
        if set(item) != required_pair_keys:
            raise ValueError(f"pairs[{index}] has an invalid schema")
        pair = PairKey.make(item["first"], item["second"])
        if item["first"] != pair.left or item["second"] != pair.right:
            raise ValueError(f"pairs[{index}] first/second are not canonical")
        if item["pair"] != pair.to_list():
            raise ValueError(f"pairs[{index}].pair is not canonical")
        if pair.left not in target_ids or pair.right not in target_ids:
            raise ValueError(f"pairs[{index}] references an unknown target")
        key = (pair.left, pair.right)
        if previous is not None and key <= previous:
            raise ValueError("candidate pairs must be sorted and unique")
        previous = key
        if (
            not isinstance(item["reasons"], list)
            or item["reasons"] != sorted(item["reasons"])
            or not item["reasons"]
            or any(not isinstance(reason, str) or not reason for reason in item["reasons"])
        ):
            raise ValueError(f"pairs[{index}].reasons is invalid")
        if is_multiview:
            _validate_multiview_pair(item, active_views, index)
        else:
            score = item["cheap_score"]
            if not isinstance(score, (int, float)) or isinstance(score, bool) or not math.isfinite(score) or not 0.0 <= score <= 1.0:
                raise ValueError(f"pairs[{index}].cheap_score is invalid")
            for key_name in ("body_rank", "relation_rank"):
                value = item[key_name]
                if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
                    raise ValueError(f"pairs[{index}].{key_name} is invalid")
        shared_round = item["last_shared_round"]
        if shared_round is not None and (
            not isinstance(shared_round, int)
            or isinstance(shared_round, bool)
            or shared_round < 0
        ):
            raise ValueError(f"pairs[{index}].last_shared_round is invalid")
        for key_name in (
            "same_out_signature", "same_in_signature", "same_final_color", "same_prior_color"
        ):
            if item[key_name] is not None and not isinstance(item[key_name], bool):
                raise ValueError(f"pairs[{index}].{key_name} is invalid")


def build_candidate_artifact_from_files(
    *,
    body_path: str | Path,
    fixture_path: str | Path,
    top_k: int,
    mode: CGWLMode,
    track: str | None = None,
    candidate_scope: str | None = None,
    anchor_policy: str | None = None,
) -> dict[str, Any]:
    """Load one body/fixture pair, validate the join, and run F5."""

    _validate_top_k(top_k)
    if mode not in CG_WL_MODES:
        raise ValueError(f"unknown CG-WL mode: {mode!r}")
    body_file = Path(body_path)
    fixture_file = Path(fixture_path)
    body_artifact = json.loads(body_file.read_text(encoding="utf-8"))
    bodies = load_body_evidence(body_artifact)
    case = load_case(str(fixture_file))
    _validate_body_fixture_join(body_artifact, case)
    analysis = case.analysis.to_dict() if case.analysis is not None else {}
    requested = {
        "track": normalize_track(track) if track is not None else None,
        "candidate_scope": normalize_candidate_scope(candidate_scope) if candidate_scope is not None else None,
        "anchor_policy": anchor_policy,
    }
    if case.analysis is None:
        # Schema v4 controlled fixtures predate track/scope metadata.  They
        # are accepted only for their unambiguous legacy combination.
        legacy = {
            "track": "direct",
            "candidate_scope": "subject",
            "anchor_policy": "address",
        }
        for key, value in requested.items():
            if value is not None and value != legacy[key]:
                raise ValueError(
                    f"legacy fixture has no analysis/{key}; expected {legacy[key]!r}"
                )
    else:
        for key, value in requested.items():
            if value is not None and analysis.get(key) != value:
                raise ValueError(
                    f"fixture analysis/{key} mismatch: {analysis.get(key)!r} != {value!r}"
                )
    result = run_cg_wl(case, mode=mode, trace=True)
    relation = relation_context_from_cgwl(case, result)
    fixture_sha = hashlib.sha256(fixture_file.read_bytes()).hexdigest()
    provenance = {
        "body_evidence_sha256": hashlib.sha256(body_file.read_bytes()).hexdigest(),
        "fixture_sha256": fixture_sha,
        **dict(body_artifact.get("provenance", {})),
    }
    if case.analysis is not None:
        provenance.update({
            "projection_config_sha256": case.analysis.projection_config_sha256,
            "track": case.analysis.track,
            "anchor_policy": case.analysis.anchor_policy,
            "edge_policy": list(case.analysis.edge_policy),
            "oracle_level": case.analysis.oracle_level,
        })
    artifact = build_candidate_artifact(
        case=case.case,
        build=case.build,
        profile=case.profile,
        scope=bodies_scope(body_artifact),
        bodies=bodies,
        pairs=generate_candidate_pairs(
            bodies,
            top_k=top_k,
            final_groups=relation["final_groups"],
            prior_round_groups=relation["prior_round_groups"],
            final_round=relation["final_round"],
            out_signatures=relation["out_signatures"],
            in_signatures=relation["in_signatures"],
        ),
        top_k=top_k,
        provenance=provenance,
        relation={
            "mode": relation["mode"],
            "rounds": relation["rounds"],
            "final_round": relation["final_round"],
            "final_group_count": len(relation["final_groups"]),
            "prior_round_count": len(relation["prior_round_groups"]),
        },
    )
    validate_candidate_artifact(artifact)
    return artifact


def build_multiview_candidate_artifact_from_files(
    *,
    body_path: str | Path,
    fixture_path: str | Path,
    top_k: int,
    mode: CGWLMode,
    views: Iterable[str] = MULTI_VIEW_NAMES,
    track: str | None = None,
    candidate_scope: str | None = None,
    anchor_policy: str | None = None,
) -> dict[str, Any]:
    """Load one body/fixture pair and run independent F5.2 views."""

    _validate_top_k(top_k)
    active_views = _normalize_views(views)
    if mode not in CG_WL_MODES:
        raise ValueError(f"unknown CG-WL mode: {mode!r}")
    body_file = Path(body_path)
    fixture_file = Path(fixture_path)
    body_artifact = json.loads(body_file.read_text(encoding="utf-8"))
    bodies = load_body_evidence(body_artifact)
    case = load_case(str(fixture_file))
    _validate_body_fixture_join(body_artifact, case)
    analysis = case.analysis.to_dict() if case.analysis is not None else {}
    requested = {
        "track": normalize_track(track) if track is not None else None,
        "candidate_scope": normalize_candidate_scope(candidate_scope) if candidate_scope is not None else None,
        "anchor_policy": anchor_policy,
    }
    if case.analysis is None:
        legacy = {
            "track": "direct",
            "candidate_scope": "subject",
            "anchor_policy": "address",
        }
        for key, value in requested.items():
            if value is not None and value != legacy[key]:
                raise ValueError(
                    f"legacy fixture has no analysis/{key}; expected {legacy[key]!r}"
                )
    else:
        for key, value in requested.items():
            if value is not None and analysis.get(key) != value:
                raise ValueError(
                    f"fixture analysis/{key} mismatch: {analysis.get(key)!r} != {value!r}"
                )

    result = run_cg_wl(case, mode=mode, trace=True)
    relation = relation_context_from_cgwl(case, result)
    fixture_sha = hashlib.sha256(fixture_file.read_bytes()).hexdigest()
    provenance = {
        "body_evidence_sha256": hashlib.sha256(body_file.read_bytes()).hexdigest(),
        "fixture_sha256": fixture_sha,
        **dict(body_artifact.get("provenance", {})),
    }
    if case.analysis is not None:
        provenance.update({
            "projection_config_sha256": case.analysis.projection_config_sha256,
            "track": case.analysis.track,
            "anchor_policy": case.analysis.anchor_policy,
            "edge_policy": list(case.analysis.edge_policy),
            "oracle_level": case.analysis.oracle_level,
        })
    artifact = build_multiview_candidate_artifact(
        case=case.case,
        build=case.build,
        profile=case.profile,
        scope=bodies_scope(body_artifact),
        bodies=bodies,
        pairs=generate_multiview_candidate_pairs(
            bodies,
            top_k=top_k,
            views=active_views,
            final_groups=relation["final_groups"],
            prior_round_groups=relation["prior_round_groups"],
            final_round=relation["final_round"],
            out_signatures=relation["out_signatures"],
            in_signatures=relation["in_signatures"],
            anchor_classes=relation["anchor_classes"],
        ),
        top_k=top_k,
        views=active_views,
        provenance=provenance,
        relation={
            "mode": relation["mode"],
            "rounds": relation["rounds"],
            "final_round": relation["final_round"],
            "final_group_count": len(relation["final_groups"]),
            "prior_round_count": len(relation["prior_round_groups"]),
        },
    )
    validate_candidate_artifact(artifact)
    return artifact


def write_candidate_artifact(path: str | Path, artifact: Mapping[str, Any]) -> None:
    validate_candidate_artifact(artifact)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def bodies_scope(artifact: Mapping[str, Any]) -> str:
    scope = artifact.get("scope")
    return normalize_candidate_scope(scope)


def _add_relation_top_k(
    profiles: Mapping[str, CheapBodyProfile],
    bodies: Mapping[str, FunctionBody],
    membership: Mapping[str, int],
    *,
    top_k: int,
    reason: str,
    add: Any,
    shared_round: int | None,
    score_fn: Any,
) -> None:
    groups: dict[int, list[str]] = defaultdict(list)
    for function_id, group_id in membership.items():
        if function_id in profiles and bodies[function_id].complete:
            groups[group_id].append(function_id)
    for group_id in sorted(groups):
        members = sorted(groups[group_id])
        for source, ranked in _symmetric_top_k(
            members,
            top_k=top_k,
            score=score_fn,
            group_key=lambda member: _cheap_profile_signature(profiles[member]),
        ).items():
            for rank, (pair_score, target) in enumerate(ranked, start=1):
                add(
                    source,
                    target,
                    reason=reason,
                    score=pair_score,
                    relation_rank=rank,
                    shared_round=shared_round,
                )


def _membership(
    groups: Iterable[Iterable[str]] | None,
) -> dict[str, int]:
    membership: dict[str, int] = {}
    if groups is None:
        return membership
    for group_index, group in enumerate(groups):
        for function_id in group:
            if not isinstance(function_id, str) or not function_id:
                raise ValueError("relation group member must be a non-empty string")
            if function_id in membership:
                raise ValueError(f"function appears in multiple relation groups: {function_id}")
            membership[function_id] = group_index
    return membership


def _same_membership(
    membership: Mapping[str, int],
    first: str,
    second: str,
) -> bool | None:
    if first not in membership or second not in membership:
        return None
    return membership[first] == membership[second]


def _same_prior_membership(
    memberships: Sequence[tuple[int, Mapping[str, int]]],
    first: str,
    second: str,
) -> bool | None:
    if not memberships:
        return None
    available = False
    for _round_index, membership in memberships:
        if first in membership and second in membership:
            available = True
            if membership[first] == membership[second]:
                return True
    return False if available else None


def _same_mapping_value(
    mapping: Mapping[str, Any] | None,
    first: str,
    second: str,
) -> bool | None:
    if mapping is None or first not in mapping or second not in mapping:
        return None
    return mapping[first] == mapping[second]


def _validate_body_fixture_join(
    body_artifact: Mapping[str, Any],
    case: Any,
) -> None:
    for key in ("case", "build", "profile"):
        if body_artifact.get(key) != getattr(case, key):
            raise ValueError(
                f"body/fixture {key} mismatch: {body_artifact.get(key)!r} != {getattr(case, key)!r}"
            )
    scope = body_artifact.get("scope")
    if case.analysis is not None and scope != case.analysis.candidate_scope:
        raise ValueError("body/fixture candidate scope mismatch")
    body_provenance = body_artifact.get("provenance")
    if not isinstance(body_provenance, Mapping):
        raise ValueError("body evidence is missing provenance")
    fixture_provenance = case.provenance.to_dict() if case.provenance is not None else {}
    if body_provenance.get("stripped_sha256") != fixture_provenance.get("stripped_sha256"):
        raise ValueError("body/fixture stripped binary mismatch")
    if case.analysis is not None:
        for key in ("raw_graph_sha256", "candidate_selection_sha256"):
            if body_provenance.get(key) != getattr(case.analysis, key):
                raise ValueError(f"body/fixture {key} mismatch")


def _json_safe_relation_metadata(relation: Mapping[str, Any]) -> dict[str, Any]:
    # Keep the artifact small: group arrays and signatures are used to make
    # candidates, while this summary is sufficient to identify the relation
    # context.  The full fixture remains the source of those arrays.
    result: dict[str, Any] = {}
    for key in ("mode", "rounds", "final_round"):
        if key in relation:
            result[key] = relation[key]
    for key in ("final_group_count", "prior_round_count"):
        if key in relation:
            result[key] = relation[key]
    return result


def _ngrams(values: Sequence[str]) -> list[tuple[str, ...]]:
    if not values:
        return []
    if len(values) < NGRAM_SIZE:
        return [tuple(values)]
    return [
        tuple(values[index:index + NGRAM_SIZE])
        for index in range(len(values) - NGRAM_SIZE + 1)
    ]


def _ratio(first: int, second: int) -> float:
    denominator = max(first, second)
    return min(first, second) / denominator if denominator else 1.0


def _tuple_counter_jaccard(
    first: tuple[tuple[str, int], ...],
    second: tuple[tuple[str, int], ...],
) -> float:
    left = dict(first)
    right = dict(second)
    keys = left.keys() | right.keys()
    union = sum(max(left.get(key, 0), right.get(key, 0)) for key in keys)
    intersection = sum(min(left.get(key, 0), right.get(key, 0)) for key in keys)
    return intersection / union if union else 1.0


def _set_jaccard(first: Iterable[Any], second: Iterable[Any]) -> float:
    left = first if isinstance(first, (set, frozenset)) else set(first)
    right = second if isinstance(second, (set, frozenset)) else set(second)
    union_count = len(left) + len(right) - len(left & right)
    return len(left & right) / union_count if union_count else 1.0


def _symmetric_top_k(
    members: Sequence[str],
    *,
    top_k: int,
    score: Any,
    group_key: Any | None = None,
) -> dict[str, list[tuple[float, str]]]:
    """Return deterministic top-k neighbors while scoring each pair once.

    When ``group_key`` is supplied, members with the same key are known to
    have the same score against every other key.  We score profile groups
    rather than individual functions, then expand only the IDs needed for
    each top-k list.  This preserves the exact score/ID tie order for the
    cheap profile used by F5 while avoiding the large duplicate work caused
    by monomorphized siblings.
    """

    ordered = sorted(members)
    if group_key is not None:
        return _grouped_symmetric_top_k(
            ordered,
            top_k=top_k,
            score=score,
            group_key=group_key,
        )
    member_index = {member: index for index, member in enumerate(ordered)}
    heaps: dict[str, list[tuple[float, int, str]]] = {
        member: [] for member in ordered
    }

    def push(source: str, target: str, value: float) -> None:
        item = (float(value), -member_index[target], target)
        heap = heaps[source]
        if len(heap) < top_k:
            heapq.heappush(heap, item)
        elif item > heap[0]:
            heapq.heapreplace(heap, item)

    for index, first in enumerate(ordered):
        for second in ordered[index + 1:]:
            value = score(first, second)
            push(first, second, value)
            push(second, first, value)

    return {
        source: [
            (item[0], item[2])
            for item in sorted(
                heap,
                key=lambda item: (-item[0], item[2]),
            )
        ]
        for source, heap in heaps.items()
    }


def _grouped_symmetric_top_k(
    members: Sequence[str],
    *,
    top_k: int,
    score: Any,
    group_key: Any,
) -> dict[str, list[tuple[float, str]]]:
    """Expand exact top-k neighbors from score-equivalent member groups."""

    groups: dict[Any, list[str]] = defaultdict(list)
    for member in members:
        groups[group_key(member)].append(member)
    group_items = sorted(groups.items(), key=lambda item: item[1][0])
    group_scores: dict[Any, dict[Any, float]] = {
        key: {} for key, _group_members in group_items
    }
    for index, (left_key, left_members) in enumerate(group_items):
        for right_key, right_members in group_items[index:]:
            value = float(score(left_members[0], right_members[0]))
            group_scores[left_key][right_key] = value
            group_scores[right_key][left_key] = value

    result: dict[str, list[tuple[float, str]]] = {}
    for source_key, source_members in group_items:
        by_score: dict[float, list[Any]] = defaultdict(list)
        for target_key, value in group_scores[source_key].items():
            by_score[value].append(target_key)
        ranked_ids: list[str] = []
        ranked_scores: list[float] = []
        for value in sorted(by_score, reverse=True):
            level_ids: list[str] = []
            for target_key in by_score[value]:
                level_ids.extend(groups[target_key])
            # The old per-member heap resolves equal scores by target ID.
            level_ids.sort()
            ranked_ids.extend(level_ids)
            ranked_scores.extend([value] * len(level_ids))
            # One extra ID is enough because the source member itself may be
            # present in its own equivalent group.
            if len(ranked_ids) >= top_k + 1:
                break
        for source in source_members:
            neighbors = [
                (value, target)
                for value, target in zip(ranked_scores, ranked_ids)
                if target != source
            ][:top_k]
            result[source] = neighbors
    return result


def _cheap_profile_signature(profile: CheapBodyProfile) -> tuple[Any, ...]:
    return (
        profile.size,
        profile.instruction_count,
        profile.block_count,
        profile.mnemonic_counts,
        profile.mnemonic_ngrams,
    )


def _minimum_rank(old: int | None, new: int | None) -> int | None:
    if new is None:
        return old
    return new if old is None else min(old, new)


def _maximum_round(old: int | None, new: int) -> int:
    return new if old is None else max(old, new)


def _validate_top_k(value: Any) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("top_k must be a positive integer")


def _normalize_views(views: Iterable[str]) -> tuple[str, ...]:
    values = {views} if isinstance(views, str) else set(views)
    if not values:
        raise ValueError("at least one retrieval view is required")
    unknown = values - set(VIEW_NAMES)
    if unknown:
        raise ValueError(f"unknown retrieval view(s): {sorted(unknown)}")
    return tuple(name for name in VIEW_NAMES if name in values)


def _view_profile_signature(profile: Any) -> tuple[Any, ...]:
    signature = getattr(profile, "signature", None)
    if signature is None:
        raise ValueError("retrieval profile does not expose a signature")
    return signature


def _validate_multiview_config(config: Any) -> tuple[str, ...]:
    if not isinstance(config, Mapping) or set(config) != {
        "top_k", "view_top_k", "views", "view_profiles"
    }:
        raise ValueError("multiview candidate artifact config has an invalid schema")
    _validate_top_k(config["top_k"])
    active_views = _normalize_views(config["views"])
    if list(active_views) != config["views"]:
        raise ValueError("multiview config views must be in canonical order")
    view_top_k = config["view_top_k"]
    if not isinstance(view_top_k, Mapping) or set(view_top_k) != set(active_views):
        raise ValueError("multiview config view_top_k has an invalid schema")
    for name in active_views:
        _validate_top_k(view_top_k[name])
        if view_top_k[name] != config["top_k"]:
            raise ValueError("multiview config view_top_k must match top_k")
    view_profiles = config["view_profiles"]
    if not isinstance(view_profiles, Mapping) or set(view_profiles) != set(active_views):
        raise ValueError("multiview config view_profiles has an invalid schema")
    for name in active_views:
        if view_profiles[name] != VIEW_PROFILE_VERSIONS[name]:
            raise ValueError(f"unsupported {name} retrieval profile version")
    return active_views


def _validate_multiview_pair(
    item: Mapping[str, Any],
    active_views: tuple[str, ...],
    index: int,
) -> None:
    reasons = item["reasons"]
    if (
        not isinstance(reasons, list)
        or reasons != sorted(reasons)
        or not reasons
        or any(not isinstance(reason, str) or not reason for reason in reasons)
    ):
        raise ValueError(f"pairs[{index}].reasons is invalid")
    views = item["views"]
    if not isinstance(views, Mapping) or set(views) != set(active_views):
        raise ValueError(f"pairs[{index}].views has an invalid schema")
    selected_reasons = set()
    for name in active_views:
        value = views[name]
        if value is None:
            continue
        if not isinstance(value, Mapping) or set(value) != {"score", "rank"}:
            raise ValueError(f"pairs[{index}].views[{name}] is invalid")
        score = value["score"]
        rank = value["rank"]
        if (
            not isinstance(score, (int, float))
            or isinstance(score, bool)
            or not math.isfinite(score)
            or not 0.0 <= score <= 1.0
        ):
            raise ValueError(f"pairs[{index}].views[{name}].score is invalid")
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            raise ValueError(f"pairs[{index}].views[{name}].rank is invalid")
        selected_reasons.add(f"{name}_top_k")
    if not selected_reasons.issubset(reasons):
        raise ValueError(f"pairs[{index}] is missing a selected-view reason")
    if not any(views[name] is not None for name in active_views):
        raise ValueError(f"pairs[{index}] has no selected view")
    for key_name in (
        "same_out_signature", "same_in_signature", "same_final_color", "same_prior_color"
    ):
        if item[key_name] is not None and not isinstance(item[key_name], bool):
            raise ValueError(f"pairs[{index}].{key_name} is invalid")
    shared_round = item["last_shared_round"]
    if shared_round is not None and (
        not isinstance(shared_round, int)
        or isinstance(shared_round, bool)
        or shared_round < 0
    ):
        raise ValueError(f"pairs[{index}].last_shared_round is invalid")


def _last_shared_round(
    first: str,
    second: str,
    final_membership: Mapping[str, int],
    prior_memberships: Iterable[tuple[int, Mapping[str, int]]],
    final_round: int | None,
) -> int | None:
    shared: list[int] = []
    if (
        final_round is not None
        and first in final_membership
        and second in final_membership
        and final_membership[first] == final_membership[second]
    ):
        shared.append(int(final_round))
    for round_index, membership in prior_memberships:
        if (
            first in membership
            and second in membership
            and membership[first] == membership[second]
        ):
            shared.append(int(round_index))
    return max(shared) if shared else None


def _default_output(case: str, build: str, profile: str, scope: str) -> str:
    return (
        f"results/{case}/{profile}/{case}.{normalize_build(build)}."
        f"{normalize_candidate_scope(scope)}.v1.candidates.json"
    )


def _default_multiview_output(
    case: str,
    build: str,
    profile: str,
    scope: str,
    variant: str,
) -> str:
    return (
        f"results/{case}/{profile}/{case}.{normalize_build(build)}."
        f"{normalize_candidate_scope(scope)}.v1.{variant}.candidates.json"
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="F5: generate a bounded candidate-pair artifact without GT."
    )
    parser.add_argument("case")
    parser.add_argument("--build", default=DEFAULT_BUILD)
    parser.add_argument("--profile", default=DEFAULT_PROFILE)
    parser.add_argument("--body-evidence")
    parser.add_argument("--fixture")
    parser.add_argument("--output")
    parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument(
        "--variant",
        choices=("legacy", "composite", "token", "cfg", "relation", "multi"),
        default="legacy",
        help="legacy composite+relation F5 or an independent F5.2 view variant",
    )
    parser.add_argument("--mode", choices=CG_WL_MODES, default="out-in")
    parser.add_argument("--track", choices=ANALYSIS_TRACKS, default="angr")
    parser.add_argument(
        "--candidate-scope", choices=CANDIDATE_SCOPES, default="rust-nonstd"
    )
    parser.add_argument(
        "--anchor-policy", choices=ANCHOR_POLICIES, default="role"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    build = normalize_build(args.build)
    profile = normalize_profile(args.profile)
    scope = normalize_candidate_scope(args.candidate_scope)
    fixture = args.fixture or resolve_fixture_json(
        args.case,
        build,
        profile,
        args.track,
        scope,
        args.anchor_policy,
    )
    body = args.body_evidence or body_evidence_for(
        args.case, build, profile, scope
    )
    output = args.output or _default_output(args.case, build, profile, scope)
    try:
        if args.variant == "legacy":
            artifact = build_candidate_artifact_from_files(
                body_path=body,
                fixture_path=fixture,
                top_k=args.top_k,
                mode=args.mode,
                track=args.track,
                candidate_scope=scope,
                anchor_policy=args.anchor_policy,
            )
        else:
            selected_views = MULTI_VIEW_NAMES if args.variant == "multi" else (args.variant,)
            if args.output is None:
                output = _default_multiview_output(
                    args.case,
                    build,
                    profile,
                    scope,
                    args.variant,
                )
            artifact = build_multiview_candidate_artifact_from_files(
                body_path=body,
                fixture_path=fixture,
                top_k=args.top_k,
                mode=args.mode,
                views=selected_views,
                track=args.track,
                candidate_scope=scope,
                anchor_policy=args.anchor_policy,
            )
        write_candidate_artifact(output, artifact)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {output}")
    print(f"targets={artifact['universe']['target_count']}")
    print(f"complete_bodies={artifact['universe']['complete_body_count']}")
    print(f"candidate_pairs={len(artifact['pairs'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
