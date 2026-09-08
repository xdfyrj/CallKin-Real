"""R4: run the frozen F6 over the F5 consensus3 queue.

Strict grouping. The policy is `frozen_v1/configs/v1.formal.json`, unchanged:

    structure_match_threshold       0.95
    slot_match_threshold            1.0
    require_informative_slot        true
    abstain_on_opaque_indirect      true
    max_comparison_count            10,000
    max_alignment_cell_budget       500,000,000

`frozen_v1/v1_engine.py` carries one named CallKin-Real adaptation for the
opt-in lazy path. With the flag omitted, its default cache and builder path
remain the frozen F6 behavior; a family produced here is a family the formal
V1 results would have produced from the same queue.

The budget is priced before any comparison runs and the whole artifact is
refused if it does not fit -- the frozen rule, because spending the budget
while walking a function-id-ordered candidate list would silently analyse an
arbitrary prefix of the binary. When that happens, this module records the
refusal with the numbers that caused it rather than lowering the ceiling.
Changing a frozen threshold to make a run succeed is a research decision and
is not made here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from real_v1_adapter import RealV1Input, load_from_run

_FROZEN = Path(__file__).resolve().parent / "frozen_v1"
for _entry in (_FROZEN, _FROZEN / "analysis"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from v1_engine import (  # noqa: E402
    PairEvidenceCache,
    PairPolicyConfig,
    _pair_from_record,
    build_family_artifact,
)

FORMAL_CONFIG = _FROZEN / "configs" / "v1.formal.json"
# Spec 10.4: strict F6 takes the queue all three views chose.
STRICT_QUEUE = "consensus3"

BUDGET_REFUSED = "budget-refused"
COMPLETED = "completed"


def price(
    candidate_artifact: dict[str, Any],
    source: RealV1Input,
    config: PairPolicyConfig,
    *,
    lazy_nonmatch: bool = False,
) -> dict[str, Any]:
    """What F6 would have to spend on this queue, before it spends any of it.

    The same accounting F6 does at its own gate, exposed so a refusal can say
    what it refused and by how much. An alignment cell is one left normalized
    instruction paired with one right one.
    """
    bodies = {
        function_id: source.bodies[function_id]
        for function_id in candidate_artifact["universe"]["target_ids"]
        if function_id in source.bodies
    }
    cache = PairEvidenceCache(
        bodies,
        candidate_artifact["pairs"],
        config,
        lazy_nonmatch=lazy_nonmatch,
    )
    pairs = [_pair_from_record(item) for item in candidate_artifact["pairs"]]
    required_pairs = [pair for pair in pairs if cache.would_compare(pair)]
    comparisons, cells = cache.demand(required_pairs)

    # A refusal is dominated by a few very large functions, so the distribution
    # is worth recording: a ceiling is a different problem from a long tail.
    priced_pairs = required_pairs if lazy_nonmatch else pairs
    per_pair = sorted(
        len(bodies[pair.left].instructions) * len(bodies[pair.right].instructions)
        for pair in priced_pairs
        if pair.left in bodies and pair.right in bodies
    )
    total = sum(per_pair) or 1
    accounting = {
        "pair_count": len(pairs),
        "required_comparisons": comparisons,
        "required_alignment_cells": cells,
        "max_comparison_count": config.max_comparison_count,
        "max_alignment_cell_budget": config.max_alignment_cell_budget,
        "within_budget": cache.within_budget(comparisons, cells),
        "alignment_cells_median": per_pair[len(per_pair) // 2] if per_pair else 0,
        "alignment_cells_max": per_pair[-1] if per_pair else 0,
        "alignment_cells_top10_share": round(sum(per_pair[-10:]) / total, 4),
        "alignment_cells_top50_share": round(sum(per_pair[-50:]) / total, 4),
    }
    if lazy_nonmatch:
        accounting.update({
            "accounting_mode": "lazy-nonmatch",
            "cheap_check_count": cache.cheap_check_count,
            "cheap_nonmatch_count": cache.cheap_nonmatch_count,
        })
    return accounting


def build_strict_families(
    candidate_artifact: dict[str, Any],
    source: RealV1Input,
    *,
    config: PairPolicyConfig,
    candidate_sha256: str,
    lazy_nonmatch: bool = False,
) -> tuple[str, dict[str, Any] | None, dict[str, Any]]:
    """Run F6, or record why it refused.

    Returns `(status, family_artifact_or_None, accounting)`. The artifact is
    None exactly when the budget refused the queue, because a partial F6 is
    not a smaller F6: it is an answer about a prefix of the binary presented as
    an answer about the binary.

    `body_provenance` is not passed. The three keys it would cross-check --
    stripped_sha256, candidate_selection_sha256, raw_graph_sha256 -- name
    oracle-pipeline artifacts that CallKin-Real does not produce, so the check
    would compare None against None and prove nothing. The equivalent check is
    already done, and done more strictly, by the adapter: it compares the
    actual bytes of body.json against the hash the universe recorded.
    """
    accounting = price(
        candidate_artifact, source, config, lazy_nonmatch=lazy_nonmatch
    )
    if not accounting["within_budget"]:
        return BUDGET_REFUSED, None, accounting

    bodies = {
        function_id: source.bodies[function_id]
        for function_id in candidate_artifact["universe"]["target_ids"]
        if function_id in source.bodies
    }
    families = build_family_artifact(
        candidate_artifact=candidate_artifact,
        bodies=bodies,
        config=config,
        body_sha256=source.stage_sha256["body"],
        candidate_sha256=candidate_sha256,
        cache_factory=(
            _lazy_cache_factory if lazy_nonmatch else None
        ),
    )
    return COMPLETED, families, accounting


def _lazy_cache_factory(
    bodies: dict[str, Any],
    candidate_records: list[dict[str, Any]],
    config: PairPolicyConfig,
    *,
    feature_provider: Any = None,
) -> PairEvidenceCache:
    return PairEvidenceCache(
        bodies,
        candidate_records,
        config,
        feature_provider=feature_provider,
        lazy_nonmatch=True,
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> str:
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return _sha256_bytes(encoded)


def summarize(families: dict[str, Any]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    for cluster in families["clusters"]:
        statuses[cluster["status"]] = statuses.get(cluster["status"], 0) + 1
    return {
        "cluster_status_counts": dict(sorted(statuses.items())),
        "accepted_family_count": statuses.get("accepted", 0),
        "accepted_member_count": len(families["status_members"]["accepted"]),
        "abstain_member_count": len(families["status_members"]["abstain"]),
        "blocked_merge_count": len(families["blocked_merges"]),
        "metrics": families["metrics"],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="a callkin-real run manifest (run.json)")
    parser.add_argument(
        "--candidates",
        help=f"F5 queue; defaults to the {STRICT_QUEUE} file beside the run",
    )
    parser.add_argument(
        "--config",
        default=str(FORMAL_CONFIG),
        help="F6 policy; defaults to the frozen v1.formal.json",
    )
    parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument(
        "--lazy-nonmatch",
        action="store_true",
        help="certify exact non-matches from normalized mnemonic counts before F4",
    )
    parser.add_argument("--output", help="families.strict.json path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        run_path = Path(args.run)
        source = load_from_run(run_path)
        candidate_path = (
            Path(args.candidates) if args.candidates
            else run_path.parent
            / f"{run_path.stem}.v1.{STRICT_QUEUE}.k{args.top_k}.candidates.json"
        )
        raw = candidate_path.read_bytes()
        candidate_artifact = json.loads(raw.decode("utf-8"))
        config = PairPolicyConfig.from_file(args.config)
        status, families, accounting = build_strict_families(
            candidate_artifact, source,
            config=config, candidate_sha256=_sha256_bytes(raw),
            lazy_nonmatch=args.lazy_nonmatch,
        )
        output = (
            Path(args.output) if args.output
            else run_path.parent / f"{run_path.stem}.v1.families.strict.json"
        )
        written = None
        if families is not None:
            written = {"path": str(output), "sha256": write_json(output, families)}
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    report: dict[str, Any] = {
        "f6_status": status,
        "queue": {"path": str(candidate_path), "sha256": _sha256_bytes(raw),
                  "kind": STRICT_QUEUE},
        "config": config.to_dict(),
        "budget": accounting,
    }
    if families is not None:
        report["families"] = written
        report.update(summarize(families))
    print(json.dumps(report, ensure_ascii=False))
    # A budget refusal is a result, not a crash: the queue is too expensive for
    # the frozen ceiling and the fix belongs in F5 or in a research decision
    # about the ceiling. Exit 2 so a script can tell it from success and from
    # an error, without either being silent.
    return 0 if status == COMPLETED else 2


if __name__ == "__main__":
    raise SystemExit(main())
