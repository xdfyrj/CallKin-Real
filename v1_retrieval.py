"""R4: run the frozen F5 over CallKin-Real artifacts.

Produces the three candidate artifacts the frozen V1 pipeline expects:

    candidates.multi.k16   the union of three independent top-k view searches
    candidates.consensus3  the pairs all three views chose
    candidates.consensus2  the pairs at least two views chose

The retrieval itself is not reimplemented. `frozen_v1/` holds byte-identical
copies of `v1_candidates.py`, `v1_retrieval_views.py`, `paths.py` and
`analysis/v1_consensus_candidates.py`; the only edited files there are refusal
stubs for the oracle-side modules those import but CallKin-Real never calls.

What this module supplies is the input the oracle pipeline used to supply from
a projected fixture: the universe, the complete bodies, and the relation
partition, all from `real_v1_adapter`.

Four provenance fields the F5 artifact schema requires -- case, build, profile,
scope -- describe a controlled compilation. A stripped binary found in the wild
does not carry them, and the schema is closed, so they cannot be filled with
"unknown". They are set to the least wrong value the schema allows and the
provenance records that they were not observed. See `_subject_metadata`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import callkin_real
from real_v1_adapter import RealV1Input, load_from_run

_FROZEN = Path(__file__).resolve().parent / "frozen_v1"
for _entry in (_FROZEN, _FROZEN / "analysis"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from v1_candidates import (  # noqa: E402
    build_multiview_candidate_artifact,
    generate_multiview_candidate_pairs,
    validate_candidate_artifact,
)
from v1_consensus_candidates import build_consensus_artifact, cost_summary  # noqa: E402
from v1_retrieval_views import MULTI_VIEW_NAMES  # noqa: E402

DEFAULT_TOP_K = 16
# `subject` and `rust-nonstd` are the only scopes the schema accepts.
# `rust-nonstd` means "owners core/alloc/std/__rustc excluded", which is the
# rule zoxide's F10 propagation failed on and which R1 removed. CallKin-Real
# excludes nothing by owner, so `subject` is the accurate one of the two.
CANDIDATE_SCOPE = "subject"
# The universe rule this scope label stands for here, recorded because the
# label alone cannot express it.
CANDIDATE_SCOPE_RULE = (
    "every internal function with a complete body, whatever its owner"
)

# F7 refuses a strict partition and a rescue queue whose provenance disagrees,
# and it checks seven named fields. Five of them name oracle-pipeline artifacts,
# but each has an exact counterpart here, so they are filled with the
# counterpart rather than left absent -- an absent field makes the frozen check
# raise, and a check that cannot run protects nothing.
#
#     stripped_sha256              the binary
#     raw_graph_sha256             discovery.json, which is the raw graph
#     candidate_selection_sha256   universe.json, which is the selection
#     projection_config_sha256     the rules below, hashed
#     anchor_policy                how fixed nodes were coloured
#     edge_policy                  which transfers became edges
#
PROJECTION_RULES = {
    "relation_mode": callkin_real.RELATION_MODE,
    "grouping_role_rule": callkin_real.GROUPING_ROLE_RULE,
    "edge_rule": callkin_real.EDGE_RULE,
    "anchor_policy": callkin_real.ANCHOR_POLICY,
}


def _subject_metadata(binary_sha256: str) -> dict[str, str]:
    """case/build/profile for a binary whose compilation is unknown.

    The schema requires all three and accepts a closed set of values for two of
    them, so there is no way to write "not observed" in the field itself. The
    binary hash is used as the case name because it is the only identifier that
    is actually true of the input, and `provenance.subject_metadata_observed`
    records that build and profile are placeholders.
    """
    return {
        "case": f"callkin-real-{binary_sha256[:16]}",
        "build": "UNKNOWN",
        "profile": "plain",
    }


def build_candidate_artifacts(
    source: RealV1Input,
    *,
    top_k: int = DEFAULT_TOP_K,
    views: tuple[str, ...] = MULTI_VIEW_NAMES,
) -> dict[str, dict[str, Any]]:
    """Run F5 once and derive both consensus queues from that single run.

    The consensus artifacts are filtered from the multi-view one rather than
    retrieved again, which is what the frozen derivation does: a pair's
    selection reasons already say which views chose it, so re-running would
    only be a chance to disagree with the record.
    """
    relation = source.relation
    subject = _subject_metadata(source.binary_sha256)
    provenance = {
        "tool": "CallKin-Real",
        "binary_sha256": source.binary_sha256,
        "body_evidence_sha256": source.stage_sha256["body"],
        "universe_sha256": source.stage_sha256["universe"],
        "relation_sha256": source.stage_sha256["relation"],
        # The seven fields F7 cross-checks. See PROJECTION_RULES.
        "stripped_sha256": source.binary_sha256,
        "raw_graph_sha256": source.stage_sha256["discovery"],
        "candidate_selection_sha256": source.stage_sha256["universe"],
        "projection_config_sha256": callkin_real.canonical_sha256(PROJECTION_RULES),
        "anchor_policy": callkin_real.ANCHOR_POLICY,
        "edge_policy": [callkin_real.EDGE_RULE],
        # Said plainly, because the four schema fields above cannot say it.
        "subject_metadata_observed": False,
        "candidate_scope_rule": CANDIDATE_SCOPE_RULE,
        "relation_source": "callkin-real relation.json",
        "universe_member_count": len(source.members),
        "universe_incomplete_excluded": list(source.excluded_incomplete),
    }

    pairs = generate_multiview_candidate_pairs(
        source.bodies,
        top_k=top_k,
        views=views,
        final_groups=relation["final_groups"],
        prior_round_groups=relation["prior_round_groups"],
        final_round=relation["final_round"],
        out_signatures=relation["out_signatures"],
        in_signatures=relation["in_signatures"],
        anchor_classes=relation["anchor_classes"],
    )
    multi = build_multiview_candidate_artifact(
        case=subject["case"],
        build=subject["build"],
        profile=subject["profile"],
        scope=CANDIDATE_SCOPE,
        bodies=source.bodies,
        pairs=pairs,
        top_k=top_k,
        views=views,
        provenance=provenance,
        relation={
            "mode": "out-in",
            "rounds": relation["rounds"],
            "final_round": relation["final_round"],
            "final_group_count": len(relation["final_groups"]),
            "prior_round_count": len(relation["prior_round_groups"]),
        },
    )
    return {
        "multi": multi,
        "consensus3": build_consensus_artifact(multi, minimum_views=3),
        "consensus2": build_consensus_artifact(multi, minimum_views=2),
    }


def write_candidate_artifacts(
    artifacts: dict[str, dict[str, Any]],
    output_dir: Path,
    stem: str,
    *,
    top_k: int,
) -> dict[str, dict[str, Any]]:
    """Write the three artifacts and return what was written where.

    `source_candidate_sha256` in each consensus artifact is filled in from the
    multi-view file on disk, so the derivation names the bytes it came from
    rather than an object that was never saved.
    """
    import hashlib

    output_dir.mkdir(parents=True, exist_ok=True)
    names = {
        "multi": f"{stem}.v1.multi.k{top_k}.candidates.json",
        "consensus3": f"{stem}.v1.consensus3.k{top_k}.candidates.json",
        "consensus2": f"{stem}.v1.consensus2.k{top_k}.candidates.json",
    }

    def write(name: str, artifact: dict[str, Any]) -> tuple[Path, str]:
        path = output_dir / names[name]
        encoded = (
            json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        path.write_bytes(encoded)
        return path, hashlib.sha256(encoded).hexdigest()

    multi_path, multi_sha = write("multi", artifacts["multi"])
    written = {"multi": {"path": str(multi_path), "sha256": multi_sha}}
    for name in ("consensus3", "consensus2"):
        artifact = artifacts[name]
        artifact["provenance"]["candidate_derivation"]["source_candidate_sha256"] = (
            multi_sha
        )
        validate_candidate_artifact(artifact)
        path, digest = write(name, artifact)
        written[name] = {"path": str(path), "sha256": digest}
    return written


def summarize(
    artifacts: dict[str, dict[str, Any]],
    source: RealV1Input,
) -> dict[str, Any]:
    return {
        name: cost_summary(artifact, source.bodies)
        for name, artifact in artifacts.items()
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="a callkin-real run manifest (run.json)")
    parser.add_argument("--top-k", type=int, default=DEFAULT_TOP_K)
    parser.add_argument("--output-dir", help="defaults to the run manifest's directory")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        run_path = Path(args.run)
        source = load_from_run(run_path)
        artifacts = build_candidate_artifacts(source, top_k=args.top_k)
        output_dir = Path(args.output_dir) if args.output_dir else run_path.parent
        written = write_candidate_artifacts(
            artifacts, output_dir, run_path.stem, top_k=args.top_k
        )
        cost = summarize(artifacts, source)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "binary_sha256": source.binary_sha256,
        "top_k": args.top_k,
        "views": list(MULTI_VIEW_NAMES),
        "universe": {
            "members": len(source.members),
            "comparable": len(source.comparable),
            "incomplete_excluded": len(source.excluded_incomplete),
        },
        "pairs": {name: block["pair_count"] for name, block in cost.items()},
        "alignment_cells": {
            name: block["alignment_cells"] for name, block in cost.items()
        },
        "artifacts": written,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
