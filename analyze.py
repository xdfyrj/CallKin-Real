"""R8: one command from a stripped binary to every analysis artifact.

Spec 8.1:

    python analyze.py /path/to/stripped.bin --case zoxide --output-dir results/zoxide

Runs discovery, body, universe and the label-blind V0 relation, then F5, F6,
F7, the provisional relaxed pass, and the FLIRT overlay with F10 propagation.
No ground truth, no catalog, no fixture: `evaluate.py` is a separate command
and this module must never reach it.

Two properties the driver is responsible for, neither of which any single
stage can guarantee on its own.

A stage that cannot run is recorded, not skipped silently. FLIRT may be
unavailable, F6 may refuse a queue that exceeds the frozen budget, and F7 has
nothing to do when F6 accepted nothing. Each of those is a result about the
binary or the environment, and the manifest says which happened. A missing
file with no explanation beside it is the one outcome that would be
indistinguishable from a bug.

And the label stage may not move the grouping. `--no-flirt` and a full run
must produce identical hashes for discovery, body, universe, relation, both
consensus queues, families.strict and families.rescue. That is the invariant
R1 introduced and every stage since has had to preserve; `--verify-label-blind`
runs the analysis twice and checks it rather than trusting it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import callkin_real

# Every artifact whose bytes must not depend on whether FLIRT ran.
LABEL_BLIND_ARTIFACTS = (
    "discovery", "body", "universe", "relation",
    "candidates.multi", "candidates.consensus3", "candidates.consensus2",
    "candidates.consensus3-budgeted",
    "families.strict", "families.rescue",
)

COMPLETED = "completed"
UNAVAILABLE = "unavailable"
SKIPPED = "skipped"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stage(name: str, status: str, **detail: Any) -> dict[str, Any]:
    return {"stage": name, "status": status, **detail}


def analyze(
    binary: Path,
    output_dir: Path,
    *,
    case: str | None = None,
    no_flirt: bool = False,
    top_k: int = 16,
    component_budgeted_v1: bool = False,
    lazy_nonmatch: bool = False,
) -> dict[str, Any]:
    """Run every stage, recording what each one did or could not do."""
    # Imported here rather than at module scope so a stage that fails to import
    # is reported as an unavailable stage instead of stopping the run before it
    # has produced anything.
    import v1_grouping
    import v1_relaxed
    import v1_rescue
    import v1_retrieval
    from real_v1_adapter import load_from_run

    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)
    run_path = output_dir / "run.json"
    stem = run_path.stem
    stages: list[dict[str, Any]] = []
    artifacts: dict[str, dict[str, str]] = {}

    def record(name: str, path: Path) -> None:
        artifacts[name] = {"path": path.name, "sha256": _sha256(path)}

    argv = [str(binary), "--output", str(run_path)]
    if no_flirt:
        argv.append("--no-flirt")
    if callkin_real.main(argv) != 0:
        raise RuntimeError("discovery failed")
    run = json.loads(run_path.read_text(encoding="utf-8"))
    for name in ("discovery", "body", "universe", "relation"):
        record(name, output_dir / run["artifacts"][name]["path"])
    stages.append(_stage("discovery", COMPLETED, **run["summary"]["grouping_role"]))

    label_path = output_dir / f"{stem}.labels.direct.json"
    if "labels_artifact" in run:
        record("labels.direct", label_path)
        stages.append(_stage("labels.direct", COMPLETED,
                             **run["labels_artifact"]["summary"]))
    else:
        stages.append(_stage(
            "labels.direct", SKIPPED if no_flirt else UNAVAILABLE,
            reason="--no-flirt" if no_flirt else run.get("flirt", {}).get("status"),
        ))

    source = load_from_run(run_path)
    queues = v1_retrieval.build_candidate_artifacts(source, top_k=top_k)
    written = v1_retrieval.write_candidate_artifacts(
        queues, output_dir, stem, top_k=top_k
    )
    for name, item in written.items():
        artifacts[f"candidates.{name}"] = {
            "path": Path(item["path"]).name, "sha256": item["sha256"],
        }
    stages.append(_stage("f5.retrieval", COMPLETED, **{
        name: len(artifact["pairs"]) for name, artifact in queues.items()
    }))

    from v1_engine import PairPolicyConfig

    config = PairPolicyConfig.from_file(v1_grouping.FORMAL_CONFIG)
    queue = queues[v1_grouping.STRICT_QUEUE]
    queue_sha256 = written[v1_grouping.STRICT_QUEUE]["sha256"]
    if component_budgeted_v1:
        import v1_component_budget

        queue, budget_report = v1_component_budget.build_budgeted_candidate_artifact(
            queue, source, config, queue_sha256
        )
        budgeted_path = (
            output_dir
            / f"{stem}.v1.consensus3-budgeted.k{top_k}.candidates.json"
        )
        budgeted_sha256 = v1_grouping.write_json(budgeted_path, queue)
        artifacts["candidates.consensus3-budgeted"] = {
            "path": budgeted_path.name,
            "sha256": budgeted_sha256,
        }
        budget_summary = {
            key: value
            for key, value in budget_report.items()
            if not isinstance(value, (dict, list, tuple, set))
        }
        stages.append(_stage(
            "f5.component-budget", COMPLETED,
            artifact="candidates.consensus3-budgeted",
            budget=budget_summary,
        ))
        queue_sha256 = budgeted_sha256
    strict_kwargs = {
        "config": config,
        "candidate_sha256": queue_sha256,
    }
    if lazy_nonmatch:
        strict_kwargs["lazy_nonmatch"] = True
    status, families, accounting = v1_grouping.build_strict_families(
        queue, source, **strict_kwargs
    )
    families_path = output_dir / f"{stem}.v1.families.strict.json"
    if families is None:
        # The frozen rule: the whole queue is refused rather than a prefix of
        # the binary being analysed and reported as the binary.
        stages.append(_stage("f6.strict", v1_grouping.BUDGET_REFUSED, **accounting))
    else:
        v1_grouping.write_json(families_path, families)
        record("families.strict", families_path)
        stages.append(_stage("f6.strict", COMPLETED,
                             **v1_grouping.summarize(families), budget=accounting))

    rescue_path = output_dir / f"{stem}.v1.families.rescue.json"
    if families is None:
        stages.append(_stage("f7.rescue", SKIPPED,
                             reason="strict F6 produced no partition to rescue"))
    else:
        from family_rescue import RescueBudget

        report = v1_rescue.build_rescue_artifact(
            families, queues[v1_rescue.RESCUE_QUEUE],
            v1_rescue.discovery_payload_for(run_path), source,
            budget=RescueBudget(),
            provenance={
                "family_artifact_sha256": _sha256(families_path),
                "candidate_artifact_sha256": written[
                    v1_rescue.RESCUE_QUEUE
                ]["sha256"],
                "body_evidence_sha256": source.stage_sha256["body"],
                "raw_graph_sha256": source.stage_sha256["discovery"],
            },
        )
        v1_rescue.write_json(rescue_path, report)
        record("families.rescue", rescue_path)
        stages.append(_stage("f7.rescue", COMPLETED, **report["summary"]))

        relaxed_path = output_dir / f"{stem}.v1.families.relaxed.json"
        try:
            # The relaxed pass reads the strict artifact alone: the pair
            # decisions it needs are already recorded there, so it never
            # re-scores a candidate and cannot disagree with F6.
            relaxed = v1_relaxed.build_provisional_artifact(
                families, family_artifact_sha256=_sha256(families_path),
            )
            v1_relaxed.write_json(relaxed_path, relaxed)
            record("families.relaxed", relaxed_path)
            stages.append(_stage("v1.relaxed", COMPLETED,
                                 **relaxed.get("summary", {})))
        except Exception as exc:
            stages.append(_stage("v1.relaxed", UNAVAILABLE, reason=str(exc)))

    if families is not None and "labels_artifact" in run:
        import label_propagation

        label_raw = label_path.read_bytes()
        propagation = label_propagation.build_propagation(
            families, json.loads(label_raw.decode("utf-8")), None,
            family_artifact_sha256=_sha256(families_path),
            label_artifact_sha256=hashlib.sha256(label_raw).hexdigest(),
            rescue_artifact_sha256=None,
        )
        propagation_path = output_dir / f"{stem}.v1.labels.strict.json"
        label_propagation.write_json(propagation_path, propagation)
        record("labels.propagated.strict", propagation_path)
        stages.append(_stage("f10.propagation", COMPLETED,
                             **label_propagation.summarize(propagation)))
    else:
        stages.append(_stage("f10.propagation", SKIPPED, reason=(
            "no strict partition" if families is None else "no direct labels"
        )))

    command = {"no_flirt": no_flirt, "top_k": top_k}
    if component_budgeted_v1:
        command["component_budgeted_v1"] = True
    if lazy_nonmatch:
        command["lazy_nonmatch"] = True
    manifest = {
        "schema_version": 1,
        "artifact": "callkin-real-analysis-manifest",
        "case": case or binary.stem,
        "binary": {"path": str(binary), "sha256": run["binary"]["sha256"],
                   "format": run["binary"]["format"]},
        "toolchain": run["toolchain"],
        "command": command,
        "artifacts": artifacts,
        "stages": stages,
        "label_blind_sha256": {
            name: artifacts[name]["sha256"]
            for name in LABEL_BLIND_ARTIFACTS if name in artifacts
        },
        "execution": {"duration_seconds": round(time.perf_counter() - started, 3)},
    }
    manifest_path = output_dir / "run.manifest.json"
    callkin_real.write_json(manifest_path, manifest)
    return manifest


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="stripped x86-64 ELF or PE32+ binary")
    parser.add_argument("--case", help="a name for this subject; defaults to the filename")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--no-flirt", action="store_true")
    parser.add_argument("--top-k", type=int, default=16)
    parser.add_argument(
        "--component-budgeted-v1",
        action="store_true",
        help="derive a whole-component F5 queue within the frozen F6 budget",
    )
    parser.add_argument(
        "--lazy-nonmatch",
        action="store_true",
        help="certify exact non-matches from normalized mnemonic counts before F4",
    )
    parser.add_argument(
        "--verify-label-blind",
        action="store_true",
        help="run twice, with and without FLIRT, and compare every "
             "label-blind artifact hash",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    binary = Path(args.binary)
    output_dir = Path(args.output_dir)
    try:
        manifest = analyze(
            binary, output_dir, case=args.case,
            no_flirt=args.no_flirt, top_k=args.top_k,
            component_budgeted_v1=args.component_budgeted_v1,
            lazy_nonmatch=args.lazy_nonmatch,
        )
        comparison = None
        if args.verify_label_blind:
            other = analyze(
                binary, output_dir.parent / f"{output_dir.name}-no-flirt",
                case=args.case, no_flirt=not args.no_flirt, top_k=args.top_k,
                component_budgeted_v1=args.component_budgeted_v1,
                lazy_nonmatch=args.lazy_nonmatch,
            )
            mine, theirs = manifest["label_blind_sha256"], other["label_blind_sha256"]
            shared = sorted(set(mine) & set(theirs))
            differing = [name for name in shared if mine[name] != theirs[name]]
            only_in_first = sorted(set(mine) - set(theirs))
            only_in_second = sorted(set(theirs) - set(mine))
            comparison = {
                "compared": shared,
                "identical": not (differing or only_in_first or only_in_second),
                "differing": differing,
                "only_in_first": only_in_first,
                "only_in_second": only_in_second,
            }
            if not comparison["identical"]:
                raise RuntimeError(
                    "label-blind artifacts differ: "
                    f"differing={comparison['differing']}, "
                    f"only_in_first={comparison['only_in_first']}, "
                    f"only_in_second={comparison['only_in_second']}"
                )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "case": manifest["case"],
        "manifest": str(output_dir / "run.manifest.json"),
        "artifacts": sorted(manifest["artifacts"]),
        "stages": [
            {"stage": item["stage"], "status": item["status"]}
            for item in manifest["stages"]
        ],
        "label_blind_verification": comparison,
        "duration_seconds": manifest["execution"]["duration_seconds"],
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
