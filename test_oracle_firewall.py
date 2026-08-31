"""R7: the analysis path cannot reach an oracle, and the evaluator only scores.

Spec 12.4 is explicit that hiding a CLI argument is not enough. An oracle that
is importable is an oracle that can be called, and a later edit two modules
deep would not fail any test that only checks the command line. So the import
graph is walked, and `evaluate.py` -- the one module that reads ground truth --
must not appear anywhere in it.

The reverse direction matters too and is easier to get wrong: `evaluate` must
not modify what it scores. A scorer that rewrites an artifact has destroyed the
thing the score was about.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import callkin_real
import evaluate as evaluator

HERE = Path(__file__).resolve().parent

# Every module reachable from `analyze`. `frozen_v1/` is included because a
# frozen module that imported an oracle would be just as fatal, and two of the
# stubs there exist precisely because their originals did.
ANALYSIS_ROOTS = (
    "analyze.py",
    "callkin_real.py", "body_builder.py", "body_comparison.py",
    "real_v1_adapter.py", "v1_retrieval.py", "v1_grouping.py", "v1_rescue.py",
    "v1_relaxed.py",
    "flirt_labels.py", "label_propagation.py", "rust_symbol_parser.py",
)
# Names that must never be importable from the analysis path.
FORBIDDEN_MODULES = (
    "gt_extractor", "all_rust_catalog", "scores", "evaluate",
    "gt_mangled_audit", "compare_profiles", "run_summary",
)
# Directory names `analyze` must never build a path out of. Matched only
# inside path-shaped strings: the frozen F7 artifact carries a literal
# `"ground_truth": {"used_for": "not used"}` field, which is a declaration that
# no oracle was consulted, not a place to open.
FORBIDDEN_PATH_NAMES = ("ground_truth", "catalog", "users", "non_stripped")
_SEPARATORS = ("/", chr(92))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def _reachable() -> dict[str, set[str]]:
    """Every local module `analyze` can reach, and what each imports."""
    local = {path.stem: path for path in HERE.glob("*.py")}
    local.update({
        path.stem: path for path in (HERE / "frozen_v1").glob("*.py")
    })
    local.update({
        path.stem: path for path in (HERE / "frozen_v1" / "analysis").glob("*.py")
    })
    graph: dict[str, set[str]] = {}
    queue = [Path(name).stem for name in ANALYSIS_ROOTS]
    while queue:
        name = queue.pop()
        if name in graph or name not in local:
            continue
        graph[name] = _imports(local[name])
        queue.extend(graph[name])
    return graph


def test_no_analysis_module_can_import_an_oracle() -> str:
    graph = _reachable()
    offences = [
        f"{module} imports {name}"
        for module, imported in graph.items()
        for name in imported
        if name in FORBIDDEN_MODULES
    ]
    if offences:
        raise AssertionError("the analysis path can reach an oracle:\n  "
                             + "\n  ".join(offences))
    assert "evaluate" not in graph, "evaluate.py is reachable from analyze"
    return f"  ({len(graph)} analysis modules, none reaching an oracle)"


def test_the_analyze_parser_has_no_oracle_argument():
    # Spec 8.2: these three belong to `evaluate` and must not exist on analyze.
    options = set()
    for action in callkin_real.build_arg_parser()._actions:
        options.update(action.option_strings)
    for forbidden in ("--ground-truth", "--all-rust-catalog", "--linkage-audit",
                      "--gt", "--non-stripped"):
        assert forbidden not in options, f"analyze accepts {forbidden}"


def test_the_evaluate_parser_is_where_the_oracle_arguments_live():
    options = set()
    for action in evaluator.build_arg_parser()._actions:
        options.update(action.option_strings)
    for required in ("--run-manifest", "--ground-truth", "--linkage-audit"):
        assert required in options, f"evaluate is missing {required}"


def test_the_analysis_modules_build_no_oracle_path():
    offences = []
    for name in ANALYSIS_ROOTS:
        source = (HERE / name).read_text(encoding="utf-8")
        # Comments explain why these are absent, so only string literals count.
        for node in ast.walk(ast.parse(source)):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            value = node.value.lower()
            if not any(separator in value for separator in _SEPARATORS):
                continue
            normalized = value.replace(_SEPARATORS[1], "/")
            # An absolute path into a home directory is not a repository
            # oracle directory. `C:/Users/...` and `/mnt/c/users/...` are where
            # Oxidizer lives; the spec's `users/` is a fixture directory in the
            # frozen repository, and reaching it means a repo-relative path.
            if normalized.startswith(("/mnt/", "~")) or ":" in normalized.split("/")[0]:
                continue
            hit = {part for part in normalized.split("/") if part} & set(
                FORBIDDEN_PATH_NAMES
            )
            if hit:
                offences.append(f"{name} builds a path through {sorted(hit)}")
    if offences:
        raise AssertionError(
            "the analysis path names an oracle directory:\n  " + "\n  ".join(offences)
        )


def _fixture(room: Path):
    """A tiny finished analysis and the ground truth that describes it."""
    binary = "a" * 64
    ids = ["FUN_00101000", "FUN_00102000", "FUN_00103000"]

    def envelope(stage, payload, inputs):
        path = room / f"run.{stage}.json"
        digest = callkin_real.write_json(path, callkin_real.artifact_envelope(
            stage=stage, binary_sha256=binary, inputs=inputs, payload=payload,
        ))
        return path, digest

    body = {"functions": [
        {"id": i, "address": hex(0x1000 * (n + 1)), "quality": {
            "complete_decode": n != 2,
            "failure_reason": None if n != 2 else "decode_gap",
        }} for n, i in enumerate(ids)
    ]}
    universe = {"functions": [
        {"id": i, "analysis_status": "complete" if n != 2 else "incomplete",
         "grouping_role": "member" if n != 2 else "abstain",
         "quality": {"complete_decode": n != 2}}
        for n, i in enumerate(ids)
    ], "abstentions": []}
    relation = {
        "rounds": 1, "predicted_clusters": {"C1": ids[:2]},
        "round_history": [{"round": 0, "clusters": {"C1": ids[:2]}}],
        "anchor_classes": {}, "edges": [],
        "functions": [{"id": i, "relation_status": "relation-member"} for i in ids],
    }
    _, discovery_sha = envelope("discovery", {"functions": [], "transfers": []}, {})
    _, body_sha = envelope("body", body, {"discovery": discovery_sha})
    _, universe_sha = envelope(
        "universe", universe, {"discovery": discovery_sha, "body": body_sha}
    )
    _, relation_sha = envelope("relation", relation, {"universe": universe_sha})

    run = {
        "artifact": "callkin-real-run",
        "binary": {"sha256": binary, "path": "/tmp/x.bin"},
        "artifacts": {
            name: {"path": f"run.{name}.json", "sha256": digest}
            for name, digest in (
                ("discovery", discovery_sha), ("body", body_sha),
                ("universe", universe_sha), ("relation", relation_sha),
            )
        },
        "stage_sha256": {
            "discovery": discovery_sha, "body": body_sha,
            "universe": universe_sha, "relation": relation_sha,
        },
        "toolchain": {"python": "3.14.7"},
        "execution": {"duration_seconds": 1.5},
    }
    run_path = room / "run.json"
    callkin_real.write_json(run_path, run)
    ground_truth = {
        "schema_version": 1, "case": "test", "build": "O3S", "profile": "plain",
        "provenance": {"stripped_sha256": binary},
        "symbols": {ids[0]: ["test::f<u8>"], ids[1]: ["test::f<u16>"]},
        "origins": [{"origin": "test::f", "members": ids[:2]}],
    }
    gt_path = room / "gt.json"
    callkin_real.write_json(gt_path, ground_truth)
    return run_path, gt_path


def test_evaluate_scores_a_run_without_touching_it():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(room.glob("*.json"))
        }
        report = evaluator.evaluate(run_path, gt_path)
        after = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(room.glob("*.json"))
        }
    assert before == after, "evaluate modified what it was scoring"
    assert report["ground_truth"]["used_for"] == "scoring only"
    # The two grouped members are one origin family, so V0 gets that pair right.
    v0 = report["grouping"]["methods"]["v0_relation_only"]
    assert v0["true_positive"] == 1 and v0["false_positive"] == 0
    assert v0["precision"] == 1.0
    assert report["grouping"]["methods"]["v1_strict"]["status"] == "not produced"


def test_discovery_is_scored_apart_from_grouping():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        report = evaluator.evaluate(*_fixture(room))
    discovery = report["discovery"]
    assert discovery["discovered_count"] == 2
    assert discovery["complete_body_count"] == 2
    assert discovery["complete_body_coverage"] == 1.0
    # And it is its own block: no grouping number appears inside it.
    assert not (set(discovery) & set(report["grouping"]))


def test_ground_truth_for_another_binary_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        ground_truth = json.loads(gt_path.read_text(encoding="utf-8"))
        ground_truth["provenance"]["stripped_sha256"] = "b" * 64
        callkin_real.write_json(gt_path, ground_truth)
        try:
            evaluator.evaluate(run_path, gt_path)
        except evaluator.EvaluationError as exc:
            assert "ground truth describes" in str(exc)
        else:
            raise AssertionError("a run was scored against another binary")


def test_an_artifact_changed_since_the_run_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        payload = json.loads((room / "run.universe.json").read_text(encoding="utf-8"))
        payload["payload"]["functions"] = payload["payload"]["functions"][:1]
        callkin_real.write_json(room / "run.universe.json", payload)
        try:
            evaluator.evaluate(run_path, gt_path)
        except evaluator.EvaluationError as exc:
            assert "universe on disk" in str(exc)
        else:
            raise AssertionError("a changed artifact was scored")


def test_legacy_pair_only_audit_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        audit = room / "linkage.json"
        callkin_real.write_json(audit, {"pairs": [
            {"pair": ["FUN_00101000", "FUN_00102000"],
             "label": evaluator.DUPLICATE_NEUTRAL},
        ]})
        try:
            evaluator.evaluate(run_path, gt_path, linkage_audit=audit)
        except evaluator.EvaluationError as exc:
            assert "addresses overlay" in str(exc)
        else:
            raise AssertionError("legacy pair-only audit was accepted")


def _addresses_audit(
    room: Path,
    gt_path: Path,
    *,
    binary: str = "a" * 64,
    first_origins: list[str] | None = None,
    second_origins: list[str] | None = None,
    first_identity: str = "M1",
    second_identity: str = "M2",
) -> Path:
    """Write the real gt-mangled-audit address-overlay shape."""
    gt_sha256 = hashlib.sha256(gt_path.read_bytes()).hexdigest()
    values = {
        "FUN_00101000": {
            "identities": [first_identity],
            "origins": first_origins or ["test::f"],
            "raw_symbols": ["test::f::<A>"],
        },
        "FUN_00102000": {
            "identities": [second_identity],
            "origins": second_origins or ["test::f"],
            "raw_symbols": ["test::f::<B>"],
        },
        # This member is discovered but not in the grouping-member universe.
        "FUN_00103000": {
            "identities": ["M3"],
            "origins": ["test::other"],
            "raw_symbols": ["test::other"],
        },
        # This address is in the audit but is not described by GT.  It must
        # never affect the scored denominator even if a run later discovers
        # it as a grouping member.
        "FUN_00999999": {
            "identities": ["M9"],
            "origins": ["test::f"],
            "raw_symbols": ["test::f::<C>"],
        },
    }
    audit = room / "linkage.json"
    callkin_real.write_json(audit, {
        "schema_version": 1,
        "artifact": "v1-gt-mangled-audit",
        "case": "test",
        "build": "O3S",
        "profile": "plain",
        "provenance": {
            "ground_truth_sha256": gt_sha256,
            "stripped_sha256": binary,
        },
        "addresses": values,
    })
    return audit


def test_addresses_overlay_derives_duplicate_neutral_only_for_grouping_members():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        audit = _addresses_audit(room, gt_path, first_identity="M1", second_identity="M1")
        report = evaluator.evaluate(run_path, gt_path, linkage_audit=audit)

    v0 = report["grouping"]["methods"]["v0_relation_only"]
    # The only pair was undecidable, so it is neither a hit nor a miss.
    assert v0["true_positive"] == 0 and v0["false_positive"] == 0
    assert v0["false_negative"] == 0
    assert v0["neutral_pair_total"] == 1
    assert v0["neutral_pair_counts"][evaluator.DUPLICATE_NEUTRAL] == 1


def test_addresses_overlay_derives_ambiguous_neutral():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        audit = _addresses_audit(
            room,
            gt_path,
            first_origins=["test::f", "test::other"],
        )
        report = evaluator.evaluate(run_path, gt_path, linkage_audit=audit)

    v0 = report["grouping"]["methods"]["v0_relation_only"]
    assert v0["neutral_pair_total"] == 1
    assert v0["neutral_pair_counts"][evaluator.AMBIGUOUS_NEUTRAL] == 1


def test_unknown_grouping_member_does_not_change_scored_neutral_totals():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        audit = _addresses_audit(room, gt_path, first_identity="M1", second_identity="M1")
        baseline = evaluator.evaluate(run_path, gt_path, linkage_audit=audit)

        run = json.loads(run_path.read_text(encoding="utf-8"))
        universe_path = room / run["artifacts"]["universe"]["path"]
        universe_artifact = json.loads(universe_path.read_text(encoding="utf-8"))
        universe_artifact["payload"]["functions"].append({
            "id": "FUN_00999999",
            "analysis_status": "complete",
            "grouping_role": "member",
            "quality": {"complete_decode": True},
        })
        universe_sha = callkin_real.write_json(universe_path, universe_artifact)
        run["artifacts"]["universe"]["sha256"] = universe_sha
        run["stage_sha256"]["universe"] = universe_sha
        callkin_real.write_json(run_path, run)

        changed = evaluator.evaluate(run_path, gt_path, linkage_audit=audit)

    baseline_v0 = baseline["grouping"]["methods"]["v0_relation_only"]
    changed_v0 = changed["grouping"]["methods"]["v0_relation_only"]
    assert changed_v0 == baseline_v0


def test_linkage_audit_ground_truth_digest_mismatch_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        audit = _addresses_audit(room, gt_path)
        data = json.loads(audit.read_text(encoding="utf-8"))
        data["provenance"]["ground_truth_sha256"] = "b" * 64
        callkin_real.write_json(audit, data)
        try:
            evaluator.evaluate(run_path, gt_path, linkage_audit=audit)
        except evaluator.EvaluationError as exc:
            assert "ground_truth_sha256" in str(exc)
        else:
            raise AssertionError("tampered linkage audit was accepted")


def test_linkage_audit_wrong_binary_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        audit = _addresses_audit(room, gt_path, binary="b" * 64)
        try:
            evaluator.evaluate(run_path, gt_path, linkage_audit=audit)
        except evaluator.EvaluationError as exc:
            assert "stripped_sha256" in str(exc)
        else:
            raise AssertionError("wrong-binary linkage audit was accepted")


def test_linkage_audit_without_usable_addresses_is_refused():
    with tempfile.TemporaryDirectory(prefix="callkin-eval-") as directory:
        room = Path(directory)
        run_path, gt_path = _fixture(room)
        audit = room / "linkage.json"
        callkin_real.write_json(audit, {
            "schema_version": 1,
            "artifact": "v1-gt-mangled-audit",
            "case": "test",
            "build": "O3S",
            "profile": "plain",
            "provenance": {
                "ground_truth_sha256": hashlib.sha256(gt_path.read_bytes()).hexdigest(),
                "stripped_sha256": "a" * 64,
            },
            "pairs": [],
        })
        try:
            evaluator.evaluate(run_path, gt_path, linkage_audit=audit)
        except evaluator.EvaluationError as exc:
            assert "addresses overlay" in str(exc)
        else:
            raise AssertionError("empty/no-op linkage audit was accepted")


def main() -> int:
    note = test_no_analysis_module_can_import_an_oracle()
    test_the_analyze_parser_has_no_oracle_argument()
    test_the_evaluate_parser_is_where_the_oracle_arguments_live()
    test_the_analysis_modules_build_no_oracle_path()
    test_evaluate_scores_a_run_without_touching_it()
    test_discovery_is_scored_apart_from_grouping()
    test_ground_truth_for_another_binary_is_refused()
    test_an_artifact_changed_since_the_run_is_refused()
    test_legacy_pair_only_audit_is_refused()
    test_addresses_overlay_derives_duplicate_neutral_only_for_grouping_members()
    test_addresses_overlay_derives_ambiguous_neutral()
    test_linkage_audit_ground_truth_digest_mismatch_is_refused()
    test_linkage_audit_wrong_binary_is_refused()
    test_linkage_audit_without_usable_addresses_is_refused()
    print("CallKin-Real oracle firewall: PASS")
    print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
