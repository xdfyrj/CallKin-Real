"""Rescore preserved eager/lazy F6 partitions on the same GT universes.

Evaluation only: no inference is run, and the 1.1 GiB body cache is not read.
Pair labels and linkage neutral pairs come from ``evaluate.py``.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from evaluate import (  # noqa: E402
    NEUTRAL_LABELS,
    _pairs,
    check_same_binary,
    gt_members,
    neutral_pairs_from_audit,
    score_partition,
)


EXPECTED = {
    "eager_prediction": "a7f30e8e9fc5f2576983251dfe166504731363766ee494a784f5bf4b1c6c61d9",
    "lazy_prediction": "f8416b79ce1c912abbd95a45647f58b5e55a0b0fb6c0363f0071aa48018f710c",
    "run_manifest": "1395938b69d55b4fb416dfeb0d56cddc441c9f7a2984dc13cbb96b148a8f17d7",
    "ground_truth": "b5e641338cd098ead94ea299b7dccd3a4ca2b8242743656762cf8f01617d967d",
    "linkage_audit": "aea76c11cb78074695ea2ac4acc8f08026f61d81fa747d9d42948bf82f3da579",
    "universe_stage": "43a4a990d6bd40ca03edb385f27cd74c708ae6533d02c0edddba6bf3a06d9f0b",
    "relation_stage": "d203bd0c1bf2dc19a57e96764fbd394ecaee86fb872c4ca549e0d5d9e05e9896",
    "body_stage": "de5b5409110c9a99c4039603f62446b07a94e04ab894acf33bf52adf77cf4805",
    "candidate_queue": "077c1cfbf22b7e82c13c1703a77e17d1f3bec4b82ef2356a421969fe01837161",
    "nonstripped_binary": "a37ccf63601b2012ba0edbc2ab63d9442f4830fbb41e6b87f1c43a16f32dba7c",
    "stripped_binary": "3c07eb724eefb1bc5052c3cdf3e8597f9c51eb42a9b09b86265d9994bc8bbf83",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def verify_hash(name: str, path: Path, expected: str) -> str:
    actual = sha256(path)
    if actual != expected:
        raise ValueError(f"{name} SHA-256 mismatch: {actual} != {expected}")
    return actual


def accepted_clusters(prediction: dict[str, Any]) -> list[list[str]]:
    return [
        sorted(cluster["members"])
        for cluster in prediction["clusters"]
        if cluster["status"] == "accepted"
    ]


def decision_map(prediction: dict[str, Any]) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    for record in prediction["pair_decisions"]:
        pair = tuple(sorted(record["pair"]))
        decision = record["decision"]
        if pair in result and result[pair] != decision:
            raise ValueError(f"pair has conflicting decisions: {pair}")
        result[pair] = decision
    return result


def pair_kind(
    pair: tuple[str, str],
    members: dict[str, str],
    neutral: dict[tuple[str, str], str],
) -> str:
    if pair[0] not in members or pair[1] not in members:
        return "outside_gt"
    if neutral.get(pair) in NEUTRAL_LABELS:
        return "neutral"
    return "correct_join" if members[pair[0]] == members[pair[1]] else "wrong_join"


def delta_counts(
    pairs: Iterable[tuple[str, str]],
    members: dict[str, str],
    neutral: dict[tuple[str, str], str],
) -> dict[str, int]:
    counts = collections.Counter(pair_kind(pair, members, neutral) for pair in pairs)
    return {name: counts.get(name, 0) for name in (
        "correct_join", "wrong_join", "neutral", "outside_gt",
    )}


def family_deltas(
    eager: list[list[str]],
    lazy: list[list[str]],
    members: dict[str, str],
    neutral: dict[tuple[str, str], str],
) -> list[dict[str, Any]]:
    eager_sets = {tuple(group) for group in eager}
    lazy_sets = {tuple(group) for group in lazy}
    old = [set(key) for key in eager_sets - lazy_sets]
    new = [set(key) for key in lazy_sets - eager_sets]
    chosen: list[dict[str, Any]] = []
    used: set[int] = set()
    for old_members in sorted(old, key=lambda item: (len(item), sorted(item))):
        candidates = [
            (len(old_members & candidate), index, candidate)
            for index, candidate in enumerate(new)
            if index not in used
        ]
        if not candidates:
            raise ValueError("could not match changed accepted family")
        overlap, index, new_members = max(
            candidates, key=lambda item: (item[0], -len(item[2]))
        )
        used.add(index)
        added = sorted(new_members - old_members)
        removed = sorted(old_members - new_members)
        added_pairs = _pairs([sorted(new_members)]) - _pairs([sorted(old_members)])
        chosen.append({
            "eager_size": len(old_members),
            "lazy_size": len(new_members),
            "eager_gt_member_count": sum(item in members for item in old_members),
            "lazy_gt_member_count": sum(item in members for item in new_members),
            "overlap_size": overlap,
            "added_members": added,
            "removed_members": removed,
            "added_pair_count": len(added_pairs),
            "added_pair_kinds": delta_counts(added_pairs, members, neutral),
        })
    return chosen


def binary_diagnostic(binary_path: Path, new_ids: list[str]) -> dict[str, Any]:
    """Check whether each new ID is a symbol start or an extent fragment."""
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    from capstone.x86_const import X86_OP_MEM, X86_REG_RIP
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    id_bias = 0x100000
    addresses = {item: int(item[4:], 16) - id_bias for item in new_ids}
    with binary_path.open("rb") as stream:
        elf = ELFFile(stream)
        symtab = elf.get_section_by_name(".symtab")
        text = elf.get_section_by_name(".text")
        if symtab is None or text is None:
            raise ValueError("diagnostic binary lacks .symtab or .text")
        functions = [
            {
                "address": int(symbol["st_value"]),
                "size": int(symbol["st_size"]),
                "name": symbol.name,
            }
            for symbol in symtab.iter_symbols()
            if symbol["st_info"]["type"] == "STT_FUNC"
            and int(symbol["st_value"])
            and int(symbol["st_size"]) > 0
        ]
        symbols_by_address = {
            int(symbol["st_value"]): symbol.name
            for symbol in symtab.iter_symbols()
            if int(symbol["st_value"]) and symbol.name
        }
        relocations: dict[int, dict[str, Any]] = {}
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            linked = elf.get_section(section["sh_link"])
            for relocation in section.iter_relocations():
                entry = relocation.entry
                symbol = linked.get_symbol(entry["r_info_sym"])
                addend = int(entry.get("r_addend", 0))
                relocations[int(entry["r_offset"])] = {
                    "addend": addend,
                    "symbol": symbol.name or symbols_by_address.get(addend, ""),
                }
        text_address = int(text["sh_addr"])
        text_bytes = text.data()
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        rows = []
        for function_id, address in sorted(addresses.items()):
            containing = [
                item for item in functions
                if item["address"] <= address < item["address"] + item["size"]
            ]
            if len(containing) != 1:
                raise ValueError(f"{function_id} has {len(containing)} containing symbols")
            symbol = containing[0]
            offset = address - text_address
            instructions = list(decoder.disasm(text_bytes[offset:offset + 16], address, count=1))
            if not instructions:
                raise ValueError(f"{function_id} did not decode")
            instruction = instructions[0]
            got_slot = None
            relocation = None
            if instruction.mnemonic == "call" and instruction.operands:
                operand = instruction.operands[0]
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    got_slot = instruction.address + instruction.size + operand.mem.disp
                    relocation = relocations.get(got_slot)
            rows.append({
                "id": function_id,
                "address": hex(address),
                "exact_symbol_start": address == symbol["address"],
                "containing_address": hex(symbol["address"]),
                "containing_size": symbol["size"],
                "containing_symbol": symbol["name"],
                "first_instruction": f"{instruction.mnemonic} {instruction.op_str}".strip(),
                "got_slot": hex(got_slot) if got_slot is not None else None,
                "rela_addend": relocation["addend"] if relocation else None,
                "rela_symbol": relocation["symbol"] if relocation else None,
            })
    groups = collections.Counter((row["containing_address"], row["containing_size"]) for row in rows)
    return {
        "id_bias": hex(id_bias),
        "all_inside_nonzero_stt_func_extent": all(not row["exact_symbol_start"] for row in rows),
        "containing_extent_counts": {
            f"{address}+{size}": count for (address, size), count in sorted(groups.items())
        },
        "rows": rows,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    eager, eager_sha = read_json(args.eager)
    lazy, lazy_sha = read_json(args.lazy)
    if eager_sha != EXPECTED["eager_prediction"] or lazy_sha != EXPECTED["lazy_prediction"]:
        raise ValueError("prediction digest mismatch")
    run_manifest, run_sha = read_json(args.run_manifest)
    ground_truth, gt_sha = read_json(args.ground_truth)
    linkage, linkage_sha = read_json(args.linkage_audit)
    if run_sha != EXPECTED["run_manifest"] or gt_sha != EXPECTED["ground_truth"] or linkage_sha != EXPECTED["linkage_audit"]:
        raise ValueError("evaluation input digest mismatch")
    if check_same_binary(run_manifest, ground_truth) != EXPECTED["stripped_binary"]:
        raise ValueError("stripped binary digest mismatch")
    candidate_sha = verify_hash("candidate queue", args.candidate_queue, EXPECTED["candidate_queue"])
    universe_path = args.run_manifest.parent / run_manifest["artifacts"]["universe"]["path"]
    universe_artifact, universe_sha = read_json(universe_path)
    if universe_sha != EXPECTED["universe_stage"]:
        raise ValueError("universe stage digest mismatch")
    relation_path = args.run_manifest.parent / run_manifest["artifacts"]["relation"]["path"]
    relation_sha = verify_hash("relation stage", relation_path, EXPECTED["relation_stage"])
    universe = universe_artifact["payload"]
    target_ids = {
        record["id"] for record in universe["functions"]
        if record["grouping_role"] == "member"
    }
    prediction_targets = [set(eager["universe"]["target_ids"]), set(lazy["universe"]["target_ids"])]
    if target_ids != prediction_targets[0] or prediction_targets[0] != prediction_targets[1]:
        raise ValueError("prediction and original target universes differ")
    for name, prediction in (("eager", eager), ("lazy", lazy)):
        provenance = prediction["provenance"]
        if provenance.get("binary_sha256") != EXPECTED["stripped_binary"]:
            raise ValueError(f"{name} prediction binary digest mismatch")
        if provenance.get("universe_sha256") != EXPECTED["universe_stage"]:
            raise ValueError(f"{name} prediction universe digest mismatch")
        if provenance.get("relation_sha256") != EXPECTED["relation_stage"]:
            raise ValueError(f"{name} prediction relation digest mismatch")
        if provenance.get("body_evidence_sha256") != EXPECTED["body_stage"]:
            raise ValueError(f"{name} prediction body digest mismatch")
    members = gt_members(ground_truth)
    overlap_universe = target_ids & set(members)
    full_universe = set(members)
    neutral_overlap = neutral_pairs_from_audit(
        linkage, universe=target_ids, run=run_manifest,
        ground_truth=ground_truth, ground_truth_sha256=gt_sha,
    )
    neutral_full = neutral_pairs_from_audit(
        linkage, universe=full_universe, run=run_manifest,
        ground_truth=ground_truth, ground_truth_sha256=gt_sha,
    )
    eager_clusters = accepted_clusters(eager)
    lazy_clusters = accepted_clusters(lazy)
    metrics = {}
    for universe_name, scoring_universe, neutral in (
        ("gt_overlap_617", target_ids, neutral_overlap),
        ("full_gt_674", full_universe, neutral_full),
    ):
        metrics[universe_name] = {
            "eager": score_partition(eager_clusters, ground_truth, scoring_universe, neutral),
            "lazy": score_partition(lazy_clusters, ground_truth, scoring_universe, neutral),
        }
    eager_pairs = _pairs(eager_clusters)
    lazy_pairs = _pairs(lazy_clusters)
    added_pairs = lazy_pairs - eager_pairs
    removed_pairs = eager_pairs - lazy_pairs
    eager_decisions = decision_map(eager)
    lazy_decisions = decision_map(lazy)
    common_decisions = eager_decisions.keys() & lazy_decisions.keys()
    decision_diff = [
        pair for pair in common_decisions
        if eager_decisions[pair] != lazy_decisions[pair]
    ]
    new_members = sorted(set(lazy["status_members"]["accepted"]) - set(eager["status_members"]["accepted"]))
    changed_families = family_deltas(eager_clusters, lazy_clusters, members, neutral_full)
    return {
        "artifact": "lazy-quality-rescore",
        "schema_version": 1,
        "scope": "equivalent preserved-output rescoring; no new inference",
        "scoring_definition": {
            "pair_helper": "evaluate.score_partition",
            "neutral_helper": "evaluate.neutral_pairs_from_audit",
            "gt_overlap_universe": "original run member target_ids intersect GT origin members (617)",
            "full_universe": "all GT origin members (674)",
            "outside_gt": "at least one pair ID absent from GT origin members; not auto-FP",
            "labels": "normalized origin/linkage proxy; no exact source-truth claim",
        },
        "input_hashes": {
            "eager_prediction": eager_sha,
            "lazy_prediction": lazy_sha,
            "run_manifest": run_sha,
            "ground_truth": gt_sha,
            "linkage_audit": linkage_sha,
            "universe_stage": universe_sha,
            "relation_stage": relation_sha,
            "candidate_queue": candidate_sha,
            "body_stage_recorded_only": EXPECTED["body_stage"],
            "stripped_binary_recorded": EXPECTED["stripped_binary"],
            "nonstripped_binary": verify_hash("nonstripped binary", args.nonstripped_binary, EXPECTED["nonstripped_binary"]),
        },
        "body_cache_loaded": False,
        "target_universe": {
            "eager_target_count": len(prediction_targets[0]),
            "lazy_target_count": len(prediction_targets[1]),
            "target_sets_equal": prediction_targets[0] == prediction_targets[1],
            "gt_overlap_count": len(overlap_universe),
            "full_gt_count": len(full_universe),
        },
        "prediction_summary": {
            "eager_accepted_family_count": len(eager_clusters),
            "lazy_accepted_family_count": len(lazy_clusters),
            "eager_accepted_member_count": sum(map(len, eager_clusters)),
            "lazy_accepted_member_count": sum(map(len, lazy_clusters)),
            "new_lazy_accepted_members": new_members,
            "removed_eager_accepted_members": sorted(set(eager["status_members"]["accepted"]) - set(lazy["status_members"]["accepted"])),
        },
        "quality": metrics,
        "pair_decision_replay": {
            "eager_unique_records": len(eager_decisions),
            "lazy_unique_records": len(lazy_decisions),
            "common_records": len(common_decisions),
            "common_decision_mismatch_count": len(decision_diff),
            "lazy_only_records": len(lazy_decisions.keys() - eager_decisions.keys()),
        },
        "accepted_pair_delta": {
            "added_pair_count": len(added_pairs),
            "removed_pair_count": len(removed_pairs),
            "added_pair_kinds": delta_counts(added_pairs, members, neutral_full),
            "removed_pair_kinds": delta_counts(removed_pairs, members, neutral_full),
            "changed_family_count": len(changed_families),
            "families": changed_families,
        },
        "binary_containment_diagnostic": binary_diagnostic(args.nonstripped_binary, new_members),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--eager", type=Path, required=True)
    result.add_argument("--lazy", type=Path, required=True)
    result.add_argument("--run-manifest", type=Path, required=True)
    result.add_argument("--ground-truth", type=Path, required=True)
    result.add_argument("--linkage-audit", type=Path, required=True)
    result.add_argument("--candidate-queue", type=Path, required=True)
    result.add_argument("--nonstripped-binary", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    report = run(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "gt_overlap": report["quality"]["gt_overlap_617"],
        "added_pair_kinds": report["accepted_pair_delta"]["added_pair_kinds"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
