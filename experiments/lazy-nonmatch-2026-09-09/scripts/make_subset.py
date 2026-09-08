#!/usr/bin/env python3
"""Make one deterministic connected, comparable real-body candidate subset."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
from collections import defaultdict, deque
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
for import_root in (REPO, REPO / "frozen_v1"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mnemonic_jaccard(first: tuple[str, ...], second: tuple[str, ...]) -> float:
    left = collections.Counter(first)
    right = collections.Counter(second)
    union = sum((left | right).values())
    return sum((left & right).values()) / union if union else 1.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--count", type=int, default=64)
    args = parser.parse_args(argv)
    if not 2 <= args.count <= 64:
        parser.error("--count must be between 2 and 64")

    from real_v1_adapter import load_from_run

    source = load_from_run(args.run)
    candidate_raw = args.candidates.read_bytes()
    candidate = json.loads(candidate_raw.decode("utf-8"))
    comparable = {
        function_id
        for function_id in source.comparable
        if int(source.bodies[function_id].quality.get("opaque_indirect_jumps", 0)) == 0
    }
    adjacency: dict[str, set[str]] = defaultdict(set)
    for item in candidate["pairs"]:
        first, second = item["pair"]
        if first in comparable and second in comparable:
            adjacency[first].add(second)
            adjacency[second].add(first)
    components: list[set[str]] = []
    visited: set[str] = set()
    for start in sorted(adjacency):
        if start in visited:
            continue
        component: set[str] = set()
        pending = [start]
        while pending:
            current = pending.pop()
            if current in component:
                continue
            component.add(current)
            visited.add(current)
            pending.extend(adjacency[current] - component)
        if len(component) >= 2:
            components.append(component)
    if not components:
        raise ValueError("candidate queue has no comparable nonopaque component")
    component_by_member = {
        member: component
        for component in components
        for member in component
    }
    certified_pairs: list[tuple[int, tuple[str, str], float]] = []
    for item in candidate["pairs"]:
        first, second = item["pair"]
        if first not in comparable or second not in comparable:
            continue
        left = source.bodies[first]
        right = source.bodies[second]
        score = mnemonic_jaccard(
            tuple(str(value["mnemonic_class"]) for value in left.instructions),
            tuple(str(value["mnemonic_class"]) for value in right.instructions),
        )
        if score < 0.95:
            certified_pairs.append((
                len(left.instructions) * len(right.instructions),
                (first, second),
                score,
            ))
    if not certified_pairs:
        raise ValueError("candidate queue has no actual normalized nonmatch")
    certified_pairs.sort(key=lambda value: (value[0], value[1]))
    cert_cost, cert_pair, cert_score = certified_pairs[0]
    component = component_by_member[cert_pair[0]]
    core_count = min(62, args.count)
    if len(component) < core_count:
        raise ValueError(
            f"cheapest certified pair component has only {len(component)} members"
        )
    selected: list[str] = [cert_pair[0], cert_pair[1]]
    selected_set = set(selected)
    frontier: deque[str] = deque(selected)
    while frontier and len(selected) < core_count:
        current = frontier.popleft()
        for neighbor in sorted(adjacency[current]):
            if neighbor in selected_set:
                continue
            selected.append(neighbor)
            selected_set.add(neighbor)
            frontier.append(neighbor)
            if len(selected) == args.count:
                break
    while frontier and len(selected) < args.count:
        current = frontier.popleft()
        for neighbor in sorted(adjacency[current]):
            if neighbor in selected_set:
                continue
            selected.append(neighbor)
            selected_set.add(neighbor)
            frontier.append(neighbor)
            if len(selected) == args.count:
                break
    if len(selected) < args.count:
        raise ValueError(
            f"seed component has only {len(selected)} comparable nonopaque members"
        )

    selected_ids = sorted(selected)
    subset_pairs = [
        item for item in candidate["pairs"]
        if item["pair"][0] in selected_set and item["pair"][1] in selected_set
    ]
    subset = dict(candidate)
    subset["universe"] = {
        "target_count": len(selected_ids),
        "complete_body_count": len(selected_ids),
        "incomplete_ids": [],
        "target_ids": selected_ids,
    }
    subset["pairs"] = subset_pairs
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(subset, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    metadata = {
        "selection": "cheapest actual normalized nonmatch pair by instruction-product then pair; BFS over its candidate component to 62 nodes, then fill to requested count",
        "requested_count": args.count,
        "selected_count": len(selected_ids),
        "seed_pair": list(cert_pair),
        "certified_seed_instruction_product": cert_cost,
        "certified_seed_mnemonic_jaccard": cert_score,
        "seed_component_member_count": len(component),
        "selected_ids_sha256": hashlib.sha256(
            json.dumps(selected_ids, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "subset_pair_count": len(subset_pairs),
        "pair_upper_bound": args.count * (args.count - 1) // 2,
        "body_sha256": source.stage_sha256["body"],
        "original_candidate_sha256": sha256(args.candidates),
        "subset_candidate_sha256": sha256(args.output),
        "binary_sha256": source.binary_sha256,
    }
    args.metadata.write_text(
        json.dumps(metadata, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
