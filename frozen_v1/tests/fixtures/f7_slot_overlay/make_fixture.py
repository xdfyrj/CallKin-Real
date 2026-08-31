"""Freeze the raw callsite evidence F7.2 needs, for three real families.

F7.2 recovers slot observations from the F1 raw instructions plus the raw call
graph, so a synthetic record alone cannot prove the address convention and
field shapes were read correctly. This pins the real transfers of the 41
members of the three Stage A positive origins: enough to exercise direct calls,
relocations, angr-resolved indirect calls, filtered imports and unresolved
callsites.

    python tests/fixtures/f7_slot_overlay/make_fixture.py \
        results/ripgrep-main/plain/v1.feasibility.json \
        ../v0-engine-py/extractions/angr/plain/ripgrep-main.O3S.raw.json
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))))

from analysis.gt_mangled_audit import address_from_function_id  # noqa: E402
from build_manifest import sha256_file  # noqa: E402


FIXTURE_DIR = Path(__file__).resolve().parent
RAW_PATH = FIXTURE_DIR / "ripgrep_positive_41.raw.json.gz"


def build_fixture(
    feasibility: dict[str, Any],
    raw_graph: dict[str, Any],
    raw_graph_sha256: str,
) -> dict[str, Any]:
    origins: dict[str, set[str]] = {}
    for record in feasibility["pairs"]:
        if record["label"] == "positive":
            origins.setdefault(record["origin"], set()).update(record["pair"])

    members = sorted({member for ids in origins.values() for member in ids})
    address_of = {member: address_from_function_id(member) for member in members}
    wanted = {f"0x{address:x}" for address in address_of.values()}

    transfers = [item for item in raw_graph["transfers"] if item["source"] in wanted]
    functions = [item for item in raw_graph["functions"] if item["address"] in wanted]
    missing = wanted - {item["address"] for item in functions}
    if missing:
        raise ValueError(f"raw graph is missing {len(missing)} of the members")

    return {
        "source": "ripgrep-main.O3S.plain raw call graph, restricted to the "
                  "members of the Stage A positive origins",
        "provenance": {
            "raw_graph_sha256": raw_graph_sha256,
            "stripped_sha256": raw_graph["provenance"]["stripped_sha256"],
            "extractor_version": raw_graph["analysis"]["extractor_version"],
            "backend": raw_graph["analysis"]["backend"],
            "raw_schema_version": raw_graph["schema_version"],
        },
        "origins": {origin: sorted(ids) for origin, ids in sorted(origins.items())},
        "members": members,
        "address_by_member": {
            member: f"0x{address:x}" for member, address in sorted(address_of.items())
        },
        "counts": {
            "members": len(members),
            "functions": len(functions),
            "transfers": len(transfers),
            "by_resolver": dict(sorted(Counter(
                item.get("resolver") or "none" for item in transfers
            ).items())),
            "by_status": dict(sorted(Counter(
                item.get("status") or "none" for item in transfers
            ).items())),
            "by_kind": dict(sorted(Counter(
                item.get("kind") or "none" for item in transfers
            ).items())),
        },
        "functions": sorted(functions, key=lambda item: int(item["address"], 16)),
        "transfers": sorted(
            transfers,
            key=lambda item: (int(item["source"], 16), int(item["callsite"], 16)),
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feasibility")
    parser.add_argument("raw_graph")
    args = parser.parse_args(argv)

    fixture = build_fixture(
        json.loads(Path(args.feasibility).read_text(encoding="utf-8")),
        json.loads(Path(args.raw_graph).read_text(encoding="utf-8")),
        sha256_file(args.raw_graph),
    )

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(fixture, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with open(RAW_PATH, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as handle:
            handle.write(payload)

    counts = fixture["counts"]
    print(f"members={counts['members']} transfers={counts['transfers']}")
    print(f"by_resolver={counts['by_resolver']}")
    print(f"by_status={counts['by_status']}")
    print(f"wrote {RAW_PATH} ({RAW_PATH.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
