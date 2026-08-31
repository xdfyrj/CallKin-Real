"""R6: propagate direct FLIRT labels across families, with the frozen F10 rules.

The eight rules of spec 11.2 are not reimplemented. `_build_propagation_core`
in the byte-identical `frozen_v1/family_label_propagation.py` is where they
live, and it takes the family artifact, an optional rescue artifact, and a
plain list of direct matches -- so CallKin-Real's own F6/F7 output feeds it
directly.

    1. strict uses status=accepted families only
    2. rescue uses the verified final_partition
    3. a family with no direct seed is no-seed
    4. one agreeing (canonical_origin, owner) propagates to unknown members
    5. disagreeing seeds are a conflict and propagate to nobody
    6. a direct member is never re-recorded as propagated
    7. a seed outside the universe stays in the direct baseline only
    8. propagation is never fed back into F5-F7

The public `build_propagation_artifact` is not used: it validates the frozen
Oxidizer label schema, which requires a build-manifest provenance block a
stripped binary does not carry. CallKin-Real validates its own
`labels.direct.json` in `flirt_labels.py` and hands over only the direct
matches, which is the same sanitization the public entry point performs.

Rule 8 is a property of the pipeline, not of this module: nothing downstream
of here writes back into the discovery, universe, relation or candidate
artifacts. `test_label_propagation.py` checks it by hash.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import callkin_real
from flirt_labels import direct_seeds, validate_label_artifact

_FROZEN = Path(__file__).resolve().parent / "frozen_v1"
for _entry in (_FROZEN, _FROZEN / "analysis"):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

from family_label_propagation import (  # noqa: E402
    PROPAGATION_ARTIFACT,
    _build_propagation_core,
    validate_propagation_artifact,
)

STRICT = "strict"
RESCUE = "rescue"


def build_propagation(
    family_artifact: dict[str, Any],
    label_artifact: dict[str, Any],
    rescue_artifact: dict[str, Any] | None,
    *,
    family_artifact_sha256: str,
    label_artifact_sha256: str,
    rescue_artifact_sha256: str | None,
    id_bias: int = callkin_real.ID_BIAS,
) -> dict[str, Any]:
    """Run the frozen propagation core over CallKin-Real artifacts."""
    if family_artifact.get("artifact") != "v1-family-grouping":
        raise ValueError(
            "FLIRT propagation requires the strict v1-family-grouping artifact"
        )
    validate_label_artifact(label_artifact)
    if label_artifact["id_bias"] != id_bias:
        raise ValueError(
            f"label artifact id_bias {label_artifact['id_bias']} is not {id_bias}"
        )
    if label_artifact["binary"]["sha256"] != family_artifact["provenance"][
        "stripped_sha256"
    ]:
        raise ValueError("labels and families describe different binaries")

    artifact = _build_propagation_core(
        family_artifact,
        direct_seeds(label_artifact),
        rescue_artifact,
        id_bias=id_bias,
        family_artifact_sha256=family_artifact_sha256,
        oxidizer_labels_sha256=label_artifact_sha256,
        rescue_artifact_sha256=rescue_artifact_sha256,
    )
    validate_propagation_artifact(artifact)
    return artifact


def summarize(artifact: dict[str, Any]) -> dict[str, Any]:
    families = artifact["families"]
    statuses: dict[str, int] = {}
    for family in families:
        statuses[family["status"]] = statuses.get(family["status"], 0) + 1
    direct = artifact["direct_labels"]
    return {
        "method": artifact["method"],
        "family_status_counts": dict(sorted(statuses.items())),
        "direct_label_count": len(direct),
        "direct_in_universe_count": sum(1 for item in direct if item["in_universe"]),
        "direct_outside_universe_count": sum(
            1 for item in direct if not item["in_universe"]
        ),
        "propagated_label_count": len(artifact["propagated_labels"]),
        "conflict_family_count": len(artifact["conflicts"]),
    }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: Any) -> str:
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return _sha256_bytes(encoded)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", help="a callkin-real run manifest (run.json)")
    parser.add_argument("--families", help="F6 strict families artifact")
    parser.add_argument("--labels", help="labels.direct.json")
    parser.add_argument(
        "--rescue",
        help="F7 rescue artifact; propagates over its final_partition instead",
    )
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        run_path = Path(args.run)
        stem = run_path.stem
        family_path = (
            Path(args.families) if args.families
            else run_path.parent / f"{stem}.v1.families.strict.json"
        )
        label_path = (
            Path(args.labels) if args.labels
            else run_path.parent / f"{stem}.labels.direct.json"
        )
        family_raw = family_path.read_bytes()
        label_raw = label_path.read_bytes()
        rescue_artifact = None
        rescue_sha256 = None
        if args.rescue:
            rescue_raw = Path(args.rescue).read_bytes()
            rescue_artifact = json.loads(rescue_raw.decode("utf-8"))
            rescue_sha256 = _sha256_bytes(rescue_raw)

        artifact = build_propagation(
            json.loads(family_raw.decode("utf-8")),
            json.loads(label_raw.decode("utf-8")),
            rescue_artifact,
            family_artifact_sha256=_sha256_bytes(family_raw),
            label_artifact_sha256=_sha256_bytes(label_raw),
            rescue_artifact_sha256=rescue_sha256,
        )
        method = artifact["method"]
        output = (
            Path(args.output) if args.output
            else run_path.parent / f"{stem}.v1.labels.{method}.json"
        )
        digest = write_json(output, artifact)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "output": str(output),
        "sha256": digest,
        "artifact": PROPAGATION_ARTIFACT,
        "summary": summarize(artifact),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
