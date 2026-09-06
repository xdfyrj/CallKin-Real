"""R4: hand the frozen V1 exactly what it may see, and nothing else.

The input is three files: `body.json`, `universe.json`, `relation.json`. There
is no fixture, no ground truth, no `users.json` and no FLIRT label, because on
a real stripped binary none of those exist. Everything the frozen V1 needs in
order to retrieve candidates has to come out of these three, or it cannot be
run at all.

Four things this module is responsible for:

- Checking the artifacts belong together. Each names the SHA-256 of the one it
  was built from; a body scored against a different discovery is a silent
  wrong answer, so it is refused instead.
- Selecting the universe: `grouping_role == member`, whatever a function is
  called.
- Passing only complete bodies to F4/F5. An incomplete body still parses and
  every metric still returns a number, but the number describes the bytes that
  happened to decode.
- Reshaping the relation artifact into the six values the frozen relation view
  takes, which the oracle pipeline used to get from a projected fixture and a
  live V0 run.

And one thing it must not do: carry a label. `universe.json` has no `name` and
no `flirt` to begin with; `assert_label_free` states the invariant where it can
be checked rather than leaving it to the caller.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from body_comparison import load_bodies
from body_similarity import FunctionBody

STAGE_INPUTS = {
    "body": ("discovery",),
    "universe": ("discovery", "body"),
    "relation": ("universe",),
}
# What may never appear in anything handed onward. `origin` and `label` are
# ground-truth vocabulary; `flirt` and `canonical_origin` are FLIRT's; `name`
# is the disassembler's, which is a real symbol on anything not stripped.
FORBIDDEN_KEYS = (
    "flirt", "canonical_origin", "label", "label_status",
    "origin", "owner", "name",
)


class ArtifactChainError(ValueError):
    """The three artifacts do not describe the same run."""


@dataclass(frozen=True)
class RealV1Input:
    """Everything the frozen V1 may see about one binary."""

    binary_sha256: str
    #: sha256 of each stage file. `discovery` is the hash body and universe
    #: both recorded, not a file this module read.
    stage_sha256: dict[str, str]
    #: member ids, sorted. The universe, before completeness is considered.
    members: tuple[str, ...]
    #: member ids whose body decoded completely: what F4 and F5 may score.
    comparable: tuple[str, ...]
    bodies: dict[str, FunctionBody]
    relation: dict[str, Any]

    @property
    def excluded_incomplete(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.members) - set(self.comparable)))


def _read(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), hashlib.sha256(raw).hexdigest()


def _payload(artifact: dict[str, Any], stage: str) -> dict[str, Any]:
    if artifact.get("artifact") != f"callkin-real-{stage}":
        raise ArtifactChainError(
            f"expected a callkin-real-{stage} artifact, got "
            f"{artifact.get('artifact')!r}"
        )
    return artifact["payload"]


def _with_opaque_alias(body: FunctionBody) -> FunctionBody:
    quality = dict(body.quality)
    singular = quality.get("opaque_indirect_jump_count", 0)
    plural_present = "opaque_indirect_jumps" in quality
    plural = quality.get("opaque_indirect_jumps")
    for field, value in (
        ("opaque_indirect_jump_count", singular),
        ("opaque_indirect_jumps", plural),
    ):
        if field == "opaque_indirect_jumps" and not plural_present:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ArtifactChainError(
                f"{body.id} has invalid {field}: expected a non-negative "
                f"integer, got {value!r}"
            )
    if plural_present and plural != singular:
        raise ArtifactChainError(
            f"{body.id} has conflicting opaque indirect jump counts: "
            f"opaque_indirect_jump_count={singular!r}, "
            f"opaque_indirect_jumps={plural!r}"
        )
    quality["opaque_indirect_jumps"] = singular
    return replace(body, quality=quality)


def load_stage_artifacts(
    body_path: str | Path,
    universe_path: str | Path,
    relation_path: str | Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """Load the three artifacts and prove they belong to one run.

    Two checks, both of which have to hold: every artifact names the same
    binary, and every input hash an artifact records matches the file that hash
    is supposed to identify. The second is the one that catches a stale body
    sitting next to a fresh universe -- the case that otherwise produces
    numbers rather than an error.
    """
    paths = {
        "body": Path(body_path),
        "universe": Path(universe_path),
        "relation": Path(relation_path),
    }
    artifacts: dict[str, dict[str, Any]] = {}
    digests: dict[str, str] = {}
    for stage, path in paths.items():
        artifact, digest = _read(path)
        if artifact.get("artifact") != f"callkin-real-{stage}":
            raise ArtifactChainError(
                f"{path.name} is {artifact.get('artifact')!r}, not "
                f"callkin-real-{stage}"
            )
        artifacts[stage] = artifact
        digests[stage] = digest

    binaries = {stage: item["binary"]["sha256"] for stage, item in artifacts.items()}
    if len(set(binaries.values())) != 1:
        raise ArtifactChainError(f"artifacts describe different binaries: {binaries}")

    for stage, artifact in artifacts.items():
        recorded = artifact.get("inputs", {})
        missing = [name for name in STAGE_INPUTS[stage] if name not in recorded]
        if missing:
            raise ArtifactChainError(f"{stage} does not name its {missing} input")
        for name, digest in recorded.items():
            if name in digests and digests[name] != digest:
                raise ArtifactChainError(
                    f"{stage} was built from {name} {digest[:12]}, but the "
                    f"{name} artifact given is {digests[name][:12]}"
                )

    # The discovery file is not one of the three, but body and universe each
    # record its hash, so it can still be carried and cross-checked. F7 needs
    # it: the transfers it reads are the discovery payload.
    claimed = {
        stage: artifacts[stage]["inputs"]["discovery"]
        for stage in ("body", "universe")
    }
    if len(set(claimed.values())) != 1:
        raise ArtifactChainError(
            f"body and universe name different discoveries: {claimed}"
        )
    digests["discovery"] = claimed["body"]
    return artifacts, digests


def assert_label_free(value: Any, where: str) -> None:
    """Refuse anything carrying a name, a label or a ground-truth field.

    Checked on the way out rather than assumed. The stage artifacts are built
    to exclude these, and this is what would notice if that stopped being true.
    """
    text = json.dumps(value, sort_keys=True)
    for key in FORBIDDEN_KEYS:
        if f'"{key}"' in text:
            raise ValueError(f"{where} carries a {key} field")


def relation_context(payload: dict[str, Any]) -> dict[str, Any]:
    """The six values the frozen relation view takes.

    The oracle pipeline derived these from a projected fixture and a live V0
    run. Here they come out of `relation.json`, which recorded the same run.
    Signatures are rebuilt from the edges 1-WL actually saw, so a function the
    relation baseline abstained on contributes nothing rather than a zero.
    """
    history = sorted(payload["round_history"], key=lambda item: item["round"])
    if not history:
        raise ArtifactChainError("relation artifact records no rounds")
    final_groups = [sorted(group) for group in payload["predicted_clusters"].values()]
    prior_round_groups = [
        (int(item["round"]), [sorted(group) for group in item["clusters"].values()])
        for item in history[:-1]
    ]

    out_values: dict[str, list[tuple[str, int]]] = {
        record["id"]: [] for record in payload["functions"]
    }
    in_values: dict[str, list[tuple[str, int]]] = {
        record["id"]: [] for record in payload["functions"]
    }
    for edge in payload["edges"]:
        out_values.setdefault(edge["source"], []).append(
            (edge["target"], int(edge["count"]))
        )
        in_values.setdefault(edge["target"], []).append(
            (edge["source"], int(edge["count"]))
        )

    return {
        "final_groups": final_groups,
        "prior_round_groups": prior_round_groups,
        "final_round": int(history[-1]["round"]),
        "out_signatures": {
            key: tuple(sorted(values)) for key, values in sorted(out_values.items())
        },
        "in_signatures": {
            key: tuple(sorted(values)) for key, values in sorted(in_values.items())
        },
        "anchor_classes": dict(sorted(payload["anchor_classes"].items())),
        "rounds": int(payload["rounds"]),
    }


def load_real_v1_input(
    body_path: str | Path,
    universe_path: str | Path,
    relation_path: str | Path,
) -> RealV1Input:
    artifacts, digests = load_stage_artifacts(body_path, universe_path, relation_path)

    universe = _payload(artifacts["universe"], "universe")
    assert_label_free(universe, "universe.json")
    members = tuple(sorted(
        record["id"] for record in universe["functions"]
        if record["grouping_role"] == "member"
    ))
    if not members:
        raise ArtifactChainError("the universe has no members to group")

    body_payload = _payload(artifacts["body"], "body")
    all_bodies = {
        function_id: _with_opaque_alias(body)
        for function_id, body in load_bodies(body_payload).items()
    }
    member_set = set(members)
    missing = member_set - set(all_bodies)
    if missing:
        raise ArtifactChainError(
            f"{len(missing)} universe members have no body record, first: "
            f"{sorted(missing)[:3]}"
        )
    bodies = {
        function_id: body
        for function_id, body in all_bodies.items()
        if function_id in member_set and body.complete
    }

    relation = relation_context(_payload(artifacts["relation"], "relation"))
    assert_label_free(relation["anchor_classes"], "relation anchor classes")

    return RealV1Input(
        binary_sha256=artifacts["body"]["binary"]["sha256"],
        stage_sha256=digests,
        members=members,
        comparable=tuple(sorted(bodies)),
        bodies=bodies,
        relation=relation,
    )


def load_from_run(run_path: str | Path) -> RealV1Input:
    """Locate the three artifacts from a run manifest and load them."""
    run_file = Path(run_path)
    run = json.loads(run_file.read_text(encoding="utf-8"))
    if run.get("artifact") != "callkin-real-run":
        raise ArtifactChainError(f"{run_file.name} is not a run manifest")
    paths = {
        stage: run_file.parent / run["artifacts"][stage]["path"]
        for stage in ("body", "universe", "relation")
    }
    loaded = load_real_v1_input(paths["body"], paths["universe"], paths["relation"])
    for stage, digest in loaded.stage_sha256.items():
        if run["stage_sha256"][stage] != digest:
            raise ArtifactChainError(
                f"{stage} on disk is not the {stage} this run recorded"
            )
    return loaded
