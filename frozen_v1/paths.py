from __future__ import annotations

import re
from pathlib import Path


DEFAULT_BUILD = "O3S"
DEFAULT_PROFILE = "plain"
BUILD_PROFILES = ("plain", "min")
SUBJECT_CANDIDATE_SCOPE = "subject"
RUST_NONSTD_CANDIDATE_SCOPE = "rust-nonstd"
DEFAULT_CANDIDATE_SCOPE = RUST_NONSTD_CANDIDATE_SCOPE
CANDIDATE_SCOPES = (SUBJECT_CANDIDATE_SCOPE, RUST_NONSTD_CANDIDATE_SCOPE)
DIRECT_TRACK = "direct"
DIRECT_IN_TRACK = "direct-in"
ANGR_TRACK = "angr"
DEFAULT_ANALYSIS_TRACK = DIRECT_TRACK
ANALYSIS_TRACKS = (DIRECT_TRACK, DIRECT_IN_TRACK, ANGR_TRACK)
DIRECT_EVIDENCE = "direct"
ANGR_EVIDENCE = "angr"
EVIDENCE_BACKENDS = (DIRECT_EVIDENCE, ANGR_EVIDENCE)
ADDRESS_ANCHOR_POLICY = "address"
ROLE_ANCHOR_POLICY = "role"
DEFAULT_ANCHOR_POLICY = ADDRESS_ANCHOR_POLICY
ANCHOR_POLICIES = (ADDRESS_ANCHOR_POLICY, ROLE_ANCHOR_POLICY)


def normalize_build(build: str | None) -> str:
    return (build or DEFAULT_BUILD).upper()


def normalize_profile(profile: str | None) -> str:
    normalized = (profile or DEFAULT_PROFILE).lower()
    if normalized not in BUILD_PROFILES:
        raise ValueError(
            f"unknown build profile: {profile!r}. "
            f"expected one of {', '.join(BUILD_PROFILES)}"
        )
    return normalized


def normalize_track(track: str | None) -> str:
    normalized = (track or DEFAULT_ANALYSIS_TRACK).lower()
    if normalized not in ANALYSIS_TRACKS:
        raise ValueError(
            f"unknown analysis track: {track!r}. "
            f"expected one of {', '.join(ANALYSIS_TRACKS)}"
        )
    return normalized


def normalize_candidate_scope(scope: str | None) -> str:
    normalized = (scope or DEFAULT_CANDIDATE_SCOPE).lower()
    if normalized not in CANDIDATE_SCOPES:
        raise ValueError(
            f"unknown candidate scope: {scope!r}. "
            f"expected one of {', '.join(CANDIDATE_SCOPES)}"
        )
    return normalized


def normalize_anchor_policy(policy: str | None) -> str:
    normalized = (policy or DEFAULT_ANCHOR_POLICY).lower()
    if normalized not in ANCHOR_POLICIES:
        raise ValueError(
            f"unknown anchor policy: {policy!r}. "
            f"expected one of {', '.join(ANCHOR_POLICIES)}"
        )
    return normalized


def evidence_backend_for_track(track: str | None) -> str:
    return ANGR_EVIDENCE if normalize_track(track) == ANGR_TRACK else DIRECT_EVIDENCE


def strip_known_suffix(value: str, suffixes: tuple[str, ...]) -> str:
    name = Path(value).name
    for suffix in suffixes:
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def split_case_build(
    value: str,
    build: str | None = None,
    *,
    suffixes: tuple[str, ...] = (
        ".fixture.bin",
        ".gt.bin",
        ".fixture.json",
        ".gt.json",
        ".users.json",
        ".bin",
        ".json",
        ".rs",
    ),
) -> tuple[str, str]:
    stem = strip_known_suffix(value, suffixes)

    if build is None and "." in stem:
        maybe_case, maybe_build = stem.rsplit(".", 1)
        if re.fullmatch(r"O\d+[A-Z]*", maybe_build.upper()):
            return maybe_case, maybe_build.upper()

    return stem, normalize_build(build)


def output_stem(case: str, build: str) -> str:
    return f"{case}.{normalize_build(build)}"


def source_rs_for(case: str) -> str:
    return f"src/{case}.rs"


def fixture_binary_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"bin/{normalize_profile(profile)}/{output_stem(case, build)}.fixture.bin"


def gt_binary_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"gt_bin/{normalize_profile(profile)}/{output_stem(case, build)}.gt.bin"


def build_manifest_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"build_info/{normalize_profile(profile)}/{output_stem(case, build)}.json"


def resolve_fixture_binary(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return fixture_binary_for(case, build, profile)


def resolve_gt_binary(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return gt_binary_for(case, build, profile)


def fixture_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    track: str = DEFAULT_ANALYSIS_TRACK,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
    anchor_policy: str = DEFAULT_ANCHOR_POLICY,
) -> str:
    normalized_track = normalize_track(track)
    candidate_scope = normalize_candidate_scope(candidate_scope)
    anchor_policy = normalize_anchor_policy(anchor_policy)
    profile = normalize_profile(profile)
    stem = output_stem(case, build)
    parts = ["fixtures"]
    if normalized_track != DIRECT_TRACK:
        parts.append(normalized_track)
    if anchor_policy != DEFAULT_ANCHOR_POLICY:
        parts.append(anchor_policy)
    if candidate_scope != SUBJECT_CANDIDATE_SCOPE:
        parts.append(candidate_scope)
    parts.extend((profile, f"{stem}.fixture.json"))
    return "/".join(parts)


def raw_graph_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    evidence_backend: str = DIRECT_EVIDENCE,
) -> str:
    if evidence_backend not in EVIDENCE_BACKENDS:
        raise ValueError(
            f"unknown evidence backend: {evidence_backend!r}. "
            f"expected one of {', '.join(EVIDENCE_BACKENDS)}"
        )
    parts = ["extractions"]
    if evidence_backend != DIRECT_EVIDENCE:
        parts.append(evidence_backend)
    parts.extend((normalize_profile(profile), f"{output_stem(case, build)}.raw.json"))
    return "/".join(parts)


def body_evidence_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    scope = normalize_candidate_scope(candidate_scope)
    parts = ["body_evidence"]
    if scope != DEFAULT_CANDIDATE_SCOPE:
        parts.append(scope)
    parts.extend((
        normalize_profile(profile),
        f"{output_stem(case, build)}.body.json",
    ))
    return "/".join(parts)


def gt_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return _scoped_artifact_path(
        "ground_truth", case, build, profile, candidate_scope, ".gt.json"
    )


def users_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return _scoped_artifact_path(
        "users", case, build, profile, candidate_scope, ".users.json"
    )


def oxidizer_labels_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    """Return the stripped-binary FLIRT label artifact for one build."""
    return (
        f"labels/oxidizer/{normalize_profile(profile)}/"
        f"{output_stem(case, build)}.labels.json"
    )


def all_rust_catalog_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    """Return the non-stripped, evaluation-only all-Rust catalog path."""
    return (
        f"ground_truth/all-rust/{normalize_profile(profile)}/"
        f"{output_stem(case, build)}.catalog.json"
    )


def flirt_audit_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    """Return the evaluation-only direct-FLIRT audit result path."""
    return result_json_for(
        case,
        f"{output_stem(case, build)}.flirt_audit",
        profile,
    )


def boundaries_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return (
        f"boundaries/{normalize_profile(profile)}/"
        f"{output_stem(case, build)}.boundaries.json"
    )


def resolve_fixture_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    track: str = DEFAULT_ANALYSIS_TRACK,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
    anchor_policy: str = DEFAULT_ANCHOR_POLICY,
) -> str:
    return fixture_json_for(
        case, build, profile, track, candidate_scope, anchor_policy
    )


def resolve_gt_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return gt_json_for(case, build, profile, candidate_scope)


def resolve_users_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return users_json_for(case, build, profile, candidate_scope)


def _scoped_artifact_path(
    root: str,
    case: str,
    build: str,
    profile: str,
    candidate_scope: str,
    suffix: str,
) -> str:
    parts = [root]
    scope = normalize_candidate_scope(candidate_scope)
    if scope != SUBJECT_CANDIDATE_SCOPE:
        parts.append(scope)
    parts.extend((normalize_profile(profile), f"{output_stem(case, build)}{suffix}"))
    return "/".join(parts)


def result_dir_for(case: str, profile: str = DEFAULT_PROFILE) -> str:
    """Return the directory for one case's score results."""
    case_name = Path(case).name
    if not case_name or case_name in (".", ".."):
        raise ValueError(f"invalid result case: {case!r}")
    return f"results/{case_name}/{normalize_profile(profile)}"


def result_json_for(
    case: str,
    name: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    """Return a case/profile result path for a simple JSON filename."""
    filename = Path(name).name
    if not filename or filename in (".", ".."):
        raise ValueError(f"invalid result name: {name!r}")
    if not filename.endswith(".json"):
        filename += ".json"
    return f"{result_dir_for(case, profile)}/{filename}"


def f45_partition_for(
    case: str,
    build: str = DEFAULT_BUILD,
    profile: str = DEFAULT_PROFILE,
    mode: str = "out-in",
    track: str = ANGR_TRACK,
    candidate_scope: str = RUST_NONSTD_CANDIDATE_SCOPE,
    anchor_policy: str = ROLE_ANCHOR_POLICY,
) -> str:
    """Return the reproducible V0 partition artifact path for F4.5."""
    track = normalize_track(track)
    candidate_scope = normalize_candidate_scope(candidate_scope)
    anchor_policy = normalize_anchor_policy(anchor_policy)
    return result_json_for(
        case,
        f"{output_stem(case, build)}.f4_5.{track}.{candidate_scope}."
        f"{anchor_policy}.{mode}.partition",
        profile,
    )


def f45_result_for(
    case: str,
    build: str = DEFAULT_BUILD,
    profile: str = DEFAULT_PROFILE,
    mode: str = "out-in",
    track: str = ANGR_TRACK,
    candidate_scope: str = RUST_NONSTD_CANDIDATE_SCOPE,
    anchor_policy: str = ROLE_ANCHOR_POLICY,
) -> str:
    """Return the F4.5 collision diagnostic result path."""
    track = normalize_track(track)
    candidate_scope = normalize_candidate_scope(candidate_scope)
    anchor_policy = normalize_anchor_policy(anchor_policy)
    return result_json_for(
        case,
        f"{output_stem(case, build)}.f4_5.{track}.{candidate_scope}."
        f"{anchor_policy}.{mode}.collision",
        profile,
    )


def baseline_result_for(profile: str = DEFAULT_PROFILE) -> str:
    return result_json_for("micro-corpus", "baseline", profile)


def all_modes_result_for(profile: str = DEFAULT_PROFILE) -> str:
    return result_json_for("micro-corpus", "all_modes", profile)
