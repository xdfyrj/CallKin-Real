"""Every file in `frozen_v1/` is either the frozen bytes or a named stub.

The per-stage tests each check the handful of files they use. This checks the
directory as a whole, which catches the two things those cannot: a frozen file
quietly edited in place, and a new file appearing beside them that no test
compares against anything.

`frozen_v1/` is the only place CallKin-Real carries frozen V1 code. If a file
there has drifted, the formal V1 results no longer describe what this tool
does, whatever the stage tests say about the files they happen to name.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from frozen_reference import expected_hash, load_manifest

HERE = Path(__file__).resolve().parent
FROZEN_DIR = HERE / "frozen_v1"

# Written on purpose, and why. Each replaces a module the frozen code imports
# at module scope but CallKin-Real must never call.
STUBS = {
    "engine.py": "the V0 engine: the relation partition comes from relation.json",
    "loader.py": "projected fixtures do not exist for a real stripped binary",
    "build_manifest.py": "only sha256_file is needed; the rest parses build manifests",
    "graph_projector.py": "only function_id; the rest projects a fixture from build knowledge",
    "oxidizer_adapter.py": "imports gt_extractor, which spec 12.4 forbids in the analysis path",
}
TRACKED_SUFFIXES = (".py", ".json", ".gz")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inventory() -> list[Path]:
    return sorted(
        path.relative_to(FROZEN_DIR)
        for path in FROZEN_DIR.rglob("*")
        if path.is_file()
        and path.suffix in TRACKED_SUFFIXES
        and "__pycache__" not in path.parts
    )


def test_reference_manifest_covers_the_exact_callkin_inventory():
    manifest = load_manifest()
    entries = manifest["frozen_v1"]["files"]
    assert set(entries) == {path.as_posix() for path in _inventory()}
    assert sum(item["kind"] == "frozen" for item in entries.values()) == 20
    assert sum(item["kind"] == "adapted" for item in entries.values()) == 1
    assert sum(item["kind"] == "stub" for item in entries.values()) == 5
    assert expected_hash("body_similarity.py", root_file=True)


def test_every_file_is_frozen_or_a_declared_stub() -> str:
    manifest = load_manifest()
    entries = manifest["frozen_v1"]["files"]
    actual_names = {path.as_posix() for path in _inventory()}
    expected_names = set(entries)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise AssertionError(
            f"frozen_v1 inventory mismatch: missing={missing}, extra={extra}"
        )

    identical, adapted, stubs, drifted = [], [], [], []
    for relative in _inventory():
        name = relative.as_posix()
        here = FROZEN_DIR / relative
        entry = entries[name]
        if entry["kind"] == "stub":
            stubs.append(name)
        if entry["kind"] == "adapted":
            adapted.append(name)
        if _sha256(here) != entry["sha256"]:
            drifted.append(f"{name} differs from the CallKin reference")
        elif entry["kind"] == "frozen":
            identical.append(name)

    if drifted:
        raise AssertionError("frozen_v1 has drifted:\n  " + "\n  ".join(drifted))
    assert sorted(stubs) == sorted(STUBS), sorted(stubs)
    if _sha256(HERE / "body_similarity.py") != expected_hash(
        "body_similarity.py", root_file=True
    ):
        raise AssertionError("body_similarity.py differs from the CallKin reference")
    assert adapted == ["v1_engine.py"]
    return f"  ({len(identical)} frozen files, {len(adapted)} adapted files, {len(stubs)} declared stubs)"


def test_each_stub_says_why_it_refuses():
    for name in STUBS:
        text = (FROZEN_DIR / name).read_text(encoding="utf-8")
        assert "stub" in text.lower() or "only" in text.lower(), name
    # The ones that must refuse at call time, rather than merely be smaller.
    # build_manifest.py and graph_projector.py each keep one pure function that
    # is genuinely needed, so they are the exceptions.
    for name in ("engine.py", "loader.py", "oxidizer_adapter.py"):
        assert "NotImplementedError" in (FROZEN_DIR / name).read_text(encoding="utf-8")


def main() -> int:
    test_reference_manifest_covers_the_exact_callkin_inventory()
    note = test_every_file_is_frozen_or_a_declared_stub()
    test_each_stub_says_why_it_refuses()
    print("CallKin-Real frozen inventory: PASS")
    print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
