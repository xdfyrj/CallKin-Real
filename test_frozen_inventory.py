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

HERE = Path(__file__).resolve().parent
FROZEN_DIR = HERE / "frozen_v1"
FROZEN_V1 = HERE.parent / "v0-engine-py-f10"

# Written on purpose, and why. Each replaces a module the frozen code imports
# at module scope but CallKin-Real must never call.
STUBS = {
    "engine.py": "the V0 engine: the relation partition comes from relation.json",
    "loader.py": "projected fixtures do not exist for a real stripped binary",
    "build_manifest.py": "only sha256_file is needed; the rest parses build manifests",
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


def test_every_file_is_frozen_or_a_declared_stub() -> str:
    if not FROZEN_V1.is_dir():
        return "  (frozen V1 checkout absent; inventory unchecked)"

    identical, stubs, drifted, unaccounted = [], [], [], []
    for relative in _inventory():
        name = relative.as_posix()
        here = FROZEN_DIR / relative
        there = FROZEN_V1 / relative
        if name in STUBS:
            stubs.append(name)
            # A stub must not be a copy: if it were, the oracle path would be
            # available again and nothing would say so.
            if there.is_file() and _sha256(here) == _sha256(there):
                drifted.append(f"{name} is the real module, not a stub")
            continue
        if not there.is_file():
            unaccounted.append(name)
        elif _sha256(here) != _sha256(there):
            drifted.append(f"{name} differs from the frozen V1")
        else:
            identical.append(name)

    if drifted:
        raise AssertionError("frozen_v1 has drifted:\n  " + "\n  ".join(drifted))
    if unaccounted:
        raise AssertionError(
            "frozen_v1 holds files that are neither frozen nor declared stubs:\n  "
            + "\n  ".join(unaccounted)
        )
    assert sorted(stubs) == sorted(STUBS), sorted(stubs)
    return f"  ({len(identical)} frozen files, {len(stubs)} declared stubs)"


def test_each_stub_says_why_it_refuses():
    for name in STUBS:
        text = (FROZEN_DIR / name).read_text(encoding="utf-8")
        assert "stub" in text.lower() or "only" in text.lower(), name
    # The two that must refuse at call time, rather than merely be smaller.
    for name in ("engine.py", "loader.py"):
        assert "NotImplementedError" in (FROZEN_DIR / name).read_text(encoding="utf-8")


def main() -> int:
    note = test_every_file_is_frozen_or_a_declared_stub()
    test_each_stub_says_why_it_refuses()
    print("CallKin-Real frozen inventory: PASS")
    print(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
