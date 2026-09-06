"""Test-only access to the immutable V1 reference manifest.

The analyzer never imports this module. It exists so tests can verify the
bundled frozen bytes without requiring a sibling checkout of CallKin.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "frozen_reference_manifest.json"
SOURCE_COMMIT = "0abd0911b1aaeff5a8dff99d69eea9153e41d218"


def load_manifest() -> dict[str, Any]:
    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("frozen reference manifest must be an object")
    source = value.get("source")
    if not isinstance(source, Mapping) or source.get("commit") != SOURCE_COMMIT:
        raise AssertionError(
            "frozen reference manifest is not pinned to CallKin 0abd091"
        )
    files = (value.get("frozen_v1") or {}).get("files")
    if not isinstance(files, Mapping):
        raise AssertionError("frozen reference manifest has no frozen_v1 files")
    return value


def expected_hash(relative: str, *, root_file: bool = False) -> str:
    manifest = load_manifest()
    section = "root_files" if root_file else "frozen_v1"
    entries = manifest[section]["files"]
    entry = entries.get(relative)
    if not isinstance(entry, Mapping) or not isinstance(entry.get("sha256"), str):
        raise AssertionError(f"{relative} is absent from the frozen reference manifest")
    return entry["sha256"]


def verify_file(path: Path, relative: str, *, root_file: bool = False) -> None:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = expected_hash(relative, root_file=root_file)
    if actual != expected:
        raise AssertionError(
            f"{relative} differs from the frozen reference: {actual} != {expected}"
        )
