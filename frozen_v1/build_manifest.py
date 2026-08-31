"""The one function `v1_consensus_candidates.py` needs from build_manifest.

The real module parses build manifests: which subject was compiled, with which
profile, from which source tree. None of that exists for a stripped binary
found in the wild. `sha256_file` is the only name the consensus derivation
imports, and it is reproduced here with the frozen body so the
`source_candidate_sha256` it records is the same value the frozen V1 recorded.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
