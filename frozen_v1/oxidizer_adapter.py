"""Refusal stub. CallKin-Real validates its own label artifact.

The frozen `oxidizer_adapter.py` imports `normalize_all_rust_origin` and
`rust_symbol_owner` from `gt_extractor`, which spec 12.4 forbids in the
analysis path, and its `validate_label_artifact` requires a build-manifest
provenance block that a stripped binary found in the wild does not have.

CallKin-Real builds and validates `labels.direct.json` in `flirt_labels.py`,
with the normalizer reproduced in `rust_symbol_parser.py`, and calls the frozen
propagation core directly. `family_label_propagation.py` imports this name at
module scope for its own file-based entry point, which is the one CallKin-Real
does not use.
"""

from __future__ import annotations

from typing import Any

LABEL_SCHEMA_VERSION = 1
DIRECT_FLIRT = "direct-flirt"
PROPAGATED_WRAPPER = "propagated-wrapper"
CLEANUP_HEURISTIC = "cleanup-heuristic"
EVIDENCE_STAGES = (DIRECT_FLIRT, PROPAGATED_WRAPPER, CLEANUP_HEURISTIC)

_MESSAGE = (
    "the frozen Oxidizer label schema requires build-manifest provenance a "
    "stripped binary does not carry; CallKin-Real validates labels.direct.json "
    "in flirt_labels.py"
)


def validate_label_artifact(data: object) -> dict[str, Any]:
    raise NotImplementedError(_MESSAGE)
