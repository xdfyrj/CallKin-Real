"""R2: decode a discovered function extent into body evidence.

The decoder, normalizer and CFG builder come from the frozen V1 at
`v0-engine-py-f10@0abd091` unchanged, so bodies produced here are comparable
with the ones the formal V1 results were scored on. What is left behind is
everything that needed an oracle: candidate selection, users.json and the
ELF-only extent reader. CallKin-Real supplies bytes through the image reader it
already has for both ELF and PE.

A function whose bytes could not be read or decoded stays in the artifact with
`complete_decode: false` and a reason. Dropping it would let a failure look like
a function that was never there.
"""

from __future__ import annotations

import hashlib
from typing import Any, Protocol

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from body_evidence import DecodedInstruction, build_cfg, normalize_instruction


_OPERAND_KINDS = {
    X86_OP_REG: "register",
    X86_OP_MEM: "memory",
    X86_OP_IMM: "immediate",
}

# The only failures a body may report. Anything else is a bug, not a finding.
EXTENT_NOT_FILE_BACKED = "extent_not_file_backed"
TRUNCATED_EXTENT = "truncated_extent"
DECODE_GAP = "decode_gap"
ZERO_INSTRUCTION_DECODE = "zero_instruction_decode"
FAILURE_REASONS = (
    EXTENT_NOT_FILE_BACKED,
    TRUNCATED_EXTENT,
    DECODE_GAP,
    ZERO_INSTRUCTION_DECODE,
)


class ImageReader(Protocol):
    """What `ElfImage` and `PeImage` already provide.

    The contract is narrow on purpose: `read` raises `ValueError` when the
    request is not backed by file bytes, and nothing else. Any other exception
    is a defect in the reader or in this module, and must not be recorded as a
    property of the binary.
    """

    def read(self, address: int, size: int) -> bytes: ...


def decode_x86_64(code: bytes, address: int) -> tuple[DecodedInstruction, ...]:
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = False
    return tuple(
        DecodedInstruction(
            offset=instruction.address - address,
            size=instruction.size,
            mnemonic=instruction.mnemonic,
            operand_text=instruction.op_str,
            operand_kinds=tuple(
                _OPERAND_KINDS.get(operand.type, "unknown")
                for operand in instruction.operands
            ),
            groups=tuple(
                instruction.group_name(group_id)
                for group_id in instruction.groups
            ),
        )
        for instruction in decoder.disasm(code, address)
    )


def is_complete_decode(
    instructions: tuple[DecodedInstruction, ...],
    size: int,
) -> bool:
    """Every byte of the extent decoded, with no gap and no overrun."""
    next_offset = 0
    for instruction in instructions:
        if instruction.offset != next_offset:
            return False
        next_offset += instruction.size
    return next_offset == size


def build_function_body(
    function_id: str,
    address: int,
    size: int,
    code: bytes,
) -> dict[str, Any]:
    """Decode one extent. Never raises for a bad body: it reports one."""
    if not code:
        return _failed_body(function_id, address, size, EXTENT_NOT_FILE_BACKED)
    if len(code) != size:
        return _failed_body(function_id, address, size, TRUNCATED_EXTENT)

    instructions = decode_x86_64(code, address)
    if not instructions:
        return _failed_body(function_id, address, size, ZERO_INSTRUCTION_DECODE)

    normalized = tuple(
        normalize_instruction(item, function_address=address, function_size=size)
        for item in instructions
    )
    cfg = build_cfg(normalized, size)
    complete = is_complete_decode(instructions, size)
    return {
        "id": function_id,
        "address": f"0x{address:x}",
        "size": size,
        "byte_sha256": hashlib.sha256(code).hexdigest(),
        "instructions": [item.to_dict() for item in instructions],
        "normalized_instructions": [item.to_dict() for item in normalized],
        "blocks": [block.to_dict() for block in cfg.blocks],
        "cfg_edges": [edge.to_dict() for edge in cfg.edges],
        "summary": {
            "byte_size": size,
            "instruction_count": len(instructions),
            "decoded_byte_count": sum(item.size for item in instructions),
            "block_count": len(cfg.blocks),
            "cfg_edge_count": len(cfg.edges),
            "branch_count": sum(
                item.control_flow in {"conditional_branch", "local_jump",
                                      "external_jump", "indirect_jump"}
                for item in normalized
            ),
            "callsite_count": sum(
                item.control_flow == "call" for item in normalized
            ),
        },
        "quality": {
            "complete_decode": complete,
            "opaque_indirect_jump_count": cfg.opaque_indirect_jumps,
            "failure_reason": None if complete else DECODE_GAP,
        },
    }


def _failed_body(
    function_id: str,
    address: int,
    size: int,
    reason: str,
) -> dict[str, Any]:
    return {
        "id": function_id,
        "address": f"0x{address:x}",
        "size": size,
        "byte_sha256": None,
        "instructions": [],
        "normalized_instructions": [],
        "blocks": [],
        "cfg_edges": [],
        "summary": {
            "byte_size": size,
            "instruction_count": 0,
            "decoded_byte_count": 0,
            "block_count": 0,
            "cfg_edge_count": 0,
            "branch_count": 0,
            "callsite_count": 0,
        },
        "quality": {
            "complete_decode": False,
            "opaque_indirect_jump_count": 0,
            "failure_reason": reason,
        },
    }


def build_bodies(
    image: ImageReader,
    extents: dict[int, tuple[str, int]],
) -> dict[str, Any]:
    """Decode every internal extent, keeping the failures.

    `extents` maps address to `(function_id, size)`.
    """
    bodies: list[dict[str, Any]] = []
    for address in sorted(extents):
        function_id, size = extents[address]
        if size <= 0:
            bodies.append(
                _failed_body(function_id, address, size, EXTENT_NOT_FILE_BACKED)
            )
            continue
        try:
            code = image.read(address, size)
        except ValueError:
            # The reader's way of saying these bytes are not in the file.
            code = b""
        # Every other exception propagates. Catching them here would file a
        # library bug or a typo under `extent_not_file_backed`, and the summary
        # would then report a property of the binary that is really a property
        # of this run.
        bodies.append(build_function_body(function_id, address, size, code))

    complete = [b for b in bodies if b["quality"]["complete_decode"]]
    return {
        "schema_version": 2,
        "artifact": "callkin-real-body",
        "functions": bodies,
        "summary": {
            "function_count": len(bodies),
            "complete_count": len(complete),
            "incomplete_count": len(bodies) - len(complete),
            "opaque_indirect_jump_function_count": sum(
                1 for b in bodies if b["quality"]["opaque_indirect_jump_count"]
            ),
            "failure_reasons": {
                reason: sum(
                    1 for b in bodies if b["quality"]["failure_reason"] == reason
                )
                for reason in FAILURE_REASONS
            },
        },
    }


def complete_body_addresses(body_artifact: dict[str, Any]) -> set[int]:
    return {
        int(record["address"], 16)
        for record in body_artifact["functions"]
        if record["quality"]["complete_decode"]
    }


def body_quality_by_address(body_artifact: dict[str, Any]) -> dict[int, dict[str, Any]]:
    return {
        int(record["address"], 16): record["quality"]
        for record in body_artifact["functions"]
    }
