from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_ID_BIAS = 0x100000
_INTEGER_RE = re.compile(r"^[+-]?(?:0x[0-9a-fA-F]+|\d+)$")
_MEMORY_WIDTHS = {
    "byte": 8,
    "word": 16,
    "dword": 32,
    "qword": 64,
    "tbyte": 80,
    "oword": 128,
    "xmmword": 128,
    "ymmword": 256,
    "zmmword": 512,
}
_REGISTER_WIDTHS = {
    "rax": 64, "rbx": 64, "rcx": 64, "rdx": 64,
    "rsi": 64, "rdi": 64, "rbp": 64, "rsp": 64,
    "r8": 64, "r9": 64, "r10": 64, "r11": 64,
    "r12": 64, "r13": 64, "r14": 64, "r15": 64,
    "eax": 32, "ebx": 32, "ecx": 32, "edx": 32,
    "esi": 32, "edi": 32, "ebp": 32, "esp": 32,
    "r8d": 32, "r9d": 32, "r10d": 32, "r11d": 32,
    "r12d": 32, "r13d": 32, "r14d": 32, "r15d": 32,
    "ax": 16, "bx": 16, "cx": 16, "dx": 16,
    "si": 16, "di": 16, "bp": 16, "sp": 16,
    "r8w": 16, "r9w": 16, "r10w": 16, "r11w": 16,
    "r12w": 16, "r13w": 16, "r14w": 16, "r15w": 16,
    "al": 8, "bl": 8, "cl": 8, "dl": 8,
    "ah": 8, "bh": 8, "ch": 8, "dh": 8,
    "sil": 8, "dil": 8, "bpl": 8, "spl": 8,
    "r8b": 8, "r9b": 8, "r10b": 8, "r11b": 8,
    "r12b": 8, "r13b": 8, "r14b": 8, "r15b": 8,
}

@dataclass(frozen=True)
class DecodedInstruction:
    offset: int
    size: int
    mnemonic: str
    operand_text: str
    operand_kinds: tuple[str, ...]
    groups: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "mnemonic": self.mnemonic,
            "operand_text": self.operand_text,
            "operand_kinds": list(self.operand_kinds),
            "groups": list(self.groups),
        }


@dataclass(frozen=True)
class EvidenceSlot:
    kind: str
    value: str | int | None = None
    status: str | None = None
    resolver: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "status": self.status,
            "resolver": self.resolver,
        }


@dataclass(frozen=True)
class NormalizedInstruction:
    offset: int
    size: int
    mnemonic_class: str
    operands: tuple[str, ...]
    control_flow: str
    branch_target_offset: int | None = None
    slots: tuple[EvidenceSlot, ...] = ()
    constants: tuple[int, ...] = ()

    @property
    def token(self) -> str:
        return " ".join((self.mnemonic_class, *self.operands))

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "mnemonic_class": self.mnemonic_class,
            "operands": list(self.operands),
            "control_flow": self.control_flow,
            "branch_target_offset": self.branch_target_offset,
            "slots": [slot.to_dict() for slot in self.slots],
            "constants": list(self.constants),
        }


@dataclass(frozen=True)
class BasicBlock:
    label: str
    start_offset: int
    end_offset: int
    instruction_offsets: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "instruction_offsets": list(self.instruction_offsets),
        }


@dataclass(frozen=True)
class CFGEdge:
    source: str
    target: str
    kind: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class FunctionCFG:
    blocks: tuple[BasicBlock, ...]
    edges: tuple[CFGEdge, ...]
    opaque_indirect_jumps: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocks": [block.to_dict() for block in self.blocks],
            "edges": [edge.to_dict() for edge in self.edges],
            "opaque_indirect_jumps": self.opaque_indirect_jumps,
        }


def body_evidence_bytes(artifact: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            artifact,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def write_body_evidence(artifact: dict[str, Any], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body_evidence_bytes(artifact))


def normalize_instruction(
    instruction: DecodedInstruction,
    transfer: dict[str, Any] | None = None,
    *,
    function_address: int = 0,
    function_size: int = 0,
) -> NormalizedInstruction:
    """Normalize one decoded instruction without erasing variation slots."""

    operands = _split_operands(instruction.operand_text)
    mnemonic = instruction.mnemonic.upper()
    groups = set(instruction.groups)
    register_width = next(
        (
            _register_width(operand)
            for operand, kind in zip(operands, instruction.operand_kinds)
            if kind == "register"
        ),
        None,
    )
    normalized_operands = tuple(
        _normalize_operand(
            operand,
            kind,
            register_width=register_width,
            mnemonic=mnemonic,
        )
        for operand, kind in zip(operands, instruction.operand_kinds)
    )
    slots: list[EvidenceSlot] = []
    branch_target_offset: int | None = None
    control_flow = "fallthrough"

    if "call" in groups:
        control_flow = "call"
        normalized_operands = ("call_target",)
        # Local-only F2 deliberately suppresses the resolved callee identity.
        # Raw operand_text remains in the F1 record for validation, but the
        # normalized comparison evidence cannot receive call-graph answers.
        # The retained transfer parameter preserves the specified interface;
        # this experiment intentionally derives no evidence from it.
        slots.append(EvidenceSlot(
            kind="call",
            value=None,
            status=(
                "address-only"
                if len(instruction.operand_kinds) == 1
                and instruction.operand_kinds[0] == "immediate"
                else "unresolved"
            ),
            resolver=None,
        ))
    elif _is_branch_mnemonic(instruction.mnemonic):
        is_indirect_jump = (
            instruction.mnemonic == "jmp"
            and (
                not operands
                or len(operands) != 1
                or instruction.operand_kinds[:1] != ("immediate",)
            )
        )
        if is_indirect_jump:
            slots.append(EvidenceSlot(
                kind="jump",
                value=None,
                status="opaque",
                resolver="indirect",
            ))
            return NormalizedInstruction(
                offset=instruction.offset,
                size=instruction.size,
                mnemonic_class=mnemonic,
                operands=("opaque_target",),
                control_flow="indirect_jump",
                branch_target_offset=None,
                slots=tuple(slots),
                constants=(),
            )
        direct_target = _direct_branch_target(operands)
        if direct_target is not None:
            candidate = direct_target - function_address
            if candidate >= 0 and (
                not function_address
                or function_address <= direct_target < function_address + max(function_size, 1)
            ):
                branch_target_offset = candidate
        if instruction.mnemonic == "jmp":
            control_flow = "local_jump" if branch_target_offset is not None else "external_jump"
            normalized_operands = ("local_block_target",) if branch_target_offset is not None else ("external_target",)
        else:
            control_flow = "conditional_branch"
            normalized_operands = ("local_block_target",) if branch_target_offset is not None else ("external_target",)
    elif "ret" in groups:
        control_flow = "return"

    # Control-transfer targets are CFG roles or explicit call slots, not
    # numeric constants in the comparison skeleton.
    preserve_constants = control_flow not in {
        "call", "conditional_branch", "local_jump", "external_jump",
    }
    constants = tuple(
        parsed
        for parsed in (
            _parse_integer(operand)
            for operand, kind in zip(operands, instruction.operand_kinds)
            if kind == "immediate" and preserve_constants
        )
        if parsed is not None
    )
    # Preserve RIP-relative data references as explicit slots while removing
    # their addresses from the skeleton.
    for operand, kind in zip(operands, instruction.operand_kinds):
        if kind != "memory" or "rip" not in operand.lower():
            continue
        displacement = _rip_displacement(operand)
        if displacement is None:
            continue
        address = (
            function_address
            + instruction.offset
            + instruction.size
            + displacement
        )
        slots.append(EvidenceSlot(kind="data", value=_function_id(address)))

    return NormalizedInstruction(
        offset=instruction.offset,
        size=instruction.size,
        mnemonic_class=mnemonic,
        operands=normalized_operands,
        control_flow=control_flow,
        branch_target_offset=branch_target_offset,
        slots=tuple(slots),
        constants=constants,
    )


def build_cfg(
    instructions: tuple[NormalizedInstruction, ...],
    function_size: int,
) -> FunctionCFG:
    """Build an address-free intraprocedural CFG from decoded instructions."""

    by_offset = {item.offset: item for item in instructions}
    leaders = {instructions[0].offset} if instructions else set()
    for item in instructions:
        next_offset = item.offset + item.size
        if item.control_flow == "conditional_branch":
            leaders.add(next_offset)
            if item.branch_target_offset is not None:
                leaders.add(item.branch_target_offset)
        elif item.control_flow == "local_jump":
            if item.branch_target_offset is None:
                leaders.add(next_offset)
            else:
                leaders.add(item.branch_target_offset)
            if next_offset in by_offset:
                leaders.add(next_offset)
        elif item.control_flow in {"return", "external_jump", "indirect_jump"}:
            if next_offset in by_offset:
                leaders.add(next_offset)
    leaders &= set(by_offset)

    ordered_leaders = sorted(leaders)
    labels = {
        offset: f"B{index}"
        for index, offset in enumerate(ordered_leaders)
    }
    blocks: list[BasicBlock] = []
    block_by_start: dict[int, BasicBlock] = {}
    for index, start in enumerate(ordered_leaders):
        end = (
            ordered_leaders[index + 1]
            if index + 1 < len(ordered_leaders)
            else max(function_size, (instructions[-1].offset + instructions[-1].size) if instructions else 0)
        )
        block = BasicBlock(
            label=labels[start],
            start_offset=start,
            end_offset=end,
            instruction_offsets=tuple(
                item.offset for item in instructions if start <= item.offset < end
            ),
        )
        blocks.append(block)
        block_by_start[start] = block

    def block_for_offset(offset: int) -> BasicBlock | None:
        selected: BasicBlock | None = None
        for candidate in blocks:
            if candidate.start_offset <= offset < candidate.end_offset:
                selected = candidate
                break
        return selected

    edges: list[CFGEdge] = []
    opaque_count = 0
    for block in blocks:
        last = by_offset.get(block.instruction_offsets[-1]) if block.instruction_offsets else None
        next_block = block_for_offset(block.end_offset)
        successors: set[tuple[str, str]] = set()
        if last is None:
            pass
        elif last.control_flow == "return":
            pass
        elif last.control_flow == "conditional_branch":
            target_block = (
                block_for_offset(last.branch_target_offset)
                if last.branch_target_offset is not None
                else None
            )
            successors.add(
                (target_block.label if target_block else "EXIT", "conditional_target")
            )
            successors.add(
                (next_block.label if next_block else "EXIT", "fallthrough")
            )
        elif last.control_flow == "local_jump":
            target_block = (
                block_for_offset(last.branch_target_offset)
                if last.branch_target_offset is not None
                else None
            )
            successors.add(
                (target_block.label if target_block else "EXIT", "direct_jump")
            )
        elif last.control_flow == "external_jump":
            successors.add(("EXIT", "external_exit"))
        elif last.control_flow == "indirect_jump":
            opaque_count += 1
            successors.add(("OPAQUE", "opaque_successor"))
        elif next_block is not None:
            successors.add((next_block.label, "fallthrough"))

        edges.extend(
            CFGEdge(source=block.label, target=target, kind=kind)
            for target, kind in sorted(successors)
        )

    return FunctionCFG(
        blocks=tuple(blocks),
        edges=tuple(edges),
        opaque_indirect_jumps=opaque_count,
    )


def _split_operands(text: str) -> tuple[str, ...]:
    text = text.strip()
    return tuple(part.strip() for part in text.split(",")) if text else ()


def _parse_integer(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace(" ", "")
    if not _INTEGER_RE.fullmatch(text):
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _register_width(operand: str) -> int | None:
    name = operand.strip().lower()
    width = _REGISTER_WIDTHS.get(name)
    if width is not None:
        return width
    # Capstone exposes SIMD and mask registers as ordinary register
    # operands.  Keep their architectural width instead of collapsing them
    # to ``regunknown``; this is local evidence, not a type guess.
    for prefix, vector_width in (
        ("xmm", 128),
        ("ymm", 256),
        ("zmm", 512),
        ("bnd", 128),
        ("mm", 64),
        ("k", 64),
    ):
        if re.fullmatch(rf"{prefix}[0-9]+", name):
            return vector_width
    if re.fullmatch(r"st(?:\([0-7]\)|[0-7])", name):
        return 80
    return None


def _normalize_operand(
    operand: str,
    kind: str,
    *,
    register_width: int | None,
    mnemonic: str,
) -> str:
    if kind == "register":
        width = _register_width(operand)
        return f"reg{width or 'unknown'}"
    if kind == "immediate":
        value = _parse_integer(operand)
        if value is None:
            return "imm_unknown"
        return "imm_small" if abs(value) <= 0xfffff else "imm_address_like"
    if kind != "memory":
        return "unknown"

    lowered = operand.lower()
    width = _memory_width(operand) or register_width
    if width is None and mnemonic in {"LEA"}:
        width = 64
    memory_class = "general_pointer"
    if "rip" in lowered:
        memory_class = "ip_data_slot"
    elif "rsp" in lowered or "rbp" in lowered or "esp" in lowered or "ebp" in lowered:
        memory_class = "stack"
    return f"{memory_class}{width or ''}"


def _direct_branch_target(operands: tuple[str, ...]) -> int | None:
    return _parse_integer(operands[0]) if len(operands) == 1 else None


def _is_branch_mnemonic(mnemonic: str) -> bool:
    return mnemonic.startswith("j") or mnemonic in {
        "loop",
        "loope",
        "loopne",
        "loopz",
        "loopnz",
    }


def _memory_width(operand: str) -> int | None:
    match = re.search(
        r"\b(byte|word|dword|qword|tbyte|oword|xmmword|ymmword|zmmword)\s+ptr\b",
        operand.lower(),
    )
    return _MEMORY_WIDTHS.get(match.group(1)) if match else None


def _rip_displacement(operand: str) -> int | None:
    match = re.search(r"\[\s*rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\s*\]", operand)
    if match is None:
        return None
    value = _parse_integer(match.group(2))
    if value is None:
        return None
    return -value if match.group(1) == "-" else value


def _function_id(address: int, id_bias: int = DEFAULT_ID_BIAS) -> str:
    return f"FUN_{address + id_bias:08x}"


def _function_extent_hint(_: DecodedInstruction) -> int:
    return 0
