from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.metadata
import os
import json
import logging
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from body_builder import body_quality_by_address, build_bodies


ID_BIAS = 0x100000
RELATION_MODE = "out-in"
# The rules that decide the universe and the projected graph. Named here rather
# than written inline in the run manifest, so the downstream stages can hash the
# same strings the manifest reports instead of a paraphrase of them.
GROUPING_ROLE_RULE = (
    "internal function with a complete body is a member, whatever its owner or "
    "FLIRT label; root, import and address-only targets are context-only; "
    "incomplete internal functions abstain"
)
EDGE_RULE = (
    "exact direct, format-specific relocation/IAT, and angr singleton targets; "
    "address-only targets become opaque anchors"
)
# Opaque targets are coloured by their address, root by its role, imports by
# their own name. The frozen vocabulary calls that the address policy.
ANCHOR_POLICY = "address"
STANDARD_OWNERS = {"core", "alloc", "std", "__rustc"}
PAD_MNEMONICS = {"nop", "int3", "ud2"}


def function_id(address: int) -> str:
    return f"FUN_{address + ID_BIAS:08x}"


def address_from_function_id(value: str) -> int:
    """Invert `function_id`.

    The frozen V1 keeps this beside its ground-truth extractor. It is pure
    string arithmetic and importing that module into CallKin-Real would put a
    ground-truth dependency in the analysis path, so it lives here instead.
    """
    if not value.startswith("FUN_"):
        raise ValueError(f"not a function id: {value!r}")
    try:
        biased = int(value[4:], 16)
    except ValueError as exc:
        raise ValueError(f"not a function id: {value!r}") from exc
    return biased - ID_BIAS


def hex_address(address: int | None) -> str | None:
    return None if address is None else f"0x{address:x}"


def canonical_sha256(value: Any) -> str:
    """Hash a JSON value the same way regardless of key order or whitespace."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def grouping_core(
    *,
    binary_sha256: str,
    root_id: str | None,
    clusters: dict[str, list[str]],
    rounds: int,
    functions: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    abstentions: list[dict[str, Any]],
) -> dict[str, Any]:
    """The part of the result that must not depend on any label.

    Function records are stripped of `flirt` and `label_status` here rather
    than at the call site, so a caller cannot leak a label into the core by
    forgetting to remove one.
    """
    return {
        "binary_sha256": binary_sha256,
        "root": root_id,
        "rounds": rounds,
        "predicted_clusters": clusters,
        # An allowlist, not a denylist. A denylist leaks the internal `name`
        # today and would leak any label field added later.
        "functions": [
            {
                key: record[key]
                for key in (
                    "id", "address", "kind", "size", "boundary_source",
                    "analysis_status", "grouping_role", "relation_status",
                    "quality", "external_identity",
                )
                if key in record
            }
            for record in functions
        ],
        "edges": edges,
        "abstentions": abstentions,
    }


STAGE_NAMES = ("discovery", "body", "universe", "relation")

# Which earlier artifacts each stage was computed from. Recording the input
# hashes is what makes a chain of artifacts checkable after the fact: a body
# whose `inputs.discovery` does not match the discovery file beside it was
# built from something else.
STAGE_INPUTS: dict[str, tuple[str, ...]] = {
    "discovery": (),
    "body": ("discovery",),
    "universe": ("discovery", "body"),
    "relation": ("universe",),
}


def module_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        module = sys.modules.get(name)
        return getattr(module, "__version__", None) if module else None


def radare2_version() -> str | None:
    executable = shutil.which("r2")
    if executable is None:
        return None
    # On Windows the radare2 distribution puts a .BAT on PATH, and CreateProcess
    # cannot run one directly. r2pipe handles this itself, so only this probe
    # needs the interpreter.
    command = (
        ["cmd", "/c", executable, "-v"]
        if executable.lower().endswith((".bat", ".cmd"))
        else [executable, "-v"]
    )
    try:
        completed = subprocess.run(
            command, text=True, capture_output=True, timeout=30, check=False,
            env={**os.environ, "TERM": "dumb"},
        )
    except Exception:
        return None
    lines = (completed.stdout or "").strip().splitlines()
    return lines[0].strip() if lines else None


def toolchain_fingerprint() -> dict[str, Any]:
    """What produced these artifacts.

    Discovery is not a function of the binary alone. radare2's `aaa` and angr's
    CFGFast both change between versions, and the same binary has already
    yielded different function counts on two machines. Without this recorded,
    two artifacts that disagree cannot be told apart from two runs of different
    toolchains, and neither can be reproduced.
    """
    return {
        "python": platform.python_version(),
        "capstone": module_version("capstone"),
        "angr": module_version("angr"),
        "r2pipe": module_version("r2pipe"),
        "pefile": module_version("pefile"),
        "radare2": radare2_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


def relation_edges(
    edges: Mapping[int, Mapping[int, int]],
    relation_status: Mapping[int, str],
) -> list[dict[str, Any]]:
    """Only the edges 1-WL actually saw.

    Selecting by `grouping_role` instead would keep the edges of a function V1
    groups but V0 abstained on -- a complete isolated function's self-edge, for
    instance. Those edges were never read by the relation method, so recording
    them in its artifact would misstate what the baseline was given.
    """
    visible = {
        address for address, status in relation_status.items()
        if status in {RELATION_MEMBER, RELATION_CONTEXT}
    }
    return [
        {"source": function_id(source), "target": function_id(target), "count": count}
        for source in sorted(edges)
        if source in visible
        for target, count in sorted(edges[source].items())
        if target in visible
    ]


def stage_payloads(
    *,
    binary_sha256: str,
    root_id: str | None,
    functions: list[dict[str, Any]],
    transfers: list[dict[str, Any]],
    body_artifact: dict[str, Any],
    edges: list[dict[str, Any]],
    clusters: dict[str, list[str]],
    rounds: int,
    round_history: list[dict[str, Any]],
    anchor_classes: dict[str, str],
    abstentions: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """The four label-free stage payloads.

    Every one must be identical with and without FLIRT, because FLIRT runs
    after all four. Splitting them says which stage broke rather than only that
    one did.

    Each is an allowlist over the same function records, for the reason
    `grouping_core` is: a denylist leaks the internal `name` and would leak
    whatever label field is added next.
    """
    def project(keys: tuple[str, ...]) -> list[dict[str, Any]]:
        return [
            {key: record[key] for key in keys if key in record}
            for record in functions
        ]

    return {
        "discovery": {
            "binary_sha256": binary_sha256,
            "root": root_id,
            # Raw transfers, before the universe removes anything.
            "transfers": transfers,
            "functions": project((
                "id", "address", "kind", "size", "boundary_source",
                "external_identity",
            )),
        },
        "body": body_artifact,
        "universe": {
            "functions": project(("id", "analysis_status", "grouping_role", "quality")),
            "abstentions": abstentions,
        },
        "relation": {
            "rounds": rounds,
            "predicted_clusters": clusters,
            # Every round, not just the fixpoint. The relation retrieval view
            # scores how long two functions stayed together, so dropping the
            # intermediate partitions would leave it with one bit.
            "round_history": round_history,
            # Colours of the fixed nodes 1-WL refined against: root, imports
            # and address-only targets. Image facts, never a FLIRT label.
            "anchor_classes": anchor_classes,
            # The projected graph 1-WL actually saw.
            "edges": edges,
            "functions": project(("id", "relation_status")),
        },
    }


def artifact_envelope(
    *,
    stage: str,
    binary_sha256: str,
    inputs: dict[str, str],
    payload: dict[str, Any],
) -> dict[str, Any]:
    """A stage artifact: what was computed, and from what.

    No absolute path and no toolchain fingerprint. Those belong to the run,
    not to the result, and putting them here would make the raw SHA-256 of
    every stage file differ between a Windows and a WSL run of the same
    binary even when the grouping came out identical -- which is the one
    comparison these hashes are for. Where the toolchain does change the
    result, the payload changes and the hash follows. `run.json` records the
    path, the toolchain and each stage hash, so a difference can still be
    attributed.
    """
    return {
        "schema_version": 3,
        "artifact": f"callkin-real-{stage}",
        "stage": stage,
        "binary": {"sha256": binary_sha256},
        "inputs": inputs,
        "payload": payload,
    }


def tally(records: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(collections.Counter(record[key] for record in records).items()))


def write_json(path: Path, value: Any) -> str:
    """Write canonical UTF-8 with LF, and return the file's SHA-256.

    Bytes, not `write_text`: on Windows text mode turns every newline into
    CRLF, so the same run would hash differently on two platforms and the
    artifact chain would be worthless for exactly the comparison it exists for.
    """
    encoded = (
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()


def stage_artifact_path(output: Path, stage: str) -> Path:
    return output.parent / f"{output.stem}.{stage}.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class Function:
    address: int
    size: int
    name: str
    boundary_source: str
    kind: str = "code"
    flirt: dict[str, str] | None = None

    @property
    def end(self) -> int:
        return self.address + max(self.size, 0)

    @property
    def id(self) -> str:
        return function_id(self.address)


@dataclass
class Transfer:
    source: int
    callsite: int
    kind: str
    operand_kind: str
    instruction: str
    status: str
    target: int | None
    resolver: str | None
    confidence: str
    angr_status: str | None = None
    angr_targets: tuple[int, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "source": function_id(self.source),
            "source_address": hex_address(self.source),
            "callsite": hex_address(self.callsite),
            "kind": self.kind,
            "operand_kind": self.operand_kind,
            "instruction": self.instruction,
            "status": self.status,
            "target": function_id(self.target) if self.target is not None else None,
            "target_address": hex_address(self.target),
            "resolver": self.resolver,
            "confidence": self.confidence,
            "angr_status": self.angr_status,
            "angr_targets": [function_id(value) for value in self.angr_targets],
        }


class ElfImage:
    def __init__(self, path: Path) -> None:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.relocation import RelocationSection

        self.path = path
        self.format = "ELF x86-64"
        self.root_source = "ELF entry and discovered function containment"
        self.segments: list[tuple[int, int, int, int, bytes]] = []
        self.executable_ranges: list[tuple[int, int]] = []
        self.relocations: dict[int, int] = {}
        self.boundary_ranges: list[tuple[int, int]] = []

        with path.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.header["e_type"] not in {"ET_EXEC", "ET_DYN"}:
                raise ValueError("CallKin-Real currently requires an ELF executable")
            if elf.header["e_machine"] != "EM_X86_64":
                raise ValueError("CallKin-Real currently supports x86-64 ELF only")
            self.entry = int(elf.header["e_entry"])
            for segment in elf.iter_segments():
                if segment["p_type"] != "PT_LOAD":
                    continue
                start = int(segment["p_vaddr"])
                filesz = int(segment["p_filesz"])
                memsz = int(segment["p_memsz"])
                offset = int(segment["p_offset"])
                stream.seek(offset)
                data = stream.read(filesz)
                self.segments.append((start, start + memsz, offset, filesz, data))
                if int(segment["p_flags"]) & 1:
                    self.executable_ranges.append((start, start + memsz))

            for section in elf.iter_sections():
                if not isinstance(section, RelocationSection):
                    continue
                symbol_table = elf.get_section(section["sh_link"])
                for relocation in section.iter_relocations():
                    entry = relocation.entry
                    r_type = int(entry["r_info_type"])
                    addend = int(entry.get("r_addend", 0))
                    target: int | None = None
                    if r_type == 8:  # R_X86_64_RELATIVE
                        target = addend
                    elif r_type in {1, 6, 7} and symbol_table is not None:
                        symbol = symbol_table.get_symbol(entry["r_info_sym"])
                        if symbol["st_shndx"] != "SHN_UNDEF":
                            target = int(symbol["st_value"]) + addend
                    if target is not None:
                        self.relocations[int(entry["r_offset"])] = target & ((1 << 64) - 1)

    def is_executable(self, address: int) -> bool:
        return any(start <= address < end for start, end in self.executable_ranges)

    def read(self, address: int, size: int) -> bytes:
        for start, _end, offset, filesz, data in self.segments:
            relative = address - start
            if 0 <= relative and relative + size <= filesz:
                return data[relative:relative + size]
        raise ValueError(f"cannot read ELF bytes at 0x{address:x}+0x{size:x}")

    def relocation_resolver(self, slot: int) -> str:
        return "elf-relocation"

    def synthetic_functions(self) -> dict[int, Function]:
        return {}


class PeImage:
    """Minimal PE32+ image view used by the stripped-only extractor.

    PE import slots are represented as synthetic functions at their IAT
    address.  This preserves an exact imported-callee relation without
    pretending that the runtime-resolved DLL address is present in the file.
    """

    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_REL_BASED_DIR64 = 10

    def __init__(self, path: Path) -> None:
        import pefile

        self.path = path
        # Held so `read` can name the one exception that means "not in the
        # file". pefile is imported lazily, so the class is not available at
        # module scope.
        self.unmapped_error = pefile.PEFormatError
        self.pe = pefile.PE(str(path), fast_load=False)
        if self.pe.FILE_HEADER.Machine != 0x8664:
            raise ValueError("CallKin-Real currently supports x86-64 PE only")
        if self.pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise ValueError("CallKin-Real requires PE32+ (not PE32)")

        self.format = "PE32+ x86-64"
        self.root_source = "PE image entry and discovered function containment"
        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.entry = self.image_base + int(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        self.executable_ranges: list[tuple[int, int]] = []
        self.relocations: dict[int, int] = {}
        self.relocation_labels: dict[int, str] = {}
        self.import_slots: dict[int, str] = {}
        self.boundary_ranges: list[tuple[int, int]] = []

        for section in self.pe.sections:
            start = self.image_base + int(section.VirtualAddress)
            size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
            if section.Characteristics & self.IMAGE_SCN_MEM_EXECUTE and size:
                self.executable_ranges.append((start, start + size))

        self._load_imports()
        self._load_base_relocations()
        self._load_pdata()

    def _load_imports(self) -> None:
        descriptors = []
        for directory_name in ("DIRECTORY_ENTRY_IMPORT", "DIRECTORY_ENTRY_DELAY_IMPORT"):
            descriptors.extend(getattr(self.pe, directory_name, []))
        for descriptor in descriptors:
            dll = descriptor.dll.decode(errors="replace") if descriptor.dll else "unknown.dll"
            for entry in descriptor.imports:
                slot = int(entry.address)
                if entry.name:
                    symbol = entry.name.decode(errors="replace")
                elif entry.ordinal is not None:
                    symbol = f"ordinal_{int(entry.ordinal)}"
                else:
                    symbol = "unknown"
                label = f"{dll}!{symbol}"
                self.import_slots[slot] = label
                self.relocations[slot] = slot
                self.relocation_labels[slot] = label

    def _load_base_relocations(self) -> None:
        for block in getattr(self.pe, "DIRECTORY_ENTRY_BASERELOC", []):
            for entry in block.entries:
                if entry.type != self.IMAGE_REL_BASED_DIR64:
                    continue
                slot = self.image_base + int(entry.rva)
                if slot in self.import_slots:
                    continue
                try:
                    target = int.from_bytes(self.read(slot, 8), "little")
                except ValueError:
                    continue
                if target:
                    self.relocations[slot] = target
                    self.relocation_labels[slot] = "base-relocation"

    def _load_pdata(self) -> None:
        for entry in getattr(self.pe, "DIRECTORY_ENTRY_EXCEPTION", []):
            start = self.image_base + int(entry.struct.BeginAddress)
            end = self.image_base + int(entry.struct.EndAddress)
            if end > start and self.is_executable(start):
                self.boundary_ranges.append((start, end))

    def is_executable(self, address: int) -> bool:
        return any(start <= address < end for start, end in self.executable_ranges)

    def read(self, address: int, size: int) -> bytes:
        rva = address - self.image_base
        if rva < 0:
            raise ValueError(f"cannot read PE bytes at 0x{address:x}+0x{size:x}")
        try:
            data = self.pe.get_data(rva, size)
        except self.unmapped_error as exc:
            # PEFormatError is pefile's way of saying the RVA is not backed by
            # file bytes, which is what ValueError means in the reader
            # contract. Only that one is translated: catching more would move
            # the broad except out of body_builder rather than remove it, and a
            # defect here would still be filed as a property of the binary.
            raise ValueError(
                f"cannot read PE bytes at 0x{address:x}+0x{size:x}: {exc}"
            ) from exc
        if len(data) != size:
            raise ValueError(f"cannot read PE bytes at 0x{address:x}+0x{size:x}")
        return data

    def relocation_resolver(self, slot: int) -> str:
        return "pe-import-iat" if slot in self.import_slots else "pe-base-relocation"

    def synthetic_functions(self) -> dict[int, Function]:
        return {
            slot: Function(
                address=slot,
                size=0,
                name=name,
                boundary_source="pe-import-iat",
                kind="import",
            )
            for slot, name in self.import_slots.items()
        }


def discover_radare2(binary: Path, image: Any) -> dict[int, Function]:
    if shutil.which("r2") is None:
        raise RuntimeError("radare2 is required for stripped function discovery")
    try:
        import r2pipe
    except ImportError as exc:
        raise RuntimeError("install r2pipe to use radare2 discovery") from exc

    # radare2 probes the terminal on startup and writes cursor-position escapes
    # to stdout, which corrupts the first r2pipe JSON reply. Telling it there is
    # no terminal is harmless where the escapes never appeared, and required on
    # Windows.
    previous_term = os.environ.get("TERM")
    os.environ["TERM"] = "dumb"
    try:
        r2 = r2pipe.open(str(binary), flags=["-2"])
    finally:
        if previous_term is None:
            os.environ.pop("TERM", None)
        else:
            os.environ["TERM"] = previous_term
    try:
        r2.cmd("aaa")
        rows = r2.cmdj("aflj") or []
    finally:
        r2.quit()

    result: dict[int, Function] = {}
    for row in rows:
        address = row.get("offset")
        if not isinstance(address, int) or not image.is_executable(address):
            continue
        size = int(row.get("size") or 0)
        result[address] = Function(
            address=address,
            size=size,
            name=str(row.get("name") or function_id(address)),
            boundary_source="radare2",
            kind=str(row.get("type") or "code"),
        )
    return result


def link_address(project: Any, mapped: int) -> int:
    obj = project.loader.main_object
    if int(obj.mapped_base) == int(obj.linked_base):
        return mapped
    return mapped - int(obj.mapped_base) + int(obj.linked_base)


def discover_boundary_functions(image: Any) -> dict[int, Function]:
    return {
        start: Function(
            address=start,
            size=end - start,
            name=function_id(start),
            boundary_source="pe-pdata",
        )
        for start, end in getattr(image, "boundary_ranges", [])
        if end > start and image.is_executable(start)
    }


def discover_angr(
    binary: Path,
    image: Any,
) -> tuple[
    dict[int, Function],
    dict[tuple[int, int], set[int]],
    set[tuple[int, int]],
    dict[str, Any],
]:
    try:
        import angr
    except ImportError as exc:
        raise RuntimeError("install angr to run CallKin-Real") from exc

    started = time.perf_counter()
    project = angr.Project(str(binary), auto_load_libs=False)
    cfg = project.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        force_smart_scan=False,
        force_complete_scan=True,
    )
    functions: dict[int, Function] = {}
    block_to_function: dict[int, int] = {}
    for function in cfg.kb.functions.values():
        address = link_address(project, int(function.addr))
        if not image.is_executable(address):
            continue
        size = int(getattr(function, "size", 0) or 0)
        functions[address] = Function(
            address=address,
            size=size,
            name=f"{function_id(address)}.angr",
            boundary_source="angr-cfgfast",
        )
        for block in getattr(function, "block_addrs", ()):
            block_to_function[link_address(project, int(block))] = address

    targets: dict[tuple[int, int], set[int]] = collections.defaultdict(set)
    seen_sites: set[tuple[int, int]] = set()
    for source_node, target_node, edge in cfg.graph.edges(data=True):
        ins_addr = edge.get("ins_addr")
        if not isinstance(ins_addr, int):
            continue
        source_block = link_address(project, int(source_node.addr))
        source = block_to_function.get(source_block)
        if source is not None:
            seen_sites.add((source, link_address(project, ins_addr)))
        target = link_address(project, int(target_node.addr))
        target = block_to_function.get(target, target)
        if source is None or target not in functions:
            continue
        targets[(source, link_address(project, ins_addr))].add(target)

    return functions, targets, seen_sites, {
        "backend": "angr-cfgfast",
        "angr_version": getattr(angr, "__version__", "unknown"),
        "function_count": len(functions),
        "indirect_sites_seen": len(seen_sites),
        "duration_seconds": round(time.perf_counter() - started, 3),
    }


def merge_functions(
    radare: dict[int, Function],
    angr_functions: dict[int, Function],
) -> dict[int, Function]:
    def merge_source(left: str, right: str) -> str:
        parts = left.split("+")
        for part in right.split("+"):
            if part not in parts:
                parts.append(part)
        return "+".join(parts)

    merged = dict(radare)
    for address, function in angr_functions.items():
        previous = merged.get(address)
        if previous is None:
            merged[address] = function
        elif previous.size <= 0 and function.size > 0:
            previous.size = function.size
            previous.boundary_source = merge_source(previous.boundary_source, function.boundary_source)
        elif previous is not None:
            previous.boundary_source = merge_source(previous.boundary_source, function.boundary_source)
    return merged


def function_for(functions: dict[int, Function], address: int) -> Function | None:
    exact = functions.get(address)
    if exact is not None:
        return exact
    for function in functions.values():
        if function.size > 0 and function.address <= address < function.end:
            return function
    return None


def operand_kind(
    operand: Any,
    immediate_type: int,
    memory_type: int,
    register_type: int,
) -> str:
    if operand is None:
        return "unknown"
    if operand.type == immediate_type:
        return "immediate"
    if operand.type == memory_type:
        return "memory"
    if operand.type == register_type:
        return "register"
    return "unknown"


def extract_transfers(
    image: Any,
    functions: dict[int, Function],
) -> tuple[list[Transfer], dict[str, Any]]:
    from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_MODE_64, Cs
    from capstone.x86_const import (
        X86_OP_IMM,
        X86_OP_MEM,
        X86_OP_REG,
        X86_REG_INVALID,
        X86_REG_RIP,
    )

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    transfers: list[Transfer] = []
    for function in sorted(functions.values(), key=lambda item: item.address):
        if function.size <= 0:
            continue
        try:
            code = image.read(function.address, function.size)
        except ValueError:
            continue
        instructions = list(decoder.disasm(code, function.address))
        meaningful = [item for item in instructions if item.mnemonic not in PAD_MNEMONICS]
        terminal = meaningful[-1].address if meaningful else None
        end = function.address + function.size
        for instruction in instructions:
            is_call = instruction.group(CS_GRP_CALL)
            is_jump = instruction.mnemonic == "jmp"
            if not is_call and not is_jump:
                continue
            operand = instruction.operands[0] if len(instruction.operands) == 1 else None
            kind = "call" if is_call else "tail-call"
            op_kind = operand_kind(operand, X86_OP_IMM, X86_OP_MEM, X86_OP_REG)
            text = f"{instruction.mnemonic} {instruction.op_str}".strip()
            target: int | None = None
            resolver: str | None = None
            if operand is not None and operand.type == X86_OP_IMM:
                target = int(operand.imm) & ((1 << 64) - 1)
                if is_call:
                    resolver = "direct-immediate"
                elif target != function.address and not function.address <= target < end:
                    resolver = "direct-tail"
                else:
                    continue
            elif operand is not None and operand.type == X86_OP_MEM:
                slot: int | None = None
                if operand.mem.base == X86_REG_RIP:
                    slot = instruction.address + instruction.size + operand.mem.disp
                elif (
                    operand.mem.base == X86_REG_INVALID
                    and operand.mem.index == X86_REG_INVALID
                ):
                    slot = operand.mem.disp & ((1 << 64) - 1)
                if slot is None:
                    if not is_call and instruction.address != terminal:
                        continue
                    target = None
                else:
                    target = image.relocations.get(slot)
                if target is not None:
                    resolver = image.relocation_resolver(slot)
                elif not is_call and instruction.address != terminal:
                    continue
            elif not is_call and instruction.address != terminal:
                continue

            if target is not None:
                transfers.append(Transfer(
                    source=function.address,
                    callsite=instruction.address,
                    kind=kind,
                    operand_kind=op_kind,
                    instruction=text,
                    status="resolved" if target in functions else "unmapped",
                    target=target,
                    resolver=resolver,
                    confidence="exact" if resolver != "direct-tail" or target in functions else "address-only",
                ))
            else:
                transfers.append(Transfer(
                    source=function.address,
                    callsite=instruction.address,
                    kind=kind,
                    operand_kind=op_kind,
                    instruction=text,
                    status="unresolved",
                    target=None,
                    resolver=None,
                    confidence="unknown",
                ))

    by_site: dict[tuple[int, int], Transfer] = {}
    for transfer in transfers:
        by_site[(transfer.source, transfer.callsite)] = transfer
    transfers = list(sorted(by_site.values(), key=lambda item: (item.source, item.callsite)))
    indirect = [
        item for item in transfers
        if item.operand_kind in {"memory", "register"}
    ]
    unresolved_indirect = [item for item in indirect if item.status == "unresolved"]
    return transfers, {
        "total_indirect_sites": len(indirect),
        "by_operand": {
            "memory": sum(item.operand_kind == "memory" for item in indirect),
            "register": sum(item.operand_kind == "register" for item in indirect),
        },
        "initial_unresolved_indirect_sites": len(unresolved_indirect),
        "transfer_count": len(transfers),
        "resolved_transfer_count": sum(item.status == "resolved" for item in transfers),
        "opaque_target_transfer_count": sum(item.status == "unmapped" for item in transfers),
        "resolved_by_elf_relocation": sum(
            item.resolver == "elf-relocation" and item.status == "resolved"
            for item in transfers
        ),
        "resolved_by_relocation": sum(
            item.resolver in {"elf-relocation", "pe-import-iat", "pe-base-relocation"}
            and item.status == "resolved"
            for item in transfers
        ),
    }


def apply_angr_resolutions(
    transfers: list[Transfer],
    targets: dict[tuple[int, int], set[int]],
    seen_sites: set[tuple[int, int]],
) -> dict[str, Any]:
    summary = {
        "resolved_by_angr": 0,
        "multiple_targets": 0,
        "unresolvable": 0,
        "not_seen": 0,
    }
    for transfer in transfers:
        if transfer.status != "unresolved" or transfer.operand_kind not in {"memory", "register"}:
            continue
        possible = tuple(sorted(targets.get((transfer.source, transfer.callsite), set())))
        transfer.angr_targets = possible
        if len(possible) == 1:
            transfer.status = "resolved"
            transfer.target = possible[0]
            transfer.resolver = "angr-cfgfast"
            transfer.confidence = "inferred-singleton"
            transfer.angr_status = "resolved-singleton"
            summary["resolved_by_angr"] += 1
        elif len(possible) > 1:
            transfer.angr_status = "multiple-targets"
            summary["multiple_targets"] += 1
        elif (transfer.source, transfer.callsite) in seen_sites:
            transfer.angr_status = "unresolvable-target"
            summary["unresolvable"] += 1
        else:
            transfer.angr_status = "not-seen-by-angr"
            summary["not_seen"] += 1

    total = sum(
        item.status == "unresolved" and item.operand_kind in {"memory", "register"}
        for item in transfers
    )
    summary["unresolved_after_angr"] = total
    summary["angr_resolution_rate"] = (
        round(summary["resolved_by_angr"] / (summary["resolved_by_angr"] + total), 4)
        if summary["resolved_by_angr"] + total else None
    )
    return summary


def default_oxidizer_dir() -> Path:
    """Oxidizer lives on the same disk under either name, depending on the OS.

    A WSL-only default silently turns "FLIRT ran and found nothing" into "FLIRT
    could not start", which is the one distinction the label stage must keep.
    """
    for candidate in (
        Path("/mnt/c/Users/sumyr/playground/oxidizer"),
        Path("C:/Users/sumyr/playground/oxidizer"),
    ):
        if candidate.is_dir():
            return candidate
    return Path("oxidizer")


def run_flirt(
    binary: Path,
    oxidizer_dir: Path,
    probe_path: Path,
    timeout: int,
) -> tuple[dict[int, dict[str, str]], dict[str, Any]]:
    # The venv layout differs by platform: bin/python on POSIX, Scripts on Windows.
    oxidizer_python = next(
        (
            candidate
            for candidate in (
                oxidizer_dir / ".venv" / "bin" / "python",
                oxidizer_dir / ".venv" / "Scripts" / "python.exe",
            )
            if candidate.is_file()
        ),
        None,
    )
    if oxidizer_python is not None:
        command_prefix = [str(oxidizer_python)]
    elif shutil.which("uv") is not None:
        command_prefix = ["uv", "run", "--frozen", "python"]
    else:
        raise RuntimeError(
            "Oxidizer Python environment is missing and uv was not found; "
            "install Oxidizer with `uv sync --frozen --no-default-groups`"
        )
    with tempfile.TemporaryDirectory(prefix="callkin-real-flirt-") as directory:
        output = Path(directory) / "flirt.json"
        command = [
            *command_prefix, str(probe_path.resolve()),
            "--binary", str(binary.resolve()), "--output", str(output),
        ]
        completed = subprocess.run(
            command,
            cwd=oxidizer_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"Oxidizer FLIRT failed: {detail[-4000:]}")
        data = json.loads(output.read_text(encoding="utf-8"))
    matches = {}
    for item in data.get("matches", []):
        address = int(str(item["address"]), 0)
        matches[address] = item
    return matches, {
        "status": "completed",
        "direct_match_count": len(matches),
        "standard_library_match_count": sum(
            item.get("owner") in STANDARD_OWNERS for item in data.get("matches", [])
        ),
        "probe": str(probe_path),
        "tool": data.get("tool", {}),
    }


# Analysis status: how much of the function's bytes the tools actually got.
ANALYSIS_COMPLETE = "complete"
ANALYSIS_INCOMPLETE = "incomplete"
ANALYSIS_ADDRESS_ONLY = "address-only"
ANALYSIS_EXTERNAL = "external"

# Grouping role: whether the function can be a family candidate.
ROLE_MEMBER = "member"
ROLE_CONTEXT_ONLY = "context-only"
ROLE_ABSTAIN = "abstain"


def analysis_status_for(
    function: Function,
    body_quality: Mapping[int, Mapping[str, Any]],
) -> str:
    """Say how much of this function was recovered, and nothing else.

    Deliberately blind to owner, FLIRT and any name: those describe what the
    function *is*, not how much of it the tools read.

    An internal function with no body record is an error rather than an
    assumption. Guessing `complete` here is what made the earlier universe
    unusable: it recorded functions as fully decoded that were never read.
    """
    if is_import(function):
        return ANALYSIS_EXTERNAL
    if function.kind == "opaque" or function.size <= 0:
        return ANALYSIS_ADDRESS_ONLY
    quality = body_quality.get(function.address)
    if quality is None:
        raise ValueError(
            f"no body evidence for internal function {function.id} at "
            f"0x{function.address:x}; decode it before building the universe"
        )
    return (
        ANALYSIS_COMPLETE if quality.get("complete_decode")
        else ANALYSIS_INCOMPLETE
    )


def grouping_role_for(analysis_status: str, *, is_root: bool) -> str:
    """Decide whether a function can be compared, from recovery alone.

    A standard-library function that direct FLIRT already named is an internal
    function like any other: if its body is complete it is a `member`. Names
    never reach this decision.
    """
    if is_root:
        return ROLE_CONTEXT_ONLY
    if analysis_status in (ANALYSIS_EXTERNAL, ANALYSIS_ADDRESS_ONLY):
        return ROLE_CONTEXT_ONLY
    if analysis_status == ANALYSIS_INCOMPLETE:
        return ROLE_ABSTAIN
    return ROLE_MEMBER


def context_color_for(function: Function, *, is_root: bool) -> str:
    """Fixed colour for a context-only node.

    Only what the binary itself carries: the root marker, the import identity
    left in the image, and the address of a target with no body. A FLIRT name
    would make the relation depend on labels.
    """
    if is_root:
        return "root"
    if is_import(function):
        return f"import:{function.name}"
    return f"opaque:{function.address:x}"


def owner_from_name(name: str) -> str | None:
    match = re.search(r"(?:^|<)(core|alloc|std|__rustc)::", name)
    return match.group(1) if match else None


def is_import(function: Function) -> bool:
    return function.name.startswith("sym.imp.") or function.kind in {"sym", "import"}


def make_graph(
    functions: dict[int, Function],
    transfers: list[Transfer],
    root: int | None,
) -> tuple[dict[int, Function], dict[int, collections.Counter[int]], list[dict[str, Any]]]:
    functions = dict(functions)
    edges: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    for transfer in transfers:
        if transfer.status not in {"resolved", "unmapped"} or transfer.target is None:
            continue
        if transfer.target not in functions:
            functions[transfer.target] = Function(
                address=transfer.target,
                size=0,
                name=function_id(transfer.target),
                boundary_source="opaque-target",
                kind="opaque",
            )
        edges[transfer.source][transfer.target] += 1

    for address in functions:
        edges.setdefault(address, collections.Counter())

    return functions, edges, [transfer.to_json() for transfer in transfers]


def classify_nodes(
    functions: dict[int, Function],
    edges: dict[int, collections.Counter[int]],
    root: int | None,
    body_quality: Mapping[int, Mapping[str, Any]],
) -> tuple[dict[int, str], dict[int, str], list[dict[str, Any]], dict[int, str]]:
    """Assign every discovered function an analysis status and a grouping role.

    No FLIRT label, owner or name reaches this function. Running with and
    without FLIRT must produce identical roles, colours and abstentions.
    """
    roles: dict[int, str] = {}
    statuses: dict[int, str] = {}
    colors: dict[int, str] = {}
    abstentions: list[dict[str, Any]] = []
    incoming: dict[int, int] = collections.Counter()
    for source, targets in edges.items():
        for target, count in targets.items():
            if source != target:
                incoming[target] += count

    for address, function in functions.items():
        is_root = address == root
        status = analysis_status_for(function, body_quality)
        statuses[address] = status
        role = grouping_role_for(status, is_root=is_root)
        roles[address] = role
        if role == ROLE_CONTEXT_ONLY:
            colors[address] = context_color_for(function, is_root=is_root)
            continue
        if role == ROLE_ABSTAIN:
            abstentions.append({
                "id": function.id,
                "address": hex_address(address),
                "analysis_status": status,
                "reason": "incomplete_body",
            })
            continue

    return roles, colors, abstentions, statuses


# Relation status is a property of the V0 method, not of the universe. A member
# with no resolved edge has nothing for the relation view to compare, but its
# body is still there for V1, so it must not be dropped from the universe.
RELATION_MEMBER = "relation-member"
RELATION_ABSTAIN = "relation-abstain"
RELATION_CONTEXT = "relation-context"


def relation_statuses(
    roles: Mapping[int, str],
    edges: Mapping[int, collections.Counter[int]],
) -> tuple[dict[int, str], list[dict[str, Any]]]:
    """Project universe roles onto what the relation-only baseline can judge."""
    incoming: dict[int, int] = collections.Counter()
    for source, targets in edges.items():
        for target, count in targets.items():
            if source != target:
                incoming[target] += count

    statuses: dict[int, str] = {}
    abstained: list[dict[str, Any]] = []
    for address, role in roles.items():
        if role == ROLE_CONTEXT_ONLY:
            statuses[address] = RELATION_CONTEXT
            continue
        if role == ROLE_ABSTAIN:
            statuses[address] = RELATION_ABSTAIN
            continue
        out_degree = sum(
            count for target, count in edges.get(address, {}).items()
            if target != address
        )
        if out_degree or incoming[address]:
            statuses[address] = RELATION_MEMBER
        else:
            statuses[address] = RELATION_ABSTAIN
            abstained.append({
                "id": function_id(address),
                "address": hex_address(address),
                "grouping_role": ROLE_MEMBER,
                "reason": "relation_abstain",
                "note": "no resolved non-self IN or OUT edge; body evidence still applies",
            })
    return statuses, abstained


def wl_clusters(
    functions: dict[int, Function],
    edges: dict[int, collections.Counter[int]],
    statuses: dict[int, str],
    anchor_colors: dict[int, str],
    trace: bool,
) -> tuple[dict[str, list[str]], int, list[dict[str, Any]]]:
    # `member`/`context-only` is the schema-v2 vocabulary; `candidate`/`anchor`
    # is the R0 baseline's. Both are accepted so the baseline test still runs.
    groupable = {RELATION_MEMBER, ROLE_MEMBER, "candidate"}
    fixed = {RELATION_CONTEXT, ROLE_CONTEXT_ONLY, "anchor"}
    active = [address for address, status in statuses.items() if status in groupable | fixed]
    self_count = {address: edges[address].get(address, 0) for address in active}
    outgoing = {address: [(target, count) for target, count in edges[address].items() if target in active and target != address] for address in active}
    incoming: dict[int, list[tuple[int, int]]] = {address: [] for address in active}
    for source in active:
        for target, count in outgoing[source]:
            incoming[target].append((source, count))

    colors: dict[int, str] = {}
    for address in active:
        if statuses[address] in fixed:
            colors[address] = f"ANCHOR:{anchor_colors.get(address, f'address:{address:x}')}"
        else:
            colors[address] = f"USER:self={self_count[address]}:distinct_out={len(outgoing[address])}"

    # Always recorded. The relation view's profile is built from the whole
    # round history, not just the fixpoint, so an adapter that only ever sees
    # the artifacts needs it there. `--trace` still decides whether the run
    # manifest repeats it.
    traces: list[dict[str, Any]] = []

    def candidate_partition(current: dict[int, str]) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = collections.defaultdict(list)
        for address in active:
            if statuses[address] in groupable:
                grouped[current[address]].append(functions[address].id)
        clusters = sorted((sorted(values) for values in grouped.values()), key=lambda values: (values[0], len(values)))
        return {f"C{index}": members for index, members in enumerate(clusters, 1)}

    def full_partition(current: dict[int, str]) -> tuple[tuple[int, ...], ...]:
        groups: dict[str, list[int]] = collections.defaultdict(list)
        for address in active:
            groups[current[address]].append(address)
        return tuple(sorted(tuple(sorted(group)) for group in groups.values()))

    traces.append({"round": 0, "clusters": candidate_partition(colors)})

    for round_index in range(1, len(active) + 1):
        signatures: dict[int, tuple[Any, ...]] = {}
        for address in active:
            out_multiset: dict[str, int] = collections.Counter()
            in_multiset: dict[str, int] = collections.Counter()
            for target, count in outgoing[address]:
                out_multiset[colors[target]] += count
            for source, count in incoming[address]:
                in_multiset[colors[source]] += count
            out_tuple = tuple(sorted(out_multiset.items()))
            in_tuple = tuple(sorted(in_multiset.items()))
            if len(outgoing[address]) == 0:
                signature = (colors[address], out_tuple, in_tuple)
            else:
                signature = (colors[address], out_tuple)
            signatures[address] = signature
        unique = {signature: f"C:{index}" for index, signature in enumerate(sorted(set(signatures.values())))}
        new_colors = {address: unique[signature] for address, signature in signatures.items()}
        changed = full_partition(new_colors) != full_partition(colors)
        colors = new_colors
        traces.append({"round": round_index, "changed": changed, "clusters": candidate_partition(colors)})
        if not changed:
            return candidate_partition(colors), round_index, traces
    raise RuntimeError("CG-WL did not reach a fixpoint")


def choose_root(image: Any, functions: dict[int, Function]) -> int | None:
    if image.entry in functions:
        return image.entry
    containing = function_for(functions, image.entry)
    return containing.address if containing else None


def load_image(binary: Path) -> Any:
    with binary.open("rb") as stream:
        magic = stream.read(2)
    return PeImage(binary) if magic == b"MZ" else ElfImage(binary)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CallKin-Real: stripped-only anonymous Rust call-graph grouping."
    )
    parser.add_argument("binary", help="stripped x86-64 ELF or PE32+ binary")
    parser.add_argument("--output", help="JSON output path; defaults to results/<binary>.callkin-real.json")
    parser.add_argument(
        "--oxidizer-dir",
        default=str(default_oxidizer_dir()),
        help="Oxidizer checkout containing uv.lock",
    )
    parser.add_argument(
        "--flirt-probe",
        default=str(Path(__file__).with_name("oxidizer_flirt_probe.py")),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--flirt-timeout", type=int, default=900)
    parser.add_argument("--no-flirt", action="store_true", help="skip Oxidizer FLIRT for dependency diagnostics")
    parser.add_argument("--trace", action="store_true", help="include every CG-WL round")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    started = time.perf_counter()
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        print(f"error: stripped binary not found: {binary}", file=sys.stderr)
        return 1
    try:
        image = load_image(binary)
        radare = discover_radare2(binary, image)
        angr_functions, angr_targets, angr_seen_sites, angr_run = discover_angr(binary, image)
        boundary = discover_boundary_functions(image)
        functions = merge_functions(radare, boundary)
        functions = merge_functions(functions, angr_functions)
        functions = merge_functions(functions, image.synthetic_functions())
        if image.entry not in functions and image.is_executable(image.entry):
            functions[image.entry] = Function(
                address=image.entry,
                size=0,
                name=function_id(image.entry),
                boundary_source="image-entry",
                kind="entry",
            )
        transfers, direct_summary = extract_transfers(image, functions)
        angr_summary = apply_angr_resolutions(transfers, angr_targets, angr_seen_sites)
        total_indirect = direct_summary["total_indirect_sites"]
        resolved_static = direct_summary["resolved_by_relocation"]
        resolved_dynamic = angr_summary["resolved_by_angr"]
        indirect_summary = {
            **direct_summary,
            **angr_summary,
            "resolution_rate": round(
                (resolved_static + resolved_dynamic) / total_indirect, 4
            ) if total_indirect else None,
        }
        flirt: dict[int, dict[str, str]] = {}
        flirt_run: dict[str, Any]
        if args.no_flirt:
            flirt_run = {"status": "skipped", "direct_match_count": 0}
        else:
            flirt, flirt_run = run_flirt(
                binary,
                Path(args.oxidizer_dir),
                Path(args.flirt_probe),
                args.flirt_timeout,
            )
        binary_sha256 = sha256_file(binary)
        functions, edges, transfer_json = make_graph(functions, transfers, image.entry)
        root = choose_root(image, functions)
        # Decode every internal extent first: role decisions must read the
        # decode result, never assume it.
        extents = {
            address: (function.id, function.size)
            for address, function in functions.items()
            if not is_import(function) and function.kind != "opaque"
        }
        body_artifact = build_bodies(image, extents)
        body_quality = body_quality_by_address(body_artifact)

        # Roles second, with no label in scope. The FLIRT overlay comes after.
        roles, anchor_colors, abstentions, analysis_statuses = classify_nodes(
            functions, edges, root, body_quality
        )
        # Relation status is the V0 method's own projection of those roles.
        relation_status, relation_abstained = relation_statuses(roles, edges)
        abstentions = abstentions + relation_abstained
        clusters, rounds, traces = wl_clusters(
            functions,
            edges,
            relation_status,
            anchor_colors,
            args.trace,
        )
        # Grouping is finished; only now may labels be attached.
        for address, function in functions.items():
            function.flirt = flirt.get(address)
        edge_json = relation_edges(edges, relation_status)
        function_json = []
        for address in sorted(functions):
            function = functions[address]
            function_json.append({
                "id": function.id,
                "address": hex_address(address),
                "name": function.name,
                "kind": function.kind,
                "size": function.size or None,
                "analysis_status": analysis_statuses.get(address, ANALYSIS_ADDRESS_ONLY),
                "grouping_role": roles.get(address, ROLE_CONTEXT_ONLY),
                "relation_status": relation_status.get(address, RELATION_CONTEXT),
                "quality": body_quality.get(address),
                "external_identity": function.name if is_import(function) else None,
                "label_status": "direct" if function.flirt else "unknown",
                "boundary_source": function.boundary_source,
                "flirt": function.flirt,
            })
        core_sha256 = canonical_sha256(grouping_core(
            binary_sha256=binary_sha256,
            root_id=function_id(root) if root is not None else None,
            clusters=clusters,
            rounds=rounds,
            functions=function_json,
            edges=edge_json,
            abstentions=abstentions,
        ))
        output = Path(args.output) if args.output else Path("results") / f"{binary.name}.callkin-real.json"
        toolchain = toolchain_fingerprint()
        payloads = stage_payloads(
            binary_sha256=binary_sha256,
            root_id=function_id(root) if root is not None else None,
            functions=function_json,
            transfers=transfer_json,
            body_artifact=body_artifact,
            edges=edge_json,
            clusters=clusters,
            rounds=rounds,
            round_history=traces,
            anchor_classes={
                function_id(address): color
                for address, color in sorted(anchor_colors.items())
                if relation_status.get(address) == RELATION_CONTEXT
            },
            abstentions=abstentions,
        )
        # One file per stage, written in dependency order so each records the
        # hash of the artifact it was built from. `stage_sha256` is the hash of
        # the file on disk, not of an object that was never saved.
        stage_sha256: dict[str, str] = {}
        artifacts: dict[str, dict[str, str]] = {}
        for stage in STAGE_NAMES:
            path = stage_artifact_path(output, stage)
            digest = write_json(path, artifact_envelope(
                stage=stage,
                binary_sha256=binary_sha256,
                inputs={
                    name: stage_sha256[name] for name in STAGE_INPUTS[stage]
                },
                payload=payloads[stage],
            ))
            stage_sha256[stage] = digest
            artifacts[stage] = {"path": path.name, "sha256": digest}
        format_discovery = (
            ["PE IAT", "PE base relocations", "PE .pdata"]
            if image.format.startswith("PE")
            else ["ELF relocations"]
        )
        result = {
            "schema_version": 3,
            "tool": "CallKin-Real",
            # The run record. The four stage payloads live in their own files,
            # listed under `artifacts`; keeping a copy here too would let it
            # drift from the file whose hash names it.
            "artifact": "callkin-real-run",
            "analysis": {
                "input": "stripped-only",
                "relation_mode": RELATION_MODE,
                "grouping_role_rule": GROUPING_ROLE_RULE,
                "edge_rule": EDGE_RULE,
                "anchor_policy": ANCHOR_POLICY,
                "discovery": [
                    "radare2",
                    "angr-CFGFast",
                    "capstone",
                    *format_discovery,
                    "Oxidizer direct FLIRT",
                ],
            },
            "binary": {
                "path": str(binary),
                "sha256": binary_sha256,
                "format": image.format,
                "entry": hex_address(image.entry),
            },
            "toolchain": toolchain,
            "root": {
                "id": function_id(root) if root is not None else None,
                "address": hex_address(root),
                "source": image.root_source,
            },
            "artifacts": artifacts,
            "stage_sha256": stage_sha256,
            "grouping_core_sha256": core_sha256,
            "summary": {
                "body": body_artifact["summary"],
                "function_count": len(function_json),
                "relation_edge_count": len(edge_json),
                "transfer_count": len(transfer_json),
                "cluster_count": len(clusters),
                "rounds": rounds,
                "analysis_status": tally(function_json, "analysis_status"),
                "grouping_role": tally(function_json, "grouping_role"),
                "relation_status": tally(function_json, "relation_status"),
            },
            # Labels are the one thing that may not appear in any stage file.
            # They live here, joined back to stage output by id.
            "labels": [
                {
                    "id": record["id"],
                    "address": record["address"],
                    "name": record["name"],
                    "grouping_role": record["grouping_role"],
                    "label_status": record["label_status"],
                    "flirt": record["flirt"],
                }
                for record in function_json
                if record["flirt"]
            ],
            "indirect_call_summary": {
                **indirect_summary,
            },
            "discovery": {
                "radare2_function_count": len(radare),
                "angr": angr_run,
            },
            "flirt": flirt_run,
            "execution": {
                "duration_seconds": round(time.perf_counter() - started, 3),
                "warnings": [],
            },
        }
        if args.trace:
            result["trace"] = traces
        write_json(output, result)
        print(json.dumps({
            "output": str(output),
            "artifacts": {name: item["path"] for name, item in artifacts.items()},
            "grouping_core_sha256": core_sha256,
            "stage_sha256": stage_sha256,
            "cluster_count": len(clusters),
            "member_count": sum(role == ROLE_MEMBER for role in roles.values()),
            "context_only_count": sum(role == ROLE_CONTEXT_ONLY for role in roles.values()),
            "abstain_count": sum(role == ROLE_ABSTAIN for role in roles.values()),
            "relation_abstain_count": sum(
                status == RELATION_ABSTAIN for status in relation_status.values()
            ),
            "complete_body_count": body_artifact["summary"]["complete_count"],
            "incomplete_body_count": body_artifact["summary"]["incomplete_count"],
            "direct_label_count": sum(1 for f in functions.values() if f.flirt),
        }, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
