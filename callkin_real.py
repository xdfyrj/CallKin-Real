from __future__ import annotations

import argparse
import collections
import hashlib
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ID_BIAS = 0x100000
RELATION_MODE = "out-in"
STANDARD_OWNERS = {"core", "alloc", "std", "__rustc"}
PAD_MNEMONICS = {"nop", "int3", "ud2"}


def function_id(address: int) -> str:
    return f"FUN_{address + ID_BIAS:08x}"


def hex_address(address: int | None) -> str | None:
    return None if address is None else f"0x{address:x}"


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
        self.segments: list[tuple[int, int, int, int, bytes]] = []
        self.executable_ranges: list[tuple[int, int]] = []
        self.relocations: dict[int, int] = {}

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


def discover_radare2(binary: Path, image: ElfImage) -> dict[int, Function]:
    if shutil.which("r2") is None:
        raise RuntimeError("radare2 is required for stripped function discovery")
    try:
        import r2pipe
    except ImportError as exc:
        raise RuntimeError("install r2pipe to use radare2 discovery") from exc

    r2 = r2pipe.open(str(binary), flags=["-2"])
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
    return mapped - int(obj.mapped_base) + int(obj.linked_base)


def discover_angr(
    binary: Path,
    image: ElfImage,
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
    merged = dict(radare)
    for address, function in angr_functions.items():
        previous = merged.get(address)
        if previous is None:
            merged[address] = function
        elif previous.size <= 0 and function.size > 0:
            previous.size = function.size
            previous.boundary_source = "radare2+angr-cfgfast"
        elif previous is not None:
            previous.boundary_source = "radare2+angr-cfgfast"
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
    image: ElfImage,
    functions: dict[int, Function],
) -> tuple[list[Transfer], dict[str, Any]]:
    from capstone import CS_ARCH_X86, CS_GRP_CALL, CS_MODE_64, Cs
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

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
            elif (
                operand is not None
                and operand.type == X86_OP_MEM
                and operand.mem.base == X86_REG_RIP
            ):
                slot = instruction.address + instruction.size + operand.mem.disp
                target = image.relocations.get(slot)
                if target is not None:
                    resolver = "elf-relocation"
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


def run_flirt(
    binary: Path,
    oxidizer_dir: Path,
    probe_path: Path,
    timeout: int,
) -> tuple[dict[int, dict[str, str]], dict[str, Any]]:
    oxidizer_python = oxidizer_dir / ".venv" / "bin" / "python"
    if oxidizer_python.is_file():
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


def owner_from_name(name: str) -> str | None:
    match = re.search(r"(?:^|<)(core|alloc|std|__rustc)::", name)
    return match.group(1) if match else None


def is_import(function: Function) -> bool:
    return function.name.startswith("sym.imp.") or function.kind == "sym"


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
    flirt: dict[int, dict[str, str]],
) -> tuple[dict[int, str], dict[int, str], list[dict[str, Any]]]:
    statuses: dict[int, str] = {}
    colors: dict[int, str] = {}
    abstentions: list[dict[str, Any]] = []
    incoming: dict[int, int] = collections.Counter()
    for source, targets in edges.items():
        for target, count in targets.items():
            if source != target:
                incoming[target] += count

    for address, function in functions.items():
        function.flirt = flirt.get(address)
        owner = owner_from_name(function.flirt.get("name", "")) if function.flirt else None
        known_library = owner in STANDARD_OWNERS or is_import(function)
        out_degree = sum(count for target, count in edges[address].items() if target != address)
        in_degree = incoming[address]
        if address == root:
            statuses[address] = "anchor"
            colors[address] = "root"
        elif known_library or function.kind == "opaque":
            statuses[address] = "anchor"
            if function.kind == "opaque":
                colors[address] = f"opaque:{address:x}"
            elif function.flirt:
                colors[address] = f"flirt:{function.flirt.get('canonical_origin', function.flirt.get('name', 'unknown'))}"
            else:
                colors[address] = f"import:{function.name}"
        elif out_degree or in_degree:
            statuses[address] = "candidate"
        else:
            statuses[address] = "abstain"
            abstentions.append({
                "id": function.id,
                "address": hex_address(address),
                "reason": "no_resolved_nonself_in_or_out_edge",
                "flirt_label": function.flirt,
            })

    return statuses, colors, abstentions


def wl_clusters(
    functions: dict[int, Function],
    edges: dict[int, collections.Counter[int]],
    statuses: dict[int, str],
    anchor_colors: dict[int, str],
    trace: bool,
) -> tuple[dict[str, list[str]], int, list[dict[str, Any]]]:
    active = [address for address, status in statuses.items() if status in {"candidate", "anchor"}]
    self_count = {address: edges[address].get(address, 0) for address in active}
    outgoing = {address: [(target, count) for target, count in edges[address].items() if target in active and target != address] for address in active}
    incoming: dict[int, list[tuple[int, int]]] = {address: [] for address in active}
    for source in active:
        for target, count in outgoing[source]:
            incoming[target].append((source, count))

    colors: dict[int, str] = {}
    for address in active:
        if statuses[address] == "anchor":
            colors[address] = f"ANCHOR:{anchor_colors.get(address, f'address:{address:x}')}"
        else:
            colors[address] = f"USER:self={self_count[address]}:distinct_out={len(outgoing[address])}"

    traces: list[dict[str, Any]] = []

    def candidate_partition(current: dict[int, str]) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = collections.defaultdict(list)
        for address in active:
            if statuses[address] == "candidate":
                grouped[current[address]].append(functions[address].id)
        clusters = sorted((sorted(values) for values in grouped.values()), key=lambda values: (values[0], len(values)))
        return {f"C{index}": members for index, members in enumerate(clusters, 1)}

    def full_partition(current: dict[int, str]) -> tuple[tuple[int, ...], ...]:
        groups: dict[str, list[int]] = collections.defaultdict(list)
        for address in active:
            groups[current[address]].append(address)
        return tuple(sorted(tuple(sorted(group)) for group in groups.values()))

    if trace:
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
        if trace:
            traces.append({"round": round_index, "changed": changed, "clusters": candidate_partition(colors)})
        if not changed:
            return candidate_partition(colors), round_index, traces
    raise RuntimeError("CG-WL did not reach a fixpoint")


def choose_root(image: ElfImage, functions: dict[int, Function]) -> int | None:
    if image.entry in functions:
        return image.entry
    containing = function_for(functions, image.entry)
    return containing.address if containing else None


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CallKin-Real: stripped-only anonymous Rust call-graph grouping."
    )
    parser.add_argument("binary", help="stripped x86-64 ELF binary")
    parser.add_argument("--output", help="JSON output path; defaults to results/<binary>.callkin-real.json")
    parser.add_argument(
        "--oxidizer-dir",
        default="/mnt/c/Users/sumyr/playground/oxidizer",
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
        image = ElfImage(binary)
        radare = discover_radare2(binary, image)
        angr_functions, angr_targets, angr_seen_sites, angr_run = discover_angr(binary, image)
        functions = merge_functions(radare, angr_functions)
        transfers, direct_summary = extract_transfers(image, functions)
        angr_summary = apply_angr_resolutions(transfers, angr_targets, angr_seen_sites)
        total_indirect = direct_summary["total_indirect_sites"]
        resolved_static = direct_summary["resolved_by_elf_relocation"]
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
        functions, edges, transfer_json = make_graph(functions, transfers, image.entry)
        root = choose_root(image, functions)
        statuses, anchor_colors, abstentions = classify_nodes(functions, edges, root, flirt)
        clusters, rounds, traces = wl_clusters(
            functions,
            edges,
            statuses,
            anchor_colors,
            args.trace,
        )
        active = {address for address, status in statuses.items() if status in {"candidate", "anchor"}}
        edge_json = []
        for source in sorted(edges):
            for target, count in sorted(edges[source].items()):
                if source not in active or target not in active:
                    continue
                edge_json.append({
                    "source": function_id(source),
                    "target": function_id(target),
                    "count": count,
                })
        function_json = []
        for address in sorted(functions):
            function = functions[address]
            function_json.append({
                "id": function.id,
                "address": hex_address(address),
                "size": function.size or None,
                "status": statuses.get(address, "opaque"),
                "boundary_source": function.boundary_source,
                "flirt": function.flirt,
            })
        result = {
            "schema_version": 1,
            "tool": "CallKin-Real",
            "analysis": {
                "input": "stripped-only",
                "oracle_level": "none",
                "relation_mode": RELATION_MODE,
                "candidate_rule": "all discovered non-library functions with a resolved non-self IN or OUT edge",
                "edge_rule": "exact direct, exact ELF relocation, and angr singleton targets; address-only targets become opaque anchors",
                "discovery": [
                    "radare2",
                    "angr-CFGFast",
                    "capstone",
                    "ELF relocations",
                    "Oxidizer direct FLIRT",
                ],
            },
            "binary": {
                "path": str(binary),
                "sha256": sha256_file(binary),
                "format": "ELF x86-64",
                "entry": hex_address(image.entry),
            },
            "root": {
                "id": function_id(root) if root is not None else None,
                "address": hex_address(root),
                "source": "ELF entry and discovered function containment",
            },
            "predicted_clusters": clusters,
            "rounds": rounds,
            "functions": function_json,
            "edges": edge_json,
            "transfers": transfer_json,
            "abstentions": abstentions,
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
        output = Path(args.output) if args.output else Path("results") / f"{binary.name}.callkin-real.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({
            "output": str(output),
            "cluster_count": len(clusters),
            "candidate_count": sum(status == "candidate" for status in statuses.values()),
            "abstain_count": len(abstentions),
        }, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
