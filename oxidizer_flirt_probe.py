from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


RUST_OWNER = re.compile(r"(?:^|<)(core|alloc|std|__rustc)::")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def linked_address(project: object, address: int) -> int:
    main = project.loader.main_object
    if int(main.mapped_base) == int(main.linked_base):
        return address
    return address - int(main.mapped_base) + int(main.linked_base)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    binary = Path(args.binary)

    import angr

    project = angr.Project(str(binary), auto_load_libs=False, is_rust_binary=True)
    project.analyses.CFGFast(
        normalize=True,
        force_smart_scan=False,
        force_complete_scan=True,
    )
    version = project.analyses.RustcVersionIdentification()
    signature_paths = []
    for level in ("0", "1", "2", "3"):
        path = Path(version.best_sig_dir) / f"{project.rustc_version}-O{level}.sig"
        if path.is_file():
            project.analyses.Flirt(str(path))
            signature_paths.append(str(path))

    matches = []
    for function in project.kb.functions.values():
        if function.from_signature != "flirt":
            continue
        name = str(function.name)
        address = linked_address(project, int(function.addr))
        owner_match = RUST_OWNER.search(name)
        matches.append({
            "address": f"0x{address:x}",
            "name": name,
            "owner": owner_match.group(1) if owner_match else "unknown",
            "evidence": "direct-flirt",
        })
    matches.sort(key=lambda item: int(item["address"], 0))
    output = {
        "schema_version": 1,
        "input": "stripped-only",
        "binary_sha256": sha256_file(binary),
        "rustc_version": getattr(project, "rustc_version", None),
        "signature_paths": signature_paths,
        "tool": {
            "component": "Oxidizer direct-FLIRT probe",
            "python": sys.version.split()[0],
            "angr": getattr(angr, "__version__", "unknown"),
            "analysis": "RustcVersionIdentification + direct Flirt matches only",
        },
        "matches": matches,
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
