"""R6: normalize a demangled Rust symbol, without importing ground truth.

Spec 7.6 forbids CallKin-Real from importing `gt_extractor.py` or the all-Rust
catalog: both are oracle-side, and a label path that imports them puts an
oracle in the analysis process even if it never calls one.

The two functions the label stage needs are pure string arithmetic, so the
closure they need is reproduced here verbatim from
v0-engine-py-f10@0abd091 `gt_extractor.py` -- same bodies, same regex, same
constants. `test_flirt_labels.py` differentially compares this module against
that one over every name in the frozen label artifacts wherever the frozen
checkout is present, because a normalizer that behaves differently would
change which seeds agree and therefore what propagates.
"""

from __future__ import annotations

import re

ANCHOR_RUST_NAMESPACES = ("core", "alloc", "std", "__rustc")


_RUST_PATH_RE = re.compile(r"(?<![A-Za-z0-9_:])([A-Za-z_][A-Za-z0-9_]*)::")


def _matching_angle(value: str, start: int) -> int | None:
    depth = 0
    for index in range(start, len(value)):
        if value[index] == "<":
            depth += 1
        elif value[index] == ">":
            depth -= 1
            if depth == 0:
                return index
    return None


def _has_top_level_as(value: str) -> bool:
    depth = 0
    for index, char in enumerate(value):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
        elif depth == 0 and value.startswith(" as ", index):
            return True
    return False


def _outer_impl_header(name: str) -> str | None:
    depth = 0
    for index, char in enumerate(name):
        if char == "<":
            depth += 1
        elif char == ">":
            depth -= 1
            if depth == 0:
                return name[1:index]
    return None


def preserve_derived_impl_identity(name: str) -> str:
    """Keep the implementation target encoded in rustc's ::<impl ...> paths."""
    marker = "::<"
    start = 0
    while True:
        marker_index = name.find(marker, start)
        if marker_index < 0:
            return name

        content_start = marker_index + len(marker)
        depth = 1
        index = content_start
        while index < len(name) and depth:
            if name[index] == "<":
                depth += 1
            elif name[index] == ">":
                depth -= 1
            index += 1
        if depth:
            return name

        content = name[content_start:index - 1]
        if content.startswith("impl "):
            if " for " in content:
                target_type = content.rsplit(" for ", 1)[1]
                replacement = f"::impl_for={target_type}"
            else:
                target_type = content[len("impl "):]
                replacement = f"::impl={target_type}"
            name = name[:marker_index] + replacement + name[index:]
            start = marker_index + len(replacement)
        else:
            start = index


def _strip_displayed_generic_args(name: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(name):
        if name.startswith("::<", index):
            end = _matching_angle(name, index + 2)
            if end is None:
                out.append(name[index])
                index += 1
            else:
                index = end + 1
            continue
        if name[index] == "<":
            end = _matching_angle(name, index)
            if end is None:
                out.append(name[index])
                index += 1
                continue
            content = name[index + 1:end]
            if index == 0 or _has_top_level_as(content):
                out.extend(("<", _strip_displayed_generic_args(content), ">"))
            index = end + 1
            continue
        out.append(name[index])
        index += 1
    return "".join(out)


def rust_symbol_owner(demangled_name: str) -> str | None:
    """Return the crate that owns a demangled Rust function when observable."""
    if "::" not in demangled_name:
        return None
    if not demangled_name.startswith("<"):
        match = _RUST_PATH_RE.match(demangled_name)
        return match.group(1) if match else None

    header = _outer_impl_header(demangled_name)
    if header is None:
        return None
    roots = _RUST_PATH_RE.findall(header)
    for root in roots:
        if root not in ANCHOR_RUST_NAMESPACES:
            return root
    return roots[0] if roots else None


def normalize_all_rust_origin(name: str) -> str:
    """Normalize all-Rust labels, including `drop_in_place<T>` spellings.

    Existing v0 ground truth keeps its legacy normalizer for frozen regression
    artifacts. The all-Rust catalog needs the broader rule because Oxidizer and
    `nm -C` commonly render `drop_in_place<T>` without the `::<T>` separator.
    """
    name = re.sub(r"::h[0-9a-fA-F]{16}$", "", name)
    name = preserve_derived_impl_identity(name)
    return _strip_displayed_generic_args(name)
