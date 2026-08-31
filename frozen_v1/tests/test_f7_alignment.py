"""Semantics of the F7.0 instruction-level alignment."""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import (  # noqa: E402
    FunctionBody,
    _align_blocks,
    align_function_bodies,
)


def _body(identifier: str, blocks: dict[str, list[str]], edges=()) -> FunctionBody:
    """Build a body from `{block label: [mnemonic, ...]}`.

    Offsets are handed out in order across the whole function so that two
    blocks never share one.
    """
    instructions: list[dict[str, object]] = []
    block_records: list[dict[str, object]] = []
    offset = 0
    for label, mnemonics in blocks.items():
        offsets: list[int] = []
        for mnemonic in mnemonics:
            instructions.append(
                {
                    "offset": offset,
                    "mnemonic_class": mnemonic,
                    "operands": [],
                    "control_flow": "return" if mnemonic == "RET" else "none",
                }
            )
            offsets.append(offset)
            offset += 1
        block_records.append({"label": label, "instruction_offsets": offsets})
    return FunctionBody(
        id=identifier,
        size=offset,
        instructions=tuple(instructions),
        edges=tuple(edges),
        blocks=tuple(block_records),
        quality={"complete_decode": True, "opaque_indirect_jumps": 0},
    )


def test_identical_bodies_pair_every_instruction():
    left = _body("A", {"B0": ["PUSH", "MOV", "CALL", "RET"]})
    right = _body("B", {"B0": ["PUSH", "MOV", "CALL", "RET"]})

    alignment = align_function_bodies(left, right)

    assert alignment.instruction_pairs == ((0, 0), (1, 1), (2, 2), (3, 3))
    assert alignment.unmatched_reference == ()
    assert alignment.unmatched_target == ()


def test_an_inserted_instruction_keeps_the_surrounding_correspondence():
    left = _body("A", {"B0": ["PUSH", "MOV", "RET"]})
    right = _body("B", {"B0": ["PUSH", "MOV", "LEA", "RET"]})

    alignment = align_function_bodies(left, right)

    # PUSH/MOV keep their places and RET still finds RET across the insertion.
    assert alignment.instruction_pairs == ((0, 0), (1, 1), (2, 3))
    assert alignment.unmatched_reference == ()
    assert alignment.unmatched_target == (2,)


def test_repeated_tokens_align_deterministically():
    left = _body("A", {"B0": ["MOV", "MOV", "MOV", "RET"]})
    right = _body("B", {"B0": ["MOV", "MOV", "RET"]})

    first = align_function_bodies(left, right)
    for _ in range(5):
        assert align_function_bodies(left, right).instruction_pairs == (
            first.instruction_pairs
        )
    assert first.instruction_pairs == ((0, 0), (1, 1), (3, 2))
    assert first.unmatched_reference == (2,)


def test_instructions_from_different_blocks_are_never_linked():
    left = _body("A", {"B0": ["PUSH", "MOV"], "B1": ["XOR", "RET"]})
    right = _body("B", {"B0": ["PUSH", "MOV"], "B1": ["XOR", "RET"]})

    alignment = align_function_bodies(left, right)
    offsets = {offset: label
               for label, block in (("B0", (0, 1)), ("B1", (2, 3)))
               for offset in block}

    assert alignment.block_pairs == (("B0", "B0"), ("B1", "B1"))
    for reference_offset, target_offset in alignment.instruction_pairs:
        assert offsets[reference_offset] == offsets[target_offset]


def test_unshared_instructions_are_left_unmatched():
    left = _body("A", {"B0": ["PUSH", "AAA", "RET"]})
    right = _body("B", {"B0": ["PUSH", "BBB", "RET"]})

    alignment = align_function_bodies(left, right)

    assert alignment.instruction_pairs == ((0, 0), (2, 2))
    assert alignment.unmatched_reference == (1,)
    assert alignment.unmatched_target == (1,)


def test_block_alignment_matches_the_original_helper():
    left = _body("A", {"B0": ["PUSH", "MOV"], "B1": ["XOR", "RET"]})
    right = _body("B", {"B0": ["PUSH", "LEA"], "B1": ["XOR", "RET"]})
    expected_pairs, expected_count = _align_blocks(left, right)

    for with_instructions in (False, True):
        alignment = align_function_bodies(
            left, right, with_instructions=with_instructions
        )
        assert list(alignment.block_pairs) == expected_pairs
        assert alignment.candidate_block_pair_count == expected_count


def test_skipping_instructions_returns_no_instruction_detail():
    left = _body("A", {"B0": ["PUSH", "RET"]})
    right = _body("B", {"B0": ["PUSH", "RET"]})

    alignment = align_function_bodies(left, right, with_instructions=False)

    assert alignment.instruction_pairs == ()
    assert alignment.unmatched_reference == ()
    assert alignment.unmatched_target == ()


def main() -> int:
    test_identical_bodies_pair_every_instruction()
    test_an_inserted_instruction_keeps_the_surrounding_correspondence()
    test_repeated_tokens_align_deterministically()
    test_instructions_from_different_blocks_are_never_linked()
    test_unshared_instructions_are_left_unmatched()
    test_block_alignment_matches_the_original_helper()
    test_skipping_instructions_returns_no_instruction_detail()
    print("F7.0 alignment PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
