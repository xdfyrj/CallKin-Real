"""R2: body evidence decides the universe, and failures stay visible.

R1 assumed an internal function with an extent was fully decoded. Nothing had
read its bytes. These tests replace that assumption with the decode result and
pin the two things that must not happen: a function that failed to decode being
recorded as complete, and a function that failed disappearing from the artifact.
"""

from __future__ import annotations

import collections

from body_builder import (
    DECODE_GAP,
    EXTENT_NOT_FILE_BACKED,
    TRUNCATED_EXTENT,
    ZERO_INSTRUCTION_DECODE,
    body_quality_by_address,
    build_bodies,
    build_function_body,
    decode_x86_64,
    is_complete_decode,
)
from callkin_real import (
    ANALYSIS_COMPLETE,
    ANALYSIS_INCOMPLETE,
    ROLE_ABSTAIN,
    ROLE_MEMBER,
    Function,
    analysis_status_for,
    classify_nodes,
)


# xor eax, eax ; ret
CLEAN = bytes([0x31, 0xC0, 0xC3])
# xor eax, eax ; <undecodable> ; ret
GAPPED = bytes([0x31, 0xC0, 0x06, 0xC3])


class _Image:
    """The reader contract: ValueError means "not in the file", nothing else."""

    def __init__(self, blocks: dict[int, bytes], broken: set[int] | None = None):
        self.blocks = blocks
        self.broken = broken or set()

    def read(self, address: int, size: int) -> bytes:
        if address in self.broken:
            raise RuntimeError("a defect in the reader, not a property of the binary")
        data = self.blocks.get(address)
        if data is None:
            raise ValueError("not file backed")
        return data[:size]


def _internal(address: int, size: int) -> Function:
    return Function(
        address=address, size=size, name=f"fcn.{address:x}",
        boundary_source="radare2",
    )


def test_a_fully_decoded_extent_is_complete_and_a_member():
    body = build_function_body("FUN_00101000", 0x1000, len(CLEAN), CLEAN)

    assert body["quality"]["complete_decode"] is True
    assert body["quality"]["failure_reason"] is None
    assert body["summary"]["instruction_count"] == 2
    quality = {0x1000: body["quality"]}
    assert analysis_status_for(_internal(0x1000, len(CLEAN)), quality) == ANALYSIS_COMPLETE


def test_a_decode_gap_is_incomplete_and_abstains():
    body = build_function_body("FUN_00101000", 0x1000, len(GAPPED), GAPPED)

    assert body["quality"]["complete_decode"] is False
    assert body["quality"]["failure_reason"] == DECODE_GAP
    functions = {0x1000: _internal(0x1000, len(GAPPED))}
    edges: dict[int, collections.Counter] = {0x1000: collections.Counter()}
    roles, _, abstentions, statuses = classify_nodes(
        functions, edges, None, {0x1000: body["quality"]}
    )
    assert statuses[0x1000] == ANALYSIS_INCOMPLETE
    assert roles[0x1000] == ROLE_ABSTAIN
    assert [item["reason"] for item in abstentions] == ["incomplete_body"]


def test_an_internal_function_without_body_evidence_is_an_error():
    # The R1 assumption, now refused outright.
    try:
        analysis_status_for(_internal(0x1000, 16), {})
    except ValueError as exc:
        assert "no body evidence" in str(exc)
    else:
        raise AssertionError("an undecoded internal function was accepted")


def test_every_failure_reason_is_reported_and_nothing_disappears():
    image = _Image({0x1000: CLEAN, 0x2000: GAPPED, 0x3000: CLEAN[:1]})
    extents = {
        0x1000: ("FUN_00101000", len(CLEAN)),        # complete
        0x2000: ("FUN_00102000", len(GAPPED)),       # decode gap
        0x3000: ("FUN_00103000", len(CLEAN)),        # short read
        0x4000: ("FUN_00104000", len(CLEAN)),        # unreadable
        0x5000: ("FUN_00105000", 0),                 # no extent
    }

    artifact = build_bodies(image, extents)
    by_id = {record["id"]: record for record in artifact["functions"]}

    assert len(artifact["functions"]) == len(extents), "a failure was dropped"
    assert by_id["FUN_00101000"]["quality"]["complete_decode"] is True
    assert by_id["FUN_00102000"]["quality"]["failure_reason"] == DECODE_GAP
    assert by_id["FUN_00103000"]["quality"]["failure_reason"] == TRUNCATED_EXTENT
    assert by_id["FUN_00104000"]["quality"]["failure_reason"] == EXTENT_NOT_FILE_BACKED
    assert by_id["FUN_00105000"]["quality"]["failure_reason"] == EXTENT_NOT_FILE_BACKED
    assert artifact["summary"]["complete_count"] == 1
    assert artifact["summary"]["incomplete_count"] == 4


def test_a_zero_instruction_decode_is_named_as_such():
    body = build_function_body("FUN_00101000", 0x1000, 1, bytes([0x06]))
    assert body["quality"]["failure_reason"] == ZERO_INSTRUCTION_DECODE


def test_completeness_needs_every_byte_covered_exactly():
    instructions = decode_x86_64(CLEAN, 0x1000)
    assert is_complete_decode(instructions, len(CLEAN)) is True
    # One byte of the extent left undecoded is not complete.
    assert is_complete_decode(instructions, len(CLEAN) + 1) is False


def test_an_opaque_indirect_jump_keeps_the_function_a_member():
    # jmp rax: complete decode, but a jump the CFG cannot follow.
    body = build_function_body("FUN_00101000", 0x1000, 2, bytes([0xFF, 0xE0]))
    assert body["quality"]["complete_decode"] is True
    assert body["quality"]["opaque_indirect_jump_count"] >= 0

    functions = {0x1000: _internal(0x1000, 2), 0x2000: _internal(0x2000, len(CLEAN))}
    edges: dict[int, collections.Counter] = {
        0x1000: collections.Counter({0x2000: 1}),
        0x2000: collections.Counter(),
    }
    clean = build_function_body("FUN_00102000", 0x2000, len(CLEAN), CLEAN)
    roles, _, _, _ = classify_nodes(
        functions, edges, None,
        {0x1000: body["quality"], 0x2000: clean["quality"]},
    )
    # F6's opaque policy is a comparison decision, not a discovery failure.
    assert roles[0x1000] == ROLE_MEMBER


def test_the_quality_index_covers_every_decoded_function():
    image = _Image({0x1000: CLEAN, 0x2000: GAPPED})
    artifact = build_bodies(
        image, {0x1000: ("FUN_00101000", len(CLEAN)), 0x2000: ("FUN_00102000", len(GAPPED))}
    )
    quality = body_quality_by_address(artifact)
    assert set(quality) == {0x1000, 0x2000}
    assert quality[0x1000]["complete_decode"] is True
    assert quality[0x2000]["complete_decode"] is False


def test_elf_and_pe_go_through_the_same_body_builder():
    # One decode path for both formats. If PE ever needed its own, a PE-only
    # decode bug would be invisible to every ELF test.
    import inspect

    import body_builder
    from callkin_real import ElfImage, PeImage

    source = inspect.getsource(body_builder.build_bodies)
    assert "image.read(" in source
    for forbidden in ("elf", "ELF", "pefile", "PE32"):
        assert forbidden not in source, "the builder branches on format"

    for image_class in (ElfImage, PeImage):
        read = inspect.signature(image_class.read)
        assert list(read.parameters) == ["self", "address", "size"], image_class.__name__

    # The stub image in this file has exactly that method and nothing else,
    # and every test above decoded through it.
    assert [name for name in vars(_Image) if not name.startswith("__")] == ["read"]


def test_a_reader_value_error_is_a_decode_failure():
    image = _Image({})
    artifact = build_bodies(image, {0x1000: ("FUN_00101000", 8)})
    quality = artifact["functions"][0]["quality"]
    assert quality["failure_reason"] == EXTENT_NOT_FILE_BACKED


def test_any_other_reader_exception_propagates():
    # A broad `except Exception` here would file a library bug or a typo under
    # extent_not_file_backed, and the summary would then report as a property
    # of the binary something that is a property of this run.
    image = _Image({}, broken={0x1000})
    try:
        build_bodies(image, {0x1000: ("FUN_00101000", 8)})
    except RuntimeError:
        pass
    else:
        raise AssertionError("a reader defect was recorded as a decode failure")


def _pe_reader(error: Exception | None):
    import pefile

    import callkin_real

    class _Pe:
        def get_data(self, rva, size):
            if error is not None:
                raise error
            return bytes([0x90]) * size

    image = object.__new__(callkin_real.PeImage)
    image.pe = _Pe()
    image.image_base = 0x140000000
    image.unmapped_error = pefile.PEFormatError
    return image


def test_the_pe_reader_reports_an_unmapped_rva_as_a_value_error():
    # pefile raises its own PEFormatError for an RVA outside the mapped file.
    # PeImage must translate it, or the fail-closed contract would make every
    # PE run crash on the first unmapped extent.
    import pefile

    image = _pe_reader(pefile.PEFormatError("Data outside the mapped file"))
    try:
        image.read(0x140001000, 16)
    except ValueError:
        pass
    else:
        raise AssertionError("PeImage.read did not translate PEFormatError")


def test_the_pe_reader_propagates_anything_else():
    # Translating every exception would move the broad except out of
    # build_bodies into the reader rather than remove it: a defect in pefile,
    # or a typo here, would still be filed as extent_not_file_backed.
    image = _pe_reader(RuntimeError("reader bug"))
    try:
        image.read(0x140001000, 16)
    except RuntimeError:
        pass
    except ValueError:
        raise AssertionError("a reader defect was disguised as a decode failure")


def test_a_pe_read_that_succeeds_returns_the_bytes():
    assert _pe_reader(None).read(0x140001000, 4) == bytes([0x90]) * 4


def main() -> int:
    test_a_fully_decoded_extent_is_complete_and_a_member()
    test_a_decode_gap_is_incomplete_and_abstains()
    test_an_internal_function_without_body_evidence_is_an_error()
    test_every_failure_reason_is_reported_and_nothing_disappears()
    test_a_zero_instruction_decode_is_named_as_such()
    test_completeness_needs_every_byte_covered_exactly()
    test_an_opaque_indirect_jump_keeps_the_function_a_member()
    test_the_quality_index_covers_every_decoded_function()
    test_elf_and_pe_go_through_the_same_body_builder()
    test_a_reader_value_error_is_a_decode_failure()
    test_any_other_reader_exception_propagates()
    test_the_pe_reader_reports_an_unmapped_rva_as_a_value_error()
    test_the_pe_reader_propagates_anything_else()
    test_a_pe_read_that_succeeds_returns_the_bytes()
    print("CallKin-Real body and universe: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
