"""F7.1 medoid selection."""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gzip  # noqa: E402
import json  # noqa: E402
from pathlib import Path  # noqa: E402

from body_similarity import FunctionBody, parse_body  # noqa: E402
from family_template import (  # noqa: E402
    COMMON,
    OPTIONAL,
    FamilyMedoid,
    align_members_to_medoid,
    build_family_template,
    select_medoid,
    structure_similarity,
)
from slot_overlay import (  # noqa: E402
    CALL_TARGET,
    RESOLVED,
    UNRESOLVED,
    SlotObservation,
    collect_slot_observations,
    transfers_by_source,
)


def _body(identifier: str, mnemonics: list[str]) -> FunctionBody:
    instructions = [
        {
            "offset": offset,
            "mnemonic_class": mnemonic,
            "operands": [],
            "control_flow": "return" if mnemonic == "RET" else "none",
        }
        for offset, mnemonic in enumerate(mnemonics)
    ]
    return FunctionBody(
        id=identifier,
        size=len(mnemonics),
        instructions=tuple(instructions),
        edges=(),
        blocks=({"label": "B0", "instruction_offsets": list(range(len(mnemonics)))},),
        quality={"complete_decode": True, "opaque_indirect_jumps": 0},
    )


def _family(bodies: list[FunctionBody]) -> dict[str, FunctionBody]:
    return {body.id: body for body in bodies}


def test_the_central_member_is_chosen():
    # B sits between A and C, so it matches both better than they match each other.
    bodies = _family([
        _body("A", ["PUSH", "MOV", "MOV", "RET"]),
        _body("B", ["PUSH", "MOV", "XOR", "RET"]),
        _body("C", ["PUSH", "XOR", "XOR", "RET"]),
    ])

    selection = select_medoid(bodies, ["A", "B", "C"])

    assert selection.medoid == "B"
    assert selection.members == ("A", "B", "C")
    assert selection.score == max(selection.mean_similarity.values())
    assert selection.mean_similarity["B"] > selection.mean_similarity["A"]
    assert selection.mean_similarity["B"] > selection.mean_similarity["C"]


def test_the_medoid_is_a_real_member_not_a_synthetic_body():
    bodies = _family([
        _body("A", ["PUSH", "RET"]),
        _body("B", ["PUSH", "MOV", "RET"]),
        _body("C", ["PUSH", "MOV", "MOV", "RET"]),
    ])

    selection = select_medoid(bodies, ["A", "B", "C"])

    assert selection.medoid in bodies
    assert set(selection.mean_similarity) == {"A", "B", "C"}


def test_ties_break_on_the_first_id_and_input_order_does_not_matter():
    bodies = _family([
        _body("A", ["PUSH", "RET"]),
        _body("B", ["PUSH", "RET"]),
        _body("C", ["PUSH", "RET"]),
    ])

    assert select_medoid(bodies, ["C", "B", "A"]).medoid == "A"
    assert select_medoid(bodies, ["A", "B", "C"]).medoid == "A"


def test_identical_members_score_one():
    bodies = _family([_body("A", ["PUSH", "RET"]), _body("B", ["PUSH", "RET"])])

    selection = select_medoid(bodies, ["A", "B"])

    assert selection.score == 1.0
    assert structure_similarity(bodies["A"], bodies["B"]) == 1.0


def test_bad_input_is_refused():
    bodies = _family([_body("A", ["PUSH", "RET"]), _body("B", ["PUSH", "RET"])])
    for members, expected in (
        (["A"], "at least two"),
        (["A", "A", "B"], "unique"),
        (["A", "Z"], "no body"),
    ):
        try:
            select_medoid(bodies, members)
        except ValueError as exc:
            assert expected in str(exc), (members, str(exc))
        else:
            raise AssertionError(f"{members} was accepted")


def test_every_other_member_is_aligned_onto_the_medoid():
    bodies = _family([
        _body("A", ["PUSH", "MOV", "MOV", "RET"]),
        _body("B", ["PUSH", "MOV", "XOR", "RET"]),
        _body("C", ["PUSH", "XOR", "XOR", "RET"]),
    ])
    selection = select_medoid(bodies, ["A", "B", "C"])

    alignments = align_members_to_medoid(bodies, selection)

    assert set(alignments) == {"A", "C"}
    for alignment in alignments.values():
        assert alignment.block_pairs == (("B0", "B0"),)
        assert alignment.instruction_pairs, "the medoid alignment carries instructions"
        # PUSH and RET are shared by every member of this family.
        assert (0, 0) in alignment.instruction_pairs
        assert (3, 3) in alignment.instruction_pairs


def _blocks_body(identifier: str, blocks: dict[str, list[str]]) -> FunctionBody:
    instructions: list[dict[str, object]] = []
    block_records: list[dict[str, object]] = []
    offset = 0
    for label, mnemonics in blocks.items():
        offsets: list[int] = []
        for mnemonic in mnemonics:
            instructions.append({
                "offset": offset,
                "mnemonic_class": mnemonic,
                "operands": [],
                "control_flow": "return" if mnemonic == "RET" else "none",
            })
            offsets.append(offset)
            offset += 1
        block_records.append({"label": label, "instruction_offsets": offsets})
    return FunctionBody(
        id=identifier,
        size=offset,
        instructions=tuple(instructions),
        edges=(),
        blocks=tuple(block_records),
        quality={"complete_decode": True, "opaque_indirect_jumps": 0},
    )


def _call_slot(offset: int, value, state=RESOLVED) -> SlotObservation:
    return SlotObservation(
        offset=offset, index=0, kind=CALL_TARGET, value=value, state=state
    )


def test_the_medoid_observes_itself_through_an_identity_mapping():
    bodies = _family([_body("A", ["CALL", "RET"]), _body("B", ["CALL", "RET"])])
    selection = select_medoid(bodies, ["A", "B"])
    observations = {
        "A": (_call_slot(0, "0x1111"),),
        "B": (_call_slot(0, "0x2222"),),
    }

    template = build_family_template(bodies, selection, observations)

    (slot,) = template.slots
    assert template.medoid == "A"
    assert slot.values_by_member == {"A": "0x1111", "B": "0x2222"}
    assert slot.states_by_member == {"A": RESOLVED, "B": RESOLVED}
    assert slot.varies and slot.resolved_values == ("0x1111", "0x2222")


def test_an_invariant_target_is_not_a_variation_slot():
    bodies = _family([_body("A", ["CALL", "RET"]), _body("B", ["CALL", "RET"])])
    selection = select_medoid(bodies, ["A", "B"])
    observations = {"A": (_call_slot(0, "0x1111"),), "B": (_call_slot(0, "0x1111"),)}

    template = build_family_template(bodies, selection, observations)

    assert template.slots[0].resolved_values == ("0x1111",)
    assert not template.slots[0].varies
    assert template.variation_slots == ()


def test_unresolved_observations_do_not_create_variants():
    bodies = _family([_body("A", ["CALL", "RET"]), _body("B", ["CALL", "RET"])])
    selection = select_medoid(bodies, ["A", "B"])
    observations = {
        "A": (_call_slot(0, "0x1111"),),
        "B": (_call_slot(0, None, state=UNRESOLVED),),
    }

    template = build_family_template(bodies, selection, observations)
    slot = template.slots[0]

    assert slot.resolved_values == ("0x1111",)
    assert not slot.varies
    assert not slot.observed_by_all


def test_a_medoid_block_missing_from_a_member_is_optional():
    bodies = _family([
        _blocks_body("A", {"B0": ["PUSH", "MOV"], "B1": ["XOR", "RET"]}),
        _blocks_body("B", {"B0": ["PUSH", "MOV"], "B1": ["XOR", "RET"]}),
        _blocks_body("C", {"B0": ["PUSH", "MOV"]}),
    ])
    selection = select_medoid(bodies, ["A", "B", "C"])
    observations = {member: () for member in bodies}

    template = build_family_template(bodies, selection, observations)

    assert template.block_roles["B0"] == COMMON
    assert template.block_roles["B1"] == OPTIONAL


def test_member_only_blocks_stay_attributed_to_that_member():
    bodies = _family([
        _blocks_body("A", {"B0": ["PUSH", "MOV"]}),
        _blocks_body("B", {"B0": ["PUSH", "MOV"], "B1": ["XOR", "RET"]}),
        _blocks_body("C", {"B0": ["PUSH", "MOV"], "B1": ["AAA", "RET"]}),
    ])
    # Pin the medoid: this test is about template construction, not selection,
    # and A is the member the orphan blocks have to be measured against.
    selection = FamilyMedoid(
        medoid="A",
        members=("A", "B", "C"),
        mean_similarity={"A": 1.0, "B": 0.5, "C": 0.5},
    )
    observations = {member: () for member in bodies}

    template = build_family_template(bodies, selection, observations)

    # B and C each own an orphan block; they are never merged into one region.
    assert template.medoid == "A"
    assert set(template.member_specific_blocks) == {"B", "C"}
    assert template.member_specific_blocks["B"] == ("B1",)
    assert template.member_specific_blocks["C"] == ("B1",)


def test_missing_observations_for_a_member_are_refused():
    bodies = _family([_body("A", ["CALL", "RET"]), _body("B", ["CALL", "RET"])])
    selection = select_medoid(bodies, ["A", "B"])
    try:
        build_family_template(bodies, selection, {"A": ()})
    except ValueError as exc:
        assert "slot observations" in str(exc)
    else:
        raise AssertionError("a member without observations was accepted")


def test_real_line_buffer_fill_has_one_varying_call_target():
    fixtures = Path(__file__).resolve().parent / "fixtures"
    with gzip.open(fixtures / "f7_alignment" / "ripgrep_219_bodies.json.gz",
                   "rt", encoding="utf-8") as handle:
        records = {item["id"]: item for item in json.load(handle)["functions"]}
    with gzip.open(fixtures / "f7_slot_overlay" / "ripgrep_positive_41.raw.json.gz",
                   "rt", encoding="utf-8") as handle:
        raw = json.load(handle)

    members = raw["origins"]["grep_searcher::line_buffer::LineBuffer::fill"]
    bodies = {member: parse_body(records[member]) for member in members}
    index = transfers_by_source(raw)
    observations = {}
    for member in members:
        base = int(raw["address_by_member"][member], 16)
        observations[member] = collect_slot_observations(
            bodies[member], base, index.get(base, {})
        )

    selection = select_medoid(bodies, members)
    template = build_family_template(bodies, selection, observations)
    calls = [slot for slot in template.slots if slot.kind == CALL_TARGET]
    varying = [slot for slot in calls if slot.varies]

    assert len(members) == 5
    assert len(calls) == 10, len(calls)
    assert len(varying) == 1, len(varying)
    assert len(calls) - len(varying) == 9
    (slot,) = varying
    assert slot.offset == 0xEC, hex(slot.offset)
    assert len(slot.resolved_values) == 5, slot.resolved_values
    assert set(template.block_roles.values()) == {COMMON}
    assert template.member_specific_blocks == {}


def main() -> int:
    test_the_central_member_is_chosen()
    test_the_medoid_is_a_real_member_not_a_synthetic_body()
    test_ties_break_on_the_first_id_and_input_order_does_not_matter()
    test_identical_members_score_one()
    test_bad_input_is_refused()
    test_every_other_member_is_aligned_onto_the_medoid()
    test_the_medoid_observes_itself_through_an_identity_mapping()
    test_an_invariant_target_is_not_a_variation_slot()
    test_unresolved_observations_do_not_create_variants()
    test_a_medoid_block_missing_from_a_member_is_optional()
    test_member_only_blocks_stay_attributed_to_that_member()
    test_missing_observations_for_a_member_are_refused()
    test_real_line_buffer_fill_has_one_varying_call_target()
    print("F7.1 medoid and F7.2 template PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
