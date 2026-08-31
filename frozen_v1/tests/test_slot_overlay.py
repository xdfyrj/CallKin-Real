"""F7.2a: joining the raw call graph onto normalized instructions."""

from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import FunctionBody, parse_body  # noqa: E402
from slot_overlay import (  # noqa: E402
    AMBIGUOUS,
    CALL_TARGET,
    TAIL_CALL_TARGET,
    DATA_REFERENCE,
    FILTERED,
    IMMEDIATE_CONSTANT,
    MISSING,
    RESOLVED,
    UNRESOLVED,
    collect_slot_observations,
    transfers_by_source,
)


BASE = 0x1000
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _call(offset: int) -> dict:
    return {
        "offset": offset,
        "mnemonic_class": "CALL",
        "operands": ["call_target"],
        "control_flow": "call",
        "constants": [],
        "slots": [{"kind": "call", "value": None, "status": "address-only",
                   "resolver": None}],
    }


def _jump(offset: int, control_flow: str) -> dict:
    return {
        "offset": offset,
        "mnemonic_class": "JMP",
        "operands": ["external_target"],
        "control_flow": control_flow,
        "constants": [],
        "slots": [],
    }


def _body(instructions: list[dict]) -> FunctionBody:
    return FunctionBody(
        id="FUN_00001000",
        size=len(instructions) * 4,
        instructions=tuple(instructions),
        edges=(),
        blocks=({"label": "B0",
                 "instruction_offsets": [item["offset"] for item in instructions]},),
        quality={"complete_decode": True, "opaque_indirect_jumps": 0},
    )


def _transfer(offset: int, **fields) -> dict:
    record = {
        "source": f"0x{BASE:x}",
        "callsite": f"0x{BASE + offset:x}",
        "kind": "call",
    }
    record.update(fields)
    return record


def _observe(instructions, transfers):
    index = transfers_by_source({"transfers": transfers})
    return collect_slot_observations(_body(instructions), BASE, index.get(BASE, {}))


def test_resolved_direct_call_keeps_its_target():
    (call,) = _observe(
        [_call(0)],
        [_transfer(0, status="resolved", target="0x2000",
                   resolver="direct-immediate")],
    )
    assert (call.kind, call.state, call.value) == (CALL_TARGET, RESOLVED, "0x2000")
    assert call.resolver == "direct-immediate"
    assert call.usable


def test_resolved_angr_call_is_a_call_target_too():
    (call,) = _observe(
        [_call(0)],
        [_transfer(0, status="resolved", target="0x3000", resolver="angr-cfg",
                   angr_targets=["0x3000"])],
    )
    # Direct and indirect share the kind; only the resolver distinguishes them.
    assert (call.kind, call.state, call.value) == (CALL_TARGET, RESOLVED, "0x3000")
    assert call.resolver == "angr-cfg"


def test_unresolved_call_is_observed_but_not_usable():
    (call,) = _observe([_call(0)], [_transfer(0, status="unresolved", target=None)])
    assert (call.state, call.value) == (UNRESOLVED, None)
    assert not call.usable


def test_filtered_import_keeps_its_target_and_reason_but_is_not_usable():
    (call,) = _observe(
        [_call(0)],
        [_transfer(0, status="filtered", target="0x500000", resolver="angr-cfg",
                   filter_reason="import", angr_targets=["0x500000"])],
    )
    assert (call.state, call.value) == (FILTERED, "0x500000")
    assert call.filter_reason == "import"
    assert not call.usable


def test_several_angr_targets_are_ambiguous_not_a_value():
    (call,) = _observe(
        [_call(0)],
        [_transfer(0, status="resolved", target="0x3000", resolver="angr-cfg",
                   angr_targets=["0x3000", "0x4000"])],
    )
    assert (call.state, call.value) == (AMBIGUOUS, None)
    assert not call.usable


def test_a_call_without_a_transfer_is_missing():
    (call,) = _observe([_call(0)], [])
    assert (call.state, call.value) == (MISSING, None)
    assert not call.usable


def test_duplicate_source_callsite_is_refused():
    try:
        transfers_by_source({"transfers": [
            _transfer(0, status="resolved", target="0x2000"),
            _transfer(0, status="resolved", target="0x9000"),
        ]})
    except ValueError as exc:
        assert "duplicate" in str(exc)
    else:
        raise AssertionError("a duplicate transfer was accepted")


def test_data_references_and_constants_come_from_the_instruction():
    observations = _observe(
        [
            {
                "offset": 0, "mnemonic_class": "LEA", "operands": ["reg64", "mem_ip"],
                "control_flow": "fallthrough", "constants": [16],
                "slots": [{"kind": "data", "value": "FUN_00500000",
                           "status": None, "resolver": None}],
            }
        ],
        [],
    )
    kinds = {item.kind: item for item in observations}
    assert kinds[DATA_REFERENCE].value == "FUN_00500000"
    assert kinds[DATA_REFERENCE].state == RESOLVED
    assert kinds[IMMEDIATE_CONSTANT].value == 16
    assert {item.index for item in observations} == {1, 2}


def test_a_data_slot_without_a_value_is_missing():
    (data,) = _observe(
        [
            {
                "offset": 0, "mnemonic_class": "LEA", "operands": ["reg64", "mem_ip"],
                "control_flow": "fallthrough", "constants": [],
                "slots": [{"kind": "data", "value": None, "status": None,
                           "resolver": None}],
            }
        ],
        [],
    )
    assert (data.kind, data.state) == (DATA_REFERENCE, MISSING)


def test_a_resolved_direct_tail_call_is_a_usable_slot():
    (tail,) = _observe(
        [_jump(0, "external_jump")],
        [_transfer(0, kind="tail-call", status="resolved", target="0x2000",
                   resolver="direct-tail")],
    )
    assert (tail.kind, tail.state, tail.value) == (
        TAIL_CALL_TARGET, RESOLVED, "0x2000"
    )
    assert tail.usable


def test_a_resolved_angr_tail_call_is_a_usable_slot():
    (tail,) = _observe(
        [_jump(0, "external_jump")],
        [_transfer(0, kind="tail-call", status="resolved", target="0x3000",
                   resolver="angr-cfg", angr_targets=["0x3000"])],
    )
    assert (tail.kind, tail.state, tail.value) == (
        TAIL_CALL_TARGET, RESOLVED, "0x3000"
    )
    assert tail.resolver == "angr-cfg"


def test_an_unresolved_indirect_tail_call_is_observed_but_unusable():
    (tail,) = _observe(
        [_jump(0, "indirect_jump")],
        [_transfer(0, kind="tail-call", status="unresolved", target=None)],
    )
    assert (tail.kind, tail.state, tail.value) == (
        TAIL_CALL_TARGET, UNRESOLVED, None
    )
    assert not tail.usable


def test_an_indirect_jump_that_is_not_a_tail_call_gets_no_slot():
    # A jump table is not a callee choice, and only the raw graph can say so.
    assert _observe(
        [_jump(0, "indirect_jump")],
        [_transfer(0, kind="call", status="resolved", target="0x2000")],
    ) == ()
    assert _observe([_jump(0, "indirect_jump")], []) == ()


def test_a_local_jump_never_produces_a_slot():
    assert _observe([_jump(0, "local_jump")], []) == ()
    assert _observe(
        [_jump(0, "local_jump")],
        [_transfer(0, kind="tail-call", status="resolved", target="0x2000")],
    ) == ()


def test_an_external_jump_without_a_transfer_is_missing():
    # The position still exists; the raw graph simply had nothing for it.
    (tail,) = _observe([_jump(0, "external_jump")], [])
    assert (tail.kind, tail.state) == (TAIL_CALL_TARGET, MISSING)
    assert not tail.usable


def test_real_callsites_join_the_raw_graph_exactly():
    with gzip.open(FIXTURES / "f7_alignment" / "ripgrep_219_bodies.json.gz",
                   "rt", encoding="utf-8") as handle:
        records = {item["id"]: item for item in json.load(handle)["functions"]}
    with gzip.open(FIXTURES / "f7_slot_overlay" / "ripgrep_positive_41.raw.json.gz",
                   "rt", encoding="utf-8") as handle:
        raw = json.load(handle)

    index = transfers_by_source(raw)
    assert len(raw["members"]) == 41
    assert len(raw["transfers"]) == 814

    calls = joined = 0
    for member in raw["members"]:
        base = int(raw["address_by_member"][member], 16)
        body = parse_body(records[member])
        observations = collect_slot_observations(body, base, index.get(base, {}))
        member_calls = [item for item in observations if item.kind == CALL_TARGET]
        calls += len(member_calls)
        joined += sum(1 for item in member_calls if item.state != MISSING)

    assert calls == 814, calls
    assert joined == 814, joined
    used = sum(len(callsites) for callsites in index.values())
    assert used == 814, used


def main() -> int:
    test_resolved_direct_call_keeps_its_target()
    test_resolved_angr_call_is_a_call_target_too()
    test_unresolved_call_is_observed_but_not_usable()
    test_filtered_import_keeps_its_target_and_reason_but_is_not_usable()
    test_several_angr_targets_are_ambiguous_not_a_value()
    test_a_call_without_a_transfer_is_missing()
    test_duplicate_source_callsite_is_refused()
    test_data_references_and_constants_come_from_the_instruction()
    test_a_data_slot_without_a_value_is_missing()
    test_a_resolved_direct_tail_call_is_a_usable_slot()
    test_a_resolved_angr_tail_call_is_a_usable_slot()
    test_an_unresolved_indirect_tail_call_is_observed_but_unusable()
    test_an_indirect_jump_that_is_not_a_tail_call_gets_no_slot()
    test_a_local_jump_never_produces_a_slot()
    test_an_external_jump_without_a_transfer_is_missing()
    test_real_callsites_join_the_raw_graph_exactly()
    print("F7.2a slot overlay PASS (814 body calls joined to 814 raw transfers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
