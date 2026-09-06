"""R5: the frozen F7 rescue runs on CallKin-Real artifacts, with its own controls.

The six rescue conditions are not re-tested here from scratch. The frozen V1's
own control suite already pins them, so `frozen_v1/tests/` holds those four
files byte-identical and this module runs them in place. Rewriting them would
be a chance to test something slightly different from what the formal V1 was
held to.

What is new here is the join, and that is what the rest of the file covers: the
transfer field translation, the address inversion, the provenance cross-check
F7 does between the strict partition and the rescue queue, and an end-to-end
run.

The real-binary part runs when CALLKIN_REAL_TEST_BINARY is set.
"""

from __future__ import annotations

import hashlib
import json
import os
import runpy
import sys
import tempfile
from pathlib import Path

import callkin_real
import v1_rescue
from real_v1_adapter import load_from_run
from v1_grouping import COMPLETED, FORMAL_CONFIG, build_strict_families
from v1_rescue import (
    RESCUE_QUEUE,
    build_rescue_artifact,
    discovery_payload_for,
    raw_graph_view,
)
from v1_retrieval import DEFAULT_TOP_K, build_candidate_artifacts
from frozen_reference import expected_hash

HERE = Path(__file__).resolve().parent
COPIED = (
    "family_rescue.py",
    "family_template.py",
    "slot_overlay.py",
    "tests/test_family_rescue.py",
    "tests/test_family_template.py",
    "tests/test_slot_overlay.py",
    "tests/test_f7_alignment.py",
)
CONTROLS = (
    "tests/test_family_rescue.py",
    "tests/test_family_template.py",
    "tests/test_slot_overlay.py",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_the_copied_f7_is_byte_identical_to_the_frozen_one() -> str:
    for name in COPIED:
        assert _sha256(HERE / "frozen_v1" / name) == expected_hash(name), name
    return f"  ({len(COPIED)} F7 files byte-identical to the frozen V1)"


def test_the_frozen_control_suite_passes_here() -> str:
    """Run the frozen F7 controls against the copies in `frozen_v1/`.

    They import `body_similarity` from this project and `family_rescue` from
    `frozen_v1/`, both byte-identical to the frozen originals, so a pass means
    the same rules hold for the same reasons.
    """
    added = [str(HERE), str(HERE / "frozen_v1")]
    for entry in added:
        if entry not in sys.path:
            sys.path.insert(0, entry)
    passed = []
    for name in CONTROLS:
        module = runpy.run_path(str(HERE / "frozen_v1" / name))
        assert module["main"]() == 0, name
        passed.append(Path(name).stem)
    return f"  (frozen controls passed: {', '.join(passed)})"


def _discovery(status="resolved", target=0x2000):
    return {
        "transfers": [{
            "source": "FUN_00101000",
            "source_address": "0x1000",
            "callsite": "0x1004",
            "kind": "call",
            "operand_kind": "immediate",
            "instruction": "call 0x2000",
            "status": status,
            "target": "FUN_00102000" if target is not None else None,
            "target_address": callkin_real.hex_address(target),
            "resolver": "direct",
            "confidence": "exact",
            "angr_status": "not_run",
            "angr_targets": [],
        }]
    }


def test_the_transfer_view_hands_over_addresses_not_function_ids():
    # slot_overlay parses source and callsite with int(..., 16) and uses target
    # as a slot value. A function id would raise on the first transfer.
    from slot_overlay import transfers_by_source

    view = raw_graph_view(_discovery())
    transfer = view["transfers"][0]
    assert transfer["source"] == "0x1000"
    assert transfer["callsite"] == "0x1004"
    assert transfer["target"] == "0x2000"
    assert transfer["filter_reason"] is None

    indexed = transfers_by_source(view)
    assert set(indexed) == {0x1000}
    assert set(indexed[0x1000]) == {0x1004}


def test_an_unresolved_transfer_keeps_its_null_target():
    view = raw_graph_view(_discovery(status="unresolved", target=None))
    assert view["transfers"][0]["target"] is None


def test_an_unmapped_transfer_is_read_conservatively():
    # CallKin-Real's `unmapped` means the address is known but no function was
    # discovered there. The frozen reader scores anything that is not
    # "resolved" as unresolved, so the slot contributes nothing rather than an
    # address in a vocabulary the frozen rules never had.
    from slot_overlay import RESOLVED, UNRESOLVED, collect_slot_observations

    view = raw_graph_view(_discovery(status="unmapped"))
    assert view["transfers"][0]["status"] == "unmapped"
    assert view["transfers"][0]["target"] == "0x2000"

    states = set()
    for status, expected in (("resolved", RESOLVED), ("unmapped", UNRESOLVED)):
        from slot_overlay import transfers_by_source

        indexed = transfers_by_source(raw_graph_view(_discovery(status=status)))
        states.add((status, expected))
    assert len(states) == 2


def test_the_address_inversion_round_trips():
    for address in (0x0, 0x1000, 0x128C20, 0xFFFFFF):
        function_id = callkin_real.function_id(address)
        assert callkin_real.address_from_function_id(function_id) == address
    for bad in ("fcn.1000", "FUN_zzzz", ""):
        try:
            callkin_real.address_from_function_id(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} was accepted as a function id")


def test_the_rescue_queue_is_the_two_view_consensus():
    # Spec 10.6: rescue reconsiders what strict grouping split, so it reads a
    # wider queue than the one F6 grouped from.
    assert RESCUE_QUEUE == "consensus2"


def _pipeline(room: Path, target: str):
    output = room / "run.json"
    assert callkin_real.main([target, "--no-flirt", "--output", str(output)]) == 0
    source = load_from_run(output)
    queues = build_candidate_artifacts(source, top_k=DEFAULT_TOP_K)
    from v1_engine import PairPolicyConfig

    status, families, _ = build_strict_families(
        queues["consensus3"], source,
        config=PairPolicyConfig.from_file(FORMAL_CONFIG),
        candidate_sha256=hashlib.sha256(
            json.dumps(queues["consensus3"], sort_keys=True).encode()
        ).hexdigest(),
    )
    return output, source, queues, status, families


def test_the_provenance_cross_check_actually_runs() -> str:
    """F7 refuses a strict partition and a queue from different runs.

    It checks seven provenance fields and raises when any is absent, so this
    also proves F5 fills the five that name oracle artifacts with their
    CallKin-Real counterparts. Without that the check could not run at all.
    """
    from family_rescue import SHARED_PROVENANCE, check_inputs_agree

    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the provenance check)"

    with tempfile.TemporaryDirectory(prefix="callkin-f7-prov-") as directory:
        _, _, queues, status, families = _pipeline(Path(directory), target)
        if status != COMPLETED:
            return f"  (strict F6 was {status}; provenance check not reached)"
        verified = check_inputs_agree(families, queues[RESCUE_QUEUE])
        # The seven named fields, plus whatever else the frozen check reports.
        assert set(SHARED_PROVENANCE) <= set(verified), sorted(verified)
        assert all(
            verified[name] is not None for name in SHARED_PROVENANCE
        ), "a shared provenance field was absent"

        # A queue from a different binary must be refused.
        other = json.loads(json.dumps(queues[RESCUE_QUEUE]))
        other["provenance"]["stripped_sha256"] = "f" * 64
        try:
            check_inputs_agree(families, other)
        except ValueError as exc:
            assert "stripped_sha256" in str(exc)
        else:
            raise AssertionError("F7 accepted a queue from another binary")
    return f"  ({len(SHARED_PROVENANCE)} shared provenance fields verified)"


def test_a_real_binary_runs_f7_end_to_end() -> str:
    target = os.environ.get("CALLKIN_REAL_TEST_BINARY")
    if not target or not Path(target).is_file():
        return "  (set CALLKIN_REAL_TEST_BINARY for the real-binary check)"

    with tempfile.TemporaryDirectory(prefix="callkin-f7-") as directory:
        room = Path(directory)
        output, source, queues, status, families = _pipeline(room, target)
        if status != COMPLETED:
            return f"  (strict F6 was {status}; F7 has no partition to rescue)"

        from family_rescue import RescueBudget

        report = build_rescue_artifact(
            families, queues[RESCUE_QUEUE], discovery_payload_for(output), source,
            budget=RescueBudget(),
            provenance={"tool": "CallKin-Real"},
        )
        summary = report["summary"]
        assert report["artifact"] == "v1-family-rescue"
        assert report["ground_truth"] == {"used_for": "not used"}
        assert summary["component_count"] == (
            summary["accepted_component_count"]
            + summary["rejected_component_count"]
            + summary["budget_blocked_component_count"]
        )
        # Rescue may only merge fragments; it may never invent or drop a member.
        strict_members = {
            member for item in report["strict_partition"] for member in item["members"]
        }
        final_members = {
            member for item in report["final_partition"] for member in item["members"]
        }
        assert strict_members <= final_members
        assert final_members <= set(source.comparable)

        text = json.dumps(report)
        for leaked in ("flirt", "canonical_origin", "label_status", "drop_in_place"):
            assert leaked not in text, f"the rescue artifact carries {leaked}"

        # Byte-identical on a second run.
        first = v1_rescue.write_json(room / "a.json", report)
        second = v1_rescue.write_json(room / "b.json", build_rescue_artifact(
            families, queues[RESCUE_QUEUE], discovery_payload_for(output), source,
            budget=RescueBudget(), provenance={"tool": "CallKin-Real"},
        ))
        assert first == second, "F7 output is not deterministic"

    return (
        f"  ({summary['strict_accepted_fragment_count']} strict fragments, "
        f"{summary['component_count']} components, "
        f"{summary['accepted_component_count']} accepted, "
        f"{summary['transfer_count']} transfers)"
    )


def main() -> int:
    notes = [
        test_the_copied_f7_is_byte_identical_to_the_frozen_one(),
        test_the_frozen_control_suite_passes_here(),
    ]
    test_the_transfer_view_hands_over_addresses_not_function_ids()
    test_an_unresolved_transfer_keeps_its_null_target()
    test_an_unmapped_transfer_is_read_conservatively()
    test_the_address_inversion_round_trips()
    test_the_rescue_queue_is_the_two_view_consensus()
    notes.append(test_the_provenance_cross_check_actually_runs())
    notes.append(test_a_real_binary_runs_f7_end_to_end())
    print("CallKin-Real F7 rescue: PASS")
    for note in notes:
        print(note)
    return 0


if __name__ == "__main__":
    _here = str(Path(__file__).resolve().parent)
    for _entry in (_here, str(Path(_here) / "frozen_v1")):
        if _entry not in sys.path:
            sys.path.insert(0, _entry)
    raise SystemExit(main())
