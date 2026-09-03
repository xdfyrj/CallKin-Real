# Cost-bounded V1 plus FLIRT overlay implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a label-blind, component-wise cost-bounded V1 partition and evaluate post-grouping FLIRT propagation on zoxide.

**Architecture:** A small F5 derivation module selects complete candidate-graph components whose worst-case F6 comparison cost fits the frozen budget. Existing frozen F6, F7, and F10 code then runs unchanged. Prediction generation and oracle-only scoring remain separate commands.

**Tech Stack:** Python 3.12 standard library and the existing CallKin-Real/frozen V1 modules.

**Spec:** `docs/superpowers/specs/2026-09-03-component-v1-flirt.md`

## Global Constraints

- FLIRT labels and ground truth never influence V1 component selection or grouping.
- Preserve F6 thresholds and budgets: 10,000 comparisons and 500,000,000 alignment cells.
- Select or defer an entire connected component; never run a partial component.
- Preserve all input pair records and the complete target universe.
- Generate and hash prediction artifacts before oracle scoring.
- No post-result change to thresholds, budget, component order, seed rule, or metric.

---

### Task 1: Derive a component-wise budgeted F5 queue

**Files:**
- Create: `v1_component_budget.py`
- Create: `test_v1_component_budget.py`

**Interfaces:**
- Consumes: a validated consensus3 candidate artifact, `RealV1Input`, `PairPolicyConfig`, and the source artifact SHA-256.
- Produces: `build_budgeted_candidate_artifact(candidate_artifact, source, config, source_candidate_sha256) -> (artifact, report)`.

- [ ] **Step 1: Write failing behavior tests**

Test literal synthetic graphs proving: connected components are atomic; the
linear upper-bound formula matches hand-calculated pair costs; opaque and
incomplete members cost zero; ordering never reads labels; selected pair
records remain byte-for-byte equal; the universe is unchanged; provenance
names the source SHA; a malformed hash fails closed; and selected components
fit both formal limits.

- [ ] **Step 2: Run the new test and verify RED**

Run: `/usr/bin/python3.12 test_v1_component_budget.py`

Expected: import or missing-function failure for `v1_component_budget`.

- [ ] **Step 3: Implement the minimal derivation**

Use only the standard library and existing F5/F6 types. Find graph components,
calculate the full-clique upper bound, sort by
`(cells, comparisons, tuple(members))`, greedily select whole components, copy
the candidate artifact, filter its existing `pairs`, add a
`component_budget_derivation` provenance object, and validate it with
`validate_candidate_artifact`.

- [ ] **Step 4: Verify GREEN and existing F5/F6 regressions**

Run:

```text
/usr/bin/python3.12 test_v1_component_budget.py
/usr/bin/python3.12 test_v1_retrieval.py
/usr/bin/python3.12 test_v1_grouping.py
```

- [ ] **Step 5: Commit**

Commit message: `feat: bound V1 work by whole candidate components`

### Task 2: Wire the cost-bounded mode into the analysis pipeline

**Files:**
- Modify: `analyze.py`
- Modify: `test_analyze.py`

**Interfaces:**
- Consumes: Task 1's derived artifact and report.
- Produces: `--component-budgeted-v1`; a recorded `candidates.consensus3-budgeted` artifact; normal strict F6/F7/F10 artifacts when the selected queue completes.

- [ ] **Step 1: Write failing pipeline tests**

Require the new option to leave direct/no-FLIRT grouping inputs identical,
record the derived queue and cost report, pass that queue to frozen F6, and
retain the old all-or-nothing behavior when the option is absent.

- [ ] **Step 2: Run and verify RED**

Run: `/usr/bin/python3.12 test_analyze.py`

Expected: parser rejection or missing budgeted artifact.

- [ ] **Step 3: Add the smallest wiring change**

Add one boolean CLI argument. After F5, derive and write the budgeted queue
only when requested, use it as the strict F6 queue, include it in the
label-blind manifest hashes, and report selected/deferred counts. Do not
change F6, F7, or F10 logic.

- [ ] **Step 4: Verify GREEN**

Run:

```text
/usr/bin/python3.12 test_analyze.py
/usr/bin/python3.12 test_label_propagation.py
/usr/bin/python3.12 test_oracle_firewall.py
```

- [ ] **Step 5: Commit**

Commit message: `feat: run component-budgeted V1 before FLIRT propagation`

### Task 3: Freeze zoxide predictions, score them, and record the result

**Files:**
- Create outside Git results: a new zoxide component-budgeted queue, strict family, F7 rescue, direct-label, and strict/rescue propagation artifacts.
- Create in vault: `00_Inbox/CallKin FLIRT Additional Experiment.md`

**Interfaces:**
- Consumes: the persistent zoxide CallKin-Real run, its consensus queues, the matching historical direct Oxidizer result, and the scoring-only all-Rust catalog.
- Produces: prediction artifact SHA-256 values before scoring, then exact direct/combined coverage and precision.

- [ ] **Step 1: Preflight without oracle**

Check the binary hash and every run-stage/candidate hash. Convert only
Oxidizer `direct-flirt` matches, using their linked `mapped_address`; never use
wrapper or cleanup results as seeds.

- [ ] **Step 2: Generate and hash predictions before scoring**

Derive the budgeted queue, run frozen F6, run F7, and create strict and rescue
F10 prediction artifacts. Confirm no selected F6 merge was budget-blocked and
that the label-blind hashes do not depend on labels.

- [ ] **Step 3: Open the oracle only in the evaluator**

Use the frozen exact catalog scorer. Report direct, propagated, and combined
correct/incorrect counts; precision; catalog coverage; eligible/conflict
families; and success-gate status. Do not change any rule after reading it.

- [ ] **Step 4: Write the temporary Inbox note**

Explain the question, frozen rule, exact inputs and hashes, cost selection,
measured results, allowed claim, disallowed claims, and limitations in short,
plain Korean.

- [ ] **Step 5: Run final verification**

Run all focused tests, `git diff --check`, verify the code worktree is clean,
and verify that every result hash quoted in the note matches the file on disk.

