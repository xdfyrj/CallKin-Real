# Cost-bounded V1 plus FLIRT overlay specification

## Goal

Run CallKin-Real V1 without using FLIRT labels as anchors or grouping evidence,
then copy a unanimous direct FLIRT identity to the other members of each final
V1 family. The zoxide experiment must finish inside the already frozen limits
of 10,000 detailed comparisons and 500,000,000 alignment cells.

## Frozen behavior

- Reuse the existing zoxide discovery, body, universe, relation, F5 consensus
  queues, and actual Oxidizer direct-FLIRT output for the same stripped binary.
- Do not change F5 scores, F6 thresholds, F7 rules, the opaque-jump policy, or
  the two formal budget limits.
- At the CallKin-Real/frozen-V1 adapter boundary, expose
  `opaque_indirect_jump_count` as the frozen comparator's
  `opaque_indirect_jumps`. This restores the already-declared opaque abstention
  rule without rewriting either stored body artifacts or frozen V1 code.
- FLIRT labels and scoring oracle data must not affect component selection,
  pair comparison, clustering, or rescue.
- Direct FLIRT matches remain ordinary V1 members when their bodies are
  complete. They are not anchors merely because FLIRT named them.
- Every actual `direct-flirt` result remains in the direct baseline, including
  an address outside CallKin-Real's discovered/grouping universe. Such a label
  is reported as outside the universe and cannot propagate; it is not silently
  dropped. Join and member IDs use Oxidizer's `address`; a supplied
  `mapped_address` is preserved only as source evidence. Oxidizer wrapper and
  cleanup inferences remain non-seed evidence.
- F10 is applied only after F6 and F7. One seed may label a family; multiple
  seeds must agree on both `canonical_origin` and `owner`. A conflict labels
  nobody, and a direct label is never overwritten.

## Cost-bounded queue

The input is the frozen F5 consensus3 candidate graph. Split it into connected
components without reading labels or oracle data. For each component, compute
an upper bound that prices every unordered pair of comparable, non-opaque
members:

- comparisons: `n * (n - 1) // 2`
- alignment cells: `sum(len_i * len_j for i < j)`

The cell total may be computed in linear time as
`((sum(lengths) ** 2) - sum(length ** 2)) // 2`.

Sort components by `(alignment_cells, comparisons, member_ids)` and greedily
select a whole component only when adding its upper bound stays within both
formal limits. Never select part of a component. Keep the original target
universe and original pair records, but keep pairs only from selected
components. Record the source candidate SHA-256, policy, selected/deferred
component and member counts, and upper-bound costs in provenance. The derived
artifact must pass the existing closed F5 schema validator.

Running frozen F6 on this derived queue must not encounter a budget-blocked
merge: every possible within-component comparison was reserved beforehand.
Members in deferred components remain unresolved; they are not silently called
negative results.

## Experiment and scoring

Generate and hash all predictions before opening the all-Rust catalog. Then
compare:

- A: direct FLIRT only.
- B: the same direct labels plus strict/F7 V1 family propagation.

Exact correctness requires both origin and owner to match. Success requires:

- at least one newly correct member;
- combined correct catalog coverage greater than direct-only coverage;
- zero wrongly propagated members and zero families containing a wrong
  propagated member;
- direct labels unchanged byte-for-byte.

If the gate fails, report the measured failure without changing the queue
policy. A positive result supports only a zoxide O3S case-specific claim.
