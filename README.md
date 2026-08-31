# CallKin-Real

Stripped-only anonymous call-graph grouping for x86-64 Rust ELF and PE32+
binaries.

The analyzer does not read a non-stripped binary, source code, ground truth,
symbol list, candidate list, or symbol-boundary file. It discovers functions
from the stripped binary, resolves exact call evidence, asks angr about
unresolved indirect calls, uses Oxidizer FLIRT to recognize `core`, `alloc`,
`std`, and `__rustc` functions, then runs CG-WL with the fixed `out-in` mode.

## One command

```bash
cd /mnt/c/Users/sumyr/playground/REV/CallKin-Real
python3 callkin_real.py /path/to/stripped.bin
```

The result is written to:

```text
results/<binary-name>.callkin-real.json
```

To choose the output path:

```bash
python3 callkin_real.py /path/to/stripped.bin --output results/sample.json
```

Oxidizer is expected at:

```text
/mnt/c/Users/sumyr/playground/oxidizer
```

Prepare its locked environment once before the first run:

```bash
cd /mnt/c/Users/sumyr/playground/oxidizer
uv sync --frozen --no-default-groups
```

Use `--oxidizer-dir` to override it. `--no-flirt` is only for dependency
diagnostics; normal analysis runs FLIRT.

## Output

The central field is anonymous predicted grouping:

```json
"predicted_clusters": {
  "C1": ["FUN_00123a40", "FUN_00123b10"],
  "C2": ["FUN_00124000"]
}
```

The JSON also records discovered function boundaries, exact and unresolved
transfers, angr singleton/multiple/unresolvable/not-seen counts, FLIRT labels,
abstentions, and CG-WL rounds. An address that is used by an exact transfer
but has no discovered function boundary is retained as an `opaque` anchor;
it is never presented as a fully identified function. It does not emit
PR/RE/F1/ARI because those require an external evaluation ground truth.

## Scope

The analyzer accepts x86-64 ELF and PE32+. Function boundaries are
discovered evidence, not truth. PE32+ analysis also reads the import address
table and `.pdata` runtime-function ranges. The graph uses direct calls,
direct tail-calls, format-specific relocation evidence, and angr CFGFast singleton
targets. Multiple-target and unresolved indirect calls remain in the JSON and
do not become fake exact edges. A target address that is exact but outside
the discovered boundary set becomes an address-only `opaque` anchor. Functions
with no resolved non-self relation are reported as `abstain` and receive no
WL color.

The candidate scope is deliberately simple: direct FLIRT matches owned by
`core`, `alloc`, `std`, or `__rustc`, plus imports, are context anchors; every
other discovered function is a possible candidate. No source-side input is
read.

The Oxidizer environment is intentionally separate from CallKin-Real's Python
environment. Its direct FLIRT output is only a library-context label.

## Experimental relaxed V1

After strict F6 has written `run.v1.families.strict.json` and F5 has written
the `consensus2` queue, build the relaxed artifacts with:

```bash
python v1_relaxed.py results/run.json
```

The command reads `run.v1.consensus2.k16.candidates.json`, complete bodies from
the run stages, and `frozen_v1/configs/v1.formal.json`. It writes
`run.v1.families.relaxed.json`; when `run.v1.families.rescue.json` is present it
also writes `run.v1.families.rescue-relaxed.json`. Use `--candidates`,
`--families`, `--rescue`, `--config`, `--output`, or `--rescue-output` to
override these paths.

This does not change a strict family. A singleton may attach provisionally to
one strict core when a consensus3 candidate pair is a body `match`, while
`unknown`, `abstain`, and missing comparisons do not veto it. A hard `reject`
does veto it, and a singleton compatible with two cores stays ambiguous.
Each attachment is scored separately, so two provisional members are never
made siblings by transitivity. Both output artifacts are evaluation-only and
cannot be used for FLIRT label propagation. The frozen formal config currently has no
`structure_reject_threshold`, so its strict artifacts may contain no hard
`reject` decisions; relaxed results must therefore be reported as exploratory,
not as a replacement for strict V1. `evaluate.py` loads both output files when
present and reports `v1_relaxed_provisional` and
`v1_strict_rescue_relaxed_provisional` separately with partition and provenance.
