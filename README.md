# CallKin-Real

Research prototype for grouping functions in stripped, optimized x86-64 Rust
ELF and PE32+ binaries using call relations and body comparisons. Optional
FLIRT names are attached after grouping.

The analyzer never reads a non-stripped binary, source code, ground truth, a
symbol list, a candidate list, or a symbol-boundary file. That is enforced by a
test rather than by convention: `test_oracle_firewall.py` walks the import
graph from every analysis entry point and fails if a ground-truth module, a
catalog or a scorer appears anywhere in it, and `test_analyze.py` runs the
whole pipeline in a subprocess where opening any ground-truth path raises.

## Installation

Use Python 3.12 or later for the analyzer and regression tests.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python run_tests.py
```

The package requirements pin the angr version and its compatible parser.
Oxidizer is a separate optional installation, described below; use
`--no-flirt` when testing anonymous grouping alone. The historical relaxed
replay retains its stricter CPython 3.14.7 requirement.

## One command

```bash
python analyze.py /path/to/stripped.bin --case zoxide --output-dir results/zoxide
```

This runs every stage and writes `run.manifest.json` beside the artifacts. To
check the label-blindness invariant directly, which runs the analysis twice:

```bash
python analyze.py /path/to/stripped.bin --case zoxide \
  --output-dir results/zoxide --verify-label-blind
```

Scoring is a separate command, and the only one that reads ground truth:

```bash
python evaluate.py \
  --run-manifest results/zoxide/run.json \
  --ground-truth /path/to/gt.json \
  --linkage-audit /path/to/linkage-audit.json \
  --output results/zoxide/evaluation.json
```

`analyze` has no ground-truth, catalog or linkage argument, and `evaluate`
never writes to what it scores. When `--linkage-audit` is supplied, the file
must be the `v1-gt-mangled-audit` artifact with an `addresses` overlay and a
matching `provenance.ground_truth_sha256`; old pair-only files are rejected.
Neutral pairs are derived only when both addresses are in the run's
`grouping_role=member` universe. Both boundaries are checked.

## Stages and artifacts

| stage | artifact | what it decides |
| --- | --- | --- |
| discovery | `run.discovery.json` | function extents and call transfers |
| body | `run.body.json` | decoded instructions, CFG, decode quality |
| universe | `run.universe.json` | analysis status and grouping role per function |
| relation | `run.relation.json` | the label-blind V0 1-WL partition and its round history |
| F5 | `run.v1.{multi,consensus3,consensus2}.k16.candidates.json` | retrieval, three independent views |
| F6 | `run.v1.families.strict.json` | strict families under the frozen formal policy |
| F7 | `run.v1.families.rescue.json` | fragment rescue over the strict partition |
| relaxed | `run.v1.families.relaxed.json` | provisional attachments, evaluation-only |
| labels | `run.labels.direct.json`, `run.v1.labels.strict.json` | direct FLIRT and F10 propagation |

Each stage artifact records the binary hash, the hash of the artifact it was
built from, and nothing else that would make two runs differ. The absolute
path, the toolchain fingerprint and the timings live in the run manifest, so
the same grouping produces byte-identical stage files on Windows and Linux.

A stage that cannot run is recorded with a reason rather than leaving a missing
file. `f6.strict` may be `budget-refused`, `labels.direct` may be
`unavailable`, `f7.rescue` is `skipped` when F6 accepted nothing. A missing
file with nothing beside it is the one outcome indistinguishable from a bug.

Use `--component-budgeted-v1` to select complete candidate components within
the fixed comparison budget. This can defer a whole expensive component; it
does not claim to process every candidate faster.

`run.manifest.json` is the pipeline summary. The lower-level `run.json` is the
input used by `evaluate.py` and the standalone relaxed command.

## Three separated statuses

The rule that decides membership reads how much of a function was recovered,
never what it is called.

```text
analysis_status   complete | incomplete | address-only | external
grouping_role     member | context-only | abstain
label_status      direct | propagated | unknown
```

An internal function whose body decoded completely is a member whatever its
owner, and whatever FLIRT calls it. Earlier versions excluded `core`, `alloc`,
`std` and `__rustc` from grouping, which removed from the universe exactly the
functions FLIRT can identify; on zoxide that left F10 with no seed inside any
family. Labels are attached only after grouping is finished, and the four
label-blind stage hashes are identical with and without FLIRT.

## Frozen V1 code

`frozen_v1/` holds byte-identical copies of the V1 modules the formal results
were produced with, at `v0-engine-py-f10@0abd091`. A test compares all 21
against the frozen checkout on every run, and the frozen F4 golden -- 556 pairs
by 13 metrics and 4 quality fields, stored as `float.hex()` -- must reproduce
exactly.

Five files there are stubs, each replacing a module the frozen code imports at
module scope but that CallKin-Real must never call: the V0 engine, the fixture
loader, the Oxidizer adapter, and two that keep one pure function each. Calling
through the first three raises. Shipping the real modules would leave the
oracle path merely unused rather than unavailable.

Ground-truth normalization is the one thing reproduced rather than imported.
`rust_symbol_parser.py` carries `normalize_all_rust_origin` and
`rust_symbol_owner` verbatim, because importing `gt_extractor` would put an
oracle in the analysis process even unused; a test compares the two
implementations directly.

## Cost

Runtime is dominated by F5 retrieval and F6 comparison, and scales with the
number of complete bodies rather than with file size.

```text
cpp/complex.exe          66 KB     105 members       9 s
family_graph_01 (ELF)   350 KB   1,067 members   3h 14m
```

F6 prices the whole candidate queue before comparing anything and refuses it
outright if it exceeds `max_alignment_cell_budget`, because candidates are
stored in function-id order and spending the budget while walking them would
analyse an arbitrary prefix of the binary. Whether a queue fits depends on the
binary, not on its size:

```text
family_graph_01   919 consensus3 pairs     341,883,402 cells   fits
family_axis_04    983 consensus3 pairs   5,044,639,461 cells   refused
```

The difference is a few very large functions. On `family_axis_04` the median
pair costs 49 cells and the largest costs 168 million; the top 50 of 983 pairs
account for 78% of the total. The refusal records that distribution, because a
ceiling exceeded by one enormous pair is a different problem from one exceeded
by a long tail.

## Oxidizer

FLIRT runs in its own Python environment; CallKin-Real receives JSON and never
imports Oxidizer's angr fork. It is expected at
`/mnt/c/Users/sumyr/playground/oxidizer` on WSL or
`C:/Users/sumyr/playground/oxidizer` on Windows, and `--oxidizer-dir`
overrides it. Prepare its environment once:

```bash
uv sync --frozen --no-default-groups
```

Oxidizer's four result stages are kept apart, and only one may seed
propagation:

```text
matches               direct-flirt, usable as a seed
propagated_wrappers   recorded, never a seed
cleanup_heuristics    recorded, never a seed
unmatched_addresses   results that did not join the discovery universe
```

The wrappers and heuristics are Oxidizer's own inferences about the binary.
Seeding from one would let F10 propagate an inference from an inference and
report the result as a direct observation.

## What this does not claim

Function boundaries are discovered evidence, not truth. Multiple-target and
unresolved indirect calls stay in the artifact and never become exact edges. A
target address outside the discovered boundary set becomes an address-only
`opaque` anchor and is never presented as an identified function. A function
with no resolved non-self relation abstains from the V0 baseline while
remaining a member of the V1 universe, because V0 has nothing to compare and
V1 has its body.

The analyzer emits no precision, recall or F1: those need an oracle, and
`evaluate.py` is where they are computed. Boundary recovery is scored on its
own there and is never folded into the grouping score, because one number
cannot say whether a tool missed functions or mis-grouped the ones it found.

Two things are open and are not resolved by this code. F6's frozen budget
refuses some real binaries, and which threshold to move, if any, is a research
decision. And F7's accept path has not yet been reached on real CallKin-Real
data -- on the binaries tried so far F6 either accepted nothing or was
budget-refused -- so it is covered only by the frozen control suite.

## Running the tests

```bash
python run_tests.py
```

Each root-level regression script runs in a separate Python process. Frozen V1
code and the 556-pair floating-point golden are checked against bundled reference
identities. A default checkout does not require an adjacent development worktree.

The real-binary checks are optional and explicit:

```bash
CALLKIN_REAL_TEST_BINARY=/path/to/stripped.bin python run_tests.py
```

For the full archived replay-input integrity check, supply the original data
roots documented below and set `CALLKIN_CHECK_REPLAY_INPUTS=1`. Missing inputs or
hash drift then fail the check. Without those large original caches, the unit
tests still exercise the pin rejection and prediction-before-scoring boundaries.

## Experimental relaxed V1

The `analyze.py` pipeline retains its original strict-decision provisional pass.
The enhanced consensus2/F7 relaxed path is a separate command after analysis:

```bash
python v1_relaxed.py results/zoxide/run.json \
  --rescue results/zoxide/run.v1.families.rescue.json
```

This writes strict-core and, when F7 input is present, F7-core provisional
attachment artifacts. They do not replace strict families and are not used as
FLIRT seeds. The evaluator accepts these distinct methods on the same universe.

The pinned three-program research replay uses external data roots:

```bash
export CALLKIN_V1_INPUT_ROOT=/path/to/original-v1-data
export CALLKIN_FROZEN_INPUT_ROOT=/path/to/original-frozen-data
export CALLKIN_V0_INPUT_ROOT=/path/to/original-v0-data
CALLKIN_CHECK_REPLAY_INPUTS=1 python test_replay_relaxed.py
python replay_relaxed.py --mode dry-price
```

Prediction and scoring modes of that archived replay require CPython 3.14.7.
The input files must match the digests in `replay_relaxed.py`; selecting a
different directory does not relax those checks. Full original body caches are
not bundled with the repository.

## Research outputs

[Retained zoxide results](docs/results/README.md) record the original run and
its hashes: 339 directly correct names became 341 with propagation, with 9
existing incorrect names unchanged. This is one limited positive execution,
not general 100% propagation accuracy. The independent dust attempt did not
reach prediction before running out of memory.

[CallKin](https://github.com/xdfyrj/CallKin) contains the corresponding research
baseline, controlled counterexamples and broader evaluation records.
See [third-party notices](THIRD_PARTY_NOTICES.md) for derived fixture licenses.
