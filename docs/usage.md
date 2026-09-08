# Usage and reproduction

## Analysis

The quick start runs anonymous grouping with `--no-flirt`. Additional options:

- `--component-budgeted-v1`: process whole candidate components within the comparison budget; expensive components can be deferred.
- `--lazy-nonmatch`: opt into exact non-match certificates from normalized mnemonic counts before F4 alignment. The run manifest and family metrics record the changed `lazy-nonmatch` accounting mode; the default remains the historical eager path.
- `--verify-label-blind`: compare the grouping artifacts from runs with and without FLIRT.

`run.manifest.json` summarizes the pipeline. `run.json` is the lower-level manifest used by the evaluator and relaxed command.

Lazy certificates preserve per-pair decisions. They preserve the final
partition when neither run is limited by a comparison budget; under finite
budgets, saved work can change which complete-link merges fit. A certified
pair stores its exact cheap metric and a proof marker; F4-only fields remain
`null` because they were not computed.
The vendored F6 engine adaptation is pinned in
`frozen_reference_manifest.json`.

## Optional FLIRT labels

Install Oxidizer in a separate environment. From its checkout, run:

```bash
uv sync --frozen --no-default-groups
```

The default location is a sibling `oxidizer/` directory. To use another location:

```bash
export CALLKIN_OXIDIZER_DIR=/path/to/oxidizer
python analyze.py /path/to/stripped.bin --output-dir results/demo
```

Names are attached after grouping. Only direct FLIRT evidence seeds propagation.

## Evaluation

Ground truth is read only by the separate evaluator:

```bash
python evaluate.py --run-manifest results/demo/run.json \
  --ground-truth /path/to/gt.json \
  --linkage-audit /path/to/linkage-audit.json \
  --output results/demo/evaluation.json
```

The linkage audit must contain the address overlay and matching provenance. Discovery quality and grouping quality are reported separately.

## Relaxed attachments

The analyzer retains its strict-decision provisional pass. The enhanced consensus2/F7 path runs separately:

```bash
python v1_relaxed.py results/demo/run.json \
  --rescue results/demo/run.v1.families.rescue.json
```

Provisional attachments are evaluation-only; they do not replace strict families or become FLIRT seeds.

## Archived replay

The three-program replay requires the original input caches. Configure their locations:

```bash
export CALLKIN_V1_INPUT_ROOT=/path/to/original-v1-data
export CALLKIN_FROZEN_INPUT_ROOT=/path/to/original-frozen-data
export CALLKIN_V0_INPUT_ROOT=/path/to/original-v0-data
CALLKIN_CHECK_REPLAY_INPUTS=1 python test_replay_relaxed.py
python replay_relaxed.py --mode dry-price
```

Prediction and scoring modes require CPython 3.14.7. Input digests remain pinned regardless of directory location.

## Test coverage

`python run_tests.py` runs the standalone suites, including the bundled frozen-code identities and 556-pair golden fixture. Large external replay inputs are checked only when requested; missing files or digest drift then fail.

To enable the additional real-binary checks:

```bash
CALLKIN_REAL_TEST_BINARY=/path/to/stripped.bin python run_tests.py
```

See [retained results](results/README.md) for measured effects and their scope. Original body caches and the Oxidizer installation are not bundled.
