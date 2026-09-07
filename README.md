# CallKin-Real

Research analyzer for grouping functions in stripped x86-64 Rust ELF and PE32+ binaries. Combines call relations and function bodies, with optional FLIRT name propagation.

## Quick start

Python 3.12+. Commands below are for Linux or WSL.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python analyze.py /path/to/stripped.bin --output-dir results/demo --no-flirt
```

## Tests

```bash
python run_tests.py
```

## Documentation

- [Usage and reproduction](docs/usage.md)
- [Research results](docs/results/README.md)
- [CallKin](https://github.com/xdfyrj/CallKin): controlled experiments and research baseline
- [MIT license](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md)
