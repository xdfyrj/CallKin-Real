"""Run each standalone regression suite in a fresh interpreter."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent


def main():
    failed = []
    tests = sorted(ROOT.glob("test_*.py"))
    if not tests:
        raise RuntimeError("no regression scripts found")
    for test in tests:
        print(f"\nCHECK {test.name}", flush=True)
        result = subprocess.run([sys.executable, str(test)], cwd=ROOT)
        if result.returncode:
            failed.append(test.name)
    print(f"\n{len(tests)} suites; failures: {failed}", flush=True)
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
