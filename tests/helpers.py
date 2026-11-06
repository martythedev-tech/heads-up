"""Shared by the tests: a throwaway state directory, and a tiny test runner."""
import os
import sys
import tempfile
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
os.environ["STATE_DIRECTORY"] = tempfile.mkdtemp(prefix="heads-up-test-")
os.environ.pop("CREDENTIALS_DIRECTORY", None)
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))


def run_tests(namespace):
    """Run every test_ function in a module's globals; exit non-zero if any fail."""
    failed = 0
    tests = [(n, f) for n, f in namespace.items() if n.startswith("test_") and callable(f)]
    for name, fn in tests:
        try:
            fn()
            print(f"  ok    {name}")
        except Exception:
            failed += 1
            print(f"  FAIL  {name}")
            traceback.print_exc(limit=-2, file=sys.stdout)
    print(f"{len(tests) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
