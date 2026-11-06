#!/usr/bin/env python3
"""Run all the offline tests, each file in its own process."""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
failed = []
for test in sorted(HERE.glob("test_*.py")):
    print(f"\n{test.name}", flush=True)
    if subprocess.run([sys.executable, str(test)]).returncode:
        failed.append(test.name)
print("\nAll passed." if not failed else f"\nFAILED: {', '.join(failed)}")
sys.exit(1 if failed else 0)
