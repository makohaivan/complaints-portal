#!/usr/bin/env python
r"""
Static analysis with Bandit.

    python security_tests/run_bandit.py --label before

Scans accounts/, complaints/ and config/ (not tests or migrations) and saves
docs/evidence/bandit_<label>.txt / .json / .html. Prints a summary.

Bandit needs PyYAML, which has no pre-built wheel for very new Python versions on
Windows. If 'pip install bandit' fails with "Microsoft Visual C++ 14.0 or greater
is required", create a SEPARATE venv with Python 3.12 or 3.13 just for Bandit:

    py -3.12 -m venv venv-bandit
    venv-bandit\Scripts\activate
    pip install bandit
    python security_tests/run_bandit.py --label before

Bandit only reads source files, so it does not need the app's packages.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--label", default="run")
args = ap.parse_args()

out = Path("docs/evidence")
out.mkdir(parents=True, exist_ok=True)

base = [sys.executable, "-m", "bandit", "-r", "accounts", "complaints", "config",
        "-x", "*/migrations/*,*/tests.py,*/test_phase*.py", "--exit-zero"]

probe = subprocess.run([sys.executable, "-m", "bandit", "--version"],
                       capture_output=True, text=True)
if probe.returncode != 0:
    sys.exit(__doc__)

subprocess.run(base + ["-f", "txt", "-o", str(out / f"bandit_{args.label}.txt")],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(base + ["-f", "html", "-o", str(out / f"bandit_{args.label}.html")],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(base + ["-f", "json", "-o", str(out / f"bandit_{args.label}.json")],
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

data = json.loads((out / f"bandit_{args.label}.json").read_text(encoding="utf-8"))
totals = data["metrics"]["_totals"]
print(f"\nBandit ({args.label}): scanned {int(totals['loc'])} lines of code")
print(f"  HIGH: {int(totals['SEVERITY.HIGH'])}   MEDIUM: {int(totals['SEVERITY.MEDIUM'])}   "
      f"LOW: {int(totals['SEVERITY.LOW'])}   (skipped by # nosec: {int(totals['nosec'])})")
for issue in data["results"]:
    print(f"\n  FINDING {issue['test_id']} [{issue['issue_severity']}/{issue['issue_confidence']}] "
          f"{issue['issue_text']}")
    print(f"      {issue['filename']}:{issue['line_number']}")
if not data["results"]:
    print("  No issues found.")
print(f"\nSaved: docs/evidence/bandit_{args.label}.txt / .html / .json")
