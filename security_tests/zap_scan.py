#!/usr/bin/env python
"""
OWASP ZAP helper (needs Docker). For the full authenticated scan, follow
docs/ZAP_GUIDE.md instead - this script runs the quick, unauthenticated BASELINE scan.

    1. In .env:  SCAN_MODE=True   and add  host.docker.internal  to ALLOWED_HOSTS
    2. python manage.py runserver 0.0.0.0:8000
    3. python security_tests/zap_scan.py --label before
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--label", default="run")
ap.add_argument("--target", default="http://host.docker.internal:8000")
args = ap.parse_args()

if not shutil.which("docker"):
    sys.exit("Docker was not found. Use the ZAP desktop app instead - see docs/ZAP_GUIDE.md")

out = Path("docs/evidence").resolve()
out.mkdir(parents=True, exist_ok=True)
report = f"zap_baseline_{args.label}.html"

cmd = ["docker", "run", "--rm", "-v", f"{out}:/zap/wrk/:rw", "-t",
       "ghcr.io/zaproxy/zaproxy:stable", "zap-baseline.py",
       "-t", args.target, "-r", report, "-J", f"zap_baseline_{args.label}.json", "-I"]
print(" ".join(cmd), "\n")
sys.exit(subprocess.run(cmd).returncode)
