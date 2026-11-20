#!/usr/bin/env python
"""
Pre-submission audit of the repository.

    python security_tests/presubmit_check.py
    python security_tests/presubmit_check.py --run-tests     # also run the unit tests

Prints PASS / WARN / FAIL for each check. Exit code 1 if anything FAILS.
It never prints the contents of your .env.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
RESULTS = []


def record(status, name, detail=""):
    RESULTS.append((status, name, detail))
    colour = {"PASS": "\033[92m", "WARN": "\033[93m", "FAIL": "\033[91m", "INFO": "\033[96m"}[status]
    print(f"  {colour}{status}\033[0m  {name}" + (f"\n        {detail}" if detail else ""))


def git(*args):
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


def read(path):
    p = ROOT / path
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


print("\nPre-submission audit\n")

# ---------------------------------------------------------------- git state
code, _ = git("rev-parse", "--is-inside-work-tree")
if code != 0:
    record("FAIL", "This folder is a git repository", "Run: git init, then commit your work")
    tracked = []
else:
    _, files = git("ls-files")
    tracked = files.splitlines()
    record("PASS", "This folder is a git repository")

    _, count = git("rev-list", "--count", "HEAD")
    n = int(count or 0)
    record("PASS" if n >= 8 else "WARN", f"Commit count: {n}",
           "" if n >= 8 else "Aim for at least one commit per phase (8+), with meaningful messages")
    _, dates = git("log", "--format=%ad", "--date=short")
    days = sorted(set(dates.splitlines()))
    record("PASS" if len(days) >= 3 else "WARN",
           f"Commit history spans {len(days)} distinct day(s): {', '.join(days[:6])}",
           "" if len(days) >= 3 else "The brief asks for history that shows work through the week")
    _, remote = git("remote", "-v")
    record("PASS" if remote else "WARN", "A remote (GitHub/GitLab) is configured",
           "" if remote else "git remote add origin <url>; git push -u origin main")
    _, status = git("status", "--porcelain")
    record("PASS" if not status else "WARN", "Working tree is clean (everything committed)",
           "" if not status else f"{len(status.splitlines())} uncommitted change(s): git status")

# ----------------------------------------------------- things that must NOT be tracked
for pattern, label in ((r"(^|/)\.env$", ".env"), (r"(^|/)db\.sqlite3$", "db.sqlite3"),
                       (r"^media/", "media/ (uploads)"), (r"^logs/", "logs/"),
                       (r"(^|/)venv[^/]*/|pyvenv\.cfg|site-packages/", "virtual environment"), (r"__pycache__", "__pycache__")):
    bad = [f for f in tracked if re.search(pattern, f)]
    record("FAIL" if bad else "PASS", f"{label} is not committed",
           f"Tracked: {bad[:3]}. Fix: git rm -r --cached <path> and add to .gitignore" if bad else "")

big = [f for f in tracked if (ROOT / f).exists() and (ROOT / f).stat().st_size > 5_000_000]
record("WARN" if big else "PASS", "No very large files tracked (> 5 MB)", str(big[:3]) if big else "")

# ------------------------------------------------------------- secret in repo/history
env = read(".env")
m = re.search(r"^SECRET_KEY=(.+)$", env, re.M)
if m and code == 0:
    key = m.group(1).strip()
    hit_now = subprocess.run(["git", "grep", "-qF", "--", key], cwd=ROOT).returncode == 0
    _, hist = git("log", "-S" + key, "--oneline")
    if hit_now or hist:
        record("FAIL", "Your real SECRET_KEY is not in the repository or its history",
               "It IS present. Generate a new key, put it only in .env, and remove the old one "
               "from history (git filter-repo) or recreate the repository.")
    else:
        record("PASS", "Your real SECRET_KEY is not in the repository or its history")
else:
    record("INFO", "SECRET_KEY check skipped", "No .env with SECRET_KEY found (or not a git repo)")
if "SCAN_MODE=True" in env.replace(" ", ""):
    record("WARN", "SCAN_MODE is switched on in .env", "Set SCAN_MODE=False after the ZAP scan")
else:
    record("PASS", "SCAN_MODE is off")

# ------------------------------------------------------------------ files and docs
req = read("requirements.txt")
record("PASS" if "Django==" in req else "FAIL", "requirements.txt pins Django")
record("PASS" if (ROOT / ".env.example").exists() else "FAIL", ".env.example is present")

readme = read("README.md")
missing = [u for u in ("student1", "student2", "staff1", "staff2", "admin1") if u not in readme]
record("PASS" if readme and not missing else "FAIL", "README.md lists test accounts for every role",
       f"Missing: {missing}" if missing else "")
for heading in ("Installation", "Test accounts"):
    record("PASS" if heading.lower() in readme.lower() else "FAIL", f"README has a '{heading}' section")
record("PASS" if re.search(r"https?://\S*(youtu|vimeo|drive\.google|loom|onedrive|sharepoint)", readme, re.I)
       else "WARN", "README links to the demo video", "Add the video link near the top of the README")

evidence = {
    "docs/evidence/bandit_before.txt": "Bandit before", "docs/evidence/bandit_after.txt": "Bandit after",
    "docs/evidence/attack_results_before.md": "Attack tests before",
    "docs/evidence/attack_results_after.md": "Attack tests after",
}
for path, label in evidence.items():
    record("PASS" if (ROOT / path).exists() else "WARN", f"Evidence: {label}",
           "" if (ROOT / path).exists() else f"Missing {path}")
zap = list((ROOT / "docs/evidence").glob("zap*")) if (ROOT / "docs/evidence").exists() else []
record("PASS" if zap else "WARN", "Evidence: ZAP report(s) saved in docs/evidence/",
       "" if zap else "Run ZAP (docs/ZAP_GUIDE.md) and save the HTML report")
record("PASS" if (ROOT / "docs/threat_model.md").exists() else "WARN", "docs/threat_model.md exists")
dfd_ok = (ROOT / "docs/threat_model/dfd.png").exists()
record("PASS" if dfd_ok else "WARN", "docs/threat_model/dfd.png exists (diagram image)",
       "" if dfd_ok else "Copy dfd.png to docs/threat_model/dfd.png")
reports = [p for p in list(ROOT.glob("*.docx")) + list(ROOT.glob("*.pdf")) + list((ROOT / "docs").glob("*.docx"))
           + list((ROOT / "docs").glob("*.pdf")) if "report" in p.name.lower()]
record("INFO", "Report file found in the repo" if reports else
       "No report file in the repo (it is submitted separately, optional to commit)")

# ------------------------------------------------------------------ django checks
env2 = dict(os.environ, DEBUG="False")
r = subprocess.run([sys.executable, "manage.py", "check", "--deploy"], cwd=ROOT, env=env2,
                   capture_output=True, text=True)
out = r.stdout + r.stderr
issues = re.findall(r"\(security\.(W\d+|E\d+)\)", out)
record("PASS" if r.returncode == 0 and len(issues) <= 1 else "WARN",
       f"manage.py check --deploy: {len(issues)} warning(s) {issues}",
       "One warning (HSTS preload, W021) is expected and deliberate" if issues else "")

if "--run-tests" in sys.argv:
    print("\n  Running the unit tests (about a minute)...")
    t = subprocess.run([sys.executable, "manage.py", "test", "complaints"], cwd=ROOT,
                       capture_output=True, text=True)
    last = (t.stderr or t.stdout).strip().splitlines()[-3:]
    record("PASS" if t.returncode == 0 else "FAIL", "Unit tests pass", " | ".join(last))
else:
    record("INFO", "Unit tests not run", "Add --run-tests to include them")

# ------------------------------------------------------------------------ summary
counts = {s: sum(1 for r in RESULTS if r[0] == s) for s in ("PASS", "WARN", "FAIL", "INFO")}
print(f"\n{counts['PASS']} passed, {counts['WARN']} warnings, {counts['FAIL']} failed\n")
sys.exit(1 if counts["FAIL"] else 0)
