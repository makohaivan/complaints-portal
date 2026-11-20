# Submission checklist

## Deliverables (from the brief)

- [ ] **Repository link** (GitHub or GitLab) with a commit history showing work across the week
- [ ] **README** with install/run instructions and **test accounts for each role** (done in Phase 4)
- [ ] **Security report, 8-12 pages**: threat model, controls with code extracts, testing evidence,
      vulnerabilities found and fixed, reflection
- [ ] **Demo video, 5-7 minutes**: app working, then attacking it (see `docs/VIDEO_SCRIPT.md`)

## Report (Security_Report_DRAFT.docx)

1. Fill in: course/unit, lecturer, repository link on the first page.
2. Insert screenshots S1-S14 into the yellow boxes (list below). **Resize each to about half the page
   width** so the report stays within 12 pages (Word: click image > Picture Format > Height 5-6 cm).
3. Complete section 4.3 (ZAP table) and section 5 (row F-3...) from your real ZAP report. Delete the
   yellow "TO COMPLETE" box and any unused placeholder rows.
4. Replace the example log lines in 3.7 with an excerpt from YOUR `logs/security.log` if you prefer.
5. Check the page count (8-12). Then File > Export > PDF and submit the PDF (and keep the .docx).
6. Make sure every claim in the report is true of your repository: re-run the tests and the attack script
   if you changed anything.

## Screenshots to capture

| ID | What | How |
|----|------|-----|
| S1 | The working app | Student list + a complaint detail with attachment and staff reply |
| S2 | Security headers | Browser DevTools > Network > click the page > Headers (CSP etc.) |
| S3 | Security log | `logs/security.log` showing login_failed and access_denied lines |
| S4 | Audit log | `/admin/` as admin1 > Audit logs (no Add button) |
| S5 | Unit tests | `python manage.py test complaints` ending with `Ran 66 tests ... OK` |
| S6 | Bandit before | `python security_tests/run_bandit.py --label before` output (B105) |
| S7 | Bandit after | Same command with `--label after` (no issues) |
| S8 | Attack tests before | Last lines of the `--label before` run (44 passed, 1 failed, FINDING A07-11) |
| S9 | Attack tests after | Last lines of the `--label after` run (45 passed, 0 failed) |
| S10 | ZAP before | Alerts tab or the HTML report summary |
| S11 | ZAP after | Same after fixes |
| S12 | IDOR blocked | student2 opening student1's URL (404) + the log line |
| S13 | Upload rejected | Error messages for `shell.php` and `fake.png` |
| S14 | Lockout page | After 5 wrong passwords |

(If you ran the "before" attack test before applying fixes, you already have S6 and S8 evidence saved in
`docs/evidence/`. Screenshot the files.)

## Repository hygiene (run the automatic audit)

```bash
python security_tests/presubmit_check.py
python security_tests/presubmit_check.py --run-tests     # also runs the 66 tests (about 1 minute)
```

It checks, among other things, that `.env`, the database, uploads and logs are not committed, that your real
SECRET_KEY never appears in the repository or its history, that the README lists all test accounts, that the
evidence files exist, and how many days your commit history spans.

## Last checks

- [ ] `.env` is NOT in the repo, `.env.example` is
- [ ] `SCAN_MODE` is off in `.env`
- [ ] README has the demo accounts and the video link
- [ ] Commit messages are meaningful (`git log --oneline`)
- [ ] The repository is accessible to the marker (public, or invite them)
- [ ] Fresh-clone test: clone into a new folder, create the venv, `pip install -r requirements.txt`,
      create `.env`, `migrate`, `seed_demo`, `runserver`. If that works for you, it will work for the marker.
