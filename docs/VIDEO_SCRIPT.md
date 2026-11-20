# Demonstration video script (target 6:30, limit 5-7 minutes)

The brief asks for: the application working, then you attacking your own application and the
defences stopping each attack. Rehearse once with a timer. Speak slowly; show, then explain.

## Before you press record

```bash
python manage.py axes_reset                  # clear any lockouts
python manage.py seed_demo                   # make sure the demo accounts exist
python manage.py runserver                   # RESTART it: clears the in-memory rate-limit counters
```

- Set `SCAN_MODE=False` (or remove it) in `.env`, and make sure `DEBUG=True` so the demo accounts work.
- Screen 1920x1080, browser zoom 125%, terminal font large (16-18 pt).
- Do **not** show `.env` or any secret on screen.
- Open these in advance: two browser windows (normal + private) so you can be student1 and student2
  at once; a terminal in the project folder; `logs/security.log` open in a text editor (or run
  `Get-Content logs\security.log -Wait` in PowerShell) so log lines appear live.
- Create two files for the upload attack: `shell.php` containing `<?php echo 1;` and `fake.png`
  (a text file renamed to .png).
- Use `curl.exe` (not `curl`) in PowerShell.

## Part 1: the application working (0:00 - 1:45)

| Time | Show | Say |
|------|------|-----|
| 0:00 | Title slide or the home page | "I'm Makoha Ivan. This is a secure Student Complaints Portal built with Django and Bootstrap. It has three roles: student, staff and administrator, and a rule that every student can only see their own complaints." |
| 0:25 | Log in as **student1**; show the list | "student1 sees two complaints." |
| 0:40 | New complaint: title, category, description, attach a PNG; submit | "A student submits a complaint with an evidence file." |
| 1:00 | Private window: log in as **admin1**, open the unassigned complaint, assign to staff1 | "The administrator assigns the case to a staff member." |
| 1:15 | Log in as **staff1** (log out first), open it, reply, update status | "Staff can only see cases assigned to them. They reply and move the status. Only legal next steps are offered." |
| 1:35 | Back to student1: reply and new status visible; download the PNG | "The student tracks progress and downloads the attachment." |

## Part 2: threat model, briefly (1:45 - 2:15)

Show the data-flow diagram from the report (or `docs/threat_model.md`) and scroll the STRIDE table.

Say: "Before coding I built a threat model: a data flow diagram with a trust boundary, and a STRIDE
analysis of 13 threats. Each one maps to a control in the code. Now I will attack the application
and show the defences."

## Part 3: attacking my own application (2:15 - 5:30)

| # | Time | Attack (what you do) | Expected result and what to say |
|---|------|----------------------|---------------------------------|
| A1 | 2:15 | **IDOR.** As student1 copy a complaint URL. In the private window, log in as student2 and paste it. | **404 page.** "Changing the ID gives a 404, so the application does not even reveal that it exists. The attempt is in the security log." Point at the `access_denied` line. |
| A2 | 2:45 | **Privilege escalation.** As student1 open `/admin/`. Then in DevTools Console paste (replace the UUID): `fetch('/complaints/UUID/assign/',{method:'POST',headers:{'X-CSRFToken':document.querySelector('[name=csrfmiddlewaretoken]').value},body:new URLSearchParams({staff:'1'})}).then(r=>console.log(r.status))` | `/admin/` redirects to the admin login. The fetch prints **403**. "Hiding a button is not security. The server checks the role on every request." |
| A3 | 3:15 | **SQL injection.** In the search box type `' OR 1=1--` and search. | Normal results only (your own). "Parameterised queries through the ORM, so the payload is just text." |
| A4 | 3:35 | **Stored XSS.** New complaint with title `<script>alert('XSS')</script>`. Open it. | The tag is shown as text, no popup. "Output is escaped, and the Content-Security-Policy forbids all scripts anyway." Show the CSP header in DevTools, Network tab. |
| A5 | 4:00 | **Malicious upload.** Upload `shell.php`, then `fake.png`. | Both rejected with messages. "Allow-list, then magic bytes. A disguised executable fails the content check. Real files get a random name and are only served through an authorised view." |
| A6 | 4:20 | **CSRF.** In a terminal (copy the `sessionid` value from DevTools, Application tab): `curl.exe -i -X POST http://127.0.0.1:8000/complaints/new/ -H "Cookie: sessionid=PASTE" -d "title=x&category=other&description=y"` | **HTTP 403**. "No CSRF token, no action." |
| A7 | 4:40 | **Brute force.** Log in as student2 with a wrong password 5 times. | **Lockout page.** "Locked after five failures. Even the right password is refused. Because I scoped the lockout to username plus IP, other users are not affected. I found that weakness myself in testing." Then run `python manage.py axes_reset`. |
| A8 | 5:05 | **All attacks at once.** `python security_tests/attack_tests.py --label demo` | Output ends with **45 passed, 0 failed**. "This script runs 47 attack checks as an outside user: IDOR, injection, CSRF, session fixation, open redirect, upload abuse, forced browsing." |

If something takes too long, cut A3 or A6 first. Never cut A1.

## Part 4: tools and results (5:30 - 6:15)

| Time | Show | Say |
|------|------|-----|
| 5:30 | `docs/evidence/bandit_before.txt` then `bandit_after.txt` | "Bandit found one low issue, a hard-coded demo password. I triaged it as an accepted risk with a written justification." |
| 5:45 | The ZAP report summary (before and after) | "ZAP's authenticated scan found [N] alerts. I fixed [..] and documented the rest as mitigated." (Fill in from your real report.) |
| 6:00 | `python manage.py test complaints.tests` (14 tests, fast) or the saved screenshot of all 66 | "66 automated tests guard against regressions." |

## Part 5: reflection and close (6:15 - 6:45)

Say: "Weaknesses that remain: no multi-factor authentication, uploads are not virus-scanned, it uses SQLite and an
in-memory cache, and I only tested on the development server over HTTP. With more time I would add MFA, ClamAV scanning,
PostgreSQL and Redis, and deploy behind TLS. Thank you."

## After recording

- Play it back at normal speed: is text readable? Is any secret visible?
- Keep it between 5:00 and 7:00. Export as MP4 and upload (YouTube unlisted or your university's system).
- Put the video link at the top of the README and in the report.
