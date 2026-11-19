# OWASP ZAP guide (authenticated scan)

The portal requires login, so an unauthenticated scan only sees the login and register
pages. For real coverage, scan **as a logged-in user**.

## 0. Prepare the app (development machine only)

1. In `.env` add:
   ```
   SCAN_MODE=True
   ```
   `SCAN_MODE` switches OFF account lockout and rate limiting so the scanner is not
   blocked after a few requests. It is only honoured when `DEBUG=True`, so it can never
   weaken a production deployment. **Set it back to False when the scan is finished.**
2. Reset and seed: `python manage.py seed_demo`
3. Start the server: `python manage.py runserver`
4. Close any browser sessions you are using. Back up `db.sqlite3` if you care about the
   data: the active scan will create lots of junk complaints.

## 1. Install and start ZAP

Install the ZAP desktop app from https://www.zaproxy.org/download/ and choose
"No, I do not want to persist this session" on first start.

## 2. Quick unauthenticated pass (optional)

*Quick Start -> Automated Scan* -> URL `http://127.0.0.1:8000` -> **Attack**.
Note anything reported against the login page.

## 3. Authenticated scan

1. **Explore the app once manually through ZAP's browser** (Quick Start -> Manual Explore ->
   Launch Browser): log in as `student1`, open the list, a complaint, the new-complaint form,
   upload a PNG. This teaches ZAP the URLs.
2. In the *Sites* tree right-click `http://127.0.0.1:8000` -> **Include in Context ->
   New Context** (name it `portal`).
3. Double-click the context -> **Authentication** -> Method: *Form-based Authentication*.
   - Login Form Target URL: `http://127.0.0.1:8000/accounts/login/`
   - Username Parameter: `username`   Password Parameter: `password`
   - Logged-in indicator regex: `Log out`
   - Logged-out indicator regex: `Log in`
4. **Users** -> Add -> name `student1`, username `student1`, password `Complaints#2026!`.
5. **Session Management** -> keep *Cookie-based*.
6. **Forced User** mode: select the context's user `student1` and click the
   "Forced User Mode" toolbar button, so every request is authenticated.
7. Right-click the site -> **Attack -> Spider** (choose the user), then
   **Attack -> Active Scan** (choose the user and the context).
8. Repeat the active scan once as `admin1` and once as `staff1` if time allows
   (different roles reach different pages).
9. **Report -> Generate Report** -> HTML. Save into `docs/evidence/` as
   `zap_report_before.html`. Screenshot the **Alerts** tab for the security report.

## 4. Triage the alerts

For every alert, decide and write down one of:

| Verdict | Meaning | Example |
|---|---|---|
| **Fixed** | Real issue, you changed the code | e.g. missing header |
| **Accepted / mitigated** | Real but low risk or handled elsewhere | e.g. "Server leaks version" (development server) |
| **False positive** | ZAP is wrong, explain why | e.g. a pattern that is not exploitable |

Typical alerts to expect and how to treat them:

- *Cookie without Secure flag*: only on plain HTTP in DEBUG; the flag is set when `DEBUG=False`.
- *Server leaks version information*: Django development server banner; hidden by the production web server.
- *Cross-Origin-Embedder-Policy missing* / *Spectre isolation*: low-risk header; decide whether to add `Cross-Origin-Embedder-Policy`.
- *CSP: style-src 'unsafe-inline'*: appears only under `/admin/` (documented trade-off).
- *Absence of Anti-CSRF tokens*: check it is a GET form (search) and not a state-changing one.

Fix what is worth fixing, re-run the scan, and save `zap_report_after.html`.

## 5. Finish

Set `SCAN_MODE=False` (or delete it) in `.env`.
