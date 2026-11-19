# Secure Student Complaints Portal

A web application where students submit and track complaints, staff respond to the
cases assigned to them, and administrators assign cases. Built with **Django** and
**Bootstrap 5** as a security-focused project: it was designed around a STRIDE threat
model and implements defences against the OWASP Top 10.

**Roles:** Student, Staff, Administrator. Every request is authorised on the server, so a
student can see only their own complaints.

## Features

- Student self-registration, login, logout, password change
- Students submit complaints (with optional PDF/PNG/JPG attachment) and track status
- Administrators assign complaints to staff
- Staff reply to students and move complaints through a controlled status workflow
- Searchable, filterable, paginated complaint list
- Full audit trail of security-relevant actions

## Tech stack

Python 3, Django, Bootstrap 5 (self-hosted), SQLite, Argon2, django-axes, Pillow.

## Installation

```bash
git clone <your-repo-url>
cd <repo-folder>

python -m venv venv
venv\Scripts\activate            # Windows
# source venv/bin/activate       # macOS / Linux

pip install -r requirements.txt
```

Create a `.env` file in the project root (copy `.env.example`) and set a long random key:

```
SECRET_KEY=replace-with-a-long-random-string
DEBUG=True
ALLOWED_HOSTS=127.0.0.1,localhost
```

Generate a key with:
`python -c "import secrets; print(secrets.token_urlsafe(50))"`

Then:

```bash
python manage.py migrate
python manage.py seed_demo       # creates the demo accounts below (DEBUG only)
python manage.py runserver
```

Open http://127.0.0.1:8000

## Test accounts

Password for **all** demo accounts: `Complaints#2026!`

| Role          | Username   | What to try                                           |
|---------------|------------|-------------------------------------------------------|
| Student       | `student1` | Submit a complaint, upload a file, view your own only |
| Student       | `student2` | Try to open student1's complaint link (you get 404)   |
| Staff         | `staff1`   | Reply to and update the complaint assigned to you     |
| Staff         | `staff2`   | Sees only complaints assigned to staff2               |
| Administrator | `admin1`   | Assign complaints; read-only audit log in `/admin/`   |

These accounts are for demonstration only. `seed_demo` refuses to run when `DEBUG=False`.

## Running the tests

```bash
python manage.py test complaints -v 2
```

The automated tests cover authentication, role-based access control, IDOR, mass
assignment, SQL injection, XSS, CSRF, file-upload abuse, rate limiting, lockout,
open redirects, and security headers.

## Security controls

| Risk (OWASP Top 10)             | Control                                                                 |
|---------------------------------|-------------------------------------------------------------------------|
| A01 Broken Access Control       | Role mixins; all queries go through `visible_complaints()`; 404 on foreign IDs; UUID keys; POST-only actions |
| A02 Cryptographic Failures      | Argon2 password hashing; secure, HttpOnly, SameSite cookies; HSTS when `DEBUG=False` |
| A03 Injection                   | Django ORM only (parameterised SQL); output auto-escaping; strict CSP (`script-src 'none'`) |
| A04 Insecure Design             | STRIDE threat model; server-enforced status state machine; upload limits |
| A05 Security Misconfiguration   | Secrets in `.env`; `DEBUG` off by default; security headers; custom error pages |
| A06 Vulnerable Components       | Pinned `requirements.txt`; Bootstrap self-hosted (no CDN); Bandit scan |
| A07 Authentication Failures     | Password validators (min 10 chars); django-axes lockout; login/register rate limits; session expiry |
| A08 Integrity Failures          | Upload validation (allow-list, magic bytes, Pillow); no third-party scripts |
| A09 Logging and Monitoring      | `logs/security.log` plus an append-only `AuditLog` table; log-injection protection |
| A10 SSRF                        | The application makes no outbound requests from user input |

## Configuration (`.env`)

| Key             | Purpose                                                    |
|-----------------|------------------------------------------------------------|
| `SECRET_KEY`    | Django signing key (never commit)                          |
| `DEBUG`         | `True` for development only                                |
| `ALLOWED_HOSTS` | Comma-separated host names                                 |
| `ADMIN_URL`     | Path of the Django admin (default `admin/`)                |

## Project structure

```
config/         settings, URLs, security-headers middleware, rate limiter
accounts/       custom User (roles), registration, password change, login logging
complaints/     models, access control, views, forms, upload validators, audit log, tests
templates/      Bootstrap 5 templates
static/         self-hosted Bootstrap and app.css
```

## Security testing

| Tool | How to run | Evidence |
|------|-----------|----------|
| Unit and integration tests | `python manage.py test complaints -v 2` | console output |
| Static analysis (Bandit) | `python security_tests/run_bandit.py --label after` | `docs/evidence/bandit_*` |
| Dynamic scan (OWASP ZAP) | see `docs/ZAP_GUIDE.md` | `docs/evidence/zap_*` |
| Manual attack tests | `python security_tests/attack_tests.py --label after` (server running) | `docs/evidence/attack_results_*` |

The attack tests cover access control (IDOR, privilege escalation), SQL injection,
reflected and stored XSS, CSRF, mass assignment, session fixation, open redirects, file
upload abuse, forced browsing, and brute-force/lockout behaviour.

## Known limitations

See the security report for the full reflection. In short: no antivirus scanning of
uploads, no multi-factor authentication, SQLite and an in-process cache are used
(production would use PostgreSQL and Redis), and TLS termination is expected at a
reverse proxy.
