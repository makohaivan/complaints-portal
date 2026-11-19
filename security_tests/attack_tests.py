#!/usr/bin/env python
"""
Manual attack tests - run against a RUNNING copy of the portal.

    python manage.py seed_demo            (once)
    python manage.py runserver            (in another terminal; restart it before each run)
    python security_tests/attack_tests.py --label before

It acts as an attacker with a normal HTTP client (no Django internals) and tries
the classic web attacks. Every test prints PASS (defence worked) or FAIL (finding).
Results are saved to docs/evidence/attack_results_<label>.md and .json.

Uses only the standard library. Test data it creates is prefixed [ATTACK TEST].
The rate limiter counts uploads/complaints per hour, so restart runserver between runs
(counters live in server memory).
"""
import argparse
import http.cookiejar
import json
import re
import struct
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib
from datetime import datetime
from pathlib import Path


# ------------------------------------------------------------------ http client
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # we want to SEE redirects, not follow them


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body
        self.text = body.decode("utf-8", "replace")

    @property
    def location(self):
        return self.headers.get("Location", "")

    def set_cookies(self):
        return self.headers.get_all("Set-Cookie") or []


class Browser:
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            NoRedirect, urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers=headers or {})
        try:
            r = self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as e:
            r = e
        status = getattr(r, "status", None) or r.code
        return Resp(status, r.headers, r.read())

    def get(self, path, headers=None):
        return self.request("GET", path, headers=headers)

    def csrf_token(self):
        for page in ("/", "/accounts/login/"):
            m = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', self.get(page).text)
            if m:
                return m.group(1)
        return ""

    def post(self, path, data=None, token=True, headers=None):
        data = dict(data or {})
        if token:
            data["csrfmiddlewaretoken"] = self.csrf_token()
        h = dict(headers or {})
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return self.request("POST", path, urllib.parse.urlencode(data).encode(), h)

    def post_file(self, path, filename, content, ctype="application/octet-stream"):
        boundary = "----atk" + uuid.uuid4().hex
        body = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="csrfmiddlewaretoken"\r\n\r\n'
            f"{self.csrf_token()}\r\n"
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {ctype}\r\n\r\n"
        ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
        return self.request("POST", path, body,
                            {"Content-Type": f"multipart/form-data; boundary={boundary}"})

    def cookie(self, name):
        for c in self.jar:
            if c.name == name:
                return c.value
        return None

    def login(self, username, password):
        self.get("/accounts/login/")
        return self.post("/accounts/login/", {"username": username, "password": password})

    def alerts(self, html):
        return [re.sub(r"<[^>]+>", "", m).strip()
                for m in re.findall(r'<div class="alert alert-\w+">(.*?)</div>', html, re.S)]


def make_png():
    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
            + chunk(b"IEND", b""))


# ---------------------------------------------------------------------- results
class Results:
    def __init__(self):
        self.rows = []

    def check(self, tid, category, name, expected, passed, actual):
        status = "PASS" if passed else "FAIL"
        self.rows.append(dict(id=tid, category=category, name=name, expected=expected,
                              status=status, actual=actual))
        mark = "\033[92mPASS\033[0m" if passed else "\033[91mFAIL\033[0m"
        print(f"  [{mark}] {tid:7} {name}\n           expected: {expected}\n           actual:   {actual}")

    def info(self, tid, category, name, actual):
        self.rows.append(dict(id=tid, category=category, name=name, expected="(informational)",
                              status="INFO", actual=actual))
        print(f"  [INFO] {tid:7} {name}\n           {actual}")


def uuids_with_titles(html):
    return re.findall(r'href="/complaints/([0-9a-f-]{36})/">(.*?)</a>', html)


def reset_lockouts():
    if (Path.cwd() / "manage.py").exists():
        subprocess.run([sys.executable, "manage.py", "axes_reset"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--password", default="Complaints#2026!")
    ap.add_argument("--admin-url", default="/admin/")
    ap.add_argument("--label", default="run")
    args = ap.parse_args()
    base, pw, admin = args.base.rstrip("/"), args.password, args.admin_url
    R = Results()

    print(f"\nAttack tests against {base}  ({datetime.now():%Y-%m-%d %H:%M})\n")
    reset_lockouts()

    # --- sessions ---------------------------------------------------------------
    s1, s2, st1, st2, adm = (Browser(base) for _ in range(5))
    for b, u in ((s1, "student1"), (s2, "student2"), (st1, "staff1"), (st2, "staff2"), (adm, "admin1")):
        r = b.login(u, pw)
        if r.status != 302:
            sys.exit(f"Could not log in as {u} (HTTP {r.status}). Is the server running and "
                     f"seed_demo done? Lockout? Try: python manage.py axes_reset")

    s1_list = uuids_with_titles(s1.get("/").text)
    s2_list = uuids_with_titles(s2.get("/").text)
    marks = next((i for i, t in s1_list if "Wrong marks" in t), None)
    fees = next((i for i, t in s2_list if "Fees payment" in t), None)
    if not marks or not fees:
        sys.exit("Demo complaints not found. Run: python manage.py seed_demo")
    anon = Browser(base)

    # =============================================== A01 Broken Access Control
    print("A01 - Broken access control")
    r = anon.get("/")
    R.check("A01-1", "A01", "Anonymous user opens the complaint list",
            "302 redirect to login", r.status == 302 and "/accounts/login/" in r.location,
            f"HTTP {r.status} -> {r.location}")
    r = anon.get(f"/complaints/{marks}/")
    R.check("A01-2", "A01", "Anonymous user opens a complaint by its URL",
            "302 redirect to login", r.status == 302 and "/accounts/login/" in r.location,
            f"HTTP {r.status} -> {r.location}")
    r = s2.get(f"/complaints/{marks}/")
    R.check("A01-3", "A01", "IDOR: student2 opens student1's complaint",
            "404 (existence not revealed)", r.status == 404, f"HTTP {r.status}")
    r = s2.get(f"/complaints/{uuid.uuid4()}/")
    R.check("A01-4", "A01", "Guessing a random complaint UUID",
            "404", r.status == 404, f"HTTP {r.status}")
    r = s1.post(f"/complaints/{marks}/assign/", {"staff": "1"})
    R.check("A01-5", "A01", "Privilege escalation: student POSTs to the admin 'assign' action",
            "403", r.status == 403, f"HTTP {r.status}")
    r = s1.post(f"/complaints/{marks}/status/", {"status": "resolved"})
    R.check("A01-6", "A01", "Student tries to change a complaint's status",
            "403", r.status == 403, f"HTTP {r.status}")
    r = s1.post(f"/complaints/{marks}/respond/", {"message": "I answer myself"})
    R.check("A01-7", "A01", "Student posts a staff response",
            "403", r.status == 403, f"HTTP {r.status}")
    r = s1.get(admin)
    R.check("A01-8", "A01", "Student opens the Django admin site",
            "redirect to admin login, no admin content",
            r.status == 302 and "login" in r.location and "Site administration" not in r.text,
            f"HTTP {r.status} -> {r.location}")
    r = st2.get(f"/complaints/{marks}/")
    R.check("A01-9", "A01", "Staff member NOT assigned (staff2) opens the complaint",
            "404", r.status == 404, f"HTTP {r.status}")
    r = st2.post(f"/complaints/{marks}/respond/", {"message": "sneaky reply"})
    R.check("A01-10", "A01", "Unassigned staff posts a response",
            "404", r.status == 404, f"HTTP {r.status}")
    r = st1.get("/complaints/new/")
    R.check("A01-11", "A01", "Staff tries to submit a complaint",
            "403", r.status == 403, f"HTTP {r.status}")
    r = adm.get(f"/complaints/{marks}/assign/")
    R.check("A01-12", "A01", "HTTP method tampering: GET on a POST-only action",
            "405", r.status == 405, f"HTTP {r.status}")

    # ============================================================ A03 Injection
    print("\nA03 - Injection")
    sqli = ["' OR '1'='1", "' OR 1=1--", '" OR ""="', "'; DROP TABLE complaints_complaint;--",
            "' UNION SELECT username,password,1,1,1,1,1,1 FROM accounts_user--"]
    leaked, errors = [], []
    for payload in sqli:
        r = s2.get("/?q=" + urllib.parse.quote(payload))
        if r.status >= 500:
            errors.append(payload)
        if "Hostel water" in r.text or "Wrong marks" in r.text or "argon2$" in r.text:
            leaked.append(payload)
    R.check("A03-1", "A03", f"SQL injection in the search box ({len(sqli)} payloads)",
            "no errors, no other users' data", not leaked and not errors,
            f"leaked={leaked or 'none'}, server errors={errors or 'none'}")
    r = s2.get("/")
    R.check("A03-2", "A03", "Database still intact after the DROP TABLE payload",
            "student2 still sees own complaint", "Fees payment" in r.text, f"HTTP {r.status}")
    r = s2.get("/?status=" + urllib.parse.quote("' OR 1=1--"))
    R.check("A03-3", "A03", "SQL injection in the status filter",
            "200, payload ignored (allow-list)", r.status == 200 and "Hostel" not in r.text,
            f"HTTP {r.status}")
    payload = "<script>alert(1)</script>"
    r = s2.get("/?q=" + urllib.parse.quote(payload))
    R.check("A03-4", "A03", "Reflected XSS through the search box",
            "payload HTML-escaped", payload not in r.text and "&lt;script&gt;" in r.text,
            f"raw present={payload in r.text}, escaped present={'&lt;script&gt;' in r.text}")

    title = "<script>alert('xss1')</script>{{7*7}}"
    r = s1.post("/complaints/new/", {"title": title, "category": "other",
                                     "description": "<img src=x onerror=alert(1)>"})
    detail = s1.get(r.location).text if r.status == 302 else ""
    listing = s1.get("/").text
    R.check("A03-5", "A03", "Stored XSS and template injection in a complaint",
            "escaped everywhere; {{7*7}} not evaluated",
            "<script>alert" not in detail + listing and "<img src=x" not in detail
            and "{{7*7}}" in detail and "&lt;script&gt;" in detail,
            f"create HTTP {r.status}; script tag raw={'<script>alert' in detail + listing}; "
            f"img raw={'<img src=x' in detail}")

    # ==================================================================== CSRF
    print("\nCSRF")
    r = s1.post("/complaints/new/", {"title": "[ATTACK TEST] no token", "category": "other",
                                     "description": "x"}, token=False)
    R.check("CSRF-1", "A01", "State-changing POST without a CSRF token",
            "403", r.status == 403, f"HTTP {r.status}")
    r = s1.post("/complaints/new/", {"title": "[ATTACK TEST] bad token", "category": "other",
                                     "description": "x", "csrfmiddlewaretoken": "A" * 64},
                token=False)
    R.check("CSRF-2", "A01", "POST with a forged CSRF token",
            "403", r.status == 403, f"HTTP {r.status}")
    r = s1.get("/accounts/logout/")
    R.check("CSRF-3", "A01", "Logout via GET (forced-logout CSRF)",
            "405", r.status == 405, f"HTTP {r.status}")

    # ============================================ A07 Authentication failures
    print("\nA07 - Authentication and sessions")
    name = "atk_" + uuid.uuid4().hex[:6]
    new_pw = "Atk#Str0ng-Pass2026"
    atk = Browser(base)
    atk.get("/accounts/register/")
    r = atk.post("/accounts/register/", {
        "username": name, "email": f"{name}@example.com", "password1": new_pw,
        "password2": new_pw, "role": "admin", "is_superuser": "on", "is_staff": "on"})
    atk.login(name, new_pw)
    home = atk.get("/").text
    r_adm = atk.get(admin)
    R.check("A07-1", "A07", "Mass assignment: register with role=admin, is_superuser, is_staff",
            "account is a plain Student with no admin access",
            ">Student</span>" in home and "Administrator" not in home
            and r_adm.status == 302 and "login" in r_adm.location,
            f"badge Student={'>Student</span>' in home}; /admin/ -> HTTP {r_adm.status}")
    weak = Browser(base)
    weak.get("/accounts/register/")
    r = weak.post("/accounts/register/", {"username": "atk_" + uuid.uuid4().hex[:6],
                  "email": "w@example.com", "password1": "password123", "password2": "password123"})
    R.check("A07-2", "A07", "Register with a weak, common password",
            "rejected (form shown again, no redirect)", r.status == 200,
            f"HTTP {r.status}")

    fixed = "attackerchosensession" + "a" * 11
    fx = Browser(base)
    fx.get("/accounts/login/")
    csrf_cookie = fx.cookie("csrftoken")
    r = fx.request("POST", "/accounts/login/", urllib.parse.urlencode({
        "username": "student1", "password": pw,
        "csrfmiddlewaretoken": fx.csrf_token()}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded",
         "Cookie": f"csrftoken={csrf_cookie}; sessionid={fixed}"})
    new_sid = next((re.search(r"sessionid=([^;]+)", c).group(1) for c in r.set_cookies()
                    if c.startswith("sessionid=")), None)
    victim = Browser(base)
    r2 = victim.get("/", {"Cookie": f"sessionid={fixed}"})
    R.check("A07-3", "A07", "Session fixation: log in while carrying an attacker-chosen session ID",
            "server issues a NEW session ID; the fixed one is useless",
            new_sid is not None and new_sid != fixed and r2.status == 302,
            f"new sessionid issued={bool(new_sid) and new_sid != fixed}; fixed ID -> HTTP {r2.status}")

    old_sid = s2.cookie("sessionid")
    tmp = Browser(base)
    tmp.login("student2", pw)
    old = tmp.cookie("sessionid")
    tmp.post("/accounts/logout/")
    replay = Browser(base).get("/", {"Cookie": f"sessionid={old}"})
    R.check("A07-4", "A07", "Replay a session cookie after logout",
            "302 to login (session destroyed server-side)",
            replay.status == 302 and "login" in replay.location,
            f"HTTP {replay.status} -> {replay.location}")

    for target in ("https://evil.example/", "//evil.example/"):
        b = Browser(base)
        b.get("/accounts/login/")
        r = b.post("/accounts/login/", {"username": "student1", "password": pw, "next": target})
        R.check("A07-5", "A07", f"Open redirect via next={target}",
                "redirect stays on this site",
                r.status == 302 and "evil.example" not in r.location, f"-> {r.location}")

    b1, b2 = Browser(base), Browser(base)
    r_known = b1.login("student1", "wrong-password-1")
    r_unknown = b2.login("nobody_" + uuid.uuid4().hex[:6], "wrong-password-1")
    R.check("A07-6", "A07", "User enumeration through the login error message",
            "identical response for known and unknown usernames",
            r_known.status == r_unknown.status and
            b1.alerts(r_known.text) == b2.alerts(r_unknown.text) and
            ("Invalid username or password" in r_known.text) == ("Invalid username or password" in r_unknown.text),
            f"known user: HTTP {r_known.status}; unknown user: HTTP {r_unknown.status}")

    cookies = Browser(base).get("/accounts/login/").set_cookies()
    login_resp = Browser(base).login("student1", pw)
    flags = [c for c in login_resp.set_cookies() + cookies]
    sess = next((c for c in flags if c.startswith("sessionid=")), "")
    R.check("A07-7", "A07", "Session cookie attributes",
            "HttpOnly and SameSite=Lax",
            "httponly" in sess.lower() and "samesite=lax" in sess.lower(), sess.split(";", 1)[-1].strip())
    R.info("A07-8", "A07", "Secure cookie flag",
           "Only set when DEBUG=False (HTTPS). Verified by 'manage.py check --deploy' in Phase 4.")

    # ===================================================== Uploads (A04 / A08)
    print("\nFile upload abuse")
    r = s1.post("/complaints/new/", {"title": "[ATTACK TEST] upload sandbox",
                                     "category": "other", "description": "upload target"})
    cid = r.location.rstrip("/").split("/")[-1]
    up = f"/complaints/{cid}/upload/"

    def attempt(filename, content, ctype="application/octet-stream"):
        s1.post_file(up, filename, content, ctype)
        return " | ".join(s1.alerts(s1.get(f"/complaints/{cid}/").text)) or "(no message)"

    png = make_png()
    msg = attempt("evidence.png", png, "image/png")
    R.check("UP-1", "A08", "Upload a genuine PNG", "accepted", "uploaded" in msg.lower(), msg)
    msg = attempt("shell.php", b"<?php system($_GET['c']); ?>", "application/x-php")
    R.check("UP-2", "A08", "Upload a PHP web shell", "rejected", "only pdf, png" in msg.lower(), msg)
    msg = attempt("invoice.png", b"MZ\x90\x00\x03\x00\x00\x00 pretend executable", "image/png")
    R.check("UP-3", "A08", "Upload an executable renamed to .png (fake content type)",
            "rejected (content does not match extension)", "does not match" in msg.lower(), msg)
    msg = attempt("big.png", png + b"0" * (2 * 1024 * 1024 + 1), "image/png")
    R.check("UP-4", "A08", "Upload a file over the 2 MB limit", "rejected", "too large" in msg.lower(), msg)
    msg = attempt("../../evil.png", png, "image/png")
    detail = s1.get(f"/complaints/{cid}/").text
    link = re.search(r'href="(/attachments/[0-9a-f-]{36}/download/)">evil\.png<', detail)
    R.check("UP-5", "A08", "Path traversal in the file name (../../evil.png)",
            "stored under a safe random name; shown as evil.png only",
            link is not None and "uploaded" in msg.lower(), msg)

    dl_link = re.search(r'href="(/attachments/[0-9a-f-]{36}/download/)">evidence\.png<', detail)
    if dl_link:
        r = s1.get(dl_link.group(1))
        h = r.headers
        R.check("UP-6", "A08", "Download response headers",
                "attachment, nosniff, sandboxed CSP, image/png",
                h.get("Content-Disposition", "").startswith("attachment")
                and h.get("X-Content-Type-Options") == "nosniff"
                and "sandbox" in h.get("Content-Security-Policy", "")
                and h.get("Content-Type") == "image/png",
                f"{h.get('Content-Disposition')} | {h.get('Content-Type')} | CSP={h.get('Content-Security-Policy')}")
        R.check("UP-7", "A01", "IDOR on the attachment download (student2)",
                "404", s2.get(dl_link.group(1)).status == 404, f"HTTP {s2.get(dl_link.group(1)).status}")
        R.check("UP-8", "A01", "Anonymous download of an attachment",
                "302 to login", anon.get(dl_link.group(1)).status == 302,
                f"HTTP {anon.get(dl_link.group(1)).status}")
    else:
        R.check("UP-6", "A08", "Download response headers", "attachment link present", False,
                "no download link found (upload failed?)")

    # ============================================ A05 Misconfiguration/headers
    print("\nA05 - Misconfiguration and information disclosure")
    r = anon.get("/accounts/login/")
    h = r.headers
    csp = h.get("Content-Security-Policy", "")
    R.check("A05-1", "A05", "Security headers on a normal page",
            "CSP (no scripts), X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy",
            "script-src 'none'" in csp and "frame-ancestors 'none'" in csp
            and h.get("X-Frame-Options") == "DENY" and h.get("X-Content-Type-Options") == "nosniff"
            and bool(h.get("Referrer-Policy")) and bool(h.get("Permissions-Policy")),
            f"CSP={csp[:90]}...")
    r = s1.get("/")
    R.check("A05-2", "A05", "Private pages are not cacheable",
            "Cache-Control: no-store", "no-store" in r.headers.get("Cache-Control", ""),
            r.headers.get("Cache-Control", "(none)"))
    bad = []
    for path in ("/.env", "/db.sqlite3", "/manage.py", "/logs/security.log",
                 "/static/../.env", "/media/", "/media/complaint_attachments/", "/config/settings.py"):
        r = anon.get(path)
        if r.status == 200 or "SECRET_KEY" in r.text:
            bad.append(f"{path} -> {r.status}")
    R.check("A05-3", "A05", "Forced browsing to secrets, database, logs, source and uploads",
            "all 403/404, nothing readable", not bad, f"exposed: {bad or 'none'}")
    for path in ("/complaints/not-a-uuid/", f"/complaints/{uuid.uuid4()}/", "/no/such/page"):
        r = s1.get(path)
        leak = any(w in r.text for w in ("Traceback", "Exception", "urlpatterns", "settings.py"))
        R.check("A05-4", "A05", f"Error page for {path}", "clean 404, no stack trace",
                r.status == 404 and not leak, f"HTTP {r.status}, debug info leaked={leak}")
    server = anon.get("/accounts/login/").headers.get("Server", "(none)")
    R.info("A05-5", "A05", "Server banner", f"'{server}' - the development server; production "
           "would sit behind nginx/gunicorn with the version hidden.")

    # ====================================================== A07 Brute force
    print("\nA07 - Brute force and account lockout (run last)")
    reset_lockouts()
    victim_b = Browser(base)
    locked_at = None
    for i in range(1, 9):
        r = victim_b.login("student2", f"wrong-guess-{i}")
        if r.status == 429:
            locked_at = i
            break
    R.check("A07-9", "A07", "Brute-force one account with wrong passwords",
            "locked out after 5 failures (HTTP 429)",
            locked_at is not None and locked_at <= 6, f"first HTTP 429 on attempt {locked_at}")
    r = Browser(base).login("student2", pw)
    R.check("A07-10", "A07", "Correct password for the locked account",
            "still refused (429)", r.status == 429, f"HTTP {r.status}")
    r = Browser(base).login("student1", pw)
    R.check("A07-11", "A07", "Lockout DoS: can the attacker lock out OTHER users?",
            "student1 (a different user) can still log in", r.status == 302,
            f"student1 login HTTP {r.status} while student2 is locked "
            f"({'unaffected' if r.status == 302 else 'ALSO LOCKED - lockout is per IP, so one attacker blocks everyone behind the same IP'})")
    reset_lockouts()

    # ------------------------------------------------------------------ report
    rows = R.rows
    passed = sum(r["status"] == "PASS" for r in rows)
    failed = [r for r in rows if r["status"] == "FAIL"]
    print(f"\n{'=' * 70}\nRESULT: {passed} passed, {len(failed)} failed, "
          f"{sum(r['status'] == 'INFO' for r in rows)} informational\n{'=' * 70}")
    for r in failed:
        print(f"  FINDING {r['id']}: {r['name']}\n      {r['actual']}")

    out = Path("docs/evidence")
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    md = [f"# Manual attack test results ({args.label})", "", f"Run: {stamp}  |  Target: {base}", "",
          f"**{passed} passed, {len(failed)} failed**", "",
          "| ID | Test | Expected | Result | Evidence |", "|---|---|---|---|---|"]
    for r in rows:
        esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")
        md.append(f"| {r['id']} | {esc(r['name'])} | {esc(r['expected'])} | **{r['status']}** | {esc(r['actual'])} |")
    (out / f"attack_results_{args.label}.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out / f"attack_results_{args.label}.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\nSaved: docs/evidence/attack_results_{args.label}.md (+ .json)")


if __name__ == "__main__":
    main()
