from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from accounts.models import User
from complaints.models import AuditLog, Complaint

PASSWORD = "Str0ng#Test-Pass1"


def make_user(username, role):
    return User.objects.create_user(username=username, password=PASSWORD, role=role)


class Phase4Base(TestCase):
    def setUp(self):
        cache.clear()
        self.alice = make_user("alice", User.Role.STUDENT)
        self.staff = make_user("staff", User.Role.STAFF)
        self.admin = make_user("admin", User.Role.ADMIN)
        self.c = Complaint.objects.create(
            student=self.alice, title="Alice complaint", description="a",
            assigned_to=self.staff, status=Complaint.Status.ASSIGNED)


class HeaderTests(Phase4Base):
    def test_security_headers_present(self):
        r = self.client.get(reverse("login"))
        csp = r["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertEqual(r["X-Frame-Options"], "DENY")
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r["Referrer-Policy"], "same-origin")
        self.assertIn("camera=()", r["Permissions-Policy"])

    def test_admin_csp_is_relaxed_only_for_styles(self):
        r = self.client.get("/admin/login/")
        self.assertIn("style-src 'self' 'unsafe-inline'", r["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", r["Content-Security-Policy"])

    def test_private_pages_are_not_cacheable(self):
        self.client.force_login(self.alice)
        r = self.client.get(reverse("home"))
        self.assertIn("no-store", r["Cache-Control"])

    def test_pages_have_no_inline_script_or_style(self):
        """Regression guard: inline code would be blocked by the CSP anyway."""
        pages = [(None, reverse("login")), (None, reverse("register"))]
        pages += [(self.alice, reverse("home")), (self.alice, reverse("complaint_create")),
                  (self.alice, reverse("complaint_detail", args=[self.c.pk])),
                  (self.staff, reverse("complaint_detail", args=[self.c.pk])),
                  (self.admin, reverse("complaint_detail", args=[self.c.pk])),
                  (self.alice, reverse("password_change"))]
        for user, url in pages:
            self.client.logout()
            if user:
                self.client.force_login(user)
            html = self.client.get(url).content.decode().lower()
            self.assertNotIn("<script", html, url)
            self.assertNotIn(" style=", html, url)
            self.assertNotIn("cdn.", html, url)

    def test_custom_404_does_not_leak_details(self):
        r = self.client.get("/definitely-not-a-page/")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"Traceback", r.content)
        self.assertNotIn(b"urlpatterns", r.content)


@override_settings(RATELIMIT_ENABLED=True)
class RateLimitTests(Phase4Base):
    def test_registration_is_rate_limited(self):
        for _ in range(5):
            self.assertEqual(self.client.post(reverse("register"), {}).status_code, 200)
        r = self.client.post(reverse("register"), {})
        self.assertEqual(r.status_code, 429)
        self.assertIn("Retry-After", r)

    def test_complaint_creation_is_rate_limited_and_audited(self):
        self.client.force_login(self.alice)
        for _ in range(10):
            self.assertEqual(self.client.post(reverse("complaint_create"), {}).status_code, 200)
        self.assertEqual(self.client.post(reverse("complaint_create"), {}).status_code, 429)
        self.assertTrue(AuditLog.objects.filter(action="rate_limited").exists())

    def test_get_requests_are_not_counted(self):
        self.client.force_login(self.alice)
        for _ in range(15):
            self.assertEqual(self.client.get(reverse("complaint_create")).status_code, 200)


class AuthHardeningTests(Phase4Base):
    def test_lockout_after_repeated_failures_even_with_correct_password(self):
        for _ in range(5):
            self.client.post(reverse("login"), {"username": "alice", "password": "wrong-guess"})
        r = self.client.post(reverse("login"), {"username": "alice", "password": PASSWORD})
        self.assertContains(r, "temporarily locked", status_code=429)

    def test_open_redirect_is_blocked(self):
        for target in ("https://evil.example/", "//evil.example/"):
            self.client.logout()
            r = self.client.post(reverse("login"), {
                "username": "alice", "password": PASSWORD, "next": target})
            self.assertEqual(r.status_code, 302)
            self.assertNotIn("evil.example", r["Location"])

    def test_csrf_token_is_required_for_state_changing_requests(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.alice)
        r = client.post(reverse("complaint_create"), {
            "title": "x", "category": "other", "description": "y"})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Complaint.objects.filter(title="x").exists())

    def test_session_cookie_flags(self):
        self.client.post(reverse("login"), {"username": "alice", "password": PASSWORD})
        cookie = self.client.cookies["sessionid"]
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Lax")

    def test_session_is_dead_after_logout(self):
        self.client.force_login(self.alice)
        self.client.post(reverse("logout"))
        r = self.client.get(reverse("home"))
        self.assertEqual(r.status_code, 302)

    def test_weak_password_is_rejected_at_registration(self):
        for weak in ("12345678", "password", "short1!"):
            self.client.post(reverse("register"), {
                "username": "weakling", "email": "w@example.com",
                "password1": weak, "password2": weak})
        self.assertFalse(User.objects.filter(username="weakling").exists())

    def test_passwords_are_stored_with_argon2(self):
        self.assertTrue(self.alice.password.startswith("argon2$"))

    def test_password_change_requires_login(self):
        r = self.client.get(reverse("password_change"))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("login"), r["Location"])

    def test_password_change_requires_old_password(self):
        self.client.force_login(self.alice)
        self.client.post(reverse("password_change"), {
            "old_password": "not-the-old-one",
            "new_password1": "N3w#Strong-Passw0rd", "new_password2": "N3w#Strong-Passw0rd"})
        self.alice.refresh_from_db()
        self.assertTrue(self.alice.check_password(PASSWORD))

    def test_password_change_works_with_old_password(self):
        self.client.force_login(self.alice)
        r = self.client.post(reverse("password_change"), {
            "old_password": PASSWORD,
            "new_password1": "N3w#Strong-Passw0rd", "new_password2": "N3w#Strong-Passw0rd"})
        self.assertEqual(r.status_code, 302)
        self.alice.refresh_from_db()
        self.assertTrue(self.alice.check_password("N3w#Strong-Passw0rd"))
