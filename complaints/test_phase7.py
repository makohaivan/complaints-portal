import re
from pathlib import Path

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from complaints.models import AuditLog, Complaint

PASSWORD = "Str0ng#Test-Pass1"
STATIC = Path(settings.BASE_DIR) / "static"


def make_user(username, role, **extra):
    return User.objects.create_user(username=username, password=PASSWORD, role=role, **extra)


class DashboardBase(TestCase):
    def setUp(self):
        cache.clear()
        self.alice = make_user("alice", User.Role.STUDENT)
        self.bob = make_user("bob", User.Role.STUDENT)
        self.staff = make_user("staff", User.Role.STAFF)
        self.admin = make_user("admin", User.Role.ADMIN, is_staff=True)
        Complaint.objects.create(student=self.alice, title="Alice open", description="a")
        Complaint.objects.create(student=self.alice, title="Alice resolved", description="a",
                                 status=Complaint.Status.RESOLVED, assigned_to=self.staff)
        Complaint.objects.create(student=self.bob, title="Bob private", description="b",
                                 assigned_to=self.staff, status=Complaint.Status.IN_PROGRESS)

    def dash(self, user):
        self.client.force_login(user)
        return self.client.get(reverse("dashboard"))


class DashboardTests(DashboardBase):
    def test_dashboard_requires_login(self):
        r = self.client.get(reverse("dashboard"))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("login"), r["Location"])

    def test_student_dashboard_counts_only_own_complaints(self):
        r = self.dash(self.alice)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["total"], 2)
        self.assertEqual(r.context["resolved"], 1)
        self.assertContains(r, "Alice open")
        self.assertNotContains(r, "Bob private")

    def test_staff_dashboard_counts_only_assigned(self):
        r = self.dash(self.staff)
        self.assertEqual(r.context["total"], 2)
        self.assertEqual(r.context["in_progress"], 1)
        self.assertNotContains(r, "Alice open")

    def test_admin_dashboard_counts_everything_and_shows_admin_panels(self):
        AuditLog.objects.create(user=self.alice, action="access_denied", detail="x")
        r = self.dash(self.admin)
        self.assertEqual(r.context["total"], 3)
        self.assertEqual(r.context["unassigned_count"], 1)
        self.assertEqual(r.context["staff_count"], 1)
        self.assertEqual(r.context["denied_24h"], 1)
        self.assertContains(r, "Recent security activity")

    def test_admin_only_data_is_not_computed_for_other_roles(self):
        AuditLog.objects.create(user=self.alice, action="access_denied", detail="x")
        for user in (self.alice, self.staff):
            r = self.dash(user)
            self.assertIsNone(r.context.get("activity"))
            self.assertIsNone(r.context.get("unassigned_count"))
            self.assertNotContains(r, "Recent security activity")

    def test_status_bar_segments_add_up(self):
        r = self.dash(self.admin)
        self.assertEqual(sum(s["count"] for s in r.context["segments"]), 3)

    def test_login_redirects_to_the_dashboard(self):
        r = self.client.post(reverse("login"), {"username": "alice", "password": PASSWORD})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r["Location"], reverse("dashboard"))


class SideMenuTests(DashboardBase):
    def test_student_menu(self):
        html = self.dash(self.alice).content.decode()
        self.assertIn("My complaints", html)
        self.assertIn("New complaint", html)
        self.assertNotIn("Needs assignment", html)
        self.assertNotIn("Audit log", html)
        self.assertNotIn("Administrator", html)

    def test_staff_menu(self):
        html = self.dash(self.staff).content.decode()
        self.assertIn("Assigned to me", html)
        self.assertNotIn("New complaint", html)
        self.assertNotIn("Audit log", html)

    def test_admin_menu(self):
        html = self.dash(self.admin).content.decode()
        self.assertIn("All complaints", html)
        self.assertIn("Needs assignment", html)
        self.assertIn("Audit log", html)

    def test_menu_is_css_only_and_logout_is_a_post_form(self):
        html = self.dash(self.alice).content.decode()
        self.assertIn('id="nav-toggle"', html)
        self.assertIn('<form method="post" action="/accounts/logout/">', html)
        self.assertNotIn("<script", html.lower())

    def test_role_badge_still_rendered_for_the_attack_tests(self):
        self.assertIn(">Student</span>", self.dash(self.alice).content.decode())


class CspSafetyTests(DashboardBase):
    def test_no_inline_script_style_or_cdn_on_any_redesigned_page(self):
        c = Complaint.objects.first()
        pages = [(None, reverse("login")), (None, reverse("register")),
                 (None, "/does-not-exist/")]
        for u in (self.alice, self.staff, self.admin):
            pages += [(u, reverse("dashboard")), (u, reverse("home")),
                      (u, reverse("password_change"))]
        pages += [(self.alice, reverse("complaint_create")),
                  (self.admin, reverse("complaint_detail", args=[c.pk]))]
        for user, url in pages:
            self.client.logout()
            if user:
                self.client.force_login(user)
            r = self.client.get(url)
            html = r.content.decode().lower()
            self.assertNotIn("<script", html, url)
            self.assertNotIn(" style=", html, url)
            self.assertNotIn("cdn.", html, url)
            self.assertNotIn("onclick=", html, url)
            csp = r["Content-Security-Policy"]
            self.assertIn("script-src 'none'", csp)
            self.assertNotIn("unsafe-inline", csp)

    def test_status_bar_uses_svg_attributes_not_inline_style(self):
        html = self.dash(self.alice).content.decode()
        self.assertRegex(html, r'<rect class="seg-[a-z]+" x="[0-9.]+" y="0" width="[0-9.]+"')


class LoginPageTests(TestCase):
    def test_login_page_has_branding_content_and_icons(self):
        html = self.client.get(reverse("login")).content.decode()
        for text in ("Student Complaints Portal", "Raise it. Track it.", "Private by design",
                     "Real-time tracking", "Attach your evidence", "Welcome back"):
            self.assertIn(text, html)
        self.assertGreater(html.count("<use href="), 5)

    def test_login_error_message_is_unchanged_for_the_attack_tests(self):
        r = self.client.post(reverse("login"), {"username": "nobody", "password": "x"})
        self.assertContains(r, "Invalid username or password")

    def test_lockout_page_is_styled_and_still_says_temporarily_locked(self):
        make_user("alice", User.Role.STUDENT)
        for _ in range(5):
            self.client.post(reverse("login"), {"username": "alice", "password": "wrong"})
        r = self.client.post(reverse("login"), {"username": "alice", "password": PASSWORD})
        self.assertContains(r, "temporarily locked", status_code=429)
        self.assertContains(r, "auth-shell", status_code=429)


class AssetIntegrityTests(TestCase):
    def test_static_assets_exist(self):
        for rel in ("css/app.css", "css/fonts.css", "img/favicon.svg", "vendor/icons/sprite.svg",
                    "vendor/bootstrap/bootstrap.min.css"):
            self.assertTrue((STATIC / rel).exists(), rel)

    def test_every_font_file_referenced_by_fonts_css_exists_and_is_woff2(self):
        css = (STATIC / "css" / "fonts.css").read_text()
        urls = re.findall(r'url\("([^"]+)"\)', css)
        self.assertGreaterEqual(len(urls), 6)
        for u in urls:
            f = (STATIC / "css" / u).resolve()
            self.assertTrue(f.exists(), u)
            self.assertEqual(f.read_bytes()[:4], b"wOF2", u)

    def test_every_icon_used_in_templates_exists_in_the_sprite(self):
        sprite = (STATIC / "vendor" / "icons" / "sprite.svg").read_text()
        have = set(re.findall(r'<symbol[^>]* id="([^"]+)"', sprite))
        used = set()
        for tpl in Path(settings.BASE_DIR, "templates").rglob("*.html"):
            used |= set(re.findall(r'{%\s*icon\s+"([^"]+)"', tpl.read_text()))
        self.assertGreater(len(used), 25)
        self.assertEqual(used - have, set())
