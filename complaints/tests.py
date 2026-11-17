from django.test import TestCase
from django.urls import reverse

from accounts.models import User
from complaints.models import AuditLog, Complaint

PASSWORD = "Str0ng#Test-Pass1"


def make_user(username, role):
    return User.objects.create_user(username=username, password=PASSWORD, role=role)


class AccessControlTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.alice = make_user("alice", User.Role.STUDENT)
        cls.bob = make_user("bob", User.Role.STUDENT)
        cls.staff = make_user("staff", User.Role.STAFF)
        cls.other_staff = make_user("staff_other", User.Role.STAFF)
        cls.admin = make_user("admin", User.Role.ADMIN)
        cls.alice_c = Complaint.objects.create(
            student=cls.alice, title="Alice complaint", description="a", assigned_to=cls.staff)
        cls.bob_c = Complaint.objects.create(
            student=cls.bob, title="Bob complaint", description="b")

    # --- authentication
    def test_anonymous_is_redirected_to_login(self):
        r = self.client.get(reverse("home"))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("login"), r["Location"])

    def test_anonymous_cannot_open_complaint(self):
        r = self.client.get(reverse("complaint_detail", args=[self.alice_c.pk]))
        self.assertEqual(r.status_code, 302)

    # --- horizontal privilege escalation (IDOR)
    def test_student_sees_only_own_complaints(self):
        self.client.force_login(self.alice)
        r = self.client.get(reverse("home"))
        self.assertContains(r, "Alice complaint")
        self.assertNotContains(r, "Bob complaint")

    def test_student_cannot_open_another_students_complaint(self):
        self.client.force_login(self.alice)
        r = self.client.get(reverse("complaint_detail", args=[self.bob_c.pk]))
        self.assertEqual(r.status_code, 404)

    def test_idor_attempt_is_audited(self):
        self.client.force_login(self.alice)
        self.client.get(reverse("complaint_detail", args=[self.bob_c.pk]))
        self.assertTrue(AuditLog.objects.filter(user=self.alice, action="access_denied").exists())

    # --- role checks
    def test_staff_sees_only_assigned_complaints(self):
        self.client.force_login(self.staff)
        r = self.client.get(reverse("home"))
        self.assertContains(r, "Alice complaint")
        self.assertNotContains(r, "Bob complaint")

    def test_unassigned_staff_cannot_open_complaint(self):
        self.client.force_login(self.other_staff)
        r = self.client.get(reverse("complaint_detail", args=[self.alice_c.pk]))
        self.assertEqual(r.status_code, 404)

    def test_admin_sees_all_complaints(self):
        self.client.force_login(self.admin)
        r = self.client.get(reverse("home"))
        self.assertContains(r, "Alice complaint")
        self.assertContains(r, "Bob complaint")

    def test_staff_cannot_submit_complaints(self):
        self.client.force_login(self.staff)
        r = self.client.get(reverse("complaint_create"))
        self.assertEqual(r.status_code, 403)

    # --- mass assignment / ownership
    def test_student_cannot_set_owner_or_status_via_post(self):
        self.client.force_login(self.alice)
        self.client.post(reverse("complaint_create"), {
            "title": "Sneaky", "category": "other", "description": "x",
            "student": self.bob.pk, "status": "resolved", "assigned_to": self.staff.pk,
        })
        c = Complaint.objects.get(title="Sneaky")
        self.assertEqual(c.student, self.alice)
        self.assertEqual(c.status, Complaint.Status.OPEN)
        self.assertIsNone(c.assigned_to)

    def test_registration_cannot_create_admin(self):
        self.client.post(reverse("register"), {
            "username": "mallory", "email": "m@example.com",
            "password1": PASSWORD, "password2": PASSWORD, "role": "admin",
            "is_superuser": "on", "is_staff": "on",
        })
        mallory = User.objects.get(username="mallory")
        self.assertEqual(mallory.role, User.Role.STUDENT)
        self.assertFalse(mallory.is_superuser)

    # --- injection / XSS
    def test_search_is_safe_against_sql_injection(self):
        self.client.force_login(self.alice)
        r = self.client.get(reverse("home"), {"q": "' OR 1=1 --"})
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "Bob complaint")

    def test_script_in_title_is_escaped(self):
        Complaint.objects.create(
            student=self.alice, title="<script>alert(1)</script>", description="x")
        self.client.force_login(self.alice)
        r = self.client.get(reverse("home"))
        self.assertNotContains(r, "<script>alert(1)</script>")
        self.assertContains(r, "&lt;script&gt;")

    # --- logout must not be possible via GET (CSRF-able)
    def test_logout_requires_post(self):
        self.client.force_login(self.alice)
        r = self.client.get(reverse("logout"))
        self.assertEqual(r.status_code, 405)
