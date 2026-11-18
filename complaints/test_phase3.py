import io
import shutil
import tempfile
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from PIL import Image

from accounts.models import User
from complaints.models import Attachment, AuditLog, Complaint, ComplaintResponse
from complaints.validators import MAX_UPLOAD_BYTES

PASSWORD = "Str0ng#Test-Pass1"


def make_user(username, role):
    return User.objects.create_user(username=username, password=PASSWORD, role=role)


def png_bytes():
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), "red").save(buf, "PNG")
    return buf.getvalue()


class Phase3Base(TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        self.media = Path(tmp)
        self.addCleanup(shutil.rmtree, tmp, True)
        override = override_settings(MEDIA_ROOT=tmp)
        override.enable()
        self.addCleanup(override.disable)

        self.alice = make_user("alice", User.Role.STUDENT)
        self.bob = make_user("bob", User.Role.STUDENT)
        self.staff = make_user("staff", User.Role.STAFF)
        self.staff2 = make_user("staff2", User.Role.STAFF)
        self.admin = make_user("admin", User.Role.ADMIN)
        self.c = Complaint.objects.create(
            student=self.alice, title="Alice complaint", description="a",
            assigned_to=self.staff, status=Complaint.Status.ASSIGNED)
        self.unassigned = Complaint.objects.create(
            student=self.bob, title="Bob complaint", description="b")

    def upload(self, name, content, user=None, complaint=None):
        self.client.force_login(user or self.alice)
        return self.client.post(
            reverse("complaint_upload", args=[(complaint or self.c).pk]),
            {"file": SimpleUploadedFile(name, content)},
        )


class AssignmentTests(Phase3Base):
    def test_admin_can_assign_staff(self):
        self.client.force_login(self.admin)
        self.client.post(reverse("complaint_assign", args=[self.unassigned.pk]),
                         {"staff": self.staff2.pk})
        self.unassigned.refresh_from_db()
        self.assertEqual(self.unassigned.assigned_to, self.staff2)
        self.assertEqual(self.unassigned.status, Complaint.Status.ASSIGNED)
        self.assertTrue(AuditLog.objects.filter(action="complaint_assigned").exists())

    def test_student_cannot_assign(self):
        self.client.force_login(self.alice)
        r = self.client.post(reverse("complaint_assign", args=[self.c.pk]),
                             {"staff": self.staff2.pk})
        self.assertEqual(r.status_code, 403)
        self.c.refresh_from_db()
        self.assertEqual(self.c.assigned_to, self.staff)

    def test_staff_cannot_assign(self):
        self.client.force_login(self.staff)
        r = self.client.post(reverse("complaint_assign", args=[self.c.pk]),
                             {"staff": self.staff2.pk})
        self.assertEqual(r.status_code, 403)

    def test_cannot_assign_to_a_non_staff_account(self):
        self.client.force_login(self.admin)
        self.client.post(reverse("complaint_assign", args=[self.unassigned.pk]),
                         {"staff": self.bob.pk})
        self.unassigned.refresh_from_db()
        self.assertIsNone(self.unassigned.assigned_to)

    def test_assignment_requires_post(self):
        self.client.force_login(self.admin)
        r = self.client.get(reverse("complaint_assign", args=[self.c.pk]))
        self.assertEqual(r.status_code, 405)


class ResponseAndStatusTests(Phase3Base):
    def test_assigned_staff_can_respond_and_status_advances(self):
        self.client.force_login(self.staff)
        self.client.post(reverse("complaint_respond", args=[self.c.pk]), {"message": "Looking into it"})
        self.assertEqual(ComplaintResponse.objects.get().author, self.staff)
        self.c.refresh_from_db()
        self.assertEqual(self.c.status, Complaint.Status.IN_PROGRESS)

    def test_unassigned_staff_cannot_respond(self):
        self.client.force_login(self.staff2)
        r = self.client.post(reverse("complaint_respond", args=[self.c.pk]), {"message": "hi"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(ComplaintResponse.objects.count(), 0)

    def test_student_cannot_respond(self):
        self.client.force_login(self.alice)
        r = self.client.post(reverse("complaint_respond", args=[self.c.pk]), {"message": "hi"})
        self.assertEqual(r.status_code, 403)

    def test_legal_status_transition(self):
        self.client.force_login(self.staff)
        self.client.post(reverse("complaint_status", args=[self.c.pk]), {"status": "in_progress"})
        self.c.refresh_from_db()
        self.assertEqual(self.c.status, Complaint.Status.IN_PROGRESS)
        self.assertTrue(AuditLog.objects.filter(action="status_changed").exists())

    def test_illegal_status_jump_is_rejected(self):
        self.client.force_login(self.staff)
        self.client.post(reverse("complaint_status", args=[self.c.pk]), {"status": "resolved"})
        self.c.refresh_from_db()
        self.assertEqual(self.c.status, Complaint.Status.ASSIGNED)

    def test_cannot_set_status_back_to_open(self):
        self.client.force_login(self.staff)
        self.client.post(reverse("complaint_status", args=[self.c.pk]), {"status": "open"})
        self.c.refresh_from_db()
        self.assertEqual(self.c.status, Complaint.Status.ASSIGNED)

    def test_student_cannot_change_status(self):
        self.client.force_login(self.alice)
        r = self.client.post(reverse("complaint_status", args=[self.c.pk]), {"status": "resolved"})
        self.assertEqual(r.status_code, 403)
        self.c.refresh_from_db()
        self.assertEqual(self.c.status, Complaint.Status.ASSIGNED)


class UploadTests(Phase3Base):
    def test_valid_png_is_accepted_and_stored_under_a_random_name(self):
        self.upload("evidence.png", png_bytes())
        att = Attachment.objects.get()
        self.assertEqual(att.original_name, "evidence.png")
        self.assertEqual(att.content_type, "image/png")
        self.assertNotIn("evidence", att.file.name)
        self.assertTrue(att.file.name.startswith("complaint_attachments/"))
        self.assertTrue((self.media / att.file.name).exists())

    def test_valid_pdf_is_accepted(self):
        self.upload("letter.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF")
        self.assertEqual(Attachment.objects.count(), 1)

    def test_php_file_is_rejected(self):
        self.upload("shell.php", b"<?php system($_GET['c']); ?>")
        self.assertEqual(Attachment.objects.count(), 0)

    def test_double_extension_with_script_content_is_rejected(self):
        self.upload("shell.php.png", b"<?php system($_GET['c']); ?>")
        self.assertEqual(Attachment.objects.count(), 0)

    def test_executable_renamed_to_png_is_rejected(self):
        self.upload("invoice.png", b"MZ\x90\x00\x03\x00\x00\x00 fake executable")
        self.assertEqual(Attachment.objects.count(), 0)

    def test_html_renamed_to_pdf_is_rejected(self):
        self.upload("doc.pdf", b"<html><script>alert(1)</script></html>")
        self.assertEqual(Attachment.objects.count(), 0)

    def test_oversized_file_is_rejected(self):
        self.upload("big.png", png_bytes() + b"0" * (MAX_UPLOAD_BYTES + 1))
        self.assertEqual(Attachment.objects.count(), 0)

    def test_empty_file_is_rejected(self):
        self.upload("empty.png", b"")
        self.assertEqual(Attachment.objects.count(), 0)

    def test_path_traversal_filename_cannot_escape_media_root(self):
        self.upload("../../evil.png", png_bytes())
        att = Attachment.objects.get()
        self.assertEqual(att.original_name, "evil.png")
        self.assertNotIn("..", att.file.name)
        stored = (self.media / att.file.name).resolve()
        self.assertTrue(str(stored).startswith(str(self.media.resolve())))

    def test_upload_limit_per_complaint(self):
        for i in range(4):
            self.upload(f"f{i}.png", png_bytes())
        self.assertEqual(self.c.attachments.count(), 3)

    def test_only_the_owner_can_upload(self):
        self.upload("x.png", png_bytes(), user=self.bob)
        self.assertEqual(Attachment.objects.count(), 0)

    def test_staff_cannot_upload(self):
        r = self.upload("x.png", png_bytes(), user=self.staff)
        self.assertEqual(r.status_code, 403)

    def test_upload_can_be_attached_when_submitting_a_complaint(self):
        self.client.force_login(self.alice)
        self.client.post(reverse("complaint_create"), {
            "title": "With file", "category": "other", "description": "see attached",
            "attachment": SimpleUploadedFile("proof.png", png_bytes()),
        })
        self.assertEqual(Attachment.objects.get().complaint.title, "With file")

    def test_upload_is_audited(self):
        self.upload("x.png", png_bytes())
        self.assertTrue(AuditLog.objects.filter(action="attachment_uploaded").exists())


class DownloadTests(Phase3Base):
    def setUp(self):
        super().setUp()
        self.upload("evidence.png", png_bytes())
        self.att = Attachment.objects.get()

    def get(self, user):
        if user:
            self.client.force_login(user)
        else:
            self.client.logout()
        r = self.client.get(reverse("attachment_download", args=[self.att.pk]))
        if getattr(r, "streaming", False):
            b"".join(r.streaming_content)
            r.close()
        return r

    def test_owner_can_download_with_safe_headers(self):
        r = self.get(self.alice)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r["Content-Disposition"].startswith("attachment"))
        self.assertEqual(r["Content-Type"], "image/png")
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertIn("sandbox", r["Content-Security-Policy"])

    def test_assigned_staff_and_admin_can_download(self):
        self.assertEqual(self.get(self.staff).status_code, 200)
        self.assertEqual(self.get(self.admin).status_code, 200)

    def test_other_student_gets_404_and_is_logged(self):
        self.assertEqual(self.get(self.bob).status_code, 404)
        self.assertTrue(AuditLog.objects.filter(user=self.bob, action="access_denied").exists())

    def test_unassigned_staff_gets_404(self):
        self.assertEqual(self.get(self.staff2).status_code, 404)

    def test_anonymous_is_redirected_to_login(self):
        self.assertEqual(self.get(None).status_code, 302)

    def test_uploads_are_not_publicly_routable(self):
        self.client.force_login(self.alice)
        r = self.client.get("/media/" + self.att.file.name)
        self.assertEqual(r.status_code, 404)
