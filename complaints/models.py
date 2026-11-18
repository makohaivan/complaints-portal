import uuid
from pathlib import Path

from django.conf import settings
from django.db import models


def attachment_upload_path(instance, filename):
    """
    Never use the client-supplied filename on disk. A random name defeats
    path traversal (../../x), overwrites, and guessing/enumeration.
    """
    ext = Path(filename).suffix.lower()
    return f"complaint_attachments/{uuid.uuid4().hex}{ext}"


class Complaint(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ASSIGNED = "assigned", "Assigned"
        IN_PROGRESS = "in_progress", "In progress"
        RESOLVED = "resolved", "Resolved"

    class Category(models.TextChoices):
        ACADEMIC = "academic", "Academic"
        FINANCE = "finance", "Fees and finance"
        ACCOMMODATION = "accommodation", "Accommodation"
        FACILITIES = "facilities", "Facilities"
        CONDUCT = "conduct", "Staff or student conduct"
        OTHER = "other", "Other"

    # Server-enforced state machine. Staff can only make these moves, no
    # matter what a tampered POST contains.
    ALLOWED_TRANSITIONS = {
        "assigned": ["in_progress"],
        "in_progress": ["resolved"],
        "resolved": ["in_progress"],  # re-open
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="complaints"
    )
    title = models.CharField(max_length=150)
    category = models.CharField(max_length=20, choices=Category.choices, default=Category.OTHER)
    description = models.TextField(max_length=2000)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_complaints",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} [{self.get_status_display()}]"

    def allowed_next(self):
        return self.ALLOWED_TRANSITIONS.get(self.status, [])


class ComplaintResponse(models.Model):
    complaint = models.ForeignKey(Complaint, on_delete=models.CASCADE, related_name="responses")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    message = models.TextField(max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]


class Attachment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    complaint = models.ForeignKey(Complaint, on_delete=models.CASCADE, related_name="attachments")
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    file = models.FileField(upload_to=attachment_upload_path)
    original_name = models.CharField(max_length=100)
    content_type = models.CharField(max_length=50)
    size = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return self.original_name


class AuditLog(models.Model):
    """Append-only record of security-relevant actions (non-repudiation)."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    action = models.CharField(max_length=50)
    complaint = models.ForeignKey(Complaint, null=True, blank=True, on_delete=models.SET_NULL)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    detail = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M} {self.action}"
