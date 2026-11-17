import uuid

from django.conf import settings
from django.db import models


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

    # UUID keys are not guessable/enumerable like 1, 2, 3 (defence in depth:
    # the real protection is the server-side ownership filter in permissions.py).
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


class ComplaintResponse(models.Model):
    complaint = models.ForeignKey(Complaint, on_delete=models.CASCADE, related_name="responses")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    message = models.TextField(max_length=2000)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]


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
