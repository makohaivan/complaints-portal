from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom user. The role drives ALL server-side access control."""

    class Role(models.TextChoices):
        STUDENT = "student", "Student"
        STAFF = "staff", "Staff"
        ADMIN = "admin", "Administrator"

    role = models.CharField(max_length=10, choices=Role.choices, default=Role.STUDENT)

    @property
    def is_student(self):
        return self.role == self.Role.STUDENT

    @property
    def is_staff_member(self):
        return self.role == self.Role.STAFF

    @property
    def is_portal_admin(self):
        return self.role == self.Role.ADMIN

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"
