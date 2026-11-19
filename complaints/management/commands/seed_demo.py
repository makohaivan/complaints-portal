from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from accounts.models import User
from complaints.models import Complaint

# DEMO ONLY. These are test accounts for the README. Never use in production.
DEMO_PASSWORD = "Complaints#2026!"  # nosec B105 - ACCEPTED RISK: published demo credential; the command refuses to run when DEBUG=False

ACCOUNTS = [
    ("admin1", User.Role.ADMIN, "admin1@example.com"),
    ("staff1", User.Role.STAFF, "staff1@example.com"),
    ("staff2", User.Role.STAFF, "staff2@example.com"),
    ("student1", User.Role.STUDENT, "student1@example.com"),
    ("student2", User.Role.STUDENT, "student2@example.com"),
]


class Command(BaseCommand):
    help = "Create demo users (one per role) and sample complaints."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true", help="Allow when DEBUG is False")

    def handle(self, *args, **opts):
        if not settings.DEBUG and not opts["force"]:
            raise CommandError("Refusing to create demo accounts when DEBUG is False.")

        users = {}
        for username, role, email in ACCOUNTS:
            user, created = User.objects.get_or_create(
                username=username, defaults={"role": role, "email": email}
            )
            if created:
                user.set_password(DEMO_PASSWORD)  # hashed with Argon2
                if role == User.Role.ADMIN:
                    user.is_staff = True          # lets admin1 use /admin/
                    user.is_superuser = True
                user.save()
            users[username] = user
            self.stdout.write(f"{'created' if created else 'exists '}: {username} ({role})")

        samples = [
            ("student1", "Wrong marks on Database Systems exam",
             Complaint.Category.ACADEMIC,
             "My CAT1 mark was recorded as 12/30 but my script shows 21/30.", "staff1"),
            ("student1", "Hostel water shortage",
             Complaint.Category.ACCOMMODATION,
             "There has been no running water in Block B for three days.", None),
            ("student2", "Fees payment not reflected",
             Complaint.Category.FINANCE,
             "I paid on 3 November but the portal still shows a balance.", None),
        ]
        for owner, title, category, description, assignee in samples:
            complaint, created = Complaint.objects.get_or_create(
                student=users[owner],
                title=title,
                defaults={"category": category, "description": description},
            )
            if created and assignee:
                complaint.assigned_to = users[assignee]
                complaint.status = Complaint.Status.ASSIGNED
                complaint.save()

        self.stdout.write(self.style.SUCCESS(f"Demo data ready. Password for all: {DEMO_PASSWORD}"))
