from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.utils import timezone
from django.views.generic import TemplateView

from accounts.models import User

from .models import AuditLog, Complaint
from .permissions import visible_complaints

STATUS_META = [
    ("open", "Open", "seg-open"),
    ("assigned", "Assigned", "seg-assigned"),
    ("in_progress", "In progress", "seg-progress"),
    ("resolved", "Resolved", "seg-resolved"),
]


class DashboardView(LoginRequiredMixin, TemplateView):
    """
    Role-aware dashboard. Every number comes from visible_complaints(), so a student
    only ever sees statistics about their own complaints. Admin-only data (security
    activity, unassigned queue) is not even computed for other roles.
    """

    template_name = "complaints/dashboard.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        user = self.request.user
        qs = visible_complaints(user)

        counts = dict(qs.order_by().values_list("status").annotate(n=Count("pk")))
        total = sum(counts.values())
        segments, x = [], 0.0
        for value, label, css in STATUS_META:
            n = counts.get(value, 0)
            pct = (n / total * 100) if total else 0.0
            segments.append({
                "label": label, "css": css, "count": n, "pct": round(pct),
                "x": f"{x:.2f}", "w": f"{pct:.2f}",
            })
            x += pct

        ctx.update(
            total=total,
            waiting=counts.get("open", 0) + counts.get("assigned", 0),
            in_progress=counts.get("in_progress", 0),
            resolved=counts.get("resolved", 0),
            segments=segments,
            recent=qs[:5],
        )

        if user.role == User.Role.STAFF:
            ctx["queue"] = qs.exclude(status=Complaint.Status.RESOLVED)[:5]

        if user.role == User.Role.ADMIN:
            unassigned = Complaint.objects.filter(assigned_to__isnull=True)
            since = timezone.now() - timedelta(hours=24)
            ctx.update(
                unassigned_count=unassigned.count(),
                unassigned=unassigned.select_related("student")[:5],
                staff_count=User.objects.filter(role=User.Role.STAFF, is_active=True).count(),
                denied_24h=AuditLog.objects.filter(action="access_denied", created_at__gte=since).count(),
                activity=AuditLog.objects.select_related("user")[:6],
            )
        return ctx
