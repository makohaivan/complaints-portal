from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.core.exceptions import PermissionDenied
from django.http import Http404

from accounts.models import User

from .audit import log_event
from .models import Complaint


def visible_complaints(user):
    """
    THE access-control choke point (OWASP A01: Broken Access Control).

    Every view fetches complaints through this function, so a user can only
    ever load rows they are entitled to. A forged ID for someone else's
    complaint simply is not in the queryset -> 404, with no information leak.
    """
    qs = Complaint.objects.select_related("student", "assigned_to")
    if user.role == User.Role.ADMIN:
        return qs
    if user.role == User.Role.STAFF:
        return qs.filter(assigned_to=user)
    return qs.filter(student=user)


def get_visible_or_404(request, pk):
    """Fetch a complaint the user may access, else 404 (and log IDOR attempts)."""
    try:
        return visible_complaints(request.user).get(pk=pk)
    except Complaint.DoesNotExist:
        if Complaint.objects.filter(pk=pk).exists():
            log_event(request, "access_denied", detail=f"pk={pk} not owner/assignee")
        raise Http404


class RoleRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """Restrict a view to specific roles. Denied attempts are logged."""

    allowed_roles = ()

    def test_func(self):
        return self.request.user.role in self.allowed_roles

    def handle_no_permission(self):
        if self.request.user.is_authenticated:
            log_event(self.request, "access_denied", detail=f"path={self.request.path}")
            raise PermissionDenied
        return super().handle_no_permission()  # anonymous -> redirect to login
