from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import Http404
from django.urls import reverse
from django.views.generic import CreateView, DetailView, ListView

from accounts.models import User

from .audit import log_event
from .forms import ComplaintForm
from .models import Complaint
from .permissions import RoleRequiredMixin, visible_complaints


class ComplaintListView(LoginRequiredMixin, ListView):
    template_name = "complaints/complaint_list.html"
    context_object_name = "complaints"
    paginate_by = 10

    def get_queryset(self):
        qs = visible_complaints(self.request.user)

        # Status filter: allow-list, never passed through blindly.
        status = self.request.GET.get("status", "")
        if status in Complaint.Status.values:
            qs = qs.filter(status=status)

        # Search uses the ORM -> parameterised SQL (OWASP A03: Injection).
        q = self.request.GET.get("q", "").strip()[:100]
        if q:
            qs = qs.filter(Q(title__icontains=q) | Q(description__icontains=q))
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["q"] = self.request.GET.get("q", "").strip()[:100]
        ctx["status"] = self.request.GET.get("status", "")
        ctx["statuses"] = Complaint.Status.choices
        return ctx


class ComplaintCreateView(RoleRequiredMixin, CreateView):
    allowed_roles = (User.Role.STUDENT,)
    model = Complaint
    form_class = ComplaintForm
    template_name = "complaints/complaint_form.html"

    def form_valid(self, form):
        form.instance.student = self.request.user  # never trust the client for ownership
        response = super().form_valid(form)
        log_event(self.request, "complaint_created", self.object)
        messages.success(self.request, "Your complaint has been submitted.")
        return response

    def get_success_url(self):
        return reverse("complaint_detail", args=[self.object.pk])


class ComplaintDetailView(LoginRequiredMixin, DetailView):
    template_name = "complaints/complaint_detail.html"
    context_object_name = "complaint"

    def get_queryset(self):
        return visible_complaints(self.request.user)

    def get_object(self, queryset=None):
        try:
            return super().get_object(queryset)
        except Http404:
            # The complaint exists but is not this user's: that is an IDOR
            # attempt. Log it, but still answer 404 (do not reveal existence).
            if Complaint.objects.filter(pk=self.kwargs["pk"]).exists():
                log_event(
                    self.request,
                    "access_denied",
                    detail=f"pk={self.kwargs['pk']} not owner/assignee",
                )
            raise
