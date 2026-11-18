from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import FileResponse, Http404
from django.shortcuts import redirect
from django.urls import reverse
from django.views import View
from django.views.generic import CreateView, DetailView, ListView

from accounts.models import User

from .audit import log_event
from .forms import (
    AssignForm,
    AttachmentUploadForm,
    ComplaintForm,
    ResponseForm,
    StatusForm,
)
from .models import Attachment, Complaint, ComplaintResponse
from .permissions import RoleRequiredMixin, get_visible_or_404, visible_complaints
from .uploads import store_attachment
from .validators import MAX_ATTACHMENTS_PER_COMPLAINT


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
        attachment = form.cleaned_data.get("attachment")
        if attachment:
            store_attachment(self.request, self.object, attachment)
        messages.success(self.request, "Your complaint has been submitted.")
        return response

    def get_success_url(self):
        return reverse("complaint_detail", args=[self.object.pk])


class ComplaintDetailView(LoginRequiredMixin, DetailView):
    template_name = "complaints/complaint_detail.html"
    context_object_name = "complaint"

    def get_object(self, queryset=None):
        return get_visible_or_404(self.request, self.kwargs["pk"])

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        complaint, user = self.object, self.request.user
        ctx["attachments"] = complaint.attachments.select_related("uploaded_by")
        # Each role only ever receives the forms for the actions it may perform.
        if user.role == User.Role.ADMIN:
            ctx["assign_form"] = AssignForm(initial={"staff": complaint.assigned_to_id})
        elif user.role == User.Role.STAFF:
            ctx["response_form"] = ResponseForm()
            if complaint.allowed_next():
                ctx["status_form"] = StatusForm(current=complaint.status)
        elif user.role == User.Role.STUDENT:
            if complaint.attachments.count() < MAX_ATTACHMENTS_PER_COMPLAINT:
                ctx["upload_form"] = AttachmentUploadForm()
        return ctx


# ------------------------------------------------------------- POST actions
class ComplaintActionView(RoleRequiredMixin, View):
    """Base for POST-only actions on one complaint (CSRF-protected by middleware)."""

    http_method_names = ["post"]

    def post(self, request, pk):
        # Role is checked by RoleRequiredMixin first; then object-level access here.
        complaint = get_visible_or_404(request, pk)
        self.handle(request, complaint)
        return redirect("complaint_detail", pk=complaint.pk)

    def handle(self, request, complaint):
        raise NotImplementedError


class AssignComplaintView(ComplaintActionView):
    allowed_roles = (User.Role.ADMIN,)

    def handle(self, request, complaint):
        form = AssignForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Please choose a valid staff member.")
            return
        staff = form.cleaned_data["staff"]
        complaint.assigned_to = staff
        if complaint.status == Complaint.Status.OPEN:
            complaint.status = Complaint.Status.ASSIGNED
        complaint.save(update_fields=["assigned_to", "status", "updated_at"])
        log_event(request, "complaint_assigned", complaint, detail=f"assigned_to={staff.username}")
        messages.success(request, f"Complaint assigned to {staff.username}.")


class RespondView(ComplaintActionView):
    allowed_roles = (User.Role.STAFF,)

    def handle(self, request, complaint):
        form = ResponseForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Please write a response (maximum 2000 characters).")
            return
        ComplaintResponse.objects.create(
            complaint=complaint,
            author=request.user,  # from the session, never from the form
            message=form.cleaned_data["message"],
        )
        log_event(request, "response_added", complaint)
        if complaint.status == Complaint.Status.ASSIGNED:
            complaint.status = Complaint.Status.IN_PROGRESS
            complaint.save(update_fields=["status", "updated_at"])
            log_event(request, "status_changed", complaint, detail="assigned -> in_progress (auto)")
        messages.success(request, "Response sent to the student.")


class StatusUpdateView(ComplaintActionView):
    allowed_roles = (User.Role.STAFF,)

    def handle(self, request, complaint):
        form = StatusForm(request.POST, current=complaint.status)
        if not form.is_valid():
            messages.error(request, "That status change is not allowed.")
            return
        old, new = complaint.status, form.cleaned_data["status"]
        complaint.status = new
        complaint.save(update_fields=["status", "updated_at"])
        log_event(request, "status_changed", complaint, detail=f"{old} -> {new}")
        messages.success(request, "Status updated.")


class UploadAttachmentView(ComplaintActionView):
    allowed_roles = (User.Role.STUDENT,)

    def handle(self, request, complaint):
        if complaint.attachments.count() >= MAX_ATTACHMENTS_PER_COMPLAINT:
            messages.error(request, "This complaint already has the maximum number of attachments.")
            return
        form = AttachmentUploadForm(request.POST, request.FILES)
        if not form.is_valid():
            for errors in form.errors.values():
                for error in errors:
                    messages.error(request, error)
            return
        store_attachment(request, complaint, form.cleaned_data["file"])
        messages.success(request, "File uploaded.")


# -------------------------------------------------------------- downloads
class AttachmentDownloadView(LoginRequiredMixin, View):
    """
    Files are NOT under any public URL. They are only reachable through this
    view, which applies the same object-level access control as the complaint.
    """

    def get(self, request, pk):
        attachment = (
            Attachment.objects.filter(pk=pk, complaint__in=visible_complaints(request.user))
            .select_related("complaint")
            .first()
        )
        if attachment is None:
            if Attachment.objects.filter(pk=pk).exists():
                log_event(request, "access_denied", detail=f"attachment={pk}")
            raise Http404
        try:
            handle = attachment.file.open("rb")
        except FileNotFoundError:
            raise Http404

        response = FileResponse(
            handle,
            as_attachment=True,                      # never render in the browser
            filename=attachment.original_name,
            content_type=attachment.content_type,    # our value, from the allow-list
        )
        response["Content-Security-Policy"] = "default-src 'none'; sandbox"
        response["Cache-Control"] = "private, no-store"
        log_event(request, "attachment_downloaded", attachment.complaint,
                  detail=attachment.original_name)
        return response
