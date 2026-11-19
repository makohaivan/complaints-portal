import logging

from django.contrib import messages
from django.contrib.auth.views import PasswordChangeView
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import CreateView

from .forms import StudentRegistrationForm
from .utils import clean, client_ip

log = logging.getLogger("security")


class RegisterView(CreateView):
    form_class = StudentRegistrationForm
    template_name = "accounts/register.html"
    success_url = reverse_lazy("login")

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("home")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        response = super().form_valid(form)
        log.info("event=register user=%s ip=%s",
                 clean(self.object.username), client_ip(self.request))
        messages.success(self.request, "Account created. You can now log in.")
        return response


class LoggedPasswordChangeView(PasswordChangeView):
    """Requires the OLD password; keeps the session; logs the event."""

    template_name = "accounts/password_change.html"
    success_url = reverse_lazy("home")

    def form_valid(self, form):
        response = super().form_valid(form)
        log.info("event=password_changed user=%s ip=%s",
                 clean(self.request.user.username), client_ip(self.request))
        messages.success(self.request, "Your password has been changed.")
        return response
