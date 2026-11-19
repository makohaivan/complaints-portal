from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from config.ratelimit import post_rate_limit

from .views import LoggedPasswordChangeView, RegisterView

urlpatterns = [
    # Login: django-axes locks one (username + IP) pair after 5 failures, and a
    # per-IP rate limit slows down password-spraying across many usernames.
    path(
        "login/",
        post_rate_limit("login", limit=30, window=600)(
            LoginView.as_view(
                template_name="registration/login.html",
                redirect_authenticated_user=True,
            )
        ),
        name="login",
    ),
    path("logout/", LogoutView.as_view(), name="logout"),  # POST only
    path(
        "register/",
        post_rate_limit("register", limit=5, window=3600)(RegisterView.as_view()),
        name="register",
    ),
    path("password/change/", LoggedPasswordChangeView.as_view(), name="password_change"),
]
