from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

from .views import RegisterView

urlpatterns = [
    path(
        "login/",
        LoginView.as_view(
            template_name="registration/login.html",
            redirect_authenticated_user=True,
        ),
        name="login",
    ),
    path("logout/", LogoutView.as_view(), name="logout"),  # POST only (Django 5+)
    path("register/", RegisterView.as_view(), name="register"),
]
