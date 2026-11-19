from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path(settings.ADMIN_URL, admin.site.urls),  # configurable via .env (ADMIN_URL)
    path("accounts/", include("accounts.urls")),
    path("", include("complaints.urls")),
]
