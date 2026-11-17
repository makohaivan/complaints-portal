from django.urls import path

from . import views

urlpatterns = [
    path("", views.ComplaintListView.as_view(), name="home"),
    path("complaints/new/", views.ComplaintCreateView.as_view(), name="complaint_create"),
    path("complaints/<uuid:pk>/", views.ComplaintDetailView.as_view(), name="complaint_detail"),
]
