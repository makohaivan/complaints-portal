from django.urls import path

from config.ratelimit import post_rate_limit

from . import views

urlpatterns = [
    path("", views.ComplaintListView.as_view(), name="home"),
    path(
        "complaints/new/",
        post_rate_limit("complaint_create", limit=10, window=3600)(
            views.ComplaintCreateView.as_view()),
        name="complaint_create",
    ),
    path("complaints/<uuid:pk>/", views.ComplaintDetailView.as_view(), name="complaint_detail"),
    path(
        "complaints/<uuid:pk>/assign/",
        post_rate_limit("assign", limit=60, window=3600)(views.AssignComplaintView.as_view()),
        name="complaint_assign",
    ),
    path(
        "complaints/<uuid:pk>/respond/",
        post_rate_limit("respond", limit=60, window=3600)(views.RespondView.as_view()),
        name="complaint_respond",
    ),
    path(
        "complaints/<uuid:pk>/status/",
        post_rate_limit("status", limit=60, window=3600)(views.StatusUpdateView.as_view()),
        name="complaint_status",
    ),
    path(
        "complaints/<uuid:pk>/upload/",
        post_rate_limit("upload", limit=10, window=3600)(views.UploadAttachmentView.as_view()),
        name="complaint_upload",
    ),
    path("attachments/<uuid:pk>/download/", views.AttachmentDownloadView.as_view(),
         name="attachment_download"),
]
