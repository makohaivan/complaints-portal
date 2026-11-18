from django.urls import path

from . import views

urlpatterns = [
    path("", views.ComplaintListView.as_view(), name="home"),
    path("complaints/new/", views.ComplaintCreateView.as_view(), name="complaint_create"),
    path("complaints/<uuid:pk>/", views.ComplaintDetailView.as_view(), name="complaint_detail"),
    path("complaints/<uuid:pk>/assign/", views.AssignComplaintView.as_view(), name="complaint_assign"),
    path("complaints/<uuid:pk>/respond/", views.RespondView.as_view(), name="complaint_respond"),
    path("complaints/<uuid:pk>/status/", views.StatusUpdateView.as_view(), name="complaint_status"),
    path("complaints/<uuid:pk>/upload/", views.UploadAttachmentView.as_view(), name="complaint_upload"),
    path("attachments/<uuid:pk>/download/", views.AttachmentDownloadView.as_view(),
         name="attachment_download"),
]
