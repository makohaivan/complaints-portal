from django import forms

from accounts.models import User

from .models import Complaint, ComplaintResponse
from .validators import validate_upload

UPLOAD_ACCEPT = ".pdf,.png,.jpg,.jpeg"


class ComplaintForm(forms.ModelForm):
    description = forms.CharField(
        max_length=2000,
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 6}),
    )
    attachment = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={"class": "form-control", "accept": UPLOAD_ACCEPT}),
        help_text="Optional. PDF, PNG or JPG, maximum 2 MB.",
    )

    class Meta:
        model = Complaint
        # Only these fields can be set by the client. student, status and
        # assigned_to are set by the server and can never be posted.
        fields = ("title", "category", "description")
        widgets = {
            "title": forms.TextInput(attrs={"class": "form-control", "maxlength": 150}),
            "category": forms.Select(attrs={"class": "form-select"}),
        }

    def clean_attachment(self):
        f = self.cleaned_data.get("attachment")
        if f:
            validate_upload(f)
        return f


class AttachmentUploadForm(forms.Form):
    file = forms.FileField(
        widget=forms.FileInput(attrs={"class": "form-control", "accept": UPLOAD_ACCEPT}),
    )

    def clean_file(self):
        f = self.cleaned_data["file"]
        validate_upload(f)
        return f


class AssignForm(forms.Form):
    # The queryset is the validation: only active STAFF accounts are valid
    # choices, so an admin (or a tampered POST) cannot "assign" to a student.
    staff = forms.ModelChoiceField(
        queryset=User.objects.filter(role=User.Role.STAFF, is_active=True).order_by("username"),
        widget=forms.Select(attrs={"class": "form-select"}),
    )


class ResponseForm(forms.ModelForm):
    class Meta:
        model = ComplaintResponse
        fields = ("message",)
        widgets = {
            "message": forms.Textarea(
                attrs={"class": "form-control", "rows": 4, "maxlength": 2000}
            ),
        }


class StatusForm(forms.Form):
    status = forms.ChoiceField(widget=forms.Select(attrs={"class": "form-select"}))

    def __init__(self, *args, current, **kwargs):
        super().__init__(*args, **kwargs)
        labels = dict(Complaint.Status.choices)
        allowed = Complaint.ALLOWED_TRANSITIONS.get(current, [])
        # Only legal next states are valid choices (server-side state machine).
        self.fields["status"].choices = [(s, labels[s]) for s in allowed]
