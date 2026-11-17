from django import forms

from .models import Complaint


class ComplaintForm(forms.ModelForm):
    description = forms.CharField(
        max_length=2000,
        widget=forms.Textarea(attrs={"class": "form-control", "rows": 6}),
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
