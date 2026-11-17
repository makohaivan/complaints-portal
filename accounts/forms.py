from django import forms
from django.contrib.auth.forms import UserCreationForm

from .models import User


class StudentRegistrationForm(UserCreationForm):
    """
    Self-registration creates STUDENTS only.

    `role` is deliberately NOT a form field, and save() sets it server-side, so
    a tampered POST containing role=admin is ignored (mass-assignment defence).
    """

    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs["class"] = "form-control"

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data["email"]
        user.role = User.Role.STUDENT
        if commit:
            user.save()
        return user
