from django.contrib import admin

from .models import AuditLog, Complaint, ComplaintResponse


@admin.register(Complaint)
class ComplaintAdmin(admin.ModelAdmin):
    list_display = ("title", "student", "status", "assigned_to", "created_at")
    list_filter = ("status", "category")


admin.site.register(ComplaintResponse)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Read-only: even administrators cannot edit or delete audit records."""

    list_display = ("created_at", "user", "action", "complaint", "ip_address", "detail")
    list_filter = ("action",)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
