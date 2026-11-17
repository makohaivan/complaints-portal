import logging

from accounts.utils import clean, client_ip

from .models import AuditLog

security_logger = logging.getLogger("security")


def log_event(request, action, complaint=None, detail=""):
    """Write to the database audit trail AND the security log file."""
    user = request.user if request.user.is_authenticated else None
    ip = client_ip(request)
    AuditLog.objects.create(
        user=user,
        action=action,
        complaint=complaint,
        ip_address=ip if ip != "unknown" else None,
        detail=clean(detail, 255),
    )
    security_logger.info(
        "event=%s user=%s complaint=%s ip=%s detail=%s",
        action,
        user.username if user else "anonymous",
        complaint.pk if complaint else "-",
        ip,
        clean(detail),
    )
