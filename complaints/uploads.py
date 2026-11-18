import os

from accounts.utils import clean

from .audit import log_event
from .models import Attachment
from .validators import content_type_for


def store_attachment(request, complaint, uploaded):
    """Persist an already-validated upload and audit it."""
    uploaded.seek(0)
    attachment = Attachment(
        complaint=complaint,
        uploaded_by=request.user,
        original_name=clean(os.path.basename(uploaded.name), 100),
        content_type=content_type_for(uploaded.name),  # our value, not the client's
        size=uploaded.size,
    )
    # FileField.save() applies attachment_upload_path -> random filename
    attachment.file.save(uploaded.name, uploaded, save=False)
    attachment.save()
    log_event(
        request,
        "attachment_uploaded",
        complaint,
        detail=f"{attachment.original_name} ({attachment.size} bytes)",
    )
    return attachment
