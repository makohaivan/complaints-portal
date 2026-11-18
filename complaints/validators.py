"""
Secure file-upload validation (OWASP A04/A05/A08).

Defence in depth - an upload must pass ALL of these:
  1. extension on an allow-list (not a block-list)
  2. size under the cap
  3. real content matches the extension (magic bytes)
  4. images additionally parse as real images (Pillow) and are not decompression bombs
"""
import os
from pathlib import Path

from django.core.exceptions import ValidationError
from PIL import Image

MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB
MAX_ATTACHMENTS_PER_COMPLAINT = 3
MAX_IMAGE_PIXELS = 25_000_000

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8\xff"

# extension -> (content type we will serve, required leading bytes)
ALLOWED = {
    ".pdf": ("application/pdf", b"%PDF-"),
    ".png": ("image/png", PNG_MAGIC),
    ".jpg": ("image/jpeg", JPEG_MAGIC),
    ".jpeg": ("image/jpeg", JPEG_MAGIC),
}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg"}


def extension_of(name):
    return Path(os.path.basename(name or "")).suffix.lower()


def content_type_for(name):
    """The content type WE decide on - never the browser-supplied one."""
    return ALLOWED[extension_of(name)][0]


def validate_upload(uploaded):
    ext = extension_of(uploaded.name)
    if ext not in ALLOWED:
        raise ValidationError("Only PDF, PNG and JPG files are allowed.")

    if uploaded.size > MAX_UPLOAD_BYTES:
        raise ValidationError("File is too large. The maximum size is 2 MB.")
    if uploaded.size == 0:
        raise ValidationError("The file is empty.")

    uploaded.seek(0)
    head = uploaded.read(16)
    uploaded.seek(0)
    if not head.startswith(ALLOWED[ext][1]):
        raise ValidationError("The file content does not match its extension.")

    if ext in IMAGE_EXTENSIONS:
        try:
            image = Image.open(uploaded)
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise ValidationError("Image dimensions are too large.")
            image.verify()
        except ValidationError:
            raise
        except Exception:
            raise ValidationError("The file is not a valid image.")
        finally:
            uploaded.seek(0)

    return uploaded
