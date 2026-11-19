from django.conf import settings

# Public app pages: no scripts at all, styles only from our own origin.
APP_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'none'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

# Django's built-in admin needs its own scripts and some inline styles.
# Documented trade-off: relaxed ONLY under the admin URL prefix.
ADMIN_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])

PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"


class SecurityHeadersMiddleware:
    """
    Adds defence-in-depth headers to every response. Uses "only if missing" so a
    view can set a stricter header itself (the download view sets its own CSP).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        in_admin = request.path.startswith("/" + settings.ADMIN_URL)
        defaults = {
            "Content-Security-Policy": ADMIN_CSP if in_admin else APP_CSP,
            "Permissions-Policy": PERMISSIONS_POLICY,
            "Cross-Origin-Resource-Policy": "same-origin",
        }
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            # Stop the browser/proxies caching private pages (back-button after logout).
            defaults["Cache-Control"] = "no-store"

        for header, value in defaults.items():
            if header not in response:
                response[header] = value
        return response
