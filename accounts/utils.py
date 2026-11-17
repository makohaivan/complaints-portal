def client_ip(request):
    """
    Use REMOTE_ADDR only. X-Forwarded-For is client-controlled and would let an
    attacker forge the IP written to the logs (and bypass IP-based lockout).
    Behind a trusted reverse proxy you would configure that proxy instead.
    """
    if request is None:
        return "unknown"
    return request.META.get("REMOTE_ADDR", "unknown")


def clean(value, limit=150):
    """Neutralise CR/LF so user-supplied text cannot forge extra log lines."""
    return str(value).replace("\r", " ").replace("\n", " ")[:limit]
