from functools import wraps

from django.conf import settings
from django.core.cache import cache
from django.shortcuts import render

from accounts.utils import client_ip
from complaints.audit import log_event


def post_rate_limit(scope, limit, window):
    """
    Allow at most `limit` POSTs per `window` seconds per user (or per IP when
    anonymous) to the wrapped view. Over the limit -> HTTP 429.

    Uses Django's cache. LocMemCache is per-process (fine for this project);
    production would use Redis so the counters are shared across workers.
    """

    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if request.method == "POST" and settings.RATELIMIT_ENABLED:
                who = f"u{request.user.pk}" if request.user.is_authenticated \
                    else f"ip{client_ip(request)}"
                key = f"rl:{scope}:{who}"
                cache.add(key, 0, window)
                try:
                    count = cache.incr(key)
                except ValueError:  # key expired between add and incr
                    cache.set(key, 1, window)
                    count = 1
                if count > limit:
                    log_event(request, "rate_limited", detail=f"scope={scope}")
                    response = render(request, "429.html", status=429)
                    response["Retry-After"] = str(window)
                    return response
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
