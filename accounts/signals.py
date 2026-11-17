import logging

from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver

from .utils import clean, client_ip

log = logging.getLogger("security")


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    log.info("event=login_success user=%s role=%s ip=%s",
             clean(user.username), user.role, client_ip(request))


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    log.warning("event=login_failed username=%s ip=%s",
                clean(credentials.get("username", "")), client_ip(request))


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    if user:
        log.info("event=logout user=%s ip=%s", clean(user.username), client_ip(request))
