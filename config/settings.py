"""
Django settings for the Student Complaints Portal.
Security-relevant settings are annotated with the OWASP risk they address.
"""
from pathlib import Path

from decouple import Csv, config

BASE_DIR = Path(__file__).resolve().parent.parent

# --- A05 Security Misconfiguration: secrets and debug come from the environment
SECRET_KEY = config("SECRET_KEY")
DEBUG = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="127.0.0.1,localhost", cast=Csv())

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "axes",  # A07: brute-force lockout
    "accounts",
    "complaints",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",  # CSRF protection
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "axes.middleware.AxesMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# --- A03 Injection: Django ORM only (parameterised queries)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# --- A07 Identification and Authentication Failures
AUTH_USER_MODEL = "accounts.User"

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",  # strong, memory-hard
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # fallback for old hashes
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 10},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

AUTHENTICATION_BACKENDS = [
    "axes.backends.AxesStandaloneBackend",
    "django.contrib.auth.backends.ModelBackend",
]
AXES_FAILURE_LIMIT = 5          # lock after 5 failed logins
AXES_COOLOFF_TIME = 1           # hours
AXES_RESET_ON_SUCCESS = True
# Lock the (username + IP) PAIR, not the whole IP, so an attacker cannot lock out
# every student on a shared campus network (lockout denial of service).
AXES_LOCKOUT_PARAMETERS = [["username", "ip_address"]]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

# --- A02 / session management
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 30 * 60            # 30 minutes
SESSION_SAVE_EVERY_REQUEST = True       # sliding expiry
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True

# --- A05 Security headers
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Africa/Kampala"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]

# Uploads live OUTSIDE any publicly served path and are only served
# through an authorised view (see Phase 3).
MEDIA_ROOT = BASE_DIR / "media"
FILE_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = 2 * 1024 * 1024

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- A09 Security Logging and Monitoring Failures
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "security": {"format": "{asctime} {levelname} {name} {message}", "style": "{"},
    },
    "handlers": {
        "security_file": {
            "class": "logging.FileHandler",
            "filename": LOG_DIR / "security.log",
            "formatter": "security",
        },
        "console": {"class": "logging.StreamHandler", "formatter": "security"},
    },
    "loggers": {
        "security": {
            "handlers": ["security_file", "console"],
            "level": "INFO",
            "propagate": False,
        },
        "axes": {"handlers": ["security_file"], "level": "INFO", "propagate": False},
    },
}


# --- PHASE 4 HARDENING ---
import sys  # noqa: E402

ADMIN_URL = config("ADMIN_URL", default="admin/")  # change in .env to move the admin

# Rate limiting is switched off while running `manage.py test` so unrelated tests
# do not trip it; the dedicated rate-limit tests turn it back on.
RATELIMIT_ENABLED = "test" not in sys.argv

# Per-process cache used for rate-limit counters. Production: Redis (shared).
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}

# Friendly page when django-axes locks an account (HTTP 429).
AXES_LOCKOUT_TEMPLATE = "lockout.html"

SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
STATIC_ROOT = BASE_DIR / "staticfiles"

MIDDLEWARE += ["config.middleware.SecurityHeadersMiddleware"]


# --- PHASE 5 SCAN MODE ---
# For OWASP ZAP active scans ONLY. Honoured only when DEBUG=True, so it can never
# weaken a production deployment. Disables lockout and rate limiting so the scanner is
# not blocked after a few requests. Leave SCAN_MODE unset/False otherwise.
if DEBUG and config("SCAN_MODE", default=False, cast=bool):
    AXES_ENABLED = False
    RATELIMIT_ENABLED = False
