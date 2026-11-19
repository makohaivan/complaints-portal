from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import User

PASSWORD = "Str0ng#Test-Pass1"


class FindingFixTests(TestCase):
    """Regression tests for the issues found by the Phase 5 attack tests."""

    def setUp(self):
        cache.clear()
        self.alice = User.objects.create_user("alice", password=PASSWORD)
        self.bob = User.objects.create_user("bob", password=PASSWORD)

    def test_f1_locking_one_user_does_not_lock_other_users(self):
        for _ in range(5):
            self.client.post(reverse("login"), {"username": "alice", "password": "wrong"})
        locked = self.client.post(reverse("login"), {"username": "alice", "password": PASSWORD})
        self.assertEqual(locked.status_code, 429)
        r = self.client.post(reverse("login"), {"username": "bob", "password": PASSWORD})
        self.assertEqual(r.status_code, 302)  # bob, same IP, can still log in

    @override_settings(RATELIMIT_ENABLED=True)
    def test_f1_password_spraying_is_rate_limited_per_ip(self):
        for i in range(30):
            self.client.post(reverse("login"), {"username": f"user{i}", "password": "x"})
        r = self.client.post(reverse("login"), {"username": "user31", "password": "x"})
        self.assertEqual(r.status_code, 429)
