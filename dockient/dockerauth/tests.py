from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
import re
import datetime
import time

from .models import AuthToken, MAX_ACTIVE_TOKENS


class AuthTokenTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="testuser", password="12345678"
        )
        self.anonymous = AnonymousUser()

    def test_basic_flow(self):
        login_prompt = AuthToken.objects.get_docker_login(self.user)
        username, password = self.extract_credentials(login_prompt)
        can_authenticate = AuthToken.objects.authenticate(username, password)
        self.assertTrue(can_authenticate)

    def test_expiry(self):
        expires_in = datetime.timedelta(milliseconds=10)
        login_prompt = AuthToken.objects.get_docker_login(self.user, expires_in)
        username, password = self.extract_credentials(login_prompt)
        time.sleep(0.5)
        can_authenticate = AuthToken.objects.authenticate(username, password)
        self.assertFalse(can_authenticate)

    def test_anonymous_user_cannot_authenticate(self):
        with self.assertRaisesRegexp(
            Exception, "Cannot create auth token for unauthenticated user "
        ):
            AuthToken.objects.get_docker_login(self.anonymous)

    def test_user_cannot_have_several_active_tokens(self):
        for _ in range(MAX_ACTIVE_TOKENS):
            AuthToken.objects.get_docker_login(self.user)
        with self.assertRaisesRegexp(Exception, "Too many active tokens"):
            AuthToken.objects.get_docker_login(self.user)

    def extract_credentials(self, login_prompt):
        matcher = re.match(".*-u ([^ ]*) -p ([^ ]*).*", login_prompt)
        self.assertIsNotNone(matcher)
        username = matcher.group(1)
        password = matcher.group(2)
        return (username, password)
