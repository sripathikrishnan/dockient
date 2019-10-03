from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse

import re
import datetime
import time
import base64

from .models import AuthToken, MAX_ACTIVE_TOKENS


class AuthTokenTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="testuser", password="12345678"
        )
        self.anonymous = AnonymousUser()

    def test_basic_flow(self):
        login_prompt = AuthToken.objects.get_docker_login(self.user)
        username, password = extract_credentials(login_prompt)
        can_authenticate = AuthToken.objects.authenticate(username, password)
        self.assertTrue(can_authenticate)

    def test_expiry(self):
        expires_in = datetime.timedelta(milliseconds=10)
        login_prompt = AuthToken.objects.get_docker_login(self.user, expires_in)
        username, password = extract_credentials(login_prompt)
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


class RegistryApiAccessTests(TestCase):
    def setUp(self):
        api_user = get_user_model().objects.create_user(
            username="apiuser", password="12345678"
        )
        docker_login = AuthToken.objects.get_docker_login(api_user)
        self.username, self.password = extract_credentials(docker_login)

        raw_auth_string = ("%s:%s" % (self.username, self.password)).encode("ascii")
        base64string = base64.b64encode(raw_auth_string)
        self.auth_header = "Basic %s" % base64string.decode("ascii")

    def test_without_basic_auth(self):
        response = self.client.get(reverse("docker_registry_authicate"))
        self.assertEqual(response.status_code, 401)

    def test_correct_credentials(self):
        response = self.client.get(
            reverse("docker_registry_authicate"), HTTP_AUTHORIZATION=self.auth_header
        )
        self.assertEqual(response.status_code, 200)

    def test_invalid_header_format(self):
        response = self.client.get(
            reverse("docker_registry_authicate"), HTTP_AUTHORIZATION="random-string"
        )
        self.assertEqual(response.status_code, 401)

    def test_invalid_b64_token(self):
        response = self.client.get(
            reverse("docker_registry_authicate"),
            HTTP_AUTHORIZATION="Basic non-b64-string",
        )
        self.assertEqual(response.status_code, 400)


def extract_credentials(login_prompt):
    matcher = re.match(".*-u ([^ ]*) -p ([^ ]*).*", login_prompt)
    if not matcher:
        raise Exception("docker login prompt is incorrect")
    username = matcher.group(1)
    password = matcher.group(2)
    return (username, password)
