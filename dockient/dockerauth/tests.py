from django.test import TestCase, override_settings, Client
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.urls import reverse

import re
import datetime
import time
import base64
import jwt

from .models import (
    AuthToken,
    MAX_ACTIVE_TOKENS,
    AuthException,
    Namespace,
    NamespaceAccessRule,
)
from .views import docker_registry_token_service

from .acls import Request, NamespaceAccess

DUMMY_PRIVATE_KEY = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCyWlCnJEIp245b
PevGE/Ja8JAvOVYYI5jjVcnx5fDv/IpHMTG/YGOMxLm9ZFjUF/GzE6FyuvFPNH+C
B0hFY59lnPGxtQ+yVG/RrI1xYJPmI23cma4qWUBDCc8r669VQO/eLdTRo/qAgbZk
E0yhEUEFsfiaJwcd6Z6UEHgHDWRUGekHejsmyxzblxBJXXitaco2m/I/jAMyI0/Q
VjlEmvCkVXem2clGqbcARQVCzqms6KVRJPNl0A+Z5MInumCSL11wS0sPlnAxj8Dh
Su6N9ef/GxM/AHiQ0nQRFOWc+WAu5BFvXW6eg3MEvSeP5SSKl1Z0sUau4js7M2h/
oKEjXRzTAgMBAAECggEActJSOkjNj8UZ0QP8Vnlg/csCCGURWFkShMkmSeWPR/F9
1HeHX33emTHNonCH/4Oqx29L8WEJGcTikgO+M23/oJt5vr6ibFyP4J0GMofKr87/
W5ZU2k67YG1gQxZouqojwxYefRjknPblRWhnXQqOoewB8LxPiKJuxUQVAfVNMhap
HPNkUYlgJ0Q1Cp0uOzwxKCVza8J1C3R2jwh3fP6QDvrbFN/fQPQWvcj2mL05vx9l
WuuaqmpE+Nm8WCDJQTToH651+8A9zq1WqDjDEr7JOeAgsjSxixHZc0zXP/eChWde
oylplWpkK1bzZbH67mqiUBvzR4sSZQPsOcKBxqgEgQKBgQDWwDj+MOi2U6lZvsv5
/XsTuoZy1iyyRRRTNwYFQyPzbLpkramZDZ6hr0Y0JL8dWi2FSeG/aHB3Yvr21W1f
IueSkGdH4f1lcRGhkkSpPaCn02HWOEV9AzphaE91CqnSz5HAN+1MacA0Qq7qN08+
Lik3MHLgHcwuNlGXcO8IUbXijQKBgQDUnFFxWpICDJxJCswss102NzbSsuxeVfHA
35rqSfJlTUkT2UePQle605Hd0xd+XaVBQ6P1PVG3QtyoKs6AgBYgwzZNSQigQv9m
iBxu/QbueVSySOgBSEIhMKUlKOOuZfXGhbuVpC+48m5bRFw7Ay4LfoCWsn3dvZZH
5bvRQ5DU3wKBgETA6f5HvlmRU2jOMxPoWZ0pXJ4rf8fbYfR6a00H/9yRdOOCzgeY
Wq89JGbRVPaaxnQkAUh8sXUnlV2tWwTYcfd0j/xtl+kAWDq4T483kdXpUSt6fJTX
kbtZ4AaC0XgSyIEX5rtOKCETMFkAODiaIsvukPi70YECFwE7QOwS7P6JAoGAZ7cB
u8w04a8JJlCQHVY6KFJy+gGycKp4TmBGD/iWuHglJ/ucfvQcG9VNmOp60XgZP2ch
umZ5UG7beWW4atMQ+FaCTN1NyfAk6v2G8VWZZgfmGzqZgtae+9XhGemCd/bhGEDw
qyT26r/Iudj1LQx2D8FcNSdJYzwy7UvSfVj6c/0CgYEAn9sOOSBNqLQXgXiTgr3R
HR79TGnTnWmWRjqV+ke2C/AEYQIIcMvuaT/YSNBbgQwCUFQVp9OwIwQqycQZY1iP
RVJKAg0ocWv2TV/Ct7GxTH8U6XqLx6JIDny4hrLSooCQfjAkv+JdEePjMHo9rjhP
PwSsiqoL6m1YM0jJ/oGU85E=
-----END PRIVATE KEY-----"""

DUMMY_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAslpQpyRCKduOWz3rxhPy
WvCQLzlWGCOY41XJ8eXw7/yKRzExv2BjjMS5vWRY1BfxsxOhcrrxTzR/ggdIRWOf
ZZzxsbUPslRv0ayNcWCT5iNt3JmuKllAQwnPK+uvVUDv3i3U0aP6gIG2ZBNMoRFB
BbH4micHHemelBB4Bw1kVBnpB3o7Jssc25cQSV14rWnKNpvyP4wDMiNP0FY5RJrw
pFV3ptnJRqm3AEUFQs6prOilUSTzZdAPmeTCJ7pgki9dcEtLD5ZwMY/A4UrujfXn
/xsTPwB4kNJ0ERTlnPlgLuQRb11unoNzBL0nj+UkipdWdLFGruI7OzNof6ChI10c
0wIDAQAB
-----END PUBLIC KEY-----"""


class AuthTokenTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="testuser", password="12345678"
        )
        self.anonymous = AnonymousUser()

    @override_settings(ADVERTISED_URL="http://tokenservice.example.com")
    def test_basic_flow(self):
        login_prompt = AuthToken.objects.get_docker_login(self.user)
        access_key, secret_access_key = extract_credentials(login_prompt)
        can_authenticate = AuthToken.objects.authenticate(access_key, secret_access_key)
        self.assertTrue(can_authenticate)

    @override_settings(ADVERTISED_URL="http://tokenservice.example.com")
    def test_expiry(self):
        expires_in = datetime.timedelta(milliseconds=10)
        login_prompt = AuthToken.objects.get_docker_login(self.user, expires_in)
        access_key, secret_access_key = extract_credentials(login_prompt)
        time.sleep(0.5)
        with self.assertRaises(AuthException):
            AuthToken.objects.authenticate(access_key, secret_access_key)

    @override_settings(ADVERTISED_URL="http://tokenservice.example.com")
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


class TokenServiceTests(TestCase):
    def setUp(self):
        api_user = get_user_model().objects.create_user(
            username="apiuser", password="12345678"
        )
        docker_login = AuthToken.objects.get_docker_login(api_user)
        self.access_key, self.secret_access_key = extract_credentials(docker_login)

        raw_auth_string = ("%s:%s" % (self.access_key, self.secret_access_key)).encode(
            "ascii"
        )
        base64string = base64.b64encode(raw_auth_string)
        self.auth_header = "Basic %s" % base64string.decode("ascii")

    @override_settings(TOKEN_SERVICE_PRIVATE_KEY=DUMMY_PRIVATE_KEY)
    def test_without_credentials(self):
        with self.assertRaisesRegexp(Exception, "Empty Authorization Header"):
            self.get_token(None)

    @override_settings(TOKEN_SERVICE_PRIVATE_KEY=DUMMY_PRIVATE_KEY)
    def test_correct_credentials(self):
        token = self.get_token(self.auth_header)
        self.assertEqual(
            token["access"],
            {
                "type": "repository",
                "name": "samalba/my-app",
                "actions": ["pull", "push"],
            },
        )
        self.assertEqual(token["sub"], "apiuser")

    @override_settings(TOKEN_SERVICE_PRIVATE_KEY=DUMMY_PRIVATE_KEY)
    def test_invalid_authorization_header(self):
        with self.assertRaisesRegexp(
            Exception, "Invalid format of Authorization Header"
        ):
            self.get_token("random-string")

    @override_settings(TOKEN_SERVICE_PRIVATE_KEY=DUMMY_PRIVATE_KEY)
    def test_invalid_b64_token(self):
        with self.assertRaisesRegexp(
            Exception, "Invalid format of Authorization Header"
        ):
            self.get_token("Basic &(%*)$(())")

    # Internal helper method to make our tests easier to
    def get_token(self, basic_auth_header):
        c = Client()
        data = {
            "service": "Registry Service",
            "scope": "repository:samalba/my-app:pull,push",
        }
        if basic_auth_header:
            response = c.get("/token/", data=data, HTTP_AUTHORIZATION=basic_auth_header)
        else:
            response = c.get("/token/", HTTP_AUTHORIZATION=basic_auth_header)

        if "error" in response.json() or response.status_code != 200:
            raise Exception(response.json()["error"])

        return jwt.decode(
            response.json()["token"], DUMMY_PUBLIC_KEY, audience="Registry Service"
        )


class AclTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(
            username="owner", password="12345678"
        )
        self.collaborator = get_user_model().objects.create_user(
            username="collaborator", password="12345678"
        )
        self.reader = get_user_model().objects.create_user(
            username="reader", password="12345678"
        )
        self.randomjoe = get_user_model().objects.create_user(
            username="randomjoe", password="12345678"
        )
        self.anonymous = AnonymousUser()

        # Create a namespace
        self.namespace = Namespace(owner=self.owner, name="example")
        self.namespace.save()

        # Grant collaborattor push access
        NamespaceAccessRule(
            namespace=self.namespace, user=self.collaborator, action="push"
        ).save()
        NamespaceAccessRule(
            namespace=self.namespace, user=self.reader, action="pull"
        ).save()

    def test_owner_can_push(self):
        self.check_user_can_perform(self.owner, "push")

    def test_owner_can_pull(self):
        self.check_user_can_perform(self.owner, "pull")

    def test_collaborator_can_push(self):
        self.check_user_can_perform(self.collaborator, "push")

    def test_collaborator_can_pull(self):
        self.check_user_can_perform(self.collaborator, "pull")

    def test_reader_cannot_push(self):
        self.check_user_cannot_perform(self.reader, "push")

    def test_reader_can_pull(self):
        self.check_user_can_perform(self.reader, "pull")

    def check_user_can_perform(self, user, action):
        request = Request(
            user=user,
            tipe="repository",
            namespace=self.namespace.name,
            image="random",
            actions=action,
        )
        allowed_actions = NamespaceAccess().allowed_actions(request)
        self.assertTrue(action in allowed_actions)

    def check_user_cannot_perform(self, user, action):
        request = Request(
            user=user,
            tipe="repository",
            namespace=self.namespace.name,
            image="random",
            actions=action,
        )
        allowed_actions = NamespaceAccess().allowed_actions(request)
        self.assertFalse(action in allowed_actions)


def extract_credentials(login_prompt):
    matcher = re.match(".*-u ([^ ]*) -p ([^ ]*).*", login_prompt)
    if not matcher:
        raise Exception("docker login prompt is incorrect")
    access_key = matcher.group(1)
    secret_access_key = matcher.group(2)
    return (access_key, secret_access_key)
