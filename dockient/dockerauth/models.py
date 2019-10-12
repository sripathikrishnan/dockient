from django.db import models
from django.db.models import F
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.utils import timezone

import datetime
import secrets
import pytz

# The default expiry for newly created tokens
DEFAULT_EXPIRY = datetime.timedelta(days=365)

# Max number of simultaneously active tokens for a user
MAX_ACTIVE_TOKENS = 5


class AuthException(Exception):
    pass


class AuthTokenManager(models.Manager):
    def authenticate(self, access_key, secret_access_key):
        try:
            now = timezone.now()
            token = AuthToken.objects.select_related("user").get(
                access_key=access_key,
                secret_access_key=secret_access_key,
                expires_at__gt=now,
            )
            return token.user
        except ObjectDoesNotExist as e:
            raise AuthException("Invalid credentials")

    def get_docker_login(self, user, expiry=DEFAULT_EXPIRY):
        """Generate a docker login command

        This creates a new auth token every time it is called. For security reasons,
        we shouldn't reveal a token that was previously generated.
         """
        if not user.is_authenticated:
            raise Exception("Cannot create auth token for unauthenticated user ", user)
        access_key, secret_access_key = self.create_new_token(user, expiry)
        return "docker login -u {0} -p {1} {2}".format(
            access_key, secret_access_key, settings.ADVERTISED_URL
        )

    def list_tokens(self, user):
        now = timezone.now()
        tokens = (
            AuthToken.objects.filter(user=user, expires_at__gt=now)
            .order_by("-created_at")
            .values()
        )

        # Mask the tokens before returning
        for token in tokens:
            del token["secret_access_key"]
        return tokens

    def delete_token(self, user, id):
        token = AuthToken.objects.get(id=id, user=user)
        token.delete()

    def create_new_token(self, user, expiry):
        now = timezone.now()
        num_active_tokens = AuthToken.objects.filter(
            user=user, expires_at__gt=now
        ).count()
        if num_active_tokens >= MAX_ACTIVE_TOKENS:
            raise Exception("Too many active tokens")

        access_key = secrets.token_urlsafe(20)
        secret_access_key = secrets.token_urlsafe(20)
        expires_at = now + expiry
        AuthToken.objects.create(
            user=user,
            access_key=access_key,
            secret_access_key=secret_access_key,
            expires_at=expires_at,
        )
        return (access_key, secret_access_key)


# One user can have many AuthTokens
# MAX_ACTIVE_TOKENS can be valid simultaneously
class AuthToken(models.Model):
    objects = AuthTokenManager()
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    access_key = models.CharField(max_length=100, unique=True)
    secret_access_key = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()


class Namespace(models.Model):
    name = models.CharField(max_length=100, unique=True)
    owner = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)


class NamespaceAccessRule(models.Model):
    namespace = models.ForeignKey(Namespace, on_delete=models.CASCADE)
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    action = models.CharField(
        max_length=10,
        choices=(("pull", "pull only"), ("push", "pull and push"), ("admin", "admin")),
    )
