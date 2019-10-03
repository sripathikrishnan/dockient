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


class AuthTokenManager(models.Manager):
    def authenticate(self, username, auth_token):
        try:
            now = timezone.now()
            token = AuthToken.objects.get(
                user__username=username, token=auth_token, expires_at__gt=now
            )
            return True
        except ObjectDoesNotExist as e:
            return False

    def get_docker_login(self, user, expiry=DEFAULT_EXPIRY):
        """Generate a docker login command

        This creates a new auth token every time it is called. For security reasons,
        we shouldn't reveal a token that was previously generated.
         """
        if not user.is_authenticated:
            raise Exception("Cannot create auth token for unauthenticated user ", user)
        user_name, auth_token = self.create_new_token(user, expiry)
        return "docker login -u {0} -p {1} -e none {2}".format(
            user_name, auth_token, settings.ADVERTISED_URL
        )

    def create_new_token(self, user, expiry):
        now = timezone.now()
        num_active_tokens = AuthToken.objects.filter(
            user=user, expires_at__gt=now
        ).count()
        if num_active_tokens >= MAX_ACTIVE_TOKENS:
            raise Exception("Too many active tokens")

        auth_token = secrets.token_urlsafe(60)
        user_name = user.username
        expires_at = now + expiry
        AuthToken.objects.create(user=user, token=auth_token, expires_at=expires_at)
        return (user_name, auth_token)


class AuthToken(models.Model):
    objects = AuthTokenManager()
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
