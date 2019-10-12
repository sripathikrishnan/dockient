from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import logout as django_logout
from django.contrib.auth.models import AnonymousUser
from django.conf import settings

from .models import AuthToken, AuthException
import re
import base64
import jwt
import time

BASIC_AUTH_HEADER_PATTERN = re.compile("Basic ([a-zA-Z0-9+/=_:-]+)")


def login(request):
    # This brings up google oauth consent screen
    return redirect("/login/google-oauth2/")


def logout(request):
    # this only logs out the user from django
    # we cannot logout the user from google
    django_logout(request)
    return render(request, "accounts/logged_out.html")


@login_required
def homepage(request):
    existing_tokens = AuthToken.objects.list_tokens(request.user)
    context = {"user": request.user, "existing_tokens": existing_tokens}
    if request.method == "POST":
        login_command = AuthToken.objects.get_docker_login(request.user)
        context["docker_login"] = login_command
    return render(request, "home.html", context=context)


# Intentionally disabled django @login_required
#
# This method is called by nginx whenever docker push / pull command is issued
# This method should return status = 200 if the user is authorized to perform the action
# Any other status code means nginx / docker registry should deny the action
def docker_registry_token_service(request):
    try:
        basic_auth_header = request.headers.get("Authorization", None)
        user = _authenticate(basic_auth_header)
        service = request.GET["service"]
        scope = request.GET["scope"]
        token = _generate_jwt(user, service, scope)
        return JsonResponse({"token": token.decode("ascii")})
    except AuthException as e:
        return JsonResponse({"error": str(e)}, status=401)


def _authenticate(basic_auth_header):
    if not basic_auth_header:
        raise AuthException("Empty Authorization Header")
    matcher = BASIC_AUTH_HEADER_PATTERN.match(basic_auth_header)
    if not matcher:
        raise AuthException("Invalid format of Authorization Header")

    b64_str = matcher.group(1)
    try:
        username_and_password = base64.b64decode(b64_str)
    except:
        raise AuthException("Basic auth header is not valid base64")

    try:
        username_and_password = username_and_password.decode("ascii")
    except:
        raise AuthException("Basic auth header contains non-ascii symbols")

    username, password = username_and_password.split(":")
    return AuthToken.objects.authenticate(username, password)


def authorize(user, service, scope):
    pass


# scope is a string like repository:samalba/my-app:pull,push
# parsed object is similar to
# {
#   "type": "repository",
#   "name": "samalba/my-app",
#   "actions": [
#        "push", "pull"
#   ]
# }
def _parse_scope(scope):
    _type, name, raw_actions = scope.split(":")
    if "," in raw_actions:
        actions = raw_actions.split(",")
    else:
        actions = [raw_actions]
    return {"type": _type, "name": name, "actions": actions}


def _generate_jwt(user, service, scope):
    access = _parse_scope(scope)
    # iat = issued at time
    iat = round(time.time())

    # nbf = not before. JWT is considered invalid before this time
    # provide a grace period of 60s for incorrect clock
    nbf = iat - 60
    exp = iat + settings.TOKEN_SERVICE_EXPIRY_IN_SECONDS

    jti = "some_random_string"
    claims = {
        "iss": settings.TOKEN_SERVICE_ISSUER,
        "sub": user.username,
        "aud": service,
        "exp": exp,
        "nbf": nbf,
        "iat": iat,
        "jti": jti,
        "access": access,
    }

    return jwt.encode(claims, settings.TOKEN_SERVICE_PRIVATE_KEY, algorithm="RS256")
