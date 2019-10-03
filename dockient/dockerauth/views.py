from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.http import HttpResponse
from django.contrib.auth import logout as django_logout

from .models import AuthToken
import re
import base64

BASIC_AUTH_HEADER_PATTERN = re.compile("Basic (.+)")


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
    context = {"user": request.user}
    if request.method == "POST":
        login_command = AuthToken.objects.get_docker_login(request.user)
        context["docker_login"] = login_command
    return render(request, "home.html", context=context)


# Intentionally disabled django @login_required
# This method is called by nginx whenever docker push / pull command is issued
# This method should return status = 200 if the user is authorized to perform the action
# Any other status code means nginx / docker registry should deny the action
def docker_registry_authenticate(request):
    if "Authorization" in request.headers:
        basic_auth_header = request.headers["Authorization"]
        matcher = BASIC_AUTH_HEADER_PATTERN.match(basic_auth_header)
        if matcher:
            b64_str = matcher.group(1)
            try:
                username_and_password = base64.b64decode(b64_str)
            except:
                return HttpResponse(status=400)

            try:
                username_and_password = username_and_password.decode("ascii")
            except:
                return HttpResponse(status=400)

            username, password = username_and_password.split(":")
            is_authenticated = AuthToken.objects.authenticate(username, password)
            if is_authenticated:
                return HttpResponse(status=200)

    not_logged_in = HttpResponse(status=401)
    not_logged_in[
        "WWW-Authenticate"
    ] = 'Basic realm="User Visible Realm", charset="UTF-8"'
    return not_logged_in
