from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods

from .models import AuthToken


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
@require_http_methods(["POST"])
def docker_registry_authenticate(request):
    pass
