from django.conf.urls import url
from . import views

urlpatterns = [
    url(r"^$", views.homepage, name="home"),
    url(r"^accounts/login", views.login, name="login"),
    url(r"^accounts/logout", views.logout, name="logout"),
    url(
        r"^docker-registry-authenticate/",
        views.docker_registry_authenticate,
        name="docker_registry_authicate",
    ),
]
