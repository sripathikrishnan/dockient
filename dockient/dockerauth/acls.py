from .models import Namespace, NamespaceAccessRule
from django.core.exceptions import ObjectDoesNotExist


class Request:
    """ `user` is trying to perform `actions` on `image` under `namespace`"""

    def __init__(self, user, tipe, namespace, image, actions):
        # The user object
        self.user = user

        # The type of request, usually repository
        self.tipe = tipe

        # the namespace the image belongs to
        self.namespace = namespace

        # the image that is being requested
        self.image = image

        # The actions the user wants to perform on the image
        # Usually *, push or pull
        self.actions = actions


class Rule:
    def matches(self, request):
        pass

    def allowed_actions(self):
        pass


DENY = set()
COMPLETE_ACCESS = set(["push", "pull"])


class ACL:
    def __init__(self, rules):
        self.rules = rules

    def resolve(self, request):
        for rule in self.rules:
            if rule.matches(request):
                return rule.allowed_actions()
        return DENY


class NamespaceAccess(Rule):
    def matches(self, request):
        return True

    def allowed_actions(self, request):
        try:
            namespace = Namespace.objects.get(name=request.namespace)
        except ObjectDoesNotExist:
            return DENY

        if namespace.owner == request.user:
            return COMPLETE_ACCESS

        try:
            action = NamespaceAccessRule.objects.get(
                namespace=namespace, user=request.user
            ).action
            if action == "pull":
                return set(["pull"])
            elif action in ("push", "admin"):
                return set(["push", "pull"])
            else:
                raise Exception("Invalid allowed_action " + action)

            return set([action])
        except ObjectDoesNotExist:
            return DENY


class BackdoorAccess(Rule):
    def __init__(self, admins):
        self.admins = set(admins)

    def matches(self, request: Request):
        if request.account in self.admins:
            return True

    def allowed_actions(self):
        return set(["*"])
