from urllib.parse import urlparse, urlencode, urlunparse

from django.contrib import admin
from django.contrib.admin.options import ModelAdmin
from django.http import (HttpResponseForbidden, HttpResponseBadRequest, HttpResponseRedirect, QueryDict)
from django.urls import reverse
from django.urls import re_path
from django.utils import timezone
from django.views.generic.base import View
from itsdangerous import URLSafeTimedSerializer
from .models import Token, Consumer
import datetime
from webservices.models import Provider
from webservices.sync import provider_for_django
from django.contrib.auth.views import LoginView
import json
import logging
import re
from django.contrib.auth import authenticate, login, logout
from django.contrib.sites.models import Site
from django.core.signing import BadSignature, SignatureExpired, loads
from django.http import HttpResponse
from django.middleware.csrf import CSRF_TOKEN_LENGTH
from django.shortcuts import redirect, render
from django.utils.decorators import method_decorator
from django.utils.safestring import mark_safe
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from .context_processors import microsoft
from .utils import get_hook, get_scheme
from .conf import config
logger = logging.getLogger("django")

# Microsoft side

def login_to_ms_redirect(request):
    url = microsoft(request)["microsoft_authorization_url"]
    return redirect(url)

def microsoft_logout(request):
    logout(request)
    redirect_url = request.GET.get('redirect_url')
    _config_url = f"https://login.microsoftonline.com/{config.MICROSOFT_AUTH_TENANT_ID}/oauth2/v2.0/logout?post_logout_redirect_uri={redirect_url}"
    return HttpResponseRedirect(_config_url) 
    
class AuthenticateCallbackView(View):
    """Authentication callback for Microsoft to call as part of OAuth2
        implicit grant flow
    For more details:
    https://developer.microsoft.com/en-us/graph/docs/get-started/rest
    """

    messages = {
        "bad_state": _(
            "An invalid state variable was provided. "
            "Please refresh the page and try again later."
        ),
        "missing_code": _(
            "No authentication code was provided from " "Microsoft. Please try again."
        ),
        "login_failed": _(
            "Failed to authenticate you for an unknown reason. "
            "Please try again later."
        ),
    }

    # manually mark methods csrf_exempt to handle CSRF processing ourselves
    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        domain = Site.objects.get_current(self.request).domain

        scheme = get_scheme(self.request)

        self.context = {
            "base_url": "{0}://{1}/".format(scheme, domain),
            "message": {},
        }

        # validates state using Django CSRF system and sets next path value
        state = self._parse_state(kwargs.get("state"))
        self._check_csrf(state)
        if "next" in state:
            self.context["next"] = state["next"]

        # validates response from Microsoft
        self._check_microsoft_response(
            kwargs.get("error"), kwargs.get("error_description")
        )

        # validates the code param and logs user in
        self._authenticate(kwargs.get("code"))

        # populates error_description if it does not exist yet
        if (
            "error" in self.context["message"]
            and "error_description" not in self.context["message"]
        ):
            self.context["message"]["error_description"] = self.messages[
                self.context["message"]["error"]
            ]

        function = get_hook("MICROSOFT_AUTH_CALLBACK_HOOK")
        if function is not None:
            self.context = function(self.request, self.context)

        self.context["message"] = mark_safe(  # nosec
            json.dumps({"microsoft_auth": self.context["message"]})
        )
        return self.context

    def _parse_state(self, state):
        if state is None:
            state = ""

        try:
            state = loads(state, salt="microsoft_auth", max_age=300)
        except BadSignature:  # pragma: no branch
            logger.debug("state has been tempered with")
            state = {}
        except SignatureExpired:  # pragma: no cover
            logger.debug("state has expired")
            state = {}

        return state

    def _check_csrf(self, state):
        token = state.get("token", "")

        checks = (
            re.search("[a-zA-Z0-9]", token),
            len(token) == CSRF_TOKEN_LENGTH,
        )

        # validate token parameter
        if not all(checks):
            logger.debug("State validation failed:")
            logger.debug("state: {}".format(state))
            logger.debug("checks: {}".format(checks))
            self.context["message"] = {"error": "bad_state"}

    def _check_microsoft_response(self, error, error_description):
        if "error" not in self.context["message"]:
            if error is not None:
                self.context["message"] = {
                    "error": error,
                    "error_description": error_description,
                }

    def _authenticate(self, code):
        if "error" not in self.context["message"]:
            if code is None:
                self.context["message"] = {"error": "missing_code"}
            else:
                # authenticate user using Microsoft code
                user = authenticate(self.request, code=code)
                if user is None:
                    # this should not fail at this point except for network
                    # error while retrieving profile or database error
                    # adding new user
                    self.context["message"] = {"error": "login_failed"}
                else:
                    login(self.request, user)

    def post(self, request):
        """main callback for Microsoft to call
        validates Microsoft response, attempts to authenticate user and
        returns simple HTML page with Javascript that will post a message
        to parent window with details of result"""

        context = self.get_context_data(**request.POST.dict())

        status_code = 200
        if "error" in context["message"]:
            status_code = 400

        return render(
            request,
            "auth_callback.html",
            context,
            status=status_code,
        )

 
class AuthenticateCallbackRedirect(AuthenticateCallbackView):
    redirect = True

    def post(self, request):
        """main callback for Microsoft to call
        validates Microsoft response, attempts to authenticate user and
        redirects to app root on success. Returns HTTP 401 on error."""

        context = self.get_context_data(**request.POST.dict())
        print(context)
        return redirect(context.get("next", "/"))
           
# End microsoft side
class BaseProvider(Provider):
    max_age = 5

    def __init__(self, server):
        self.server = server

    def get_private_key(self, public_key):
        try:
            self.consumer = Consumer.objects.get(public_key=public_key)
        except Consumer.DoesNotExist:
            return None
        return self.consumer.private_key


class RequestTokenProvider(BaseProvider):
    def provide(self, data):
        redirect_to = data['redirect_to']
        token = Token.objects.create(consumer=self.consumer, redirect_to=redirect_to)
        return {'request_token': token.request_token}


class AuthorizeView(View):
    """
    The client get's redirected to this view with the `request_token` obtained
    by the Request Token Request by the client application beforehand.
    This view checks if the user is logged in on the server application and if
    that user has the necessary rights.
    If the user is not logged in, the user is prompted to log in.
    """
    server = None

    def get(self, request):
        request_token = request.GET.get('token', None)
        if not request_token:
            return self.missing_token_argument()
        try:
            self.token = Token.objects.select_related('consumer').get(request_token=request_token)
        except Token.DoesNotExist:
            return self.token_not_found()
        if not self.check_token_timeout():
            return self.token_timeout()
        self.token.refresh()
        if request.user.is_authenticated:
            return self.handle_authenticated_user()
        else:
            return self.handle_unauthenticated_user()

    def missing_token_argument(self):
        return HttpResponseBadRequest('Token missing')

    def token_not_found(self):
        return HttpResponseForbidden('Token not found')

    def token_timeout(self):
        return HttpResponseForbidden('Token timed out')

    def check_token_timeout(self):
        delta = timezone.now() - self.token.timestamp
        if delta > self.server.token_timeout:
            self.token.delete()
            return False
        else:
            return True

    def handle_authenticated_user(self):
        if self.server.has_access(self.request.user, self.token.consumer):
            return self.success()
        else:
            return self.access_denied()

    def handle_unauthenticated_user(self):
        next = '%s?%s' % (self.request.path, urlencode([('token', self.token.request_token)]))
        url = '%s?%s' % (reverse(self.server.auth_view_name), urlencode([('next', next)]))
        return HttpResponseRedirect(url)

    def access_denied(self):
        return HttpResponseForbidden("Access denied")

    def success(self):
        self.token.user = self.request.user
        self.token.save()
        serializer = URLSafeTimedSerializer(self.token.consumer.private_key)
        parse_result = urlparse(self.token.redirect_to)
        query_dict = QueryDict(parse_result.query, mutable=True)
        query_dict['access_token'] = serializer.dumps(self.token.access_token)
        url = urlunparse((parse_result.scheme, parse_result.netloc, parse_result.path, '', query_dict.urlencode(), ''))
        return HttpResponseRedirect(url)


class VerificationProvider(BaseProvider, AuthorizeView):
    def provide(self, data):
        token = data['access_token']
        try:
            self.token = Token.objects.select_related('user').get(access_token=token, consumer=self.consumer)
        except Token.DoesNotExist:
            return self.token_not_found()
        if not self.check_token_timeout():
            return self.token_timeout()
        if not self.token.user:
            return self.token_not_bound()
        extra_data = data.get('extra_data', None)
        return self.server.get_user_data(
            self.token.user, self.consumer, extra_data=extra_data)

    def token_not_bound(self):
        return HttpResponseForbidden("Invalid token")


class ConsumerAdmin(ModelAdmin):
    readonly_fields = ['public_key', 'private_key']


class Server:
    request_token_provider = RequestTokenProvider
    authorize_view = AuthorizeView
    verification_provider = VerificationProvider
    token_timeout = datetime.timedelta(minutes=5)
    client_admin = ConsumerAdmin
    auth_view_name = 'login'

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
        self.register_admin()

    def register_admin(self):
        admin.site.register(Consumer, self.client_admin)

    def has_access(self, user, consumer):
        return True

    def get_user_extra_data(self, user, consumer, extra_data):
        raise NotImplementedError()

    def get_user_data(self, user, consumer, extra_data=None):
        user_data = {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_staff': False,
            'is_superuser': False,
            'is_active': user.is_active,
        }
        if extra_data:
            user_data['extra_data'] = self.get_user_extra_data(
                user, consumer, extra_data)
        return user_data

    def get_urls(self):
        return [
            re_path(r'^request-token/$', provider_for_django(self.request_token_provider(server=self)),
                    name='simple-sso-request-token'),
            re_path(r'^authorize/$', self.authorize_view.as_view(server=self), name='simple-sso-authorize'),
            re_path(r'^verify/$', provider_for_django(
                    self.verification_provider(server=self)), name='simple-sso-verify'),
            re_path(r'^login/$', login_to_ms_redirect, name="login"),
            re_path(r'^logout/$', microsoft_logout , name="logout"),
        ]