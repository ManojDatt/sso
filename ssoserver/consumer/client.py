import json
import logging
import jwt
import requests
from django.contrib.sites.models import Site
from django.core.cache import cache
from django.urls import reverse
from jwt.algorithms import RSAAlgorithm
from requests_oauthlib import OAuth2Session
from .utils import get_scheme

logger = logging.getLogger("django")
from .conf import (
    CACHE_KEY_JWKS,
    CACHE_KEY_OPENID,
    CACHE_TIMEOUT,
    config,
)

class MicrosoftClient(OAuth2Session):
    """Simple Microsoft OAuth2 Client to authenticate them
    Extended from Requests-OAuthlib's OAuth2Session class which
        does most of the heavy lifting
    https://requests-oauthlib.readthedocs.io/en/latest/
    Microsoft OAuth documentation can be found at
    https://developer.microsoft.com/en-us/graph/docs/get-started/rest
    """

    _config_url = "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"  # noqa
    config = None

    # required OAuth scopes
    SCOPE_MICROSOFT = ["Calendars.Read", "Mail.Read", "Directory.Read.All", "User.Read", "User.Read.All", "Calendars.ReadWrite", "profile", "User.ReadBasic.All", "Mail.ReadBasic", "openid", "email"]

    def __init__(self, state=None, request=None, *args, **kwargs):
        self.config = config

        super().__init__(
            self.config.MICROSOFT_AUTH_CLIENT_ID,
            scope=self._get_scopes(),
            state=state,
            redirect_uri=self._get_redirect_uri(request),
            *args,
            **kwargs,
        )

        if self.config.MICROSOFT_AUTH_PROXIES:
            self.proxies = self.config.MICROSOFT_AUTH_PROXIES

    def _get_scopes(self):
        scope = " ".join(self.SCOPE_MICROSOFT)
        extra_scopes = self.config.MICROSOFT_AUTH_EXTRA_SCOPES
        scope = "{} {}".format(scope, extra_scopes).strip()

        return scope

    def _get_redirect_uri(self, request):
        try:
            current_site = Site.objects.get_current(request)
        except Site.DoesNotExist:
            current_site = Site.objects.first()

        domain = current_site.domain
        callback = reverse("auth-callback")
        redirect = reverse("from-auth-redirect")
        if not request or "redirect" not in request.path:
            path = callback
        else:
            path = redirect

        return f"{get_scheme(request, self.config)}://{domain}{path}"

    @property
    def openid_config(self):
        config = cache.get(CACHE_KEY_OPENID)

        if config is None:
            config_url = self._config_url.format(
                tenant=self.config.MICROSOFT_AUTH_TENANT_ID
            )
            response = self.get(config_url)

            if response.ok:
                config = response.json()
                print(config)
                cache.set(CACHE_KEY_OPENID, config, CACHE_TIMEOUT)

        return config

    @property
    def jwks(self):
        jwks = cache.get(CACHE_KEY_JWKS, [])

        if len(jwks) == 0:
            jwks_uri = self.openid_config["jwks_uri"]
            if jwks_uri is None:
                return []

            response = self.get(jwks_uri)

            if response.ok:
                jwks = response.json()["keys"]
                cache.set(CACHE_KEY_JWKS, jwks, CACHE_TIMEOUT)
        return jwks

    def get_claims(self, allow_refresh=True):
        if self.token is None:
            return None

        token = self.token["id_token"].encode("utf8")

        kid = jwt.get_unverified_header(token)["kid"]
        jwk = None
        public_key = None
        for key in self.jwks:
            if kid == key["kid"]:
                jwk = key
                break

        if jwk is None:
            if allow_refresh:
                logger.warn(
                    "could not find public key for id_token, " "refreshing OIDC config"
                )
                cache.delete(CACHE_KEY_JWKS)
                cache.delete(CACHE_KEY_OPENID)

                return self.get_claims(allow_refresh=False)
            else:
                logger.warn("could not find public key for id_token")
                return None

        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))

        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.config.MICROSOFT_AUTH_CLIENT_ID,
            )
        except jwt.PyJWTError as e:
            logger.warn("could not verify id_token sig: {}".format(e))
            return None

        return claims

    def authorization_url(self):
        """Generates Microsoft/Xbox or a Office 365 Authorization URL"""

        auth_url = self.openid_config["authorization_endpoint"]
        return super().authorization_url(auth_url, response_mode="form_post")

    def fetch_token(self, **kwargs):
        """Fetchs OAuth2 Token with given kwargs"""
        print(self.openid_config["token_endpoint"])
        return super().fetch_token(  # pragma: no cover
            self.openid_config["token_endpoint"],
            client_secret=self.config.MICROSOFT_AUTH_CLIENT_SECRET,
            **kwargs,
        )

    def valid_scopes(self, scopes):
        """Validates response scopes based on MICROSOFT_AUTH_LOGIN_TYPE"""

        scopes = set(scopes)
        required_scopes = None
        required_scopes = set(self.SCOPE_MICROSOFT)

        # verify all require_scopes are in scopes
        return required_scopes <= scopes