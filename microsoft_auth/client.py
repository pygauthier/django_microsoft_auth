"""
MIT License
Copyright (c) 2017, Christopher Bailey
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from django.conf import settings
from django.contrib.sites.models import Site
from django.http import HttpRequest
from django.urls import reverse
from django.utils.functional import cached_property
import jwt
from jwt.algorithms import RSAAlgorithm
from requests_oauthlib import OAuth2Session

from .utils import get_scheme

logger = logging.getLogger("django")


class MicrosoftClient(OAuth2Session):
    """ Simple Microsoft OAuth2 Client to authenticate them

    Extended from Requests-OAuthlib's OAuth2Session class which
    does most of the heavy lifting

    https://requests-oauthlib.readthedocs.io/en/latest/

    Microsoft OAuth documentation can be found at
    https://developer.microsoft.com/en-us/graph/docs/get-started/rest
    """

    _config_url = "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"  # noqa

    # required OAuth scopes
    SCOPE_MICROSOFT = ["openid", "email", "profile"]

    def __init__(
        self, state: str = None, request: HttpRequest = None, base_url: str = None, *args: Any, **kwargs: Any
    ) -> None:
        extra_scopes = getattr(settings, 'MICROSOFT_AUTH_EXTRA_SCOPES', "")

        try:
            current_site = Site.objects.get_current(request)
        except Site.DoesNotExist:
            current_site = Site.objects.first()

        domain = current_site.domain
        path = base_url or reverse("microsoft_auth:auth-callback")
        scope = " ".join(self.SCOPE_MICROSOFT)

        scope = f'{scope} {extra_scopes}'.strip()

        scheme = get_scheme(request)

        super().__init__(
            getattr(settings, 'MICROSOFT_AUTH_CLIENT_ID', ""),
            scope=scope,
            state=state,
            redirect_uri=f'{scheme}://{domain}{path}',
            *args,
            **kwargs
        )

    @cached_property
    def openid_config(self) -> dict:
        config_url = self._config_url.format(
            tenant=getattr(settings, 'MICROSOFT_AUTH_TENANT_ID', "")
        )
        response = self.get(config_url)

        if response.ok:
            return response.json()
        return {}

    @cached_property
    def jwks(self) -> List[str]:
        response = self.get(self.openid_config["jwks_uri"])  # Ignore PyLintBear (E1136)
        if response.ok:
            return response.json()["keys"]

        return []

    def get_claims(self) -> Optional[Dict[Any, Any]]:
        if self.token is None:
            return None

        token = self.token["id_token"].encode("utf8")

        kid = jwt.get_unverified_header(token)["kid"]

        for key in self.jwks:
            if kid == key["kid"]:
                jwk = key
                break

        if jwk is None:
            logger.warning("could not find public key for id_token")
            return None

        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))

        try:
            claims = jwt.decode(
                token,
                public_key,
                algoithm="RS256",
                audience=getattr(settings, 'MICROSOFT_AUTH_CLIENT_ID', ""),
            )
        except jwt.PyJWTError as e:
            logger.warning(f"could verify id_token sig: {e}")
            return None

        return claims

    def authorization_url(self) -> str:
        """ Generates Microsoft or a Office 365 Authorization URL """

        auth_url = self.openid_config["authorization_endpoint"]  # Ignore PyLintBear (E1136)

        return super().authorization_url(auth_url, response_mode="form_post")

    def fetch_token(self, **kwargs: Any) -> Dict[str, str]:
        """ Fetch OAuth2 Token with given kwargs"""
        token_endpoint = self.openid_config["token_endpoint"]  # Ignore PyLintBear (E1136)

        return super().fetch_token(  # pragma: no cover
            token_endpoint,
            client_secret=getattr(settings, 'MICROSOFT_AUTH_CLIENT_SECRET', ""),
            **kwargs
        )

    def valid_scopes(self, scopes: str) -> bool:
        # verify all require_scopes are in scopes
        return set(self.SCOPE_MICROSOFT) <= set(scopes)

    def refresh_token(self, user: 'User') -> bool:
        token_endpoint = self.openid_config["token_endpoint"]  # Ignore PyLintBear (E1136)
        token_payload = super().refresh_token(
            token_endpoint, 
            refresh_token=user.microsoft_refresh,
            client_id=getattr(settings, 'MICROSOFT_AUTH_CLIENT_ID', ""),
            client_secret=getattr(settings, 'MICROSOFT_AUTH_CLIENT_SECRET', ""),
        )
        if "refresh_token" in token_payload and "access_token" in token_payload:
            try:
                user.microsoft_code = token_payload["access_token"]
                user.microsoft_refresh = token_payload["refresh_token"]
                user.microsoft_expires_at = token_payload["expires_at"]
                user.save()
            except:
                return False
            return True
        return False