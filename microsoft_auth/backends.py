"""
MIT License
Copyright (c) 2017, Christopher Bailey
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional, TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db import IntegrityError
from django.http import HttpRequest

import json
from .client import MicrosoftClient

if TYPE_CHECKING:
    from django.contrib.auth.models import User

logger = logging.getLogger("django")


class MicrosoftAuthenticationBackend(ModelBackend):
    microsoft: MicrosoftClient

    def authenticate(self, request: HttpRequest, code: str = None, **kwargs: Any) -> Optional[User]:
        """
        Authenticates the user against the Django backend
        using a Microsoft auth code from
        https://login.microsoftonline.com/common/oauth2/v2.0/authorize or
        https://login.live.com/oauth20_authorize.srf

        For more details:
        https://developer.microsoft.com/en-us/graph/docs/get-started/rest
        """
        base_url = None
        frontend_url = getattr(settings, 'MICROSOFT_FRONTEND_URL', None)
        if frontend_url and str(frontend_url) == request.path:
            base_url = frontend_url
        self.microsoft = MicrosoftClient(request=request, base_url=base_url)

        user = None
        if code is not None:
            # fetch OAuth token
            token = self.microsoft.fetch_token(code=code)

            # validate permission scopes
            scope = self.microsoft.valid_scopes(token["scope"])
            refresh_token = ""
            microsoft_expires_at = "0"
            if "expires_at" in token and scope:
                microsoft_expires_at = token["expires_at"]
            if "refresh_token" in token and scope:
                refresh_token = token["refresh_token"]
            if "access_token" in token and scope:
                user = self._authenticate_user(
                    ms_token=token["access_token"],
                    refresh_token=refresh_token,
                    microsoft_expires_at=microsoft_expires_at
                )
        return user

    def _authenticate_user(self, ms_token: str = "", 
        refresh_token: str = "", microsoft_expires_at: str = ""
    ) -> Optional[User]:
        claims = self.microsoft.get_claims()

        if claims is not None:
            return self._get_user_from_microsoft(
                claims, ms_token, refresh_token,
                microsoft_expires_at
            )

        return None

    def _get_user_from_microsoft(self, data: Dict[str, str], ms_token: str = "", 
        refresh_token: str = "", microsoft_expires_at: str = ""
    ) -> Optional[User]:  # Ignore PyLintBear (E0601)
        User = get_user_model()  # Ignore PyLintBear (W0621)

        user = User.objects.filter(microsoft_id=data["sub"]).first()

        if user is None:
            namepart = data.get("name", '').split(" ", 1)
            if len(namepart) > 1:
                first_name, last_name = namepart
            else:
                first_name, last_name = namepart[0], ""

            try:
                email = ""
                if re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", data["preferred_username"]):
                    email = data["preferred_username"]

                user = User.objects.get_or_create(
                    username=data["preferred_username"],
                    defaults={
                        'first_name': first_name,
                        'last_name': last_name,
                        'username': data["preferred_username"][:150],
                        'microsoft_id': data["sub"],
                        'microsoft_code': ms_token,
                        'microsoft_refresh': refresh_token,
                        'microsoft_expires_at':microsoft_expires_at,
                        'email': email
                    }
                )[0]
            except IntegrityError as error:
                logger.error(f"Enable to create user {error}.")
                return None

            if not user.microsoft_id:
                user.microsoft_id = data["sub"]
                user.save()

            if user.first_name == "" and user.last_name == "":
                user.first_name = first_name
                user.last_name = last_name
                user.save()

        user.microsoft_code = ms_token
        user.microsoft_refresh = refresh_token
        user.microsoft_expires_at = microsoft_expires_at
        user.save()
        return user
