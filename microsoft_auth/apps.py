from __future__ import annotations

from typing import Any, List

from django.apps import AppConfig, apps
from django.conf import settings
from django.core.checks import CheckMessage, Critical, register
from django.core.checks import Warning as CheckWarnings
from django.utils.translation import ugettext_lazy as _


class MicrosoftAuthConfig(AppConfig):
    name = "microsoft_auth"
    verbose_name = _("Microsoft Auth")


@register()
def microsoft_auth_validator(app_configs: AppConfig, **kwargs: Any) -> List[CheckMessage]:

    errors = []

    if apps.is_installed("microsoft_auth") and not apps.is_installed(
        "django.contrib.sites"
    ):

        errors.append(
            Critical(
                "`django.contrib.sites` is not installed",
                hint=(
                    "`microsoft_auth` requires `django.contrib.sites` "
                    "to be installed and configured"
                ),
                id="microsoft_auth.E001",
            )
        )

    if getattr(settings, 'MICROSOFT_AUTH_LOGIN_ENABLED', True):  # pragma: no branch
        if getattr(settings, 'MICROSOFT_AUTH_CLIENT_ID', "") == "":
            errors.append(
                CheckWarnings(
                    "`MICROSOFT_AUTH_CLIENT_ID` is not configured",
                    hint=(
                        "`MICROSOFT_AUTH_LOGIN_ENABLED` is `True`, but "
                        "`MICROSOFT_AUTH_CLIENT_ID` is empty. Microsoft "
                        "auth will be disabled"
                    ),
                    id="microsoft_auth.W003",
                )
            )
        if getattr(settings, 'MICROSOFT_AUTH_CLIENT_SECRET', "") == "":
            errors.append(
                CheckWarnings(
                    "`MICROSOFT_AUTH_CLIENT_SECRET` is not configured",
                    hint=(
                        "`MICROSOFT_AUTH_LOGIN_ENABLED` is `True`, but "
                        "`MICROSOFT_AUTH_CLIENT_SECRET` is empty. Microsoft "
                        "auth will be disabled"
                    ),
                    id="microsoft_auth.W004",
                )
            )
    return errors
