from typing import Any, Dict

from django import template
from django.conf import settings
from django.core.signing import TimestampSigner
from django.middleware.csrf import get_token
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _

from ..client import MicrosoftClient

register = template.Library()


@register.simple_tag(takes_context=True)
def load_auth_values(context: Dict[str, Any]) -> str:
    login_type = _("Microsoft")

    signer = TimestampSigner()
    state = signer.sign(get_token(context['request']))
    base_url = getattr(settings, 'MICROSOFT_FRONTEND_URL', None) if context.get('frontend', False) is True else None
    microsoft = MicrosoftClient(state=state, request=context['request'], base_url=base_url)
    auth_url = microsoft.authorization_url()[0]

    context.update({
        "microsoft_login_enabled": getattr(settings, 'MICROSOFT_AUTH_LOGIN_ENABLED', True),
        "microsoft_authorization_url": mark_safe(auth_url),
        "microsoft_login_type_text": login_type,
    })

    return ""
