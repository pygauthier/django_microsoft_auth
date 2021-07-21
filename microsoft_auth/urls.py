from typing import List

from django.conf import settings
from django.urls import URLPattern

app_name = "microsoft_auth"

urlpatterns: List[URLPattern] = []

if getattr(settings, 'MICROSOFT_AUTH_LOGIN_ENABLED', True):  # pragma: no branch
    from django.conf.urls import url
    from . import views

    urlpatterns = [
        url(
            r"^auth-callback/$",
            views.AuthenticateCallbackView.as_view(),
            name="auth-callback",
        )
    ]
