from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest


def get_scheme(request: HttpRequest) -> str:
    scheme = "https"
    if settings.DEBUG and request is not None:
        if "HTTP_X_FORWARDED_PROTO" in request.META:
            scheme = request.META["HTTP_X_FORWARDED_PROTO"]
        else:
            scheme = request.scheme
    return scheme
