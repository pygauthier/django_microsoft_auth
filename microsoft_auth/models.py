from django.db import models
from django.utils.translation import ugettext_lazy as _


class MicrosoftAccountMixin(models.Model):
    microsoft_id = models.CharField(_("microsoft account id"), max_length=64, null=True)
    microsoft_code = models.TextField(_("microsoft api token"), null=True, blank=True)
    microsoft_refresh = models.TextField(_("microsoft api refresh token"), null=True, blank=True)
    microsoft_expires_at = models.TextField(_("microsoft api expire Timestamp"), null=True, blank=True)
    class Meta:
        abstract = True
