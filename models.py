from django.db import models
from django.contrib.auth.models import User


# Models a record of an SSO sign in.
class SsoRecord(models.Model):
    # The ID of the user on the SSO provider system.
    external_id = models.TextField(primary_key=True)

    # This flag can be used to sign the user out upon the next request.
    sso_logged_in = models.BooleanField(default=False)

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True)
