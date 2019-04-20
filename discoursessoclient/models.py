from django.db import models
from django.contrib.auth.models import User


class SsoRecord(models.Model):
    external_id = models.TextField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    sso_logged_in = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True)
