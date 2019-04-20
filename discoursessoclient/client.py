import base64
import hashlib
import hmac
import secrets
import urllib.parse

from django.conf import settings
from django.contrib import auth
from django.http import HttpResponseBadRequest, HttpResponseRedirect

from discoursessoclient.models import SsoRecord



class DiscourseSsoClientMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        if request.path == '/sso/init':
            return self.sso_init(request)
        elif request.path == '/sso/login':
            return self.sso_login(request)
        else:
            return self.get_response(request)

    def sso_init(self, request):
        nonce = request.session['sso_nonce'] = secrets.token_hex(16)
        return_url = settings.SSO_CLIENT_BASE_URL
        payload = f'nonce={nonce}&return_sso_url={return_url}/sso/login'
        payload = base64.b64encode(bytes(payload, encoding='utf-8'))
        signature = self.sign_payload(str(payload))
        payload = urllib.parse.quote_plus(str(payload))
        to_url = f'{settings.SSO_PROVIDER_URL}?sso={payload}&sig={signature}'
        return HttpResponseRedirect(to_url)

    def sso_login(self, request):
        # Check signature
        payload = request.GET.get('sso')
        signature = request.GET.get('sig')

        if payload is None or signature is None:
            return HttpResponseBadRequest('no_payload_or_sig')

        payload = urllib.parse.unquote(payload)
        if len(payload) == 0:
            return HttpResponseBadRequest('empty_payload')

        if 'sso_nonce' not in request.session:
            return HttpResponseBadRequest('no_nonce_in_session')

        nonce = request.session['sso_nonce']
        try:
            qstring = base64.decodestring(payload.encode(encoding='utf-8')).decode(encoding='utf-8')
            if nonce not in qstring:
                return HttpResponseBadRequest('wrong_nonce_in_payload')
        except ValueError:
            return HttpResponseBadRequest('bad_payload_encoding')

        if not hmac.compare_digest(self.sign_payload(payload), signature):
            return HttpResponseBadRequest('invalid_signature')

        params = urllib.parse.parse_qs(qstring, strict_parsing=True)
        if 'external_id' not in params:
            return HttpResponseBadRequest('missing_external_id')
        if 'email' not in params:
            return HttpResponseBadRequest('missing_email')

        user = self.get_user(params)
        request.user = user
        auth.login(request, user)

        # If next was passed, redirect there, else redirect to root.
        if request.GET.get('next') is None:
            return HttpResponseRedirect(settings.SSO_CLIENT_BASE_URL)
        else:
            return HttpResponseRedirect(request.GET.get('next'))

    # Generates signature for utf-8 string payload.
    def sign_payload(self, payload):
        return hmac.new(bytes(settings.SSO_SECRET, encoding='utf-8'),
                        bytes(payload, encoding='utf-8'),
                        digestmod=hashlib.sha256).hexdigest()


    def get_user(self, params):
        # If existing sso record for external_id, update and return associated user
        # Else, if user with matching email, update them, create sso record, and return
        # Else, create user and sso record

        try:
            return SsoRecord.objects.get(external_id=params['external_id'][0]).user
        except SsoRecord.DoesNotExist:
            return None

    def update_user_from_sso_payload(self, user, payload):
        1
