import base64
import hashlib
import hmac
import secrets
import urllib.parse

from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.conf import settings


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
        payload = f'nonce={nonce}&return_sso_url={return_url}/login'
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
            decoded = str(base64.decodestring(bytes(payload, encoding='utf-8')))
            if nonce not in decoded:
                return HttpResponseBadRequest('wrong_nonce_in_payload')
        except ValueError:
            return HttpResponseBadRequest('bad_payload_encoding')

        if not hmac.compare_digest(self.sign_payload(payload), signature):
            return HttpResponseBadRequest('invalid_signature')

        parse_qs(payload, strict_parsing=True)

        return HttpResponseBadRequest('good_so_far')

    # Generates signature for utf-8 string payload.
    def sign_payload(self, payload):
        return hmac.new(bytes(settings.SSO_SECRET, encoding='utf-8'),
                        bytes(payload, encoding='utf-8'),
                        digestmod=hashlib.sha256).hexdigest()


    def get_user(self, payload):
        # If existing sso record for external_id, update and return associated user
        # Else, if user with matching email, update them, create sso record, and return
        # Else, create user and sso record
        1

    def update_user_from_sso_payload(self, user, payload):
        1
