import base64
import hashlib
import hmac
import secrets
import urllib.parse

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.models import User
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
        next_url = request.GET.get('next')
        payload = f'nonce={nonce}&return_sso_url={return_url}/sso/login&custom.next={next_url}'
        payload = base64.b64encode(payload.encode(encoding='utf-8'))
        signature = self.sign_payload(payload)
        payload = urllib.parse.quote_plus(payload.decode(encoding='utf-8'))
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
            qstring = base64.decodestring(payload.encode(encoding='utf-8')) \
                            .decode(encoding='utf-8')
            if nonce not in qstring:
                return HttpResponseBadRequest('wrong_nonce_in_payload')
            else:
                # At this point we've validated the nonce so we can expire it.
                del request.session['sso_nonce']
        except ValueError:
            return HttpResponseBadRequest('bad_payload_encoding')

        if not hmac.compare_digest(self.sign_payload(payload), signature):
            return HttpResponseBadRequest('invalid_signature')

        params = urllib.parse.parse_qs(qstring, strict_parsing=True)
        if 'external_id' not in params:
            return HttpResponseBadRequest('missing_external_id')
        if 'email' not in params:
            return HttpResponseBadRequest('missing_email')

        user = self.get_and_update_user(params)
        request.user = user
        auth.login(request, user)

        # If next was passed, redirect there, else redirect to root.
        if params.get('custom.next') is None:
            return HttpResponseRedirect(settings.SSO_CLIENT_BASE_URL)
        else:
            return HttpResponseRedirect(params.get('custom.next')[0])

    # Generates signature for string or bytes payload.
    def sign_payload(self, payload):
        try:
            payload = payload.encode(encoding='utf-8')
        except AttributeError:
            pass
        return hmac.new(settings.SSO_SECRET.encode(encoding='utf-8'),
                        payload,
                        digestmod=hashlib.sha256).hexdigest()

    def get_and_update_user(self, params):
        ext_id = params['external_id'][0]
        email = params['email'][0]

        try:
            sso = SsoRecord.objects.get(external_id=ext_id)
        except SsoRecord.DoesNotExist:
            try:
                # Else, look for user with matching email.
                sso = SsoRecord.objects.create(
                    user=User.objects.get(email=email),
                    external_id=ext_id)
            except User.DoesNotExist:
                # Else create user and sso record.
                user = User.objects.create(email=email)
                sso = SsoRecord.objects.create(
                    user=user,
                    external_id=ext_id)

        sso.sso_logged_in = True
        sso.save()
        self.update_user_from_params(sso.user, params)
        return sso.user

    def update_user_from_params(self, user, params):
        user.first_name = params.get('custom.first_name', [None])[0]
        user.last_name = params.get('custom.last_name', [None])[0]
        user.email = params['email'][0]  # Email is not optional
        user.save()
