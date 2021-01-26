import base64
import hashlib
import hmac
import secrets
import time
import urllib.parse

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from allauth.account.models import EmailAddress
from django_mailman3.models import Profile
from discoursessoclient.models import SsoRecord

class DiscourseSsoClientMiddleware:
    class BadRequest(Exception):
        pass

    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        if request.path == '/sso/init':
            return self.sso_init(request)
        elif request.path == '/sso/login':
            return self.sso_login(request)
        elif request.path == '/sso/update':
            return self.sso_update(request)
        elif request.path == '/sso/logout':
            return self.sso_logout(request)
        else:
            return self.sso_passthru(request)

    def sso_init(self, request):
        nonce = request.session['sso_nonce'] = secrets.token_hex(16)
        request.session['sso_expiry'] = time.time() + 60 * 10
        return_url = settings.SSO_CLIENT_BASE_URL
        next_url = request.GET.get('next')
        payload = f'nonce={nonce}&return_sso_url={return_url}/sso/login&custom.next={next_url}'
        payload = base64.b64encode(payload.encode(encoding='utf-8'))
        signature = self.sign_payload(payload)
        payload = urllib.parse.quote_plus(payload.decode(encoding='utf-8'))
        to_url = f'{settings.SSO_PROVIDER_URL}?sso={payload}&sig={signature}'
        return HttpResponseRedirect(to_url)

    def sso_login(self, request):
        try:
            params = self.decode_check_sig_and_get_params(request)
            self.check_nonce(request, params)
            self.check_id_presence(params)
            self.check_email_presence(params)
            user = self.get_and_update_user_via_id_and_email(params)
            auth.login(request, user)
            sso = SsoRecord.objects.get(user=user)
            sso.sso_logged_in = True
            sso.save()
            # If next was passed, redirect there, else redirect to root.
            if params.get('custom.next') is None:
                return HttpResponseRedirect(settings.SSO_CLIENT_BASE_URL)
            else:
                return HttpResponseRedirect(params.get('custom.next')[0])
        except DiscourseSsoClientMiddleware.BadRequest as e:
            return HttpResponseBadRequest(str(e))

    def sso_update(self, request):
        try:
            params = self.decode_check_sig_and_get_params(request)
            self.check_id_presence(params)
            self.check_email_presence(params)
            self.get_and_update_user_via_id_and_email(params)
            return HttpResponse(status=204)
        except DiscourseSsoClientMiddleware.BadRequest as e:
            return HttpResponseBadRequest(str(e))

    def sso_logout(self, request):
        try:
            params = self.decode_check_sig_and_get_params(request)
            self.check_id_presence(params)
            sso = SsoRecord.objects.get(external_id=params['external_id'][0])
            sso.sso_logged_in = False
            sso.save()
            return HttpResponse(status=204)
        except SsoRecord.DoesNotExist:
            return HttpResponseBadRequest('user_not_found')
        except DiscourseSsoClientMiddleware.BadRequest as e:
            return HttpResponseBadRequest(str(e))

    # Lets the request proceed, but logs out the logged in user if they don't have a valid SsoRecord
    def sso_passthru(self, request):
        if request.user.is_authenticated:
            try:
                SsoRecord.objects.get(user=request.user, sso_logged_in=True)
            except SsoRecord.DoesNotExist:
                auth.logout(request)
        return self.get_response(request)

    def decode_check_sig_and_get_params(self, request):
        # Check signature
        payload = request.GET.get('sso')
        signature = request.GET.get('sig')

        if payload is None or signature is None:
            raise DiscourseSsoClientMiddleware.BadRequest('no_payload_or_sig')

        payload = urllib.parse.unquote(payload)
        if len(payload) == 0:
            raise DiscourseSsoClientMiddleware.BadRequest('empty_payload')

        try:
            qstring = base64.decodestring(payload.encode(encoding='utf-8')) \
                            .decode(encoding='utf-8')
        except ValueError:
            raise DiscourseSsoClientMiddleware.BadRequest('bad_payload_encoding')

        if not hmac.compare_digest(self.sign_payload(payload), signature):
            raise DiscourseSsoClientMiddleware.BadRequest('invalid_signature')

        return urllib.parse.parse_qs(qstring, strict_parsing=True)

    def check_nonce(self, request, params):
        if 'sso_nonce' not in request.session:
            raise DiscourseSsoClientMiddleware.BadRequest('no_nonce_in_session')

        nonce = request.session['sso_nonce']
        if 'nonce' not in params or params['nonce'][0] != nonce:
            raise DiscourseSsoClientMiddleware.BadRequest('wrong_nonce_in_payload')

        if time.time() > request.session['sso_expiry']:
            raise DiscourseSsoClientMiddleware.BadRequest('expired_nonce')

        # At this point we've validated the nonce so we can remove it.
        del request.session['sso_nonce']
        del request.session['sso_expiry']

    def check_id_presence(self, params):
        if 'external_id' not in params:
            raise DiscourseSsoClientMiddleware.BadRequest('missing_external_id')

    def check_email_presence(self, params):
        if 'email' not in params:
            raise DiscourseSsoClientMiddleware.BadRequest('missing_email')

    # Generates signature for string or bytes payload.
    def sign_payload(self, payload):
        try:
            payload = payload.encode(encoding='utf-8')
        except AttributeError:
            pass
        return hmac.new(settings.SSO_SECRET.encode(encoding='utf-8'),
                        payload,
                        digestmod=hashlib.sha256).hexdigest()

    def get_and_update_user_via_id_and_email(self, params):
        ext_id = params['external_id'][0]
        email = params['email'][0]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None

        try:
            sso = SsoRecord.objects.get(external_id=ext_id)
            # If a user with the given email exists and is not associated with this ID,
            # that's an error and should never happen so we fail loudly.
            if user is not None and sso.user != user:
                raise DiscourseSsoClientMiddleware.BadRequest(f"email_collision_detected (ID: {params['external_id'][0]})")
        except SsoRecord.DoesNotExist:
            if user is None:
                user = User.objects.create(email=email)
            else:
                # If a user with the given email exists and is associated with a different ID,
                # that's an error and should never happen so we fail loudly.
                if SsoRecord.objects.filter(user=user).exists():
                    raise DiscourseSsoClientMiddleware.BadRequest(f"email_collision_detected (ID: {params['external_id'][0]})")

            sso = SsoRecord.objects.create(user=user, external_id=ext_id)

        self.update_user_from_params(sso.user, params)
        return sso.user

    def update_user_from_params(self, user, params):
        user.username = params.get('username', [None])[0]
        user.first_name = params.get('custom.first_name', [None])[0]
        user.last_name = params.get('custom.last_name', [None])[0]
        user.email = params['email'][0]  # Email is not optional
        user.save()

        try:
            address = EmailAddress.objects.get(user_id=user.id)
            address.email = user.email
            address.verified = True
            address.save()
        except EmailAddress.MultipleObjectsReturned:
            raise DiscourseSsoClientMiddleware.BadRequest(f"Multiple addresses returned for user {user.username} (ID: {params['external_id'][0]})") from None
        except EmailAddress.DoesNotExist:
            EmailAddress.objects.create(user=user, email=user.email, verified=True)

        if params.get('custom.timezone') is not None:
            profile = Profile.objects.get(user=user)
            profile.timezone = params.get('custom.timezone')[0]
            profile.save()
