import base64
import hashlib
import hmac
import time
from django.test import TestCase
from unittest.mock import Mock, patch

from django.contrib import auth
from django.contrib.auth.models import User
from django_mailman3.models import Profile
from allauth.account.models import EmailAddress
from discoursessoclient.client import DiscourseSsoClientMiddleware
from discoursessoclient.models import SsoRecord

class SsoInitTestCase(TestCase):
    def setUp(self):
        self.middleware = DiscourseSsoClientMiddleware(lambda x: x)

    @patch('secrets.token_hex',
           return_value='228cd25bd24bbc31a2bfc81ff8ea6d39')
    def test_sso_init(self, _):
        qs = {'next': '/foo'}
        get = Mock(get=lambda x: qs[x] if x in qs else None)
        request = Mock(path="/sso/init", session={}, GET=get)
        with self.settings(SSO_PROVIDER_URL='https://example.com/sso',
                           SSO_SECRET='b54cc7b3e42b215d1792c300487f1cb1'):
            response = self.middleware.__call__(request)
            self.assertIsNotNone(request.session['sso_nonce'])
            self.assertIsNotNone(request.session['sso_expiry'])
            self.assertEqual(
                response.url,
                'https://example.com/sso?sso='
                'bm9uY2U9MjI4Y2QyNWJkMjRiYmMzMWEyYmZjODFmZjhlYTZkMzkmcmV0dXJu'
                'X3Nzb191cmw9aHR0cDovL2xvY2FsaG9zdDo4MDAwL3Nzby9sb2dpbiZjdXN0'
                'b20ubmV4dD0vZm9v&sig=b570eb834187a663bec96f33810718ba15183ce'
                '56461689b4462cee9741d2c7b')

class SsoLoginTestCase(TestCase):

    def setUp(self):
        self.middleware = DiscourseSsoClientMiddleware(lambda x: x)

    def test_with_no_payload(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'no_payload_or_sig')

        self.call_middleware({}, {}, asserts)

    def test_with_empty_payload(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'empty_payload')

        self.call_middleware({'sso': '', 'sig': ''}, {}, asserts)

    def test_with_no_nonce_in_session(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'no_nonce_in_session')

        self.call_middleware({'sso': 'x', 'sig': ''}, {}, asserts)

    def test_with_bad_payload(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'bad_payload_encoding')

        qs = {'sso': 'x', 'sig': ''}
        self.call_middleware(qs, self.session(), asserts)

    def test_with_bad_signature(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'invalid_signature')

        payload = 'sso_nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': 'xxx'}
        self.call_middleware(qs, self.session(), asserts)

    def test_with_wrong_nonce(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'wrong_nonce_in_payload')

        payload = 'sso_nonce=31ab54'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(), asserts)

    def test_with_expired_nonce(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'expired_nonce')

        payload = 'sso_nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(expiry=time.time() - 10), asserts)

    def test_with_no_external_id(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'missing_external_id')

        payload = 'sso_nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(), asserts)

    def test_with_no_email(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'missing_email')

        payload = 'sso_nonce=31ab53&external_id=123'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(), asserts)

    def test_nonce_deletion_after_login_attempt(self):
        def asserts(request, response):
            self.assertIsNone(request.session.get('sso_nonce'))
            self.assertIsNone(request.session.get('sso_expiry'))

        payload = 'sso_nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(), asserts)

    @patch.object(auth, 'login')
    def test_with_matching_external_id_and_email(self, mock):
        def asserts(request, response):
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, '/foo')
            mock.assert_called_with(request, user)
            self.assertTrue(SsoRecord.objects.get(external_id=123).sso_logged_in)
            user.refresh_from_db()
            self.assertEqual(user.email, 'a@c.com')
            self.assertEqual(user.first_name, 'M')
            self.assertEqual(user.last_name, 'B')
            self.assertEqual(user.username, 'z')
            self.assertEqual(Profile.objects.get(user=user).timezone, 'America/St_Vincent')
            self.assertTrue(EmailAddress.objects.get(user_id=user.id).verified)

        user = User.objects.create_user(username='x', email='a@b.com')
        EmailAddress.objects.create(user=user, email=user.email, verified=False)
        SsoRecord.objects.create(user=user, external_id='123', sso_logged_in=False)
        payload = 'sso_nonce=31ab53&username=z&external_id=123&email=a@c.com&custom.first_name=M&custom.last_name=B&custom.timezone=America/St_Vincent&custom.next=/foo'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(), asserts)

    @patch.object(auth, 'login')
    def test_with_matching_email_but_not_external_id(self, mock):
        def asserts(request, response):
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, 'https://example.org')
            mock.assert_called_with(request, user)
            self.assertTrue(SsoRecord.objects.get(external_id=124).sso_logged_in)
            user.refresh_from_db()
            self.assertEqual(user.first_name, 'M')
            self.assertEqual(user.last_name, 'B')
            self.assertEqual(user.username, 'z')
            self.assertTrue(EmailAddress.objects.get(user_id=user.id).verified)

        user = User.objects.create_user(username='x', email='a@b.com')
        EmailAddress.objects.create(user=user, email=user.email, verified=False)
        SsoRecord.objects.create(user=user, external_id='123', sso_logged_in=False)
        payload = 'sso_nonce=31ab53&username=z&external_id=124&email=a@b.com&custom.first_name=M&custom.last_name=B'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(), asserts)

    @patch.object(auth, 'login')
    def test_with_no_matching_email_or_external_id(self, mock):
        def asserts(request, response):
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, 'https://example.org')
            user2 = User.objects.filter(email='a@c.com').first()
            mock.assert_called_with(request, user2)
            sso = SsoRecord.objects.get(external_id=124)
            self.assertTrue(sso.sso_logged_in)
            self.assertEqual(sso.user, user2)
            self.assertEqual(user2.email, 'a@c.com')
            self.assertEqual(user2.first_name, 'M')
            self.assertEqual(user2.last_name, 'B')
            self.assertEqual(user2.username, 'z')
            self.assertTrue(EmailAddress.objects.get(user_id=user2.id).verified)

        decoy_user = User.objects.create_user(username='x', email='a@b.com')
        SsoRecord.objects.create(user=decoy_user, external_id='123', sso_logged_in=False)
        payload = 'sso_nonce=31ab53&username=z&external_id=124&email=a@c.com&custom.first_name=M&custom.last_name=B'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, self.session(), asserts)

    def encode(self, payload):
        return base64.b64encode(payload.encode(encoding='utf-8')).decode(encoding='utf-8')

    def sign(self, payload):
        return hmac.new(b'b54cc7b3e42b215d1792c300487f1cb1',
                        payload.encode(encoding='utf-8'),
                        digestmod=hashlib.sha256).hexdigest()

    def session(self, expiry=None):
        return {'sso_nonce': '31ab53', 'sso_expiry': expiry or time.time() + 600}

    def call_middleware(self, qs, session, func):
        get = Mock(get=lambda x: qs[x] if x in qs else None)
        request = Mock(path="/sso/login",
                       session=session,
                       GET=get)
        with self.settings(SSO_PROVIDER_URL='https://example.com/sso',
                           SSO_SECRET='b54cc7b3e42b215d1792c300487f1cb1',
                           SSO_CLIENT_BASE_URL='https://example.org'):
            response = self.middleware.__call__(request)
            func(request, response)
