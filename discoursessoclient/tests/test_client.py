import base64
import hashlib
import hmac
from django.test import TestCase
from unittest.mock import Mock, patch

from django.contrib import auth
from django.contrib.auth.models import User

from discoursessoclient.client import DiscourseSsoClientMiddleware
from discoursessoclient.models import SsoRecord

class SsoInitTestCase(TestCase):
    def setUp(self):
        self.middleware = DiscourseSsoClientMiddleware(lambda x: x)

    @patch('secrets.token_hex',
           return_value='228cd25bd24bbc31a2bfc81ff8ea6d39')
    def test_sso_init(self, _):
        request = Mock(path="/sso/init", session={})
        with self.settings(SSO_PROVIDER_URL='https://example.com/sso',
                           SSO_SECRET='b54cc7b3e42b215d1792c300487f1cb1'):
            response = self.middleware.__call__(request)
            self.assertEqual(
                response.url,
                'https://example.com/sso?sso='
                'b%27bm9uY2U9MjI4Y2QyNWJkMjRiYmMzMWEyYmZjODFmZjhlYTZkMzk'
                'mcmV0dXJuX3Nzb191cmw9aHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9zc2'
                '8vbG9naW4%3D%27&sig=b35fd875d9442f0569732f9617a7dde1404'
                '7f8c85725512ef441b5d14f3ad55b')

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

        self.call_middleware({'sso': 'x', 'sig': ''}, {'sso_nonce': 'y'}, asserts)

    def test_with_wrong_nonce(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'wrong_nonce_in_payload')

        payload = base64.b64encode(b'sso_nonce=31ab53').decode(encoding='utf-8')
        qs = {'sso': payload, 'sig': ''}
        self.call_middleware(qs, {'sso_nonce': '31ab54'}, asserts)

    def test_with_no_external_id(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'missing_external_id')

        payload = base64.b64encode(b'sso_nonce=31ab53').decode(encoding='utf-8')
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, {'sso_nonce': '31ab53'}, asserts)

    def test_with_no_email(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'missing_email')

        payload = base64.b64encode(b'sso_nonce=31ab53&external_id=123').decode(encoding='utf-8')
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, {'sso_nonce': '31ab53'}, asserts)

    @patch.object(auth, 'login')
    def test_with_matching_external_id(self, mock):
        def asserts(request, response):
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, 'https://example.org')
            mock.assert_called_with(request, user)

        user = User.objects.create_user(username='x', email='a@b.com')
        SsoRecord.objects.create(user=user, external_id='123', sso_logged_in=True)
        payload = base64.b64encode(b'sso_nonce=31ab53&external_id=123&email=a@b.com').decode(encoding='utf-8')
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, {'sso_nonce': '31ab53'}, asserts)

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

        user = User.objects.create_user(username='x', email='a@b.com')
        SsoRecord.objects.create(user=user, external_id='123', sso_logged_in=True)
        payload = base64.b64encode(b'sso_nonce=31ab53&external_id=124&email=a@b.com&first_name=M&last_name=B').decode(encoding='utf-8')
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(qs, {'sso_nonce': '31ab53'}, asserts)

    def sign(self, payload):
        return hmac.new(b'b54cc7b3e42b215d1792c300487f1cb1',
                        payload.encode(encoding='utf-8'),
                        digestmod=hashlib.sha256).hexdigest()

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
