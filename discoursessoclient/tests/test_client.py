import base64
from django.test import TestCase
from unittest.mock import Mock, patch

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
                'mcmV0dXJuX3Nzb191cmw9aHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9sb2'
                'dpbg%3D%3D%27&sig=94f4e09bf34e7003acc93da3b0182306d64de'
                'cd2ca4c295953f93f286e40f6f3')

class SsoLoginTestCase(TestCase):

    def setUp(self):
        self.middleware = DiscourseSsoClientMiddleware(lambda x: x)

    def test_with_no_payload(self):
        def asserts(response):
            self.assertEqual(response.content, b'no_payload_or_sig')
        self.call_middleware({}, {}, asserts)

    def test_with_empty_payload(self):
        def asserts(response):
            self.assertEqual(response.content, b'empty_payload')
        self.call_middleware({'sso': '', 'sig': ''}, {}, asserts)

    def test_with_no_nonce_in_session(self):
        def asserts(response):
            self.assertEqual(response.content, b'no_nonce_in_session')
        self.call_middleware({'sso': 'x', 'sig': ''}, {}, asserts)

    def test_with_bad_payload(self):
        def asserts(response):
            self.assertEqual(response.content, b'bad_payload_encoding')
        self.call_middleware({'sso': 'x', 'sig': ''}, {'sso_nonce': 'y'}, asserts)

    def test_with_wrong_nonce(self):
        def asserts(response):
            self.assertEqual(response.content, b'wrong_nonce_in_payload')
        qs = {'sso': base64.b64encode(b'sso_nonce=31ab53').decode(encoding='utf-8'), 'sig': ''}
        self.call_middleware(qs, {'sso_nonce': '31ab54'}, asserts)

    def test_with_bad_signature(self):
        def asserts(response):
            self.assertEqual(response.content, b'invalid_signature')
        qs = {'sso': base64.b64encode(b'sso_nonce=31ab53').decode(encoding='utf-8'), 'sig': 'asfadfas'}
        self.call_middleware(qs, {'sso_nonce': '31ab53'}, asserts)

    def call_middleware(self, qs, session, func):
        request = Mock(path="/sso/login", session=session, GET=Mock(get=lambda x: qs[x] if x in qs else None))
        with self.settings(SSO_PROVIDER_URL='https://example.com/sso',
                           SSO_SECRET='b54cc7b3e42b215d1792c300487f1cb1'):
            response = self.middleware.__call__(request)
            func(response)
