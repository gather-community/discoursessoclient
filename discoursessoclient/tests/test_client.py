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
