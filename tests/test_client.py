import base64
import hashlib
import hmac
import time
from django.test import TestCase
from unittest.mock import Mock, patch

from django.contrib import auth
from django.contrib.auth.models import User, AnonymousUser
from django_mailman3.models import Profile
from allauth.account.models import EmailAddress
from discoursessoclient.client import DiscourseSsoClientMiddleware
from discoursessoclient.models import SsoRecord

class SsoTestMixin:
    def setUp(self):
        self.middleware = DiscourseSsoClientMiddleware(lambda x: x)

    def encode(self, payload):
        return base64.b64encode(payload.encode(encoding='utf-8')).decode(encoding='utf-8')

    def sign(self, payload):
        return hmac.new(b'b54cc7b3e42b215d1792c300487f1cb1',
                        payload.encode(encoding='utf-8'),
                        digestmod=hashlib.sha256).hexdigest()

    def mock_qs(self, qs):
        return Mock(get=lambda x: qs[x] if x in qs else None)

    def call_middleware(self, callback, qs=None, session=None, user=None):
        request = Mock(user=user or AnonymousUser(), path=self.url,
            session=session or {}, GET=self.mock_qs(qs or {}))
        with self.settings(SSO_PROVIDER_URL='https://example.com/sso',
                           SSO_SECRET='b54cc7b3e42b215d1792c300487f1cb1',
                           SSO_CLIENT_BASE_URL='https://example.org'):
            response = self.middleware.__call__(request)
            callback(request, response)

class SsoWithPayloadTestMixin(SsoTestMixin):
    def test_with_no_payload(self):
        def asserts(request, response):
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'no_payload_or_sig')

        self.call_middleware(asserts)

    def test_with_empty_payload(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'empty_payload')

        self.call_middleware(asserts, qs={'sso': '', 'sig': ''})

    def test_with_bad_payload(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'bad_payload_encoding')

        qs = {'sso': 'x', 'sig': ''}
        self.call_middleware(asserts, qs=qs)

    def test_with_bad_signature(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'invalid_signature')

        payload = 'nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': 'xxx'}
        self.call_middleware(asserts, qs=qs)

class SsoInitTestCase(SsoTestMixin, TestCase):
    url = '/sso/init'

    @patch('secrets.token_hex',
           return_value='228cd25bd24bbc31a2bfc81ff8ea6d39')
    def test_sso_init(self, _):
        def asserts(request, response):
            self.assertIsNotNone(request.session['sso_nonce'])
            self.assertIsNotNone(request.session['sso_expiry'])
            self.assertEqual(
                response.url,
                'https://example.com/sso?sso=bm9uY2U9MjI4Y2QyNWJkMjRiYmMzMWEyYmZjODFmZjhlYTZkMzkmcmV'
                '0dXJuX3Nzb191cmw9aHR0cHM6Ly9leGFtcGxlLm9yZy9zc28vbG9naW4mY3VzdG9tLm5leHQ9L2Zvbw%3D%'
                '3D&sig=5f9033b9acd322e7a46e5781aece51f57eb5603e2fb9e425c4bc7fe83f06b71a')

        self.call_middleware(asserts, qs={'next': '/foo'})

class SsoLoginTestCase(SsoWithPayloadTestMixin, TestCase):
    url = '/sso/login'

    def test_with_no_nonce_in_session(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'no_nonce_in_session')

        payload = 'nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs)

    def test_with_wrong_nonce(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'wrong_nonce_in_payload')

        payload = 'nonce=31ab54'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

    def test_with_expired_nonce(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'expired_nonce')

        payload = 'nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session(expiry=time.time() - 10))

    def test_nonce_deletion_after_login_attempt(self):
        def asserts(request, response):
            self.assertIsNone(request.session.get('sso_nonce'))
            self.assertIsNone(request.session.get('sso_expiry'))

        payload = 'nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

    def test_with_no_external_id(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'missing_external_id')

        payload = 'nonce=31ab53'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

    def test_with_no_email(self):
        def asserts(request, response):
            self.assertEqual(response.content, b'missing_email')
            self.assertFalse(SsoRecord.objects.filter(external_id=123).exists())

        payload = 'nonce=31ab53&external_id=123'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

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

        user = User.objects.create_user(username='x', email='a@c.com')
        EmailAddress.objects.create(user=user, email=user.email, verified=False)
        SsoRecord.objects.create(user=user, external_id='123', sso_logged_in=False)
        payload = 'nonce=31ab53&username=z&external_id=123&email=a@c.com&custom.first_name=M&custom.last_name=B&custom.timezone=America/St_Vincent&custom.next=/foo'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

    @patch.object(auth, 'login')
    def test_with_matching_sso_record_but_another_sso_account_has_our_email(self, mock):
        def asserts(request, response):
            # This should be unlikely since we should be pushing an update when users change email addresses.
            # For this to happen, something like this would have to have happened:
            # - Person A changes from x@example.com => y@example.com,
            #   AND this change is not sync'd for some reason
            # - Person B changes from z@example.com => x@example.com and then sso's in. The system sees
            #   that x@example.com is associated with Person A's account.
            # In this case, we can't change Person A's email b/c we don't know what to change it to,
            # and email is a required field. The safest thing to do is throw a descriptive error
            # and let admins investigate.
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'email_collision_detected (ID: 124)')
            self.assertFalse(SsoRecord.objects.get(external_id=124).sso_logged_in)
            userA.refresh_from_db()
            self.assertEqual(userA.username, 'PersonA')

        userA = User.objects.create_user(username='PersonA', email='x@example.com')
        SsoRecord.objects.create(user=userA, external_id='123', sso_logged_in=False)
        userB = User.objects.create_user(username='PersonB', email='z@example.com')
        SsoRecord.objects.create(user=userB, external_id='124', sso_logged_in=False)
        payload = 'nonce=31ab53&username=PersonB&external_id=124&email=x@example.com&custom.first_name=Person&custom.last_name=B'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

    @patch.object(auth, 'login')
    def test_with_no_matching_sso_record_and_another_sso_account_has_our_email(self, mock):
        def asserts(request, response):
            # This is similar to the previous example.
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'email_collision_detected (ID: 124)')
            self.assertFalse(SsoRecord.objects.filter(external_id=124).exists())
            userA.refresh_from_db()
            self.assertEqual(userA.username, 'PersonA')

        userA = User.objects.create_user(username='PersonA', email='x@example.com')
        SsoRecord.objects.create(user=userA, external_id='123', sso_logged_in=False)
        payload = 'nonce=31ab53&username=PersonB&external_id=124&email=x@example.com&custom.first_name=Person&custom.last_name=B'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

    @patch.object(auth, 'login')
    def test_with_no_matching_sso_record_and_a_non_sso_account_has_our_email(self, mock):
        def asserts(request, response):
            # This could happen if an account got created in some other manner but hasn't been linked
            # with SSO. In this case we should just link the two accounts via the SSO record.
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.url, 'https://example.org')
            mock.assert_called_with(request, user)
            self.assertTrue(SsoRecord.objects.get(external_id=123).sso_logged_in)
            self.assertEqual(SsoRecord.objects.get(external_id=123).user, user)
            user.refresh_from_db()
            self.assertEqual(user.email, 'x@example.com')
            self.assertEqual(user.first_name, 'Person')
            self.assertEqual(user.last_name, 'A')
            self.assertEqual(user.username, 'PersonA')
            self.assertTrue(EmailAddress.objects.get(user_id=user.id).verified)

        user = User.objects.create_user(username='PersonA', email='x@example.com')
        EmailAddress.objects.create(user=user, email=user.email, verified=False)
        payload = 'nonce=31ab53&username=PersonA&external_id=123&email=x@example.com&custom.first_name=Person&custom.last_name=A'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

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
        payload = 'nonce=31ab53&username=z&external_id=124&email=a@c.com&custom.first_name=M&custom.last_name=B'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs, session=self.session())

    def session(self, expiry=None):
        return {'sso_nonce': '31ab53', 'sso_expiry': expiry or time.time() + 600}

class SsoUpdateTestCase(SsoWithPayloadTestMixin, TestCase):
    url = '/sso/update'

    @patch.object(auth, 'login')
    def test_with_matching_external_id_and_email(self, mock):
        def asserts(request, response):
            self.assertEqual(response.status_code, 204)
            self.assertEqual(response.content, b'')

            # User should not get logged in as a result of this update. It's just a metadata update.
            self.assertFalse(SsoRecord.objects.get(external_id=123).sso_logged_in)
            mock.assert_not_called()

            # Update should still happen otherwise.
            user.refresh_from_db()
            self.assertEqual(user.email, 'a@c.com')
            self.assertEqual(user.first_name, 'M')
            self.assertEqual(user.last_name, 'B')
            self.assertEqual(user.username, 'z')
            self.assertEqual(Profile.objects.get(user=user).timezone, 'America/St_Vincent')
            self.assertTrue(EmailAddress.objects.get(user_id=user.id).verified)

        user = User.objects.create_user(username='x', email='a@c.com')
        EmailAddress.objects.create(user=user, email=user.email, verified=False)
        SsoRecord.objects.create(user=user, external_id='123', sso_logged_in=False)
        payload = 'username=z&external_id=123&email=a@c.com&custom.first_name=M&custom.last_name=B&custom.timezone=America/St_Vincent'
        payload = self.encode(payload)
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs)

class SsoLogoutTestCase(SsoWithPayloadTestMixin, TestCase):
    url = '/sso/logout'

    def test_with_missing_external_id(self):
        def asserts(request, response):
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.content, b'user_not_found')

        payload = self.encode('external_id=123')
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs)

    def test_with_valid_external_id(self):
        def asserts(request, response):
            self.assertEqual(response.status_code, 204)
            self.assertEqual(response.content, b'')
            self.assertFalse(SsoRecord.objects.get(external_id=123).sso_logged_in)

        user = User.objects.create_user(username='x')
        SsoRecord.objects.create(user=user, external_id='123', sso_logged_in=True)
        payload = self.encode('external_id=123')
        qs = {'sso': payload, 'sig': self.sign(payload)}
        self.call_middleware(asserts, qs=qs)

class SsoPassthruTestCase(SsoTestMixin, TestCase):
    url = '/any-url'

    def setUp(self):
        super().setUp()
        self.middleware.get_response = Mock()

    def test_with_no_user_in_session(self):
        # It should not interfere with the request
        def asserts(request, response):
            self.middleware.get_response.assert_called_with(request)

        self.call_middleware(asserts, user=None)

    @patch.object(auth, 'logout')
    def test_with_user_in_session_but_no_sso_record_present(self, logout_mock):
        # It should log out the user and still call the request
        def asserts(request, response):
            logout_mock.assert_called_with(request)
            self.middleware.get_response.assert_called_with(request)

        user = User.objects.create_user(username='x')
        self.call_middleware(asserts, user=user)

    @patch.object(auth, 'logout')
    def test_with_sso_record_with_matching_user_but_logged_in_false(self, logout_mock):
        # It should log out the user and still call the request
        def asserts(request, response):
            logout_mock.assert_called_with(request)
            self.middleware.get_response.assert_called_with(request)

        user = User.objects.create_user(username='x')
        SsoRecord.objects.create(user=user, sso_logged_in=False)
        self.call_middleware(asserts, user=user)


    @patch.object(auth, 'logout')
    def test_with_sso_record_with_matching_and_logged_in_true(self, logout_mock):
        # It should not interfere with the user or the request
        def asserts(request, response):
            logout_mock.assert_not_called
            self.middleware.get_response.assert_called_with(request)

        user = User.objects.create_user(username='x')
        SsoRecord.objects.create(user=user, sso_logged_in=True)
        self.call_middleware(asserts, user=user)
