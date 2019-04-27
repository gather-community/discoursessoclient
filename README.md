# discoursessoclient

A Django implementation of the client side of the [Discourse SSO protocol](https://meta.discourse.org/t/official-single-sign-on-for-discourse-sso/13045).

Implemented as Django middleware.

## Production Use

1. Clone this repo into your top-level Django directory or elsewhere in your Python path.
1. Add `discoursessoclient` to your Django `INSTALLED_APPS`.
1. Add `discoursessoclient.client.DiscourseSsoClientMiddleware` in your middleware list **after** `django.contrib.auth.middleware.AuthenticationMiddleware`.
1. Add the following settings to your `settings.py`:

        ######################################################################
        # Discourse-style single sign on

        # Enter something non-trivially random, like the output of `secrets.token_hex`
        SSO_SECRET = 'xxx'

        # The URL of the SSO provider endpoint as described in the Discourse protocol.
        # Typically a system that you control where users' credentials are stored and where sign-in takes place.
        SSO_PROVIDER_URL = 'https://example.com/sso'

        # The base URL of the server where this app is being used. Needed below to construct the LOGIN_URL.
        SSO_CLIENT_BASE_URL = 'https://example.org'
1. Ensure the `LOGIN_URL` setting is pointing at `/sso/init`. This can either be by entering that path explicitly or,
if your app is expecting a named URL pattern in that setting, by creating a named URL pattern pointing at
`/sso/init` and entering its name as `LOGIN_URL`.
1. Run migrations.
1. Attempt to visit a protected resource. You should be redirected to the SSO_PROVIDER_URL with a proper payload, initiating the SSO flow.

## Development

To work on this app in development:

1. Create a sample Django project.
1. Add a view protected with `@login_required` and map it to a URL. Confirm that you see the login page when attempting to view it.
1. Add the discoursessoclient app as described above.
1. Run the tests with `python manage.py test`.
1. Visit the protected URL again. You should be redirected to SSO_PROVIDER_URL. You can either set up a
separate development server at that URL to implement the provider portion of the flow, or manually decode
the payload and make a new one to send back to `/sso/login` to test the rest of the flow.
