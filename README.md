⚠️ This project has not been security audited. Use at your own risk.

# oauth-pkce-proxy

A stateless proxy that enables the PKCE extension ([RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)) to the OAuth Authorization Code Flow, for authorization servers that don't support it yet.

The server is stateless and, therefore, doesn't depend on a database being deployed or doesn't have to be run as a single instance. This is accomplished by using the `state` field in the authorization flow to pass data between the authorization request and the authorization callback. All the sensitive data (`code_challenge` and `code` from the target authorization server) is signed and encrypted, and only the proxy should be able to access it.

## Flow

1. The client app starts a PKCE authorization flow with the proxy's endpoint (`/oauth/authorization`)
1. The proxy encrypts the `code_challenge` value into the `state` field and redirects to the target authorization server
1. The user authorizes the app and will be redirected to the proxy's `/callback` endpoint
1. The proxy callback encrypts the `code` received from the target authorization server and stores it and the already encrypted `code_challenge` into the authorization code returned to the client app
1. The client app sends the access token request to the proxy (`/oauth/token`) alongside the `code_verifier`, the proxy decrypts the encrypted data (the upstream authorization code and the initial `code_challenge`), verifies that the PKCE is correct and exchanges the target authorization code for an access token which is passed directly to the client app.

## Running the proxy

### Configuration

Take a look at `.env.sample` to see what environment variables you need to configure.

For the `OAUTH_` variables, you will need to do a couple of things:
1. Create an OAuth app on your OAuth provider webpage; for the Redirect URL you should use the proxy's callback URL (depending on where you are hosting the proxy, it will be something like `myproxyhost.com/callback`); set the `OAUTH_REDIRECT_URL` with the same callback URL

2. When creating an OAuth app you should be provided with a client ID and a client secret; these should be set in `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` respectively

3. The OAuth provider should document its authorization and token endpoints; the URLs should be set in `OAUTH_AUTH_URL` and  `OAUTH_TOKEN_URL`

You will also need 2 secrets:
1. A JWT signing key to be stored in the `JWT_SIGNING_KEY` environment variable
2. An encryption key used to encrypt the sensitive data that we don't want accessible on the user's device, stored in `ENCRYPTION_KEY`

`PORT` defines the port on which the HTTP server will listen.


## References

* [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
* [Protecting Mobile Apps with PKCE](https://www.oauth.com/oauth2-servers/pkce/)
