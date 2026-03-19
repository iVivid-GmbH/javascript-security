# OAuth 2.0 and OpenID Connect (OIDC) Security in JavaScript

## Definition

OAuth 2.0 is an authorization framework that allows users to grant applications access to their resources without sharing passwords. OpenID Connect (OIDC) extends OAuth 2.0 to provide authentication. However, both have numerous security pitfalls: open redirects, state parameter bypass (CSRF), token leakage in URLs, authorization code interception, and improper ID token validation.

## OAuth 2.0 Flows

### Authorization Code Flow (Recommended)

The most secure flow for web applications, where the authorization server returns an authorization code (not tokens) to the client:

```
1. User clicks "Login with Google"
2. App redirects to: https://accounts.google.com/oauth/authorize?
     client_id=123&
     redirect_uri=https://myapp.com/callback&
     response_type=code&
     scope=profile%20email&
     state=random_string

3. User logs in and grants permission
4. Google redirects to: https://myapp.com/callback?
     code=auth_code_xyz&
     state=random_string

5. App exchanges code for tokens (backend):
   POST https://accounts.google.com/oauth/token
   client_id=123&
   client_secret=secret&
   code=auth_code_xyz&
   redirect_uri=https://myapp.com/callback

6. Google returns:
   {
     "access_token": "access_token_value",
     "token_type": "Bearer",
     "expires_in": 3600,
     "id_token": "id_token_jwt"
   }
```

### Implicit Flow (Deprecated - Don't Use)

Older flow where tokens are returned directly in the URL fragment (vulnerable):

```
// DEPRECATED - DO NOT USE
https://accounts.google.com/oauth/authorize?
  client_id=123&
  redirect_uri=https://myapp.com/callback&
  response_type=token&
  scope=profile

// Returns: https://myapp.com/callback#access_token=abc123
// Tokens in URL fragment are exposed in browser history, logs, referrer headers
```

### Authorization Code Flow with PKCE (For Mobile/SPAs)

Uses Proof Key for Code Exchange for increased security without client secrets:

```
1. Client generates code_verifier (random string)
2. Client generates code_challenge = SHA256(code_verifier)

3. Redirect to: https://accounts.google.com/oauth/authorize?
     client_id=123&
     redirect_uri=https://myapp.com/callback&
     response_type=code&
     code_challenge=challenge_hash&
     code_challenge_method=S256&
     state=random_string

4. After authorization, exchange code:
   POST https://accounts.google.com/oauth/token
   client_id=123&
   code=auth_code_xyz&
   code_verifier=original_code_verifier&
   redirect_uri=https://myapp.com/callback

5. Authorization server verifies:
   SHA256(code_verifier) == code_challenge
```

## PKCE (Proof Key for Code Exchange)

PKCE protects against authorization code interception on mobile and public clients:

### How PKCE Works

```javascript
const crypto = require('crypto');

// Step 1: Generate code_verifier (43-128 characters)
const codeVerifier = crypto.randomBytes(32).toString('hex');

// Step 2: Generate code_challenge
const codeChallenge = crypto
  .createHash('sha256')
  .update(codeVerifier)
  .digest('base64url');

// Step 3: Send code_challenge to authorization endpoint
// Step 4: After code returned, send code_verifier to token endpoint

// Server verifies: SHA256(code_verifier) == code_challenge
// If intercepted authorization code without verifier, it's useless
```

### Why PKCE Matters

```
Without PKCE:
1. Attacker intercepts authorization code from redirect URI
2. Attacker can exchange code for tokens using app's client_id
3. Attacker gains access to user's resources

With PKCE:
1. Attacker intercepts authorization code
2. Attacker needs code_verifier (not disclosed)
3. Can't exchange code without verifier
4. Authorization code is useless without verifier
```

## Common Vulnerabilities

### 1. Open Redirect in redirect_uri

An attacker modifies the redirect_uri to send the authorization code to their server:

```javascript
// VULNERABLE: Accepting arbitrary redirect_uri
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type } = req.query;

  // VULNERABLE: No validation of redirect_uri
  // Attacker provides: redirect_uri=https://attacker.com/steal

  const authCode = generateAuthorizationCode(client_id);

  // Redirect with code goes to attacker's server!
  res.redirect(`${redirect_uri}?code=${authCode}`);
});

// SECURE: Validate redirect_uri against registered URIs
const registeredClients = {
  '123': {
    secret: 'secret-key',
    redirectUris: ['https://myapp.com/callback'] // Whitelist
  }
};

app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type } = req.query;

  const client = registeredClients[client_id];

  // SECURE: Verify redirect_uri is registered
  if (!client || !client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'Invalid redirect_uri' });
  }

  const authCode = generateAuthorizationCode(client_id);
  res.redirect(`${redirect_uri}?code=${authCode}`);
});
```

### 2. State Parameter Missing (CSRF)

The state parameter prevents CSRF attacks by ensuring the response matches the request:

```javascript
// VULNERABLE: No state parameter
window.location = `https://accounts.google.com/oauth/authorize?
  client_id=123&
  redirect_uri=https://myapp.com/callback&
  response_type=code`;

// CSRF Attack:
// Attacker tricks user into clicking malicious link that initiates OAuth flow
// User is redirected to myapp.com with attacker's code
// App exchanges code and logs user as attacker

// SECURE: Use state parameter
const state = generateRandomState();
sessionStorage.setItem('oauth_state', state);

window.location = `https://accounts.google.com/oauth/authorize?
  client_id=123&
  redirect_uri=https://myapp.com/callback&
  response_type=code&
  state=${state}`;

// In callback handler:
const urlParams = new URLSearchParams(location.search);
const returnedState = urlParams.get('state');
const savedState = sessionStorage.getItem('oauth_state');

if (returnedState !== savedState) {
  throw new Error('State mismatch - CSRF attack!');
}

// Continue with token exchange
```

### 3. Token Leakage in URL Fragments

Tokens in URL fragments are logged and sent in Referer headers:

```
// VULNERABLE: Implicit flow with tokens in URL
https://myapp.com/callback#access_token=abc123&token_type=Bearer

// Problems:
// 1. Visible in browser history
// 2. Sent in Referer header to other sites
// 3. Accessible to JavaScript (XSS vulnerable)
// 4. Exposed in server logs

// SECURE: Authorization Code flow with code in query string
https://myapp.com/callback?code=auth_code_xyz&state=random
// Code is exchanged server-side for tokens
// Tokens never exposed in browser URL
```

### 4. Authorization Code Interception

Attacker intercepts the authorization code and exchanges it for tokens:

```javascript
// VULNERABLE: Without PKCE
// Attacker intercepts: https://myapp.com/callback?code=xyz123
// Can exchange it: POST /token with client_id and code
// Gets access_token without code_verifier

// SECURE: With PKCE
// Attacker intercepts: https://myapp.com/callback?code=xyz123
// Can't exchange it: needs code_verifier
// code_verifier was generated client-side, not sent to auth server initially
// Attacker can't get code_verifier
```

## Vulnerable OAuth Implementation Examples

### 1. Open Redirect Vulnerability

```javascript
const express = require('express');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// VULNERABLE: No redirect_uri validation
app.get('/vulnerable/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope } = req.query;

  // VULNERABLE: Accept any redirect_uri
  // Attacker can use: redirect_uri=https://attacker.com/steal

  // Simulate user login and consent
  const authCode = generateAuthCode();

  res.redirect(`${redirect_uri}?code=${authCode}&state=${req.query.state}`);
});

// VULNERABLE: Token endpoint doesn't validate client
app.post('/vulnerable/oauth/token', express.urlencoded({ extended: false }), (req, res) => {
  const { client_id, client_secret, code, redirect_uri } = req.body;

  // VULNERABLE: No validation of redirect_uri
  // VULNERABLE: No client secret verification

  const token = generateAccessToken(client_id);

  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: 3600
  });
});

// Client implementation with redirect to attacker
// User clicks "Login with Vulnerable OAuth"
// Redirected to: /vulnerable/oauth/authorize?
//   client_id=123&
//   redirect_uri=https://attacker.com/callback&
//   response_type=code
// Authorization code is sent to attacker!
```

### 2. Missing State Parameter (CSRF)

```javascript
const express = require('express');
const app = express();

// VULNERABLE: No state parameter
app.get('/vulnerable/login-oauth', (req, res) => {
  res.send(`
    <a href="https://oauth-provider.com/authorize?
      client_id=123&
      redirect_uri=https://myapp.com/callback&
      response_type=code">
      Login with OAuth
    </a>
  `);
});

// VULNERABLE: No state validation
app.get('/vulnerable/callback', async (req, res) => {
  const { code, state } = req.query;

  // VULNERABLE: Doesn't check state

  // Exchange code for token
  const tokenResponse = await fetch('https://oauth-provider.com/token', {
    method: 'POST',
    body: new URLSearchParams({
      client_id: '123',
      client_secret: 'secret',
      code: code,
      redirect_uri: 'https://myapp.com/callback'
    })
  });

  const tokens = await tokenResponse.json();

  // VULNERABLE: Creates session with attacker's token
  req.session.accessToken = tokens.access_token;
  req.session.userId = tokens.user_id;

  res.redirect('/dashboard');
});

// CSRF Attack:
// Attacker creates: <img src="https://oauth-provider.com/authorize?client_id=attacker_app&redirect_uri=https://myapp.com/callback">
// User visits attacker's site
// Browser makes request to OAuth provider
// User is redirected to myapp.com with attacker's code
// App exchanges it and logs user as attacker
```

### 3. Implicit Flow with Tokens in URL

```javascript
// VULNERABLE: Using deprecated implicit flow
const loginButton = document.getElementById('login');

loginButton.addEventListener('click', () => {
  // VULNERABLE: Tokens returned in URL fragment
  window.location = `https://oauth-provider.com/authorize?
    client_id=123&
    redirect_uri=https://myapp.com/callback&
    response_type=token&
    scope=profile%20email`;
});

// Browser redirects to:
// https://myapp.com/callback#access_token=abc123&token_type=Bearer&expires_in=3600

// Problems:
// 1. Token in URL visible in browser history
// 2. Token sent in Referer header to attacker.com if user clicks link
// 3. Token accessible to malicious scripts
```

### 4. Missing PKCE in Native App

```javascript
// VULNERABLE: Android app without PKCE
const client_id = '123';
const redirect_uri = 'com.myapp://callback';
const response_type = 'code';

Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse(
  `https://oauth-provider.com/authorize?
    client_id=${client_id}&
    redirect_uri=${redirect_uri}&
    response_type=${response_type}`
));
startActivity(intent);

// On receiving authorization code:
String authCode = uri.getQueryParameter('code');

// VULNERABLE: Exchange code without PKCE
HttpRequest request = new HttpRequest.POST('https://oauth-provider.com/token');
request.setBody(new URLEncodedFormBody(
  'client_id', client_id,
  'client_secret', client_secret,
  'code', authCode,
  'redirect_uri', redirect_uri
));

// Attacker can intercept authorization code and exchange it:
// POST /token with client_id and code
// Gets access_token (no PKCE to verify)
```

## Secure OAuth Implementation

### 1. Authorization Code Flow with State

```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: true, secure: true }
}));

const OAuth_CONFIG = {
  client_id: process.env.OAUTH_CLIENT_ID,
  client_secret: process.env.OAUTH_CLIENT_SECRET,
  authorization_endpoint: 'https://oauth-provider.com/authorize',
  token_endpoint: 'https://oauth-provider.com/token',
  userinfo_endpoint: 'https://oauth-provider.com/userinfo',
  redirect_uri: 'https://myapp.com/oauth/callback',
  scopes: 'openid profile email'
};

// SECURE: Initiate OAuth with state
app.get('/oauth/login', (req, res) => {
  // Generate state parameter
  const state = crypto.randomBytes(32).toString('hex');

  // Save state in session
  req.session.oauthState = state;

  // Redirect to authorization endpoint
  const authUrl = new URL(OAuth_CONFIG.authorization_endpoint);
  authUrl.searchParams.append('client_id', OAuth_CONFIG.client_id);
  authUrl.searchParams.append('redirect_uri', OAuth_CONFIG.redirect_uri);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', OAuth_CONFIG.scopes);
  authUrl.searchParams.append('state', state);

  res.redirect(authUrl.toString());
});

// SECURE: Handle OAuth callback
app.get('/oauth/callback', async (req, res) => {
  const { code, state } = req.query;

  // SECURE: Validate state parameter
  if (!state || state !== req.session.oauthState) {
    return res.status(400).json({ error: 'Invalid state parameter - CSRF attack detected' });
  }

  // Clear state from session
  delete req.session.oauthState;

  try {
    // Exchange authorization code for tokens
    const tokenResponse = await fetch(OAuth_CONFIG.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: OAuth_CONFIG.redirect_uri,
        client_id: OAuth_CONFIG.client_id,
        client_secret: OAuth_CONFIG.client_secret
      })
    });

    if (!tokenResponse.ok) {
      throw new Error('Token exchange failed');
    }

    const tokens = await tokenResponse.json();

    // SECURE: Validate token response
    if (!tokens.access_token || !tokens.token_type) {
      throw new Error('Invalid token response');
    }

    // Fetch user information
    const userResponse = await fetch(OAuth_CONFIG.userinfo_endpoint, {
      headers: {
        'Authorization': `${tokens.token_type} ${tokens.access_token}`
      }
    });

    const userInfo = await userResponse.json();

    // Create session for user
    req.session.userId = userInfo.sub;
    req.session.userEmail = userInfo.email;
    req.session.accessToken = tokens.access_token;

    res.redirect('/dashboard');
  } catch (error) {
    console.error('OAuth error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
});

app.listen(3000);
```

### 2. Authorization Code Flow with PKCE

```javascript
const express = require('express');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();

// PKCE helper functions
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCodeChallenge(verifier) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// SECURE: PKCE login
app.get('/secure/pkce-login', (req, res) => {
  // Generate PKCE parameters
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  const state = crypto.randomBytes(32).toString('hex');

  // Save in session
  req.session.pkceVerifier = codeVerifier;
  req.session.oauthState = state;

  // Build authorization URL
  const authUrl = new URL('https://oauth-provider.com/authorize');
  authUrl.searchParams.append('client_id', process.env.OAUTH_CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', 'https://myapp.com/pkce-callback');
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('scope', 'openid profile email');
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');

  res.redirect(authUrl.toString());
});

// SECURE: PKCE callback
app.get('/secure/pkce-callback', async (req, res) => {
  const { code, state } = req.query;

  // Validate state
  if (state !== req.session.oauthState) {
    return res.status(400).json({ error: 'State mismatch' });
  }

  // Get stored code verifier
  const codeVerifier = req.session.pkceVerifier;

  if (!codeVerifier) {
    return res.status(400).json({ error: 'No PKCE verifier found' });
  }

  try {
    // Exchange code with PKCE verifier
    const tokenResponse = await fetch('https://oauth-provider.com/token', {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        client_id: process.env.OAUTH_CLIENT_ID,
        redirect_uri: 'https://myapp.com/pkce-callback',
        code_verifier: codeVerifier
      })
    });

    const tokens = await tokenResponse.json();

    // Create session
    req.session.userId = tokens.user_id;
    req.session.accessToken = tokens.access_token;

    // Clear PKCE data
    delete req.session.pkceVerifier;
    delete req.session.oauthState;

    res.redirect('/dashboard');
  } catch (error) {
    res.status(500).json({ error: 'Token exchange failed' });
  }
});

app.listen(3000);
```

### 3. Secure Redirect URI Validation

```javascript
const express = require('express');
const app = express();

// Registered OAuth clients
const registeredClients = {
  'client-123': {
    secret: process.env.CLIENT_SECRET,
    redirectUris: [
      'https://myapp.com/callback',
      'https://myapp.com/oauth/callback',
      'https://app.example.com/auth/callback'
    ],
    scopes: ['openid', 'profile', 'email']
  }
};

// SECURE: Validate redirect_uri
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  // Get client configuration
  const client = registeredClients[client_id];

  // SECURE: Verify client exists
  if (!client) {
    return res.status(400).json({ error: 'Unknown client' });
  }

  // SECURE: Verify redirect_uri is registered
  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({
      error: 'Invalid redirect_uri',
      message: 'Redirect URI not registered for this client'
    });
  }

  // SECURE: Verify response_type
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'Unsupported response type' });
  }

  // SECURE: Verify scopes
  const requestedScopes = scope.split(' ');
  const validScopes = requestedScopes.every(s => client.scopes.includes(s));

  if (!validScopes) {
    return res.status(400).json({ error: 'Invalid scope requested' });
  }

  // Generate authorization code
  const authCode = generateAuthorizationCode(client_id);

  // Redirect with code and state
  const callbackUrl = new URL(redirect_uri);
  callbackUrl.searchParams.append('code', authCode);
  callbackUrl.searchParams.append('state', state);

  res.redirect(callbackUrl.toString());
});

app.listen(3000);
```

## OpenID Connect (OIDC) ID Token Validation

OpenID Connect extends OAuth 2.0 with an ID token (JWT) for authentication:

```javascript
const jwt = require('jsonwebtoken');
const express = require('express');
const jwksClient = require('jwks-rsa');

const app = express();

// Initialize JWKS client for fetching public keys
const client = jwksClient({
  jwksUri: 'https://oauth-provider.com/.well-known/jwks.json'
});

// SECURE: ID Token validation
async function validateIdToken(idToken) {
  // Decode token without verification first (to get kid)
  const decoded = jwt.decode(idToken, { complete: true });

  if (!decoded) {
    throw new Error('Invalid ID token format');
  }

  // Get signing key
  const key = await client.getSigningKey(decoded.header.kid);
  const signingKey = key.getPublicKey();

  // SECURE: Verify token signature and claims
  const verified = jwt.verify(idToken, signingKey, {
    algorithms: ['RS256'],
    issuer: 'https://oauth-provider.com/',
    audience: process.env.OAUTH_CLIENT_ID
  });

  // Validate required claims
  if (!verified.sub || !verified.aud || !verified.iss) {
    throw new Error('Missing required claims');
  }

  // Validate expiry
  if (verified.exp && Date.now() >= verified.exp * 1000) {
    throw new Error('ID token expired');
  }

  return verified;
}

// SECURE: OAuth callback with ID token validation
app.get('/oauth/callback', async (req, res) => {
  const { code, state, id_token } = req.query;

  try {
    // Validate state
    if (state !== req.session.oauthState) {
      throw new Error('State mismatch');
    }

    // SECURE: Validate ID token
    const userInfo = await validateIdToken(id_token);

    // Create session
    req.session.userId = userInfo.sub;
    req.session.userEmail = userInfo.email;

    res.redirect('/dashboard');
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

app.listen(3000);
```

## Best Practices for OAuth 2.0 / OIDC Security

1. **Use Authorization Code flow** - Never use deprecated Implicit flow
2. **Implement PKCE** - Required for mobile and SPA applications
3. **Always validate state** - Prevent CSRF attacks
4. **Whitelist redirect_uri** - Validate against registered URIs
5. **Use HTTPS only** - Protect tokens in transit
6. **Store tokens securely** - Use HttpOnly cookies for tokens
7. **Validate ID tokens** - Check signature, issuer, audience, expiry
8. **Keep client secrets secret** - Don't expose in client-side code
9. **Use short-lived access tokens** - Implement token refresh
10. **Monitor for suspicious activity** - Log authorization failures
11. **Keep libraries updated** - Security patches for OAuth libraries
12. **Implement rate limiting** - Prevent token exchange attacks

## References

- OAuth 2.0 Authorization Framework: https://tools.ietf.org/html/rfc6749
- PKCE (RFC 7636): https://tools.ietf.org/html/rfc7636
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
- OWASP OAuth 2.0 Threat Model: https://tools.ietf.org/html/draft-ietf-oauth-security-topics
- OAuth 2.0 for Browser-Based Apps: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
