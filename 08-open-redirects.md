# Open Redirects

## Definition

An open redirect is a vulnerability that allows an attacker to redirect users to arbitrary external websites under the legitimate domain's name. An application accepts a URL parameter and redirects the user to that URL without validating that it's a legitimate internal or trusted destination.

Attackers exploit open redirects in phishing attacks, OAuth token theft, credential harvesting, and malware distribution. The vulnerability is dangerous because users trust links on legitimate domains, even if the domain doesn't explicitly control the target.

---

## How Open Redirects Are Exploited

### Attack Vector 1: Simple Phishing

```javascript
// VULNERABLE: No validation of redirect URL
app.get('/redirect', (req, res) => {
  const redirectUrl = req.query.url;
  res.redirect(redirectUrl); // ❌ Redirects to any URL
});

// Attacker crafts link:
// https://example.com/redirect?url=https://attacker.com/phishing

// User sees legitimate domain (example.com) in the URL bar
// Clicks the link expecting a safe site
// Gets redirected to attacker's phishing site
// Attacker's site looks like legitimate login page
// User enters credentials, attacker steals them
```

### Attack Vector 2: OAuth Token Theft via redirect_uri

```javascript
// OAuth flow:
// 1. User clicks "Login with GitHub"
// 2. Redirected to GitHub authorization
// 3. GitHub redirects back to application with code
// 4. Application exchanges code for access token

app.get('/auth/callback', (req, res) => {
  const code = req.query.code;
  const state = req.query.state;

  // VULNERABLE: redirect_uri parameter allows any URL
  const redirectUri = req.query.redirect_uri; // User input!

  // Exchange code for token
  const token = await exchangeCodeForToken(code, state);

  // Redirect to user's desired location (attacker-provided!)
  res.redirect(redirectUri + '?token=' + token); // ❌ Token sent to attacker!
});

// Attack:
// 1. Attacker crafts: https://example.com/auth/callback?code=...&redirect_uri=https://attacker.com
// 2. User clicks link
// 3. Legitimate site exchanges code for token
// 4. Token is sent to attacker's site
// 5. Attacker now has OAuth token = account access
```

### Attack Vector 3: OAuth redirect_uri Bypass

```javascript
// OAuth provider allows certain redirect URIs
// But vulnerable application allows parameter override

app.get('/oauth-login', (req, res) => {
  const clientId = process.env.OAUTH_CLIENT_ID;
  // VULNERABLE: Appending user-provided URL
  const redirectUri = 'https://example.com/callback' + req.query.after;

  // If redirectUri isn't validated, attacker can break out
  // ?after=.example.com@attacker.com -> redirects to attacker's domain
  // Or ?after=evil.com/
  // Or ?after=../../../evil.com

  const authUrl = `https://oauth-provider.com/authorize?` +
    `client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}`;

  res.redirect(authUrl);
});
```

### Attack Vector 4: Open Redirect to Malware

```javascript
// VULNERABLE: Download page redirect
app.get('/download', (req, res) => {
  const url = req.query.file;
  res.redirect(url); // ❌ Can redirect to any file
});

// Attacker: https://example.com/download?file=https://attacker.com/malware.exe
// User expects to download a file from legitimate site
// Gets malware instead
```

---

## Real Vulnerable Code Examples

### Example 1: Simple Redirect Parameter

```javascript
// VULNERABLE: Naive redirect implementation
const express = require('express');
const app = express();

app.get('/login', (req, res) => {
  // Render login form
  res.render('login');
});

app.post('/login', (req, res) => {
  const user = authenticateUser(req.body);

  if (user) {
    // VULNERABLE: Redirect to user-provided URL
    const redirectUrl = req.query.next || req.body.next;
    res.redirect(redirectUrl); // ❌ Can be any URL!
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});

// Attack:
// POST /login?next=https://attacker.com/phishing
// After login, user is redirected to attacker's site
// But login appears successful, user trusted the domain
```

**HTML form that enables the vulnerability:**

```html
<!-- Login form includes hidden redirect parameter -->
<form method="POST" action="/login?next=https://attacker.com/phishing">
  <input name="email" type="email" required>
  <input name="password" type="password" required>
  <button>Login</button>
</form>

<!-- Or attacker crafts the URL themselves -->
<!-- https://example.com/login?next=https://attacker.com -->
```

### Example 2: URL Parameter Manipulation

```javascript
// VULNERABLE: Checking URL format but not domain
app.get('/leave-site', (req, res) => {
  const url = req.query.url;

  // WEAK validation: Only checks if it's a valid URL
  if (isValidUrl(url)) {
    res.redirect(url); // ❌ Domain not validated!
  } else {
    res.status(400).json({ error: 'Invalid URL' });
  }
});

function isValidUrl(url) {
  try {
    new URL(url); // Only checks if URL is valid, not if domain is trusted
    return true;
  } catch {
    return false;
  }
}

// isValidUrl('https://attacker.com') returns true!
// User is redirected to attacker's site
```

### Example 3: Relative URL Vulnerability

```javascript
// VULNERABLE: Trusting relative URLs but allowing absolute override
app.get('/callback', (req, res) => {
  const path = req.query.path;

  // VULNERABLE: Assumes relative paths are safe
  // But attacker can use //
  const safeUrl = '/app/' + path;

  // Path with //attacker.com overrides the domain!
  // /app///attacker.com becomes //attacker.com (protocol-relative URL)
  res.redirect(safeUrl);
});

// Attack: /callback?path=//attacker.com
// Becomes: /app///attacker.com
// Browser interprets as: //attacker.com (protocol-relative)
// Redirects to attacker's site with same protocol!
```

### Example 4: JavaScript-based Redirect

```javascript
// Frontend code - also vulnerable
function redirectAfterLogin() {
  const params = new URLSearchParams(window.location.search);
  const redirectUrl = params.get('returnTo');

  // ❌ VULNERABLE: Direct redirect without validation
  if (redirectUrl) {
    window.location.href = redirectUrl;
  } else {
    window.location.href = '/dashboard';
  }
}

// Attacker sends: https://example.com/login?returnTo=https://attacker.com
// After login, JavaScript redirects to attacker's site
```

### Example 5: OAuth Implementation Vulnerability

```javascript
// VULNERABLE: OAuth callback with unvalidated redirect_uri
const express = require('express');
const axios = require('axios');
const app = express();

app.get('/auth/github/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;
  const returnUrl = req.query.return_url; // USER INPUT!

  // Validate state (CSRF protection)
  if (state !== req.session.oauthState) {
    return res.status(400).json({ error: 'Invalid state' });
  }

  try {
    // Exchange code for token
    const response = await axios.post(
      'https://github.com/login/oauth/access_token',
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code: code
      }
    );

    const accessToken = response.data.access_token;

    // VULNERABLE: Redirect to user-provided URL with token
    const redirectUrl = returnUrl + '?token=' + accessToken;
    res.redirect(redirectUrl); // ❌ Token sent to attacker!
  } catch (error) {
    res.status(500).json({ error: 'Authentication failed' });
  }
});

// Attack:
// 1. Attacker sends: https://example.com/auth/github/callback?...&return_url=https://attacker.com/steal
// 2. User clicks, GitHub authentication succeeds
// 3. Application redirects to attacker's site WITH ACCESS TOKEN
// 4. Attacker uses token to access user's GitHub account
```

---

## URL Parsing Pitfalls in JavaScript

### Pitfall 1: Protocol-Relative URLs

```javascript
// VULNERABLE: Assuming /path is always relative
function safeRedirect(url) {
  if (url.startsWith('/')) {
    res.redirect(url); // ASSUME IT'S RELATIVE
  } else {
    res.status(400).json({ error: 'Invalid URL' });
  }
}

// Attack: //attacker.com
// Starts with / but is actually a protocol-relative URL
// Redirects to attacker.com using current protocol!

// What /attacker.com means:
// /path -> relative path (safe)
// //attacker.com -> protocol-relative (uses attacker's domain!)
// ///example.com -> same as above
```

### Pitfall 2: Data URLs and JavaScript URLs

```javascript
// VULNERABLE: Only checking for http/https
function isExternalRedirect(url) {
  return url.startsWith('http://') || url.startsWith('https://');
}

const safeUrl = isExternalRedirect(url) ? url : '/default';

// Attack: javascript:alert('XSS')
// Not http/https, so treated as internal
// But browser executes JavaScript code!

// Attack: data:text/html,<script>alert('XSS')</script>
// Not http/https, but executes code!
```

### Pitfall 3: URL Encoding Bypass

```javascript
// VULNERABLE: Checking origin but not decoding
function isInternalRedirect(url) {
  const origin = new URL(url, window.location.origin).origin;
  return origin === window.location.origin;
}

// URL: https://example.com/evil
// Decoded: https://example.com/evil
// Looks internal... but attacker can encode

// Attack: Encoded //attacker.com as ///a@attacker.com
// new URL('///a@attacker.com') tries to parse but might bypass check
```

### Pitfall 4: Double URL Encoding

```javascript
// Attack with multiple encodings
const url = 'https%3A%2F%2Fattacker.com'; // URL-encoded

// First decoding:
decodeURIComponent(url); // 'https://attacker.com'

// But what if application decodes twice?
// Second decoding might reveal hidden redirects
```

---

## Prevention with Whitelist

### Whitelist Approach 1: Approved Paths

```javascript
// SECURE: Whitelist of approved internal paths
const allowedPaths = [
  '/dashboard',
  '/profile',
  '/settings',
  '/logout'
];

app.post('/login', (req, res) => {
  const user = authenticateUser(req.body);

  if (user) {
    const redirectPath = req.query.next;

    // Only redirect to whitelisted paths
    if (allowedPaths.includes(redirectPath)) {
      res.redirect(redirectPath); // ✓ SAFE
    } else {
      res.redirect('/dashboard'); // Default safe redirect
    }
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});
```

### Whitelist Approach 2: Approved Domains

```javascript
// SECURE: Whitelist of approved domains
const ALLOWED_DOMAINS = [
  'example.com',
  'app.example.com',
  'partner1.com'
];

function isAllowedRedirect(url) {
  try {
    const parsed = new URL(url);
    return ALLOWED_DOMAINS.includes(parsed.hostname);
  } catch {
    return false;
  }
}

app.get('/redirect', (req, res) => {
  const redirectUrl = req.query.url;

  if (isAllowedRedirect(redirectUrl)) {
    res.redirect(redirectUrl); // ✓ SAFE
  } else {
    res.status(400).json({ error: 'Invalid redirect URL' });
  }
});
```

### Whitelist Approach 3: Validation with URL Parsing

```javascript
// SECURE: Proper URL validation
function isInternalRedirect(url) {
  try {
    const parsed = new URL(url, process.env.APP_URL);

    // Check that hostname matches
    const appUrl = new URL(process.env.APP_URL);
    if (parsed.hostname !== appUrl.hostname) {
      return false; // Different domain
    }

    // Ensure it's http/https
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    // Ensure it's not a malicious path
    if (!parsed.pathname.startsWith('/')) {
      return false;
    }

    // Ensure no ../ traversal
    if (parsed.pathname.includes('..')) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

app.post('/login', (req, res) => {
  const user = authenticateUser(req.body);

  if (user) {
    const redirectUrl = req.query.next;

    if (isInternalRedirect(redirectUrl)) {
      res.redirect(redirectUrl); // ✓ SAFE
    } else {
      res.redirect('/dashboard'); // Default safe redirect
    }
  }
});
```

### Whitelist Approach 4: Encrypted/Signed Redirects

```javascript
// SECURE: Redirect token instead of URL
const crypto = require('crypto');

// During login, generate a redirect token
app.post('/login', (req, res) => {
  const user = authenticateUser(req.body);

  if (user) {
    const redirectToken = crypto.randomBytes(32).toString('hex');

    // Store mapping in session/cache
    redirectCache.set(redirectToken, '/dashboard');

    // Return token instead of URL
    res.json({
      success: true,
      redirectToken: redirectToken
    });
  }
});

// On frontend, use token to get redirect
app.get('/goto/:token', (req, res) => {
  const redirectUrl = redirectCache.get(req.params.token);

  if (redirectUrl) {
    redirectCache.delete(req.params.token); // One-time use
    res.redirect(redirectUrl); // ✓ SAFE - from server storage
  } else {
    res.status(400).json({ error: 'Invalid redirect token' });
  }
});
```

---

## Secure Redirect Implementation

### Complete Secure Example

```javascript
const express = require('express');
const app = express();

// Configuration
const TRUSTED_DOMAINS = ['example.com', 'app.example.com'];
const TRUSTED_PATHS = ['/dashboard', '/profile', '/settings'];
const DEFAULT_REDIRECT = '/dashboard';

/**
 * Validates if a redirect URL is safe
 * @param {string} url - The URL to validate
 * @returns {boolean} - Whether the URL is safe to redirect to
 */
function isSafeRedirect(url) {
  // No URL provided - use default
  if (!url) {
    return true; // Will use DEFAULT_REDIRECT
  }

  try {
    // Parse the URL
    const parsed = new URL(url, process.env.APP_URL);

    // Check protocol is http/https
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    // Check hostname is trusted
    const isAllowedDomain = TRUSTED_DOMAINS.some(domain => {
      return parsed.hostname === domain ||
             parsed.hostname.endsWith('.' + domain);
    });

    if (!isAllowedDomain) {
      return false;
    }

    // Check for suspicious patterns in pathname
    if (parsed.pathname.includes('..') ||
        parsed.pathname.includes('//') ||
        parsed.pathname.includes('%2e%2e')) { // Encoded ..
      return false;
    }

    return true;
  } catch {
    // Invalid URL format
    return false;
  }
}

app.post('/login', (req, res) => {
  const user = authenticateUser(req.body);

  if (!user) {
    return res.status(401).render('login', {
      error: 'Invalid credentials'
    });
  }

  // Create session
  req.session.userId = user.id;

  // Get redirect URL
  let redirectUrl = req.query.next || req.body.next || DEFAULT_REDIRECT;

  // Validate redirect
  if (!isSafeRedirect(redirectUrl)) {
    redirectUrl = DEFAULT_REDIRECT;
  }

  res.redirect(redirectUrl); // ✓ SAFE
});

// Handle redirect with validation (for frontend)
app.get('/redirect', (req, res) => {
  const targetUrl = req.query.url;

  if (!isSafeRedirect(targetUrl)) {
    return res.status(400).json({
      error: 'Invalid redirect URL'
    });
  }

  res.json({ redirectUrl: targetUrl }); // Return to frontend for client-side redirect
});

// OAuth callback example - SECURE
app.get('/auth/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state;

  // Validate state
  if (state !== req.session.oauthState) {
    return res.status(400).json({ error: 'Invalid state' });
  }

  // DO NOT accept redirect_uri from user!
  // Use a fixed configured redirect_uri with OAuth provider
  const token = await exchangeCodeForToken(
    code,
    'https://example.com/auth/callback' // Fixed, not from user input!
  );

  // Use safe redirect
  const redirectUrl = req.query.next || '/dashboard';
  if (!isSafeRedirect(redirectUrl)) {
    return res.redirect('/dashboard');
  }

  // Store token in session, NOT in URL
  req.session.accessToken = token;
  res.redirect(redirectUrl); // ✓ SAFE
});

module.exports = app;
```

---

## Best Practices Checklist

1. **Always Whitelist Redirect URLs**
   - Use allowlist, not blocklist
   - Include approved domains/paths
   - Default to safe location if not whitelisted

2. **Avoid User-Provided Redirect URLs in OAuth**
   - Register fixed redirect URIs with OAuth provider
   - Never accept redirect_uri as parameter
   - Always validate against registered URIs

3. **Validate URL Format**
   ```javascript
   // Use URL constructor for parsing
   const parsed = new URL(url, baseURL);
   // Check protocol, hostname, pathname
   ```

4. **Use Relative URLs When Possible**
   ```javascript
   // ✓ SAFE: Relative path
   res.redirect('/dashboard');

   // ❌ RISKY: Can be manipulated
   res.redirect(userProvidedUrl);
   ```

5. **Prevent Protocol-Relative URLs**
   ```javascript
   // ❌ VULNERABLE: Allows //attacker.com
   if (url.startsWith('/')) { redirect(url); }

   // ✓ SAFE: Explicit protocol and domain check
   const parsed = new URL(url);
   if (parsed.protocol !== 'https:') { return false; }
   ```

6. **Beware of URL Encoding Tricks**
   ```javascript
   // %2e%2e is encoded ..
   // %252e%252e is double-encoded
   // Decode properly before validation
   ```

7. **Never Send Tokens in Redirect URLs**
   ```javascript
   // ❌ VULNERABLE
   res.redirect(redirectUrl + '?token=' + token);

   // ✓ SAFE: Store in session/cookie
   req.session.token = token;
   res.redirect(redirectUrl);
   ```

8. **Test Common Attack Patterns**
   ```javascript
   const testCases = [
     '//attacker.com',
     '///attacker.com',
     'http://attacker.com',
     'https://attacker.com',
     '//attacker.com@example.com',
     'java&#x09;script:alert(1)',
     '../../../attacker.com'
   ];

   testCases.forEach(url => {
     if (isSafeRedirect(url)) {
       console.error('VULNERABLE TO:', url);
     }
   });
   ```

9. **Log Redirect Attempts**
   ```javascript
   app.get('/redirect', (req, res) => {
     const url = req.query.url;

     if (!isSafeRedirect(url)) {
       console.warn('OPEN REDIRECT ATTEMPT:', {
         ip: req.ip,
         url: url,
         timestamp: new Date()
       });
     }

     // Safe redirect
   });
   ```

10. **Use Content Security Policy**
    ```http
    Content-Security-Policy: default-src 'self'
    ```
    Limits redirect targets somewhat

11. **Document Redirect Logic**
    - Explain why each redirect is safe
    - Document whitelist maintenance
    - Add comments for security checks

12. **Security Testing**
    - Test with OWASP ZAP or Burp Suite
    - Fuzz redirect parameters
    - Check OAuth implementations carefully

---

## Real-World Examples

- **Facebook**: Multiple open redirect vulnerabilities in share dialogs
- **Google**: Open redirect in OAuth implementations
- **Microsoft**: Open redirect in authentication flows
- **Twitter**: Open redirects via shortened URLs
- **LinkedIn**: Open redirect in job links

---

## Related Reading

- OWASP: Unvalidated Redirects and Forwards
- CWE-601: URL Redirection to Untrusted Site
- RFC 7231: HTTP/1.1 Semantics and Content (Location header)
- OAuth 2.0 Security Best Practices
- URL Parsing specification and edge cases
