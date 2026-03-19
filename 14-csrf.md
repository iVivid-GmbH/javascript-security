# Cross-Site Request Forgery (CSRF) in JavaScript/Node.js

## Definition

Cross-Site Request Forgery (CSRF) is a security vulnerability where an attacker tricks an authenticated user into performing unwanted actions on a website where the user is logged in. The attacker crafts a malicious request that uses the victim's existing session/authentication cookies to perform state-changing operations without the user's knowledge or consent.

## How CSRF Works

### The Attack Vector

1. **Victim logs into legitimate site** - User authenticates to `bank.com` and receives session cookie
2. **Victim visits attacker's site** - While still logged in, victim visits `attacker.com`
3. **Attacker's site makes hidden request** - The malicious page sends a request to `bank.com`
4. **Victim's browser includes cookies automatically** - Browser automatically includes `bank.com` session cookies
5. **Unwanted action is performed** - The request succeeds because the user is authenticated

### Key Understanding: Automatic Cookie Inclusion

Browsers automatically include cookies for any request to the same origin, regardless of where the request originated. This is the core vulnerability exploited by CSRF.

```javascript
// User is logged into: https://bank.com

// Attacker's site includes:
<img src="https://bank.com/transfer?amount=1000&to=attacker" />

// Browser automatically sends bank.com cookies with this request
// The transfer happens because the user is authenticated!
```

## Concrete Attack HTML Page Example

### Attack Scenario 1: Hidden Form Submission

```html
<!-- Attacker's malicious page: attacker.com/attack.html -->
<html>
<head>
  <title>You've Won a Prize!</title>
</head>
<body>
  <h1>Click here to claim your prize!</h1>

  <!-- Hidden CSRF attack form -->
  <form id="csrf-form" action="https://bank.com/transfer" method="POST" style="display:none;">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="recipient" value="attacker@evil.com">
    <input type="hidden" name="description" value="Legitimate payment">
  </form>

  <button onclick="document.getElementById('csrf-form').submit()">Click to Claim Prize</button>

  <script>
    // Auto-submit the form when page loads (no user click needed)
    // Uncomment to make it truly hidden:
    // window.onload = function() {
    //   document.getElementById('csrf-form').submit();
    // };
  </script>
</body>
</html>
```

### Attack Scenario 2: Image-Based CSRF

```html
<!-- Attacker's page: attacker.com/attack.html -->
<html>
<body>
  <h1>Interesting Article</h1>
  <p>Check out this article...</p>

  <!-- Hidden image request to perform CSRF attack -->
  <img src="https://bank.com/delete-account?confirm=yes" width="0" height="0" style="display:none;">
  <!-- This request will execute if user is logged into bank.com -->

  <!-- Multiple attacks -->
  <img src="https://admin.company.com/promote-user?user_id=attacker&role=admin" style="display:none;">
  <img src="https://gmail.com/settings/forward?forward_to=attacker@evil.com" style="display:none;">
</body>
</html>
```

### Attack Scenario 3: AJAX-Based CSRF

```html
<!-- Attacker's page with JavaScript CSRF attack -->
<html>
<body>
  <h1>Free Game!</h1>

  <script>
    // Fetch request to target site (may be blocked by CORS, but not by CSRF checks)
    fetch('https://bank.com/api/transfer', {
      method: 'POST',
      credentials: 'include', // Include cookies for same-origin requests
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        amount: 5000,
        recipient: 'attacker@evil.com'
      })
    })
    .then(response => console.log('Transfer initiated'))
    .catch(error => console.log('Request blocked by CORS'));
  </script>
</body>
</html>
```

## State-Changing vs Read-Only Requests

### State-Changing Requests (Vulnerable to CSRF)

State-changing operations modify data on the server and should always be protected:

- **POST, PUT, PATCH, DELETE** - Modification requests
- **GET with side effects** - Sometimes GET requests change state (bad practice, but happens)
- Examples: transfers, password changes, account deletion, posting content

### Read-Only Requests (Not Vulnerable to CSRF)

Read-only operations don't modify data and don't need CSRF protection:

- **GET, HEAD, OPTIONS** - Information retrieval only
- They don't change server state
- However, they may still leak sensitive data via Referer headers

```javascript
// VULNERABLE: GET request that changes state (bad practice)
app.get('/delete-account/:id', (req, res) => {
  // CSRF vulnerability - GET should never change state!
  deleteAccount(req.params.id);
  res.send('Account deleted');
});

// SECURE: POST request that changes state
app.post('/delete-account/:id', (req, res) => {
  deleteAccount(req.params.id);
  res.send('Account deleted');
});
```

## CSRF Token Pattern (Synchronizer Token Pattern)

The synchronizer token pattern is the most common CSRF defense:

### How It Works

1. **Server generates unique token** - Server creates a random, unpredictable token for each session
2. **Token sent to client** - Server includes token in HTML form or response
3. **Client sends token back** - When submitting form, client includes the token
4. **Server validates token** - Server verifies token matches session before processing request
5. **Attacker cannot forge token** - Attacker cannot generate valid tokens for victim's session

### Vulnerable Code (Without CSRF Token)

```javascript
const express = require('express');
const session = require('express-session');
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true
}));

// VULNERABLE: No CSRF token validation
app.post('/transfer', (req, res) => {
  const { amount, recipient } = req.body;

  // Process transfer without verifying CSRF token
  processTransfer(req.session.userId, amount, recipient);
  res.send('Transfer completed');
});
```

### Secure Code (With CSRF Token)

```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true
}));

// Middleware to generate CSRF token
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
});

// Display form with CSRF token
app.get('/transfer', (req, res) => {
  res.send(`
    <form action="/transfer" method="POST">
      <input type="hidden" name="csrfToken" value="${req.session.csrfToken}">
      <input type="number" name="amount" required>
      <input type="email" name="recipient" required>
      <button type="submit">Transfer</button>
    </form>
  `);
});

// SECURE: Verify CSRF token before processing
app.post('/transfer', (req, res) => {
  const { amount, recipient, csrfToken } = req.body;

  // Validate CSRF token
  if (!csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({ error: 'CSRF token invalid' });
  }

  // Token is valid, process the request
  processTransfer(req.session.userId, amount, recipient);
  res.json({ success: true, message: 'Transfer completed' });
});

function processTransfer(userId, amount, recipient) {
  // Process transfer logic here
  console.log(`User ${userId} transferred $${amount} to ${recipient}`);
}

app.listen(3000);
```

## Double Submit Cookie Pattern

The Double Submit Cookie pattern is an alternative CSRF defense that doesn't require server-side state:

### How It Works

1. **Server sends unique cookie** - Server creates a random token and sends it as a cookie
2. **Client reads cookie from JavaScript** - Client-side code reads the token from the cookie
3. **Client includes token in request** - Client sends token in header or form field
4. **Server compares values** - Server verifies cookie token matches submitted token
5. **Only SameSite-aware attacks fail** - Works because attacker's site cannot read cookies

### Implementation

```javascript
const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const app = express();

app.use(express.json());
app.use(cookieParser());

// Generate CSRF token and set as cookie
app.get('/csrf-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');

  // Send token as cookie (not accessible to attacker's JS if HttpOnly)
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false, // Must be false so client-side JS can read it
    secure: true,
    sameSite: 'strict'
  });

  // Also return token in response for easier access
  res.json({ token });
});

// Middleware to verify CSRF token
function verifyCsrfToken(req, res, next) {
  const tokenFromCookie = req.cookies['XSRF-TOKEN'];
  const tokenFromHeader = req.headers['x-csrf-token'];

  // Token must be present in both places
  if (!tokenFromCookie || !tokenFromHeader) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }

  // Tokens must match
  if (tokenFromCookie !== tokenFromHeader) {
    return res.status(403).json({ error: 'CSRF token invalid' });
  }

  next();
}

// Protected endpoint
app.post('/transfer', verifyCsrfToken, (req, res) => {
  const { amount, recipient } = req.body;
  processTransfer(req.session.userId, amount, recipient);
  res.json({ success: true });
});

app.listen(3000);
```

### Client-Side Implementation (Double Submit Cookie)

```javascript
// Get CSRF token from cookie
function getCsrfToken() {
  const name = 'XSRF-TOKEN';
  const nameEQ = name + "=";
  const cookies = document.cookie.split(';');

  for (let cookie of cookies) {
    cookie = cookie.trim();
    if (cookie.indexOf(nameEQ) === 0) {
      return cookie.substring(nameEQ.length);
    }
  }
  return null;
}

// Send request with CSRF token
fetch('/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCsrfToken()
  },
  body: JSON.stringify({
    amount: 1000,
    recipient: 'user@example.com'
  })
});
```

## SameSite Cookie Attribute (Modern Defense)

The SameSite attribute is a modern CSRF defense that prevents cookies from being sent with cross-site requests.

### SameSite Values

| Value | Behavior | CSRF Protection |
|-------|----------|-----------------|
| **Strict** | Cookie never sent in cross-site requests | Strongest |
| **Lax** | Cookie sent in safe top-level navigations (GET) only | Strong |
| **None** | Cookie always sent (requires Secure flag) | No protection |

### Strict Implementation

```javascript
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'secret',
  cookie: {
    httpOnly: true,
    secure: true,    // HTTPS only
    sameSite: 'strict' // Strongest protection
  }
}));

// With Strict, cookies are never sent in cross-site requests
// CSRF attacks cannot use session cookies
```

### Lax Implementation (Default)

```javascript
const express = require('express');
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'secret',
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'lax' // Default, allows safe GET requests
  }
}));

// With Lax:
// - Cookies sent with safe top-level navigations (GET, HEAD, OPTIONS)
// - Cookies NOT sent with POST, PUT, PATCH, DELETE
// - Cookies NOT sent with iframes or images
// - Protects against most CSRF attacks
```

### Browser Support Warning

```javascript
// Issue: SameSite support varies across browsers
// Solution: Combine SameSite with token-based CSRF protection

app.use(session({
  secret: 'secret',
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'lax'
  }
}));

// Also validate CSRF tokens for defense-in-depth
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: false });

app.post('/transfer', csrfProtection, (req, res) => {
  // Protected by both SameSite and CSRF token
  processTransfer(req.session.userId, req.body.amount, req.body.recipient);
  res.json({ success: true });
});
```

## When SameSite Alone Is Insufficient

SameSite cookies alone are not sufficient in these scenarios:

### 1. Same-Site but Different Subdomain

```
// If attacker controls subdomain attack.example.com
// And victim is logged into example.com
// SameSite Lax/Strict still protects, but requires care

// Subdomains can set cookies for parent domain if enabled
// Mitigation: Use explicit domain restrictions
```

### 2. Browser Support Issues

```javascript
// Older browsers don't support SameSite
// Solution: Always combine with token-based protection

app.post('/transfer', (req, res) => {
  // Verify CSRF token regardless of SameSite
  if (req.session.csrfToken !== req.body.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  // Process request
});
```

### 3. GET Requests Changing State

```javascript
// VULNERABLE: GET request changes state
app.get('/delete-account', (req, res) => {
  deleteAccount(req.session.userId);
  res.send('Deleted');
});

// Even with SameSite=Strict, this GET could be attacked
// Mitigation: Never use GET for state-changing operations

// SECURE: Use POST instead
app.post('/delete-account', (req, res) => {
  if (req.session.csrfToken !== req.body.csrfToken) {
    return res.status(403).send('CSRF token invalid');
  }
  deleteAccount(req.session.userId);
  res.send('Deleted');
});
```

### 4. XML HttpRequest (XHR) with withCredentials

```javascript
// VULNERABLE: XHR with credentials can still be attacked in certain scenarios
fetch('https://api.example.com/transfer', {
  method: 'POST',
  credentials: 'include', // Includes cookies
  body: JSON.stringify({amount: 1000})
});

// Even with SameSite, content-type matters
// Mitigation: Require custom headers or CSRF tokens
```

## Best Practices

### 1. Use Framework-Provided CSRF Protection

```javascript
// Express with csurf middleware
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');

const app = express();
app.use(cookieParser());
app.use(session({ secret: 'secret' }));

const csrfProtection = csrf({ cookie: false });

// Generate token
app.get('/form', csrfProtection, (req, res) => {
  res.send(`<form action="/submit" method="POST">
    <input type="hidden" name="_csrf" value="${req.csrfToken()}">
    <input type="text" name="data">
    <button>Submit</button>
  </form>`);
});

// Verify token
app.post('/submit', csrfProtection, (req, res) => {
  res.send('Form submitted safely');
});
```

### 2. Set SameSite on All Cookies

```javascript
// Always set SameSite attribute on cookies
app.use(session({
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict' // or 'lax' for user flows
  }
}));

// For other cookies
res.cookie('name', 'value', {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});
```

### 3. Avoid GET for State-Changing Operations

```javascript
// NEVER do this
app.get('/delete-account/:id', (req, res) => {
  // WRONG - GET should only retrieve data
});

// DO THIS instead
app.post('/delete-account/:id', (req, res) => {
  // Correct - POST for state-changing operations
});
```

### 4. Use Content-Type Validation

```javascript
// Require specific content-type for API requests
app.post('/api/transfer', (req, res) => {
  if (req.headers['content-type'] !== 'application/json') {
    return res.status(415).send('Unsupported Media Type');
  }
  // Process request
});
```

### 5. Implement Custom Headers for AJAX

```javascript
// CSRF protection via custom header (cannot be set by forms)
app.post('/api/transfer', (req, res) => {
  // Check for custom header that forms cannot set
  if (req.headers['x-requested-with'] !== 'XMLHttpRequest') {
    return res.status(403).send('CSRF detected');
  }

  // Also verify CSRF token
  if (req.session.csrfToken !== req.body.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }

  // Process request
});
```

### 6. Log and Monitor Suspected Attacks

```javascript
app.post('/transfer', (req, res) => {
  if (req.session.csrfToken !== req.body.csrfToken) {
    // Log potential CSRF attack
    console.warn('CSRF attack detected from IP:', req.ip);
    console.warn('User Agent:', req.headers['user-agent']);
    console.warn('Referer:', req.headers['referer']);

    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
  // Process request
});
```

## Complete Secure Implementation

```javascript
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();

// Middleware
app.use(helmet()); // Security headers
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  }
}));

// CSRF protection
const csrfProtection = csrf({ cookie: false });

// Display transfer form
app.get('/transfer-form', csrfProtection, (req, res) => {
  res.send(`
    <html>
    <body>
      <h1>Money Transfer</h1>
      <form action="/transfer" method="POST">
        <input type="hidden" name="_csrf" value="${req.csrfToken()}">
        <input type="number" name="amount" placeholder="Amount" required>
        <input type="email" name="recipient" placeholder="Recipient" required>
        <button type="submit">Transfer</button>
      </form>
    </body>
    </html>
  `);
});

// Process transfer (protected by CSRF token and SameSite)
app.post('/transfer', csrfProtection, (req, res) => {
  const { amount, recipient } = req.body;

  // Validation
  if (!amount || !recipient) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  // Log transaction
  console.log(`User ${req.session.userId} transferred $${amount} to ${recipient}`);

  // Process transfer
  res.json({
    success: true,
    message: `Transfer of $${amount} to ${recipient} completed`
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('CSRF protection enabled');
});
```

## References

- OWASP Cross-Site Request Forgery (CSRF): https://owasp.org/www-community/attacks/csrf
- CWE-352: Cross-Site Request Forgery (CSRF): https://cwe.mitre.org/data/definitions/352.html
- SameSite Cookie Explained: https://web.dev/samesite-cookies-explained/
- OWASP Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
