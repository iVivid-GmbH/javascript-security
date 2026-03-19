# Authentication Failures in JavaScript/Node.js

## Definition

Authentication Failures (OWASP A07:2021) occur when systems fail to properly verify user identity. This includes weak password policies, missing or improper multi-factor authentication, insecure credential storage, broken password reset flows, and improper session management. Authentication failures allow attackers to gain unauthorized access to accounts through credential compromise, session hijacking, or account takeover.

## Common Authentication Failures

### 1. Weak Password Policies

Allowing weak passwords makes accounts vulnerable to brute force attacks:

```javascript
// VULNERABLE: Weak password requirements
app.post('/vulnerable/register', (req, res) => {
  const { email, password } = req.body;

  // No password strength validation
  // Allows passwords like: "123", "password", "abc"

  const user = { email, password: password }; // Storing plain text!
  saveUser(user);

  res.json({ success: true });
});

// SECURE: Strong password requirements
app.post('/secure/register', (req, res) => {
  const { email, password } = req.body;

  // Validate password strength
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      error: 'Password must be at least 12 characters with uppercase, lowercase, number, and special character'
    });
  }

  // Hash password with bcrypt
  const hashedPassword = bcrypt.hashSync(password, 10);
  const user = { email, password: hashedPassword };
  saveUser(user);

  res.json({ success: true });
});
```

### 2. No Multi-Factor Authentication (MFA)

Not implementing MFA leaves accounts vulnerable to credential compromise:

```javascript
// VULNERABLE: No MFA
app.post('/vulnerable/login', (req, res) => {
  const { email, password } = req.body;

  // Just password, no second factor
  const user = authenticateUser(email, password);

  if (user) {
    req.session.userId = user.id;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// SECURE: With MFA (SMS/TOTP)
app.post('/secure/login', async (req, res) => {
  const { email, password } = req.body;

  const user = authenticateUser(email, password);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (!user.mfaEnabled) {
    // User hasn't enabled MFA, prompt to set it up
    req.session.userId = user.id;
    req.session.mfaPending = false;
    return res.json({ success: true, mfaAvailable: true });
  }

  // Generate and send MFA code
  const mfaCode = generateMFACode();
  saveMFACode(user.id, mfaCode);

  // Send via SMS, email, or authenticator app
  if (user.mfaMethod === 'sms') {
    sendSMS(user.phone, mfaCode);
  }

  req.session.userId = user.id;
  req.session.mfaPending = true;

  res.json({ success: true, requiresMFA: true, method: user.mfaMethod });
});

// Verify MFA code
app.post('/secure/verify-mfa', (req, res) => {
  const { code } = req.body;
  const userId = req.session.userId;

  if (!req.session.mfaPending) {
    return res.status(400).json({ error: 'No MFA pending' });
  }

  const storedCode = getMFACode(userId);

  if (code !== storedCode) {
    return res.status(401).json({ error: 'Invalid MFA code' });
  }

  // Clear MFA pending flag
  req.session.mfaPending = false;

  res.json({ success: true, message: 'Login successful' });
});
```

### 3. Credential Stuffing and Brute Force

Not limiting login attempts allows attackers to try many credentials:

```javascript
// VULNERABLE: No rate limiting
app.post('/vulnerable/login', (req, res) => {
  const { email, password } = req.body;

  // No attempt limiting
  // Attacker can try thousands of passwords
  const user = authenticateUser(email, password);

  if (user) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// SECURE: With rate limiting and account lockout
const loginAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

app.post('/secure/login', (req, res) => {
  const { email, password } = req.body;

  // Check for account lockout
  const attempts = loginAttempts.get(email);
  if (attempts && attempts.count >= MAX_ATTEMPTS) {
    if (Date.now() - attempts.lastAttempt < LOCKOUT_TIME) {
      return res.status(429).json({
        error: 'Account locked due to too many failed attempts. Try again later.'
      });
    } else {
      // Lockout expired, reset attempts
      loginAttempts.delete(email);
    }
  }

  // Authenticate
  const user = authenticateUser(email, password);

  if (!user) {
    // Record failed attempt
    const current = loginAttempts.get(email) || { count: 0 };
    current.count++;
    current.lastAttempt = Date.now();
    loginAttempts.set(email, current);

    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Successful login - clear attempts
  loginAttempts.delete(email);

  req.session.userId = user.id;
  res.json({ success: true });
});
```

### 4. Insecure Password Reset

Weak password reset flows allow account takeover:

```javascript
// VULNERABLE: Insecure password reset
app.post('/vulnerable/forgot-password', (req, res) => {
  const { email } = req.body;

  const user = getUserByEmail(email);
  if (!user) {
    // Don't reveal if email exists (prevents enumeration)
    return res.json({ success: true }); // User won't know this is wrong
  }

  // VULNERABLE: Sequential reset token
  const resetToken = user.id + Date.now(); // Predictable!

  saveResetToken(user.id, resetToken);

  // Send reset link
  sendEmail(email, `https://example.com/reset?token=${resetToken}`);

  res.json({ success: true });
});

app.post('/vulnerable/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  // VULNERABLE: No token expiry check
  const user = getUserByResetToken(token);

  if (!user) {
    return res.status(400).json({ error: 'Invalid token' });
  }

  // VULNERABLE: No password validation
  updatePassword(user.id, newPassword); // "123"!?

  res.json({ success: true });
});

// SECURE: Proper password reset
const crypto = require('crypto');

app.post('/secure/forgot-password', async (req, res) => {
  const { email } = req.body;

  // Don't reveal if email exists
  const user = getUserByEmail(email);

  if (user) {
    // Generate secure random token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Save token with expiry (30 minutes)
    saveResetToken(user.id, tokenHash, Date.now() + 30 * 60 * 1000);

    // Send email with token
    const resetLink = `https://example.com/reset-password?token=${resetToken}`;
    sendEmail(email, resetLink);
  }

  // Always respond with success to prevent enumeration
  res.json({ success: true, message: 'Check your email for reset link' });
});

app.post('/secure/reset-password', (req, res) => {
  const { token, newPassword } = req.body;

  // Validate password strength
  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({ error: 'Password too weak' });
  }

  // Hash the token to compare
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  // Get reset request
  const resetRequest = getResetToken(tokenHash);

  if (!resetRequest) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }

  // Check expiry
  if (Date.now() > resetRequest.expiresAt) {
    deleteResetToken(tokenHash);
    return res.status(400).json({ error: 'Token expired' });
  }

  // Update password
  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  updatePassword(resetRequest.userId, hashedPassword);

  // Delete reset token (one-time use)
  deleteResetToken(tokenHash);

  res.json({ success: true, message: 'Password reset successful' });
});
```

### 5. Session Not Invalidated on Logout

Sessions remaining valid after logout allow account hijacking:

```javascript
// VULNERABLE: Logout doesn't invalidate session
app.post('/vulnerable/logout', (req, res) => {
  // Just redirect, session still valid!
  res.redirect('/');
});

// SECURE: Properly invalidate session
app.post('/secure/logout', (req, res) => {
  // Destroy session
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }

    // Clear session cookie
    res.clearCookie('connect.sid'); // Default session cookie name

    res.json({ success: true, message: 'Logged out successfully' });
  });
});
```

### 6. JWT Without Expiry or Refresh

JWTs that never expire allow unlimited access:

```javascript
// VULNERABLE: No expiry on JWT
app.post('/vulnerable/login', (req, res) => {
  const user = authenticateUser(email, password);

  // VULNERABLE: No expiresIn
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET);

  // Token is valid forever!
  res.json({ token });
});

// SECURE: JWT with expiry and refresh token
app.post('/secure/login', (req, res) => {
  const user = authenticateUser(email, password);

  // Access token with short expiry
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '15m' } // Expires in 15 minutes
  );

  // Refresh token with longer expiry, stored in database
  const refreshToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

  saveRefreshToken(user.id, tokenHash, Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  res.json({
    accessToken,
    refreshToken, // Send to client (typically in httpOnly cookie)
    expiresIn: 900 // seconds
  });
});

// Refresh access token
app.post('/secure/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
  const storedToken = getRefreshToken(tokenHash);

  if (!storedToken || Date.now() > storedToken.expiresAt) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }

  // Generate new access token
  const newAccessToken = jwt.sign(
    { id: storedToken.userId, email: storedToken.email },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  res.json({ accessToken: newAccessToken });
});
```

## Vulnerable Node.js Login Example

```javascript
const express = require('express');
const session = require('express-session');
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: 'hard-coded-secret', // VULNERABLE: Hard-coded secret
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false } // VULNERABLE: Accessible to JS
}));

// VULNERABLE: Weak login implementation
app.post('/vulnerable/login', (req, res) => {
  const { username, password } = req.body;

  // No rate limiting
  // No strong password validation
  // No MFA

  // Simulated user database
  const users = {
    'admin': 'password123', // VULNERABLE: Plain text password!
    'user': '123456'
  };

  if (users[username] === password) {
    req.session.userId = username;
    res.send('Login successful');
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.get('/vulnerable/dashboard', (req, res) => {
  // Just checks if userId exists, not validity
  if (req.session.userId) {
    res.send(`Welcome ${req.session.userId}`);
  } else {
    res.redirect('/login');
  }
});

app.listen(3000);

// Vulnerabilities:
// 1. Password stored in plain text
// 2. Hard-coded session secret
// 3. No password hashing
// 4. No rate limiting (brute force possible)
// 5. No MFA
// 6. Session cookie accessible to JavaScript
// 7. No password strength requirements
```

## Secure Authentication Implementation

### 1. Password Hashing with bcrypt

```javascript
const bcrypt = require('bcrypt');

// Hash password
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10); // 10 rounds of hashing
  return bcrypt.hash(password, salt);
}

// Verify password
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Use in registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate password strength
  if (password.length < 12) {
    return res.status(400).json({ error: 'Password too short' });
  }

  // Hash password
  const hashedPassword = await hashPassword(password);

  // Save user with hashed password
  const user = { email, password: hashedPassword };
  saveUser(user);

  res.json({ success: true });
});

// Use in login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = getUserByEmail(email);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Compare password with hash
  const isValid = await verifyPassword(password, user.password);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  req.session.userId = user.id;
  res.json({ success: true });
});
```

### 2. Multi-Factor Authentication (TOTP)

```javascript
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

// Enable MFA for user
app.post('/enable-mfa', authenticate, async (req, res) => {
  const userId = req.user.id;

  // Generate secret
  const secret = speakeasy.generateSecret({
    name: `MyApp (${req.user.email})`,
    issuer: 'MyApp'
  });

  // Generate QR code
  const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

  // Save temporary secret (not yet confirmed)
  saveTempMFASecret(userId, secret.base32);

  res.json({
    qrCode: qrCodeUrl,
    secret: secret.base32, // Backup code
    message: 'Scan with authenticator app and verify'
  });
});

// Verify MFA code and enable it
app.post('/verify-mfa-code', authenticate, (req, res) => {
  const { code } = req.body;
  const userId = req.user.id;

  // Get temporary secret
  const tempSecret = getTempMFASecret(userId);

  // Verify code matches secret
  const verified = speakeasy.totp.verify({
    secret: tempSecret,
    encoding: 'base32',
    token: code
  });

  if (!verified) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  // Save secret as confirmed
  confirmMFASecret(userId, tempSecret);

  res.json({ success: true, message: 'MFA enabled' });
});

// Login with TOTP verification
app.post('/login-with-totp', async (req, res) => {
  const { email, password, totpCode } = req.body;

  const user = authenticateUser(email, password);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Verify TOTP if enabled
  if (user.mfaEnabled) {
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: totpCode
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid TOTP code' });
    }
  }

  req.session.userId = user.id;
  res.json({ success: true });
});
```

### 3. Complete Secure Login Example

```javascript
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true, // Prevent JS access
    secure: true, // HTTPS only
    sameSite: 'strict'
  }
}));

// Rate limiting
const loginAttempts = new Map();

function isAccountLocked(email) {
  const attempts = loginAttempts.get(email);
  if (!attempts) return false;

  if (Date.now() - attempts.lastAttempt > 15 * 60 * 1000) {
    loginAttempts.delete(email);
    return false;
  }

  return attempts.count >= 5;
}

function recordFailedAttempt(email) {
  const attempts = loginAttempts.get(email) || { count: 0 };
  attempts.count++;
  attempts.lastAttempt = Date.now();
  loginAttempts.set(email, attempts);
}

function clearAttempts(email) {
  loginAttempts.delete(email);
}

// Registration
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  // Check password strength
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({
      error: 'Password must be 12+ characters with uppercase, lowercase, number, and special character'
    });
  }

  // Check if user exists
  if (getUserByEmail(email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Save user
  const user = { email, password: hashedPassword, mfaEnabled: false };
  saveUser(user);

  res.json({ success: true, message: 'Registration successful' });
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Check for account lockout
  if (isAccountLocked(email)) {
    return res.status(429).json({
      error: 'Account locked. Try again in 15 minutes.'
    });
  }

  // Get user
  const user = getUserByEmail(email);

  if (!user) {
    recordFailedAttempt(email);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Verify password
  const isValid = await bcrypt.compare(password, user.password);

  if (!isValid) {
    recordFailedAttempt(email);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Clear failed attempts
  clearAttempts(email);

  // Check MFA
  if (user.mfaEnabled) {
    // Send MFA code
    const mfaCode = generateMFACode();
    saveMFACode(user.id, mfaCode);
    sendEmail(email, `Your MFA code: ${mfaCode}`);

    // Mark session as pending MFA
    req.session.userId = user.id;
    req.session.mfaPending = true;

    return res.json({ requiresMFA: true });
  }

  // MFA not enabled, login successful
  req.session.userId = user.id;

  // Create JWT for API access
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  res.json({
    success: true,
    accessToken,
    message: 'Login successful'
  });
});

// Verify MFA code
app.post('/verify-mfa', (req, res) => {
  const { code } = req.body;
  const userId = req.session.userId;

  if (!req.session.mfaPending) {
    return res.status(400).json({ error: 'No MFA pending' });
  }

  const storedCode = getMFACode(userId);

  if (code !== storedCode) {
    return res.status(401).json({ error: 'Invalid MFA code' });
  }

  // Clear MFA pending
  req.session.mfaPending = false;

  const user = getUserById(userId);
  const accessToken = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );

  res.json({ success: true, accessToken });
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

app.listen(3000);
```

## Best Practices

1. **Hash passwords with bcrypt or argon2** - Never store plain text passwords
2. **Implement MFA** - Use TOTP, SMS, or email verification
3. **Enforce strong password policies** - Minimum 12 characters, complexity requirements
4. **Implement rate limiting** - Prevent brute force attacks
5. **Account lockout** - Lock accounts after failed attempts
6. **Secure password reset** - Use cryptographic tokens with expiry
7. **JWT with expiry** - Keep access tokens short-lived (15-30 minutes)
8. **Refresh tokens** - Use longer-lived refresh tokens stored securely
9. **HttpOnly cookies** - Prevent JavaScript access to sensitive tokens
10. **HTTPS only** - Always use secure connections
11. **Session timeout** - Invalidate sessions after period of inactivity
12. **Logout invalidation** - Destroy sessions on logout
13. **No default credentials** - Never ship with default accounts
14. **Monitor suspicious activity** - Log and alert on unusual patterns
15. **Regular security audits** - Test authentication mechanisms

## References

- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- CWE-521: Weak Password Requirements: https://cwe.mitre.org/data/definitions/521.html
- CWE-640: Weak Password Recovery Mechanism for Forgotten Password: https://cwe.mitre.org/data/definitions/640.html
- bcrypt Documentation: https://www.npmjs.com/package/bcrypt
