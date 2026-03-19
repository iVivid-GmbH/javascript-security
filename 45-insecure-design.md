# Insecure Design (OWASP A04)

## Definition

**Insecure Design** (OWASP A04:2021) refers to security flaws introduced during the design and architecture phase of development. Unlike implementation bugs that can be patched, design flaws require architectural changes and cannot be fixed with code patches alone. Insecure design includes missing security controls, inadequate threat modeling, lack of secure defaults, and failure to consider security requirements upfront. These design-level vulnerabilities affect the entire system and require substantial rework to remediate.

## Distinction: Design vs Implementation

### Implementation Bug (Patchable)

```javascript
// ❌ Implementation vulnerability: Input validation missing
app.post('/api/users', (req, res) => {
  // ❌ BUG: No email validation
  const email = req.body.email;  // Could be "not-an-email"

  const user = new User({ email });
  user.save();

  res.json(user);
});

// FIX: Add email validation
app.post('/api/users', (req, res) => {
  // ✅ FIX: Validate email
  if (!isValidEmail(req.body.email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  const user = new User({ email: req.body.email });
  user.save();

  res.json(user);
});

// This is an implementation bug - easy to patch
```

### Design Flaw (Requires Rework)

```javascript
// ❌ DESIGN FLAW: No account lockout mechanism designed in
app.post('/api/login', (req, res) => {
  const user = db.users.findOne({ email: req.body.email });

  if (!user || !bcrypt.compareSync(req.body.password, user.passwordHash)) {
    // No lockout - attacker can brute force indefinitely
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  // Login successful
  res.json({ token: generateToken(user) });
});

// FIX: Requires architectural change
// 1. Add failed_login_attempts field to User model
// 2. Add locked_until field to User model
// 3. Increment failed attempts on auth failure
// 4. Lock account after N attempts
// 5. Implement unlock mechanism (email verification, etc.)
// 6. Modify login flow to check lock status
// 7. Add monitoring for unlock attempts
// 8. Update account recovery process

// This is a design flaw - requires major rework, not just a patch
```

## Threat Modeling: STRIDE Framework

### STRIDE Components

```
S - Spoofing (Identity)
T - Tampering (Data)
R - Repudiation (Deny actions)
I - Information Disclosure (Privacy)
D - Denial of Service (Availability)
E - Elevation of Privilege (Authorization)
```

### Example: Threat Model for Login System

```
THREATS:

Spoofing (S):
- Attacker impersonates legitimate user
- MITIGATION: Strong authentication, multi-factor auth, session tokens

Tampering (T):
- Attacker modifies login request
- Attacker modifies authentication token
- MITIGATION: HTTPS, token signing, input validation, CSRF tokens

Repudiation (R):
- User denies logging in
- MITIGATION: Logging, audit trails, timestamps

Information Disclosure (I):
- Password exposed in transit
- Token leaked
- Error messages reveal user existence
- MITIGATION: HTTPS, secure token storage, generic error messages

Denial of Service (D):
- Brute force login attempts
- Account lockout attacks
- MITIGATION: Rate limiting, account lockout, CAPTCHA

Elevation of Privilege (E):
- User escalates to admin
- Token forgery
- MITIGATION: Access control, token validation, signature verification
```

## Security Requirements as User Stories

### Insecure: No Security Requirements

```
User Story: Login
As a user
I want to log in with email and password
So that I can access my account

Acceptance Criteria:
- User can enter email and password
- System validates credentials
- User receives token on success
- User sees error on failure

// ❌ No security requirements!
// No mention of:
// - Brute force protection
// - Account lockout
// - Session timeout
// - Password hashing
// - HTTPS requirement
```

### Secure: Security in User Stories

```
User Story: Secure Login
As a user
I want to log in with email and password
So that I can access my account safely

Acceptance Criteria:
- User can enter email and password
- Password must be at least 12 characters
- Password must include uppercase, lowercase, number, special char
- Passwords are hashed with bcrypt (work factor 12)
- Failed login attempts are logged
- Account locks after 5 failed attempts in 15 minutes
- User notified of lock via email
- HTTPS required for all auth endpoints
- Session timeout after 1 hour of inactivity
- All login attempts logged with timestamp, IP, user agent
- Generic error messages (don't reveal if email exists)
- CSRF tokens used for POST requests
- Multi-factor authentication available (not required)

Security Scenarios:
- Given attacker tries 100 passwords, when account locked, then attack fails
- Given user inactive for 61 minutes, when user tries action, then redirected to login
- Given request over HTTP, when sent to auth endpoint, then rejected
- Given compromised session token, when used after logout, then rejected
```

## Defense-in-Depth Principle

### Single Layer (Insecure Design)

```javascript
// ❌ Only one security layer: input validation
app.post('/api/transfer', (req, res) => {
  // ❌ Only protection: validate amount
  if (req.body.amount <= 0 || req.body.amount > 100000) {
    return res.status(400).json({ error: 'Invalid amount' });
  }

  // No other protections:
  // - No authentication check
  // - No rate limiting
  // - No logging
  // - No HTTPS requirement (in design)
  // - No CSRF protection

  const transfer = createTransfer(req.body);

  res.json(transfer);
});

// Attack scenarios:
// 1. Attacker makes 1000 transfers (no rate limiting)
// 2. Attacker intercepts request, modifies amount (no HTTPS)
// 3. Attacker uses CSRF to transfer from victim account
// 4. Attacker brute forces endpoint (no auth)
```

### Multiple Layers (Secure Design)

```javascript
// ✅ Defense-in-depth: multiple security layers
app.post('/api/transfer',
  // Layer 1: HTTPS required (design requirement)
  // Layer 2: Authentication
  authenticateToken,

  // Layer 3: Authorization
  (req, res, next) => {
    if (!req.user.hasPermission('transfer')) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  },

  // Layer 4: Rate limiting
  rateLimit({ windowMs: 60000, max: 10 }),

  // Layer 5: CSRF protection
  csrfProtection,

  // Layer 6: Input validation
  body('amount').isFloat({ min: 0.01, max: 100000 }),
  body('recipientId').isInt({ min: 1 }),

  // Layer 7: Business logic
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Layer 8: Check user's account balance
    const user = await User.findById(req.user.id);
    if (user.balance < req.body.amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Layer 9: Verify recipient exists
    const recipient = await User.findById(req.body.recipientId);
    if (!recipient) {
      return res.status(404).json({ error: 'Recipient not found' });
    }

    // Layer 10: Logging for audit
    logger.info('Transfer initiated', {
      fromUserId: req.user.id,
      toUserId: req.body.recipientId,
      amount: req.body.amount,
      ip: req.ip
    });

    // Layer 11: Execute in transaction
    const transfer = await db.transaction(async (trx) => {
      // Subtract from sender
      await User.query(trx)
        .where('id', req.user.id)
        .increment('balance', -req.body.amount);

      // Add to recipient
      await User.query(trx)
        .where('id', req.body.recipientId)
        .increment('balance', req.body.amount);

      // Record transfer
      return await Transfer.query(trx).insert({
        fromUserId: req.user.id,
        toUserId: req.body.recipientId,
        amount: req.body.amount,
        status: 'completed',
        timestamp: new Date()
      });
    });

    // Layer 12: Notify both users
    await notifyUser(req.user.id, `Transfer of ${req.body.amount} sent`);
    await notifyUser(req.body.recipientId, `Received ${req.body.amount}`);

    res.json({ success: true, transfer });
  }
);
```

## Principle of Least Privilege

### Insecure: Over-Privileged

```javascript
// ❌ Users have too many permissions
const userSchema = {
  id: Number,
  name: String,
  email: String,
  role: String,  // 'admin', 'user'
  // ❌ Admin can do everything
};

// If admin account compromised:
// - Attacker can read all user data
// - Attacker can modify any configuration
// - Attacker can delete records
// - Attacker can access backups
// - Attacker can modify billing

// If regular user account compromised:
// - Attacker can modify their own data
// - Attacker can view their own data
// - (hopefully limited to just their data)
```

### Secure: Minimal Privileges

```javascript
// ✅ Fine-grained permissions
const userPermissions = {
  id: Number,
  name: String,
  email: String,
  roles: [String],  // 'admin', 'user', 'moderator', etc.

  // Role-specific permissions
  permissions: {
    canReadUsers: Boolean,
    canUpdateUsers: Boolean,
    canDeleteUsers: Boolean,
    canAccessBilling: Boolean,
    canAccessLogs: Boolean,
    canModifySettings: Boolean,
    canManageAdmins: Boolean
  }
};

// Role definitions
const roles = {
  admin: {
    canReadUsers: true,
    canUpdateUsers: true,
    canDeleteUsers: true,
    canAccessBilling: true,
    canAccessLogs: true,
    canModifySettings: true,
    canManageAdmins: true
  },

  moderator: {
    canReadUsers: true,
    canUpdateUsers: true,
    canDeleteUsers: true,
    canAccessBilling: false,
    canAccessLogs: true,
    canModifySettings: false,
    canManageAdmins: false
  },

  user: {
    canReadUsers: false,  // Can't read other users
    canUpdateUsers: false,  // Can't update others
    canDeleteUsers: false,
    canAccessBilling: false,
    canAccessLogs: false,
    canModifySettings: false,
    canManageAdmins: false
  }
};

// Authorization check
app.get('/api/users/:id', authenticateToken, (req, res) => {
  // User can only read own profile
  if (req.user.id !== req.params.id && !req.user.permissions.canReadUsers) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const user = db.users.findById(req.params.id);

  // If not reading own profile, check permission
  if (req.user.id !== req.params.id) {
    logger.warn('User accessed other user profile', {
      userId: req.user.id,
      accessedUserId: req.params.id
    });
  }

  res.json(user);
});
```

## Fail-Safe Defaults

### Insecure: Features Enabled by Default

```javascript
// ❌ Features enabled by default (dangerous if forgotten)
const userSchema = {
  email: String,
  password: String,
  emailNotificationsEnabled: { type: Boolean, default: true },  // ❌ On by default
  publicProfile: { type: Boolean, default: true },  // ❌ Public by default
  sharingEnabled: { type: Boolean, default: true },  // ❌ On by default
  exportAllowed: { type: Boolean, default: true }  // ❌ Allowed by default
};

// If developer forgets to ask user, they get all features on
// This is unsafe!
```

### Secure: Features Disabled by Default

```javascript
// ✅ All features disabled by default
const userSchema = {
  email: String,
  password: String,
  emailNotificationsEnabled: { type: Boolean, default: false },  // Off by default
  publicProfile: { type: Boolean, default: false },  // Private by default
  sharingEnabled: { type: Boolean, default: false },  // Off by default
  exportAllowed: { type: Boolean, default: false }  // Disabled by default
};

// User must explicitly enable features they want
// Better security posture
// User understands what they're enabling
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: Insecure design
const express = require('express');
const app = express();

app.use(express.json());

// ❌ Design 1: No authentication required
app.get('/api/sensitive-data', (req, res) => {
  // Anyone can access sensitive data!
  const data = db.getSensitiveData();
  res.json(data);
});

// ❌ Design 2: No rate limiting on API
app.post('/api/process', (req, res) => {
  // Attacker can send infinite requests
  const result = expensiveOperation(req.body.data);
  res.json(result);
});

// ❌ Design 3: No account lockout
app.post('/api/login', (req, res) => {
  // Attacker can brute force passwords indefinitely
  const user = db.users.findOne({ email: req.body.email });

  if (!user || user.password !== req.body.password) {
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  res.json({ token: generateToken(user) });
});

// ❌ Design 4: All users can access all data
app.get('/api/users/:id', (req, res) => {
  // No authorization check - anyone can read anyone's data
  const user = db.users.findById(req.params.id);
  res.json(user);
});

// ❌ Design 5: No session timeout
// Sessions valid forever (or very long)

// ❌ Design 6: No logging or monitoring
// Attacks go undetected

// ❌ Design 7: Features enabled by default
const schema = {
  shareable: { type: Boolean, default: true },  // Public by default!
  exportable: { type: Boolean, default: true }  // Exported by default!
};

app.listen(3000);
```

## Secure Code Example

```javascript
// ✅ SECURE: Security-conscious design
const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// ✅ Design 1: Authentication required
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
};

// ✅ Endpoints require authentication
app.get('/api/sensitive-data',
  authenticateToken,
  (req, res) => {
    // User must be authenticated
    const data = db.getUserData(req.user.id);
    res.json(data);
  }
);

// ✅ Design 2: Rate limiting for all endpoints
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5
});

app.use(limiter);

// ✅ Stricter limit for expensive operations
app.post('/api/process',
  strictLimiter,
  authenticateToken,
  (req, res) => {
    // Rate limited and authenticated
    const result = expensiveOperation(req.body.data);
    res.json(result);
  }
);

// ✅ Design 3: Account lockout mechanism
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.findOne({ email });

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // ✅ Check if account locked
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    return res.status(403).json({
      error: 'Account locked',
      retryAfter: user.lockedUntil
    });
  }

  // Verify password
  const isValid = bcrypt.compareSync(password, user.passwordHash);

  if (!isValid) {
    // ✅ Increment failed attempts
    user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

    // ✅ Lock after 5 failed attempts
    if (user.failedLoginAttempts >= 5) {
      user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);  // 30 minutes

      logger.warn('Account locked due to failed login attempts', {
        userId: user.id,
        email,
        attempts: user.failedLoginAttempts
      });
    }

    user.save();

    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // ✅ Reset failed attempts on successful login
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  user.lastLogin = new Date();
  user.save();

  // ✅ Generate token with expiration
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });
});

// ✅ Design 4: Authorization check
app.get('/api/users/:id',
  authenticateToken,
  (req, res) => {
    // User can only read own profile
    if (req.user.id !== req.params.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const user = db.users.findById(req.params.id);
    res.json(user);
  }
);

// ✅ Design 5: Session timeout
// Token expires after 1 hour (set in jwt.sign)
// Refresh token mechanism for longer sessions

// ✅ Design 6: Comprehensive logging
logger.info('Security design: all requests logged and monitored');

// ✅ Design 7: Features disabled by default
const userSchema = {
  email: String,
  password: String,
  shareable: { type: Boolean, default: false },  // Disabled by default
  exportable: { type: Boolean, default: false }  // Disabled by default
};

// ✅ Design 8: Explicit user consent
app.post('/api/user/enable-sharing', authenticateToken, (req, res) => {
  // User explicitly enables sharing
  const user = db.users.findById(req.user.id);
  user.shareable = true;
  user.save();

  res.json({ message: 'Sharing enabled' });
});

app.listen(3000);
```

## Mitigations and Best Practices

### 1. Threat Modeling
- Identify assets to protect
- Identify threat actors
- Use STRIDE framework
- Document threats and mitigations

### 2. Security Requirements
- Include security in user stories
- Define security acceptance criteria
- Threat model before implementation
- Regular security reviews

### 3. Defense-in-Depth
- Multiple overlapping controls
- No single point of failure
- Layered authentication and authorization
- Multiple validation layers

### 4. Principle of Least Privilege
- Grant minimum necessary permissions
- Fine-grained access control
- Regular permission audits
- Segregate duties

### 5. Fail-Safe Defaults
- Secure by default
- Features disabled until enabled
- Permissions denied until granted
- Privacy-first design

### 6. Secure Architecture
- Separate concerns
- Minimize dependencies
- Isolate sensitive operations
- Use established security patterns

## Summary

Insecure design flaws cannot be patched with code changes alone - they require architectural rework. Prevent them through threat modeling using STRIDE, including security in user stories and acceptance criteria, implementing defense-in-depth with multiple security layers, applying the principle of least privilege, using fail-safe defaults with features disabled until explicitly enabled, and conducting security architecture reviews before development begins.
