# Broken Access Control in JavaScript/Node.js

## Definition

Broken Access Control (OWASP #1 in recent rankings) is a vulnerability where users can access resources or perform actions beyond their intended permissions. It includes failures to properly enforce who can access what data and perform what actions. Access control flaws allow unauthorized users to view, modify, or delete data, escalate privileges, or bypass authentication.

## Types of Access Control Failures

### 1. Vertical Privilege Escalation (Privilege Escalation)

A user with lower privileges gains higher privileges. For example, a regular user becomes an admin or a customer accesses admin functions.

```javascript
// VULNERABLE: Admin endpoint with weak access control
app.get('/admin/users', (req, res) => {
  // Only checks if user is logged in, not if they're admin
  if (!req.session.userId) {
    return res.status(401).send('Unauthorized');
  }

  // Any logged-in user can access admin data
  const users = getAllUsers();
  res.json(users);
});

// Attack: Regular user accesses /admin/users and gets all user data
```

### 2. Horizontal Privilege Escalation (IDOR - Insecure Direct Object Reference)

A user accesses resources belonging to other users at the same privilege level. For example, viewing another user's data by changing an ID parameter.

```javascript
// VULNERABLE: No ownership check
app.get('/api/profile/:userId', (req, res) => {
  const userId = req.params.userId;

  // No check if current user owns this profile
  const profile = getUserProfile(userId);
  res.json(profile);
});

// Attack: User1 (ID=1) accesses /api/profile/2 and sees User2's data
```

### 3. Missing Function-Level Access Control

Functions or endpoints exist but aren't properly protected. An attacker may discover them through enumeration or documentation.

```javascript
// VULNERABLE: No access control on sensitive function
app.post('/api/export-data', (req, res) => {
  // No permission check
  const data = exportSensitiveData();
  res.json(data);
});

// Attack: Unauthenticated user calls /api/export-data
```

### 4. Path Traversal via Access Control Bypass

Using path traversal to access files outside intended directories.

```javascript
// VULNERABLE: File download with path traversal
app.get('/download/:filename', (req, res) => {
  const filename = req.params.filename;

  // No path validation
  const filepath = path.join('/uploads/', filename);
  res.download(filepath);
});

// Attack: /download/../../../etc/passwd
// Downloads /etc/passwd instead of a file in /uploads/
```

## JWT Role-Claim Tampering Example

JWTs can be forged or their claims tampered with, especially if the secret is weak or the algorithm check is bypassed.

### Vulnerable JWT Handling

```javascript
const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

const SECRET = 'weak-secret-key'; // VULNERABLE: Weak secret

app.use(express.json());

// VULNERABLE: No algorithm verification
app.post('/vulnerable/login', (req, res) => {
  const user = { id: 123, email: 'user@example.com', role: 'user' };

  // Create JWT
  const token = jwt.sign(user, SECRET); // Uses default HS256

  res.json({ token });
});

// VULNERABLE: Accepts any algorithm
app.get('/vulnerable/profile', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    // VULNERABLE: Doesn't specify allowed algorithms
    const decoded = jwt.verify(token, SECRET); // Accepts any algorithm!

    // VULNERABLE: Trusts role claim directly
    if (decoded.role === 'admin') {
      res.json({ message: 'Admin access granted' });
    } else {
      res.json({ message: 'User access granted' });
    }
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000);

// Attack 1: Token tampering with weak secret
// Attacker uses online JWT decoder: jwt.io
// Changes role from "user" to "admin"
// Re-signs with weak secret
// New token: eyJhbGc...

// Attack 2: Algorithm confusion (HS256 to none)
// Attacker uses algorithm "none"
// Sends token without signature
// Server accepts it because algorithm checking is weak
// eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.
```

## Unprotected Admin API Endpoint Example

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// VULNERABLE: Admin endpoint with no access control
app.post('/api/users/:userId/promote-to-admin', (req, res) => {
  const userId = req.params.userId;

  // No authentication check
  // No authorization check
  // Any visitor can promote any user to admin!

  promoteToAdmin(userId);
  res.json({ success: true, message: `User ${userId} promoted to admin` });
});

// VULNERABLE: Delete endpoint with insufficient access control
app.delete('/api/users/:userId', (req, res) => {
  const userId = req.params.userId;

  // Only checks if user is authenticated
  if (!req.session.userId) {
    return res.status(401).send('Not authenticated');
  }

  // No check if user owns this resource or is admin
  // User1 can delete User2's account!

  deleteUser(userId);
  res.json({ success: true });
});

app.listen(3000);

// Attacks:
// 1. POST /api/users/123/promote-to-admin (promotes any user)
// 2. DELETE /api/users/999 (deletes any user)
// 3. Any unauthenticated user can call these endpoints
```

## Path Traversal via Access Control Bypass

```javascript
const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

// VULNERABLE: File download without proper validation
app.get('/download/:filename', (req, res) => {
  const filename = req.params.filename;

  // VULNERABLE: No path validation
  const filepath = path.join('/public/downloads/', filename);

  // No check if filepath is within allowed directory
  res.download(filepath);
});

// Attacks:
// /download/invoice.pdf (legitimate, fine)
// /download/../../../etc/passwd (traversal, accesses /etc/passwd)
// /download/../../private-data.json (traversal, accesses parent dirs)
// /download/../../../../home/user/.ssh/id_rsa (SSH key!)
```

## Vulnerable Code Examples

### 1. Vertical Privilege Escalation

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// VULNERABLE: Admin endpoints with weak access control
app.get('/admin/dashboard', (req, res) => {
  // Only checks if logged in, not if admin
  if (!req.session.userId) {
    return res.status(401).send('Login required');
  }

  const dashboard = {
    userCount: 5000,
    revenue: 1000000,
    alerts: ['Server down', 'High CPU usage']
  };

  res.json(dashboard);
});

app.post('/admin/users/:userId/delete', (req, res) => {
  const userId = req.params.userId;

  // No admin check!
  deleteUser(userId);
  res.json({ success: true });
});

app.post('/admin/settings/update', (req, res) => {
  const { setting, value } = req.body;

  // No admin check!
  updateSystemSetting(setting, value);
  res.json({ success: true });
});

app.listen(3000);

// Attack: Regular user calls these endpoints and gains admin capabilities
```

### 2. Horizontal Privilege Escalation (IDOR)

```javascript
const express = require('express');
const app = express();

// VULNERABLE: No ownership check
app.get('/api/profile/:userId', (req, res) => {
  const userId = req.params.userId;

  // No check if current user owns this profile
  const profile = {
    id: userId,
    email: getUserEmail(userId),
    phone: getUserPhone(userId),
    ssn: getUserSSN(userId)
  };

  res.json(profile);
});

// VULNERABLE: Update other user's data
app.put('/api/profile/:userId', (req, res) => {
  const userId = req.params.userId;
  const { email, phone, password } = req.body;

  // No check if current user owns this profile
  updateUserProfile(userId, { email, phone, password });
  res.json({ success: true });
});

// VULNERABLE: View user's bank accounts
app.get('/api/accounts/:accountId', (req, res) => {
  const accountId = req.params.accountId;

  // No check if user owns this account
  const account = {
    id: accountId,
    balance: getBalance(accountId),
    transactions: getTransactions(accountId)
  };

  res.json(account);
});

// Attacks:
// GET /api/profile/1 (see user 1's data)
// GET /api/profile/2 (see user 2's data)
// GET /api/profile/999 (see any user's data)
// PUT /api/profile/2 with new password (change another user's password)
```

### 3. Unprotected Admin Endpoints

```javascript
const express = require('express');
const app = express();

app.use(express.json());

// VULNERABLE: No authentication required
app.get('/api/users', (req, res) => {
  // Should require admin role, but doesn't
  const users = getAllUsers();
  res.json(users);
});

app.post('/api/users/:userId/ban', (req, res) => {
  const userId = req.params.userId;

  // Should require admin role, but doesn't
  banUser(userId);
  res.json({ success: true });
});

app.get('/api/admin/logs', (req, res) => {
  // Should require admin, but doesn't
  const logs = getSystemLogs();
  res.json(logs);
});

// These endpoints are completely unprotected
// Any user can call them without authentication
```

## Secure Access Control Implementation

### 1. Role-Based Access Control (RBAC)

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'strong-secret-key-from-env';

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // SECURE: Specify algorithm and verify
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'] // Only accept HS256
    });

    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Authorization middleware
function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  };
}

// SECURE: Admin endpoint with role check
app.get('/api/admin/users', authenticate, authorize('admin'), (req, res) => {
  const users = getAllUsers();
  res.json(users);
});

// SECURE: Endpoint with multiple allowed roles
app.post('/api/posts/:postId/publish', authenticate, authorize('editor', 'admin'), (req, res) => {
  publishPost(req.params.postId);
  res.json({ success: true });
});

// SECURE: Endpoint with role-specific logic
app.get('/api/reports', authenticate, (req, res) => {
  let reports;

  if (req.user.role === 'admin') {
    reports = getAllReports();
  } else if (req.user.role === 'manager') {
    reports = getManagerReports(req.user.id);
  } else {
    return res.status(403).json({ error: 'Cannot access reports' });
  }

  res.json(reports);
});

app.listen(3000);
```

### 2. Ownership-Based Access Control

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// Authenticate middleware
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// SECURE: Check ownership before returning data
app.get('/api/profile/:userId', authenticate, (req, res) => {
  const userId = parseInt(req.params.userId);
  const currentUserId = req.user.id;

  // SECURE: Check if user owns the profile
  if (userId !== currentUserId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Cannot access other user profiles' });
  }

  const profile = getUserProfile(userId);
  res.json(profile);
});

// SECURE: Check ownership before updating
app.put('/api/profile/:userId', authenticate, (req, res) => {
  const userId = parseInt(req.params.userId);
  const currentUserId = req.user.id;

  // SECURE: Prevent horizontal privilege escalation
  if (userId !== currentUserId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Cannot modify other user profiles' });
  }

  const { email, phone } = req.body;
  updateUserProfile(userId, { email, phone });
  res.json({ success: true });
});

// SECURE: Check account ownership
app.get('/api/accounts/:accountId', authenticate, (req, res) => {
  const accountId = parseInt(req.params.accountId);

  // Check if user owns this account
  const account = getAccount(accountId);

  if (!account) {
    return res.status(404).json({ error: 'Account not found' });
  }

  if (account.userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Cannot access this account' });
  }

  res.json(account);
});

app.listen(3000);
```

### 3. Secure JWT Implementation

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '1h';

// SECURE: Create JWT with proper settings
app.post('/secure/login', (req, res) => {
  const { email, password } = req.body;

  // Verify credentials
  const user = authenticateUser(email, password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // SECURE: Create JWT with limited claims and expiry
  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role // Populated from database, not user input
    },
    JWT_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: JWT_EXPIRY
    }
  );

  res.json({ token });
});

// SECURE: Verify JWT with strict settings
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }

  try {
    // SECURE: Specify algorithm, don't accept any
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'] // Only accept HS256
    });

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    res.status(401).json({ error: 'Invalid token' });
  }
}

// SECURE: Use middleware on protected routes
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({ message: `Hello ${req.user.email}` });
});

app.listen(3000);
```

### 4. Safe File Download with Access Control

```javascript
const express = require('express');
const path = require('path');
const fs = require('fs');
const app = express();

// SECURE: File download with ownership and path validation
app.get('/api/download/:fileId', authenticate, async (req, res) => {
  const fileId = parseInt(req.params.fileId);
  const userId = req.user.id;

  // Check if file exists in database
  const file = getFileFromDB(fileId);
  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }

  // Check if user owns this file or is admin
  if (file.userId !== userId && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Cannot download this file' });
  }

  // Resolve file path
  const baseDir = '/var/app/uploads';
  const filePath = path.resolve(baseDir, file.filename);

  // SECURE: Ensure file path is within allowed directory
  if (!filePath.startsWith(baseDir)) {
    return res.status(403).json({ error: 'Invalid file path' });
  }

  // Check if file exists on disk
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found on disk' });
  }

  // Download file
  res.download(filePath, file.originalName);
});

app.listen(3000);
```

## Enforcing RBAC on Every Endpoint

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// Middleware: Check every endpoint
function authenticate(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
}

// Define role-required routes
const roleRequired = {
  'GET /api/public': null, // No role required
  'GET /api/user': 'user', // User role
  'GET /api/admin': 'admin', // Admin role
  'DELETE /api/admin/users/:id': 'admin', // Admin only
  'POST /api/posts': ['editor', 'admin'], // Multiple roles
};

// Apply authentication and authorization
app.use((req, res, next) => {
  const route = `${req.method} ${req.path}`;

  // Skip auth for public endpoints
  if (!roleRequired[route] && !route.startsWith('GET /api/user') && !route.startsWith('GET /api/admin')) {
    return next();
  }

  // Check authentication
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Auth required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    req.user = decoded;

    // Check authorization
    const requiredRole = roleRequired[route];
    if (requiredRole) {
      const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
      if (!roles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    }

    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Routes
app.get('/api/public', (req, res) => {
  res.json({ message: 'Public data' });
});

app.get('/api/user', (req, res) => {
  res.json({ message: `User data for ${req.user.email}` });
});

app.get('/api/admin', (req, res) => {
  res.json({ message: 'Admin panel' });
});

app.listen(3000);
```

## Best Practices

1. **Always authenticate before authorization** - Verify user identity first
2. **Implement explicit access checks** - Check ownership and role on every endpoint
3. **Use strong JWT secrets** - Use environment variables, not hardcoded values
4. **Specify allowed algorithms in JWT** - Don't accept any algorithm
5. **Implement role-based access control** - Use consistent role definitions
6. **Validate all input** - Even authenticated users shouldn't access arbitrary resources
7. **Deny by default** - Require explicit permission rather than allowing and blocking
8. **Log access attempts** - Monitor failed authorization attempts
9. **Use secure password hashing** - bcrypt, argon2, not MD5/SHA1
10. **Implement rate limiting** - Prevent brute force attacks on auth
11. **Regular security audits** - Test for access control flaws
12. **Use framework-provided tools** - Leverage auth libraries and middleware

## References

- OWASP Broken Access Control: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- CWE-639: Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
- CWE-284: Improper Access Control: https://cwe.mitre.org/data/definitions/284.html
- OWASP RBAC: https://owasp.org/www-community/attacks/Horizontal_Privilege_Escalation
