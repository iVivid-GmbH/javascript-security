# Security Misconfiguration (OWASP A05)

## Definition

**Security Misconfiguration** (OWASP A05:2021) refers to improper setup, deployment, or configuration of security controls. This includes using default credentials, leaving debug mode enabled in production, exposing error messages with sensitive information, enabling unnecessary HTTP methods, having overly permissive access controls (CORS, S3 buckets), and missing security headers. Misconfiguration often results from incomplete security implementations, unnecessary features left enabled, or lack of security hardening during deployment.

## Common Security Misconfiguration Examples

### 1. Default Credentials

```javascript
// ❌ VULNERABLE: Using default credentials
const admin_username = 'admin';
const admin_password = 'admin';  // Default password!

app.post('/admin/login', (req, res) => {
  if (req.body.username === admin_username &&
      req.body.password === admin_password) {
    res.json({ success: true });
  }
});

// Attackers try common defaults first:
// admin:admin
// admin:password
// root:root
// admin:123456

// Database systems with default credentials:
// MySQL: root (no password)
// PostgreSQL: postgres:postgres
// MongoDB: no auth enabled by default
// AWS: default security group allows all inbound
```

### 2. Debug Mode in Production

```javascript
// ❌ VULNERABLE: Debug mode enabled in production
const express = require('express');
const app = express();

// Express debug mode
process.env.DEBUG = 'express:*';  // ❌ In production!

app.use(express.static('public'));

// Debug information leaked in responses
if (process.env.NODE_ENV !== 'production') {
  // ❌ This check doesn't work if NODE_ENV not set!
  app.use(require('express').errorHandler());
}

// Problems:
// 1. Detailed error messages expose internal details
// 2. Stack traces reveal source code structure
// 3. Debug logs expose configuration
// 4. Performance degraded by debug logging
// 5. Security vulnerabilities in debug code
```

### 3. Verbose Error Messages

```javascript
// ❌ VULNERABLE: Exposes sensitive information in errors
app.get('/api/users/:id', (req, res) => {
  try {
    const user = db.getUserById(req.params.id);

    if (!user) {
      res.status(404).json({
        error: 'User not found',
        query: `SELECT * FROM users WHERE id = ${req.params.id}`,  // ❌ SQL exposed
        database: 'MySQL 5.7.30',  // ❌ Version exposed
        table: 'users'  // ❌ Structure exposed
      });
    }

    res.json(user);
  } catch (err) {
    // ❌ Full error with stack trace
    res.status(500).json({
      error: err.message,
      stack: err.stack,  // Full stack trace!
      query: err.query,  // SQL query exposed
      code: err.code,
      sqlState: err.sqlState
    });
  }
});

// Attacker learns:
// - Database type and version
// - Table names and structure
// - Exact SQL queries being used
// - File paths and code structure
```

### 4. Directory Listing

```javascript
// ❌ VULNERABLE: Directory listing enabled
const express = require('express');
const app = express();

// Without proper configuration, express.static allows directory browsing
app.use(express.static('public'));  // Can list directories!

// User can visit /public/ and see:
// [DIR]  images/
// [DIR]  uploads/
// [FILE] backup.sql (500KB)
// [FILE] .env.old (exposed credentials!)
// [FILE] private.key
// [FILE] users.csv
```

### 5. Open Cloud Storage

```
// ❌ VULNERABLE: AWS S3 bucket with public read access
S3 Bucket: company-backups

Bucket Policy:
{
  "Statement": [
    {
      "Principal": "*",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::company-backups/*"
    }
  ]
}

Result:
- Publicly readable backups
- Database exports visible
- Configuration files exposed
- Customer data accessible
- Anyone can download all files
```

### 6. Overly Permissive CORS

```javascript
// ❌ VULNERABLE: CORS allows all origins
const cors = require('cors');

app.use(cors({
  origin: '*'  // ❌ Allow requests from ANY origin!
}));

// OR directly in code:
app.use((req, res, next) => {
  // ❌ Accepts requests from malicious.com
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', '*');  // ❌ All headers!
  next();
});

// Problems:
// 1. Other websites can make requests on behalf of users
// 2. Cookie-based authentication can be stolen
// 3. CSRF protection bypassed
// 4. Sensitive data accessed from malicious sites
```

### 7. Unnecessary HTTP Methods

```javascript
// ❌ VULNERABLE: Unnecessary methods allowed
app.post('/api/users/:id', (req, res) => {
  updateUser(req.params.id, req.body);
  res.json({ success: true });
});

// ❌ PUT method also allowed (unintended)
app.put('/api/users/:id', (req, res) => {
  // If authentication check missing here
  updateUser(req.params.id, req.body);
  res.json({ success: true });
});

// ❌ DELETE method allowed when it shouldn't be
app.delete('/api/users/:id', (req, res) => {
  deleteUser(req.params.id);
  res.json({ success: true });
});

// ❌ TRACE method enabled
// Shows request headers and body
curl -X TRACE http://example.com/api/data
// Returns the entire request, including auth headers!

// ❌ OPTIONS method shows capabilities
curl -X OPTIONS http://example.com/api/data
// Response: Allow: GET, POST, PUT, DELETE, TRACE
// Attacker learns what methods are available
```

### 8. Missing Security Headers

```javascript
// ❌ VULNERABLE: Missing security headers
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('<html><body>Hello</body></html>');
  // Missing:
  // - X-Content-Type-Options: nosniff
  // - X-Frame-Options: DENY
  // - X-XSS-Protection: 1; mode=block
  // - Strict-Transport-Security
  // - Content-Security-Policy
  // - Referrer-Policy
});

app.listen(3000);
```

## Environment-Specific Configuration

### Vulnerable: Same Config Everywhere

```javascript
// ❌ VULNERABLE: Hardcoded configs
const config = {
  debug: true,                    // ❌ Debug in production
  database: 'localhost:27017',    // ❌ Hardcoded
  adminUser: 'admin',
  adminPass: 'admin123',          // ❌ Default password
  enableFileUpload: true,         // ❌ No restriction
  uploadDir: '/tmp/uploads',      // ❌ World-writable
  jwtSecret: 'secret',            // ❌ Weak secret
  apiKey: 'sk-1234567890'         // ❌ Hardcoded
};

// Same in development, staging, production
// Development settings make production insecure
```

### Secure: Environment-Specific

```javascript
// ✅ SECURE: Environment-specific configuration
require('dotenv').config();

const config = {
  // Environment
  environment: process.env.NODE_ENV || 'development',
  debug: process.env.DEBUG === 'true',

  // Database
  database: {
    url: process.env.DATABASE_URL,
    pool: process.env.NODE_ENV === 'production' ? 20 : 5
  },

  // Credentials
  admin: {
    username: process.env.ADMIN_USERNAME,
    password: process.env.ADMIN_PASSWORD_HASH  // Hashed!
  },

  // File uploads
  fileUpload: {
    enabled: process.env.NODE_ENV === 'production',
    dir: process.env.UPLOAD_DIR || '/tmp/uploads',
    maxSize: process.env.MAX_UPLOAD_SIZE || 10 * 1024 * 1024
  },

  // Security
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: '1h'
  },

  api: {
    key: process.env.API_KEY,
    rateLimit: process.env.NODE_ENV === 'production' ? 100 : 1000
  }
};

// .env file (not in Git)
// NODE_ENV=production
// DEBUG=false
// DATABASE_URL=postgresql://prod-host/db
// ADMIN_USERNAME=admin_user_1234
// ADMIN_PASSWORD_HASH=$2b$12$...
// UPLOAD_DIR=/var/uploads
// JWT_SECRET=random-256-bit-value
// API_KEY=sk-production-key-12345

module.exports = config;
```

## Security Headers Checklist

```javascript
// ✅ SECURE: Complete security headers setup
const helmet = require('helmet');
const express = require('express');
const app = express();

app.use(helmet({
  // Prevent MIME type sniffing
  noSniff: true,  // Sets X-Content-Type-Options: nosniff

  // Frame options
  frameguard: {
    action: 'deny'  // Sets X-Frame-Options: DENY
  },

  // xssFilter is disabled by default in Helmet 5+ — X-XSS-Protection is deprecated
  // and can introduce vulnerabilities in IE; rely on CSP instead
  // xssFilter: false,

  // HSTS (force HTTPS)
  hsts: {
    maxAge: 31536000,           // 1 year
    includeSubDomains: true,
    preload: true
  },

  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://trusted-cdn.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },

  // Referrer policy
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  },

  // Feature policy
  featurePolicy: {
    camera: ["'none'"],
    microphone: ["'none'"],
    geolocation: ["'none'"]
  }
}));

// Additional custom headers
app.use((req, res, next) => {
  // Disable caching for sensitive pages
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

  // Disable client-side caching
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  next();
});

app.listen(3000);
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: Multiple misconfigurations
const express = require('express');
const cors = require('cors');

const app = express();

// ❌ MISCONFIG 1: CORS allows all origins
app.use(cors({
  origin: '*',  // Allow any origin!
  credentials: true  // And send credentials!
}));

app.use(express.json());

// ❌ MISCONFIG 2: No security headers
// No helmet, no custom headers

// ❌ MISCONFIG 3: Debug enabled in production
app.set('env', 'development');
process.env.DEBUG = '*';

// ❌ MISCONFIG 4: Default credentials
const adminCreds = {
  username: 'admin',
  password: 'admin'
};

// ❌ MISCONFIG 5: Directory listing enabled
app.use(express.static('public'));  // Shows directory contents

// ❌ MISCONFIG 6: All HTTP methods allowed
app.get('/api/resource/:id', (req, res) => {
  res.json({ data: 'resource data' });
});

app.post('/api/resource/:id', (req, res) => {
  updateResource(req.params.id);
  res.json({ success: true });
});

app.put('/api/resource/:id', (req, res) => {
  updateResource(req.params.id);
  res.json({ success: true });
});

app.delete('/api/resource/:id', (req, res) => {
  deleteResource(req.params.id);
  res.json({ success: true });
});

app.options('/api/resource/:id', (req, res) => {
  // ❌ Reveals available methods
  res.setHeader('Allow', 'GET, POST, PUT, DELETE, OPTIONS');
  res.send();
});

// ❌ MISCONFIG 7: Verbose error messages
app.get('/api/users/:id', (req, res) => {
  try {
    const user = db.getUserById(req.params.id);

    if (!user) {
      // ❌ Exposes internal details
      res.status(404).json({
        error: 'User not found',
        query: 'SELECT * FROM users WHERE id = ' + req.params.id,
        database: 'MySQL 5.7',
        tables: ['users', 'orders', 'payments']
      });
    }

    // ❌ Returns all user data
    res.json(user);
  } catch (err) {
    // ❌ Full error exposed
    res.status(500).json({
      error: err.message,
      stack: err.stack.split('\n'),
      file: err.fileName,
      line: err.lineNumber
    });
  }
});

// ❌ MISCONFIG 8: Admin accessible without auth
app.get('/admin', (req, res) => {
  // No authentication check!
  res.sendFile('admin.html');
});

app.post('/admin/login', (req, res) => {
  // Weak password validation
  if (req.body.username === adminCreds.username &&
      req.body.password === adminCreds.password) {
    res.json({
      success: true,
      token: 'user123',  // ❌ Predictable token
      admin: true
    });
  }
});

app.listen(3000);
```

## Secure Code Example

```javascript
// ✅ SECURE: Proper configuration
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();

// ✅ Security Config 1: Restricted CORS
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://example.com'],
  credentials: false,  // Don't send credentials with CORS
  methods: ['GET', 'POST'],  // Only necessary methods
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));

// ✅ Security Config 2: Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "https:"],
      connectSrc: ["'self'", "https://api.example.com"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// ✅ Security Config 3: Debug disabled in production
app.set('env', process.env.NODE_ENV || 'production');

if (process.env.NODE_ENV === 'development') {
  // Only in development
  process.env.DEBUG = 'app:*';
}

// ✅ Security Config 4: Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);

app.use(express.json());

// ✅ Security Config 5: Static files without directory listing
app.use(express.static('public', {
  index: false,  // Don't serve index.html for directories
  redirect: false  // Don't redirect to parent directories
}));

// ✅ Security Config 6: Only necessary HTTP methods
app.get('/api/resource/:id', (req, res) => {
  res.json({ data: 'resource data' });
});

app.post('/api/resource', (req, res) => {
  createResource(req.body);
  res.json({ success: true });
});

// DELETE only for authorized users
app.delete('/api/resource/:id', authenticateToken, (req, res) => {
  deleteResource(req.params.id);
  res.json({ success: true });
});

// ❌ PUT, TRACE, OPTIONS not implemented - return 405
app.all('/api/resource/:id', (req, res) => {
  if (!['GET', 'POST', 'DELETE'].includes(req.method)) {
    res.status(405).json({
      error: 'Method not allowed'
    });
  }
});

// ✅ Security Config 7: Generic error messages
app.get('/api/users/:id', (req, res) => {
  try {
    const user = db.getUserById(req.params.id);

    if (!user) {
      // ✅ Generic message, no details
      return res.status(404).json({
        error: 'User not found'
      });
    }

    // ✅ Only return necessary fields
    res.json({
      id: user.id,
      email: user.email,
      name: user.name
      // Don't include: password, api_keys, etc.
    });
  } catch (err) {
    // ✅ Log error internally, but don't expose to client
    console.error('Database error:', err);
    res.status(500).json({
      error: 'Internal server error'
      // No stack trace, no SQL, no internals
    });
  }
});

// ✅ Security Config 8: Protected admin with proper auth
app.get('/admin', authenticateToken, authorizeAdmin, (req, res) => {
  // Requires authentication and admin role
  res.sendFile('admin.html');
});

app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;

  // ✅ Validate against securely stored credentials
  const adminUser = getAdminUser(username);

  if (!adminUser) {
    // ✅ Generic error (no user enumeration)
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // ✅ Use bcrypt for comparison
  const isValid = bcrypt.compareSync(password, adminUser.passwordHash);

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // ✅ Generate secure token with expiration
  const token = jwt.sign(
    { userId: adminUser.id, role: 'admin' },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({ token });
});

// ✅ Auth middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = decoded;
    next();
  });
}

// ✅ Admin check middleware
function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  next();
}

// ✅ Custom error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);

  // ✅ Never expose error details
  res.status(500).json({
    error: 'Internal server error'
  });
});

app.listen(3000);
```

## Security Headers Checklist

```
✓ X-Content-Type-Options: nosniff
✓ X-Frame-Options: DENY or SAMEORIGIN
✗ X-XSS-Protection — deprecated, disabled in Chrome/Firefox; omit or set to 0
✓ Strict-Transport-Security: max-age=31536000; includeSubDomains
✓ Content-Security-Policy: (with appropriate directives)
✓ Referrer-Policy: strict-origin-when-cross-origin
✓ Permissions-Policy: (deny unnecessary features)
✓ Cache-Control: no-store (for sensitive pages)
✓ Pragma: no-cache
✓ Expires: 0
```

## Mitigations and Best Practices

### 1. Change all default credentials
### 2. Disable debug mode in production
### 3. Disable unnecessary features
### 4. Disable unnecessary HTTP methods
### 5. Use environment-specific configuration
### 6. Apply security headers
### 7. Implement proper error handling
### 8. Disable directory listing
### 9. Implement proper access controls
### 10. Regularly audit configuration

## Summary

Security misconfiguration often results from poor deployment practices. Use environment-specific configurations, implement security headers with Helmet, change default credentials, disable debug mode in production, restrict HTTP methods to only what's needed, implement proper access controls, and handle errors securely without exposing internal details.
