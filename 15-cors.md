# Cross-Origin Resource Sharing (CORS) in JavaScript

## Definition

Cross-Origin Resource Sharing (CORS) is a browser security mechanism that controls which websites can access resources from a server. By default, the Same-Origin Policy prevents scripts on one origin from accessing resources on another origin. CORS allows servers to specify which origins are allowed to access their resources. Misconfigured CORS can expose sensitive data or allow unauthorized access.

## Same-Origin Policy

The Same-Origin Policy is a fundamental browser security feature that restricts cross-origin requests.

### What Defines an Origin?

An origin consists of three parts: **scheme**, **domain**, and **port**.

```
https://example.com:443
  |         |       |
scheme    domain   port

Two origins are the same if all three parts match.
```

### Examples of Same vs Different Origins

```
// SAME origin as https://example.com:443
https://example.com           ✓ (port 443 is default for HTTPS)
https://example.com:443       ✓
https://example.com/page      ✓ (path doesn't matter)
https://example.com/page?id=1 ✓ (query string doesn't matter)

// DIFFERENT origin from https://example.com:443
https://example.com:8443      ✗ (different port)
http://example.com            ✗ (different scheme)
https://api.example.com       ✗ (different domain)
https://example.net           ✗ (different domain)
https://example.com.attacker  ✗ (different domain)
```

### Same-Origin Policy in Action

```javascript
// Code running on https://example.com

// ALLOWED: Same origin
fetch('https://example.com/api/data')  // ✓ Allowed
fetch('/api/data')                     // ✓ Allowed (same origin)

// BLOCKED: Different origin
fetch('https://api.example.com/data')  // ✗ Blocked by SOP
fetch('https://example.net/data')      // ✗ Blocked by SOP
fetch('http://example.com/data')       // ✗ Blocked by SOP
```

### Exceptions to Same-Origin Policy

Some tags bypass SOP for convenience:

```html
<!-- ALLOWED: Script tag (no SOP enforcement) -->
<script src="https://different-origin.com/script.js"></script>

<!-- ALLOWED: Image tag (no SOP enforcement) -->
<img src="https://different-origin.com/image.png">

<!-- ALLOWED: Link tag (no SOP enforcement) -->
<link rel="stylesheet" href="https://different-origin.com/style.css">

<!-- ALLOWED: Form submission (legacy reason) -->
<form action="https://different-origin.com/submit" method="POST"></form>

<!-- BLOCKED: XHR/Fetch (SOP enforcement) -->
<script>
  fetch('https://different-origin.com/api')  // ✗ BLOCKED
</script>
```

## Preflight Requests (OPTIONS)

For certain requests, browsers automatically send a preflight OPTIONS request to check if the server allows the actual request.

### When Preflight Is Required

Preflight requests are sent for:

```javascript
// Methods that trigger preflight:
fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } })
fetch(url, { method: 'PUT' })
fetch(url, { method: 'DELETE' })
fetch(url, { method: 'PATCH' })

// Custom headers trigger preflight:
fetch(url, { headers: { 'X-Custom-Header': 'value' } })

// Credentials with certain configurations:
fetch(url, { credentials: 'include', ... })
```

### Simple Requests (No Preflight)

These requests don't trigger preflight:

```javascript
// Simple methods (no preflight):
fetch(url, { method: 'GET' })
fetch(url, { method: 'HEAD' })
fetch(url, { method: 'POST' })

// Simple headers only:
fetch(url, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  }
})

// No credentials:
fetch(url)  // No credentials by default
```

### Preflight Request Flow

```
Browser sends OPTIONS preflight request:

OPTIONS /api/resource HTTP/1.1
Host: api.example.com
Origin: https://example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, X-Custom-Header

Server responds with CORS headers:

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: POST, GET, OPTIONS
Access-Control-Allow-Headers: Content-Type, X-Custom-Header
Access-Control-Max-Age: 86400

Browser then sends actual request (if preflight succeeds):

POST /api/resource HTTP/1.1
Host: api.example.com
Origin: https://example.com
Content-Type: application/json
```

## CORS Headers Explained

### Access-Control-Allow-Origin

Specifies which origins can access the resource.

```javascript
// Allow one specific origin
res.setHeader('Access-Control-Allow-Origin', 'https://example.com');

// Allow all origins (DANGEROUS for sensitive data)
res.setHeader('Access-Control-Allow-Origin', '*');

// Allow multiple origins (manual checking)
const allowedOrigins = [
  'https://example.com',
  'https://app.example.com',
  'https://trusted-partner.com'
];
const origin = req.headers.origin;
if (allowedOrigins.includes(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}
```

### Access-Control-Allow-Methods

Specifies which HTTP methods are allowed.

```javascript
// Allow specific methods
res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT');

// Allow all methods
res.setHeader('Access-Control-Allow-Methods', '*');
```

### Access-Control-Allow-Headers

Specifies which headers clients can send.

```javascript
// Allow specific headers
res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

// Allow any header with wildcard
res.setHeader('Access-Control-Allow-Headers', '*');

// Allow Authorization but not with credentials=include
// Avoid: res.setHeader('Access-Control-Allow-Headers', '*');
```

### Access-Control-Allow-Credentials

Specifies whether credentials (cookies, auth headers) can be included.

```javascript
// Allow credentials
res.setHeader('Access-Control-Allow-Credentials', 'true');

// Note: When credentials are allowed, origin CANNOT be wildcard
// This combination is invalid and will be rejected by browsers
```

### Access-Control-Max-Age

Specifies how long preflight responses can be cached.

```javascript
// Cache preflight for 24 hours
res.setHeader('Access-Control-Max-Age', '86400');

// Cache preflight for 7 days
res.setHeader('Access-Control-Max-Age', '604800');
```

### Access-Control-Expose-Headers

Specifies which response headers are exposed to the browser.

```javascript
// Expose custom headers to JavaScript
res.setHeader('Access-Control-Expose-Headers', 'X-Total-Count, X-Page-Number');

// JavaScript can then read these headers
fetch(url).then(response => {
  const totalCount = response.headers.get('X-Total-Count');
  const pageNum = response.headers.get('X-Page-Number');
});
```

## Dangerous CORS Misconfigurations

### 1. Wildcard Origin with Credentials

```javascript
// EXTREMELY DANGEROUS: Allows any site to access with credentials
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

// This combination is INVALID and browsers will reject it
// But some servers might still process it incorrectly
// Attacker can access sensitive data using victim's credentials

// Attack:
// Attacker's site makes request with credentials=include
// Server responds with * and true (invalid but processed)
// Victim's cookies are sent and data is leaked
```

### 2. Reflecting Origin Header Blindly

```javascript
// VULNERABLE: Reflecting user-supplied Origin header
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // DANGEROUS: Trusting any Origin header
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  next();
});

// Attack:
// Any origin can access the API because we blindly reflect the Origin
// fetch('https://api.example.com/user/data', { credentials: 'include' })
// Server responds with Access-Control-Allow-Origin: https://attacker.com
// Credentials are sent to attacker's site
```

### 3. Trusting Null Origin

```javascript
// VULNERABLE: Allowing null origin
app.use((req, res, next) => {
  const origin = req.headers.origin || 'null';

  if (origin === 'null' || origin === 'https://example.com') {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  next();
});

// Problem: null origin appears when:
// - Local files (file://)
// - iframes with sandbox attribute
// - Attacker can trigger null origin with data: URLs

// Attack:
// Attacker creates iframe with sandbox
// Origin header is 'null'
// Server allows 'null' origin with credentials
// Attacker can access sensitive data
```

### 4. Insufficient Origin Validation

```javascript
// VULNERABLE: Weak origin validation
const allowedOrigins = ['example.com'];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  // VULNERABLE: Substring matching instead of full domain check
  if (origin && origin.includes('example.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  next();
});

// Attack: attacker-example.com.attacker.net
// String contains 'example.com' so it's allowed!
```

### 5. Allowing Sensitive Methods

```javascript
// VULNERABLE: Allowing DELETE, PUT without proper restrictions
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH');
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }

  next();
});

// Attack: Attacker makes DELETE request from their site
// fetch('https://api.example.com/users/123', { method: 'DELETE' })
// CORS allows it and resource is deleted!
```

## Secure CORS Setup in Express

### Basic Secure Configuration

```javascript
const express = require('express');
const cors = require('cors');

const app = express();

// Define allowed origins
const allowedOrigins = [
  'https://example.com',
  'https://app.example.com',
  'https://admin.example.com'
];

// SECURE: Explicit origin validation
const corsOptions = {
  origin: function(origin, callback) {
    // Allow requests with no origin (same-origin requests)
    if (!origin) {
      return callback(null, true);
    }

    // Check if origin is in allowlist
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
};

app.use(cors(corsOptions));
```

### Advanced Secure Configuration

```javascript
const express = require('express');
const app = express();

// Detailed CORS implementation
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Define allowed origins - no wildcards
  const allowedOrigins = [
    'https://example.com',
    'https://api.example.com'
  ];

  // Validate origin
  if (origin && allowedOrigins.includes(origin)) {
    // Only set origin header if valid
    res.setHeader('Access-Control-Allow-Origin', origin);

    // Explicitly list allowed methods
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');

    // Explicitly list allowed headers
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Allow credentials
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    // Cache preflight for 24 hours
    res.setHeader('Access-Control-Max-Age', '86400');

    // Expose headers that JavaScript needs
    res.setHeader('Access-Control-Expose-Headers', 'Content-Length, X-JSON-Response-Size');
  }

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }

  next();
});

// Protected endpoint
app.post('/api/protected', (req, res) => {
  // Endpoint is now CORS-protected
  res.json({ data: 'Protected data' });
});

app.listen(3000);
```

### Deny by Default Pattern

```javascript
const express = require('express');
const app = express();

// SECURE: Deny all CORS by default, allow specific routes
const allowedOrigins = [
  'https://example.com',
  'https://app.example.com'
];

function corsMiddleware(req, res, next) {
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
  }

  next();
}

// Apply CORS only to specific routes
app.options('/api/public/*', corsMiddleware);
app.get('/api/public/data', corsMiddleware, (req, res) => {
  res.json({ data: 'Public data' });
});

// This route has NO CORS headers
app.get('/api/internal', (req, res) => {
  res.json({ data: 'Internal only' });
});

app.listen(3000);
```

## Vulnerable CORS Code Examples

### 1. Vulnerable Implementation

```javascript
const express = require('express');
const app = express();

// VULNERABLE: Too permissive
app.use((req, res, next) => {
  // Allow any origin
  res.setHeader('Access-Control-Allow-Origin', '*');

  // Allow any method
  res.setHeader('Access-Control-Allow-Methods', '*');

  // Allow any header
  res.setHeader('Access-Control-Allow-Headers', '*');

  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }

  next();
});

// Sensitive API endpoint
app.get('/api/user-profile', (req, res) => {
  res.json({
    id: 123,
    email: 'user@example.com',
    phone: '555-1234',
    ssn: '123-45-6789'
  });
});

app.listen(3000);

// Attack: Attacker's site
fetch('https://api.example.com/api/user-profile')
  .then(r => r.json())
  .then(data => {
    // All user data leaked!
    console.log(data);
  });
```

### 2. Vulnerable Origin Reflection

```javascript
const express = require('express');
const app = express();

// VULNERABLE: Blindly reflecting Origin header
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // DANGEROUS: Trust any origin
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, PUT');
  }

  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
    return;
  }

  next();
});

app.get('/api/data', (req, res) => {
  res.json({ data: 'Sensitive data' });
});

app.listen(3000);

// Attack: Any domain can access
fetch('https://api.example.com/api/data', { credentials: 'include' })
```

## Best Practices

1. **Never use wildcard origin (`*`) with credentials** - Invalid and dangerous
2. **Maintain explicit allowlist** - List specific origins, don't use wildcards
3. **Validate Origin header** - Use full domain matching, not substring
4. **Reject null origin** - Don't allow `null` origin with credentials
5. **Limit HTTP methods** - Only allow methods needed (GET, POST, not DELETE)
6. **Limit headers** - Only allow headers needed, not `*`
7. **Use credentials carefully** - Only set `Access-Control-Allow-Credentials: true` when needed
8. **Cache preflight responses** - Set appropriate `Access-Control-Max-Age`
9. **Expose only necessary headers** - Limit `Access-Control-Expose-Headers`
10. **Monitor CORS requests** - Log and alert on unusual CORS patterns
11. **Regular security audits** - Review CORS configuration periodically
12. **Use CORS middleware library** - Use well-tested libraries like `cors` package

## Complete Secure CORS Implementation

```javascript
const express = require('express');
const cors = require('cors');
const app = express();

app.use(express.json());

// Configuration
const ENV = process.env.NODE_ENV || 'development';
const allowedOrigins = {
  development: ['http://localhost:3000', 'http://localhost:3001'],
  production: [
    'https://example.com',
    'https://app.example.com',
    'https://admin.example.com'
  ]
};

const origins = allowedOrigins[ENV] || [];

// Detailed CORS implementation
const corsOptions = {
  // Custom origin validation
  origin: function(origin, callback) {
    // Allow same-origin requests (no origin header)
    if (!origin) {
      return callback(null, true);
    }

    // Check against allowlist
    if (origins.includes(origin)) {
      callback(null, true);
    } else {
      // Log rejected CORS requests
      console.warn(`CORS request rejected from: ${origin}`);
      callback(new Error('CORS not allowed'), false);
    }
  },

  // Credentials handling
  credentials: true,

  // Methods allowlist
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST'],

  // Headers allowlist
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Accept'
  ],

  // Expose headers for JavaScript
  exposedHeaders: [
    'X-Total-Count',
    'X-Page-Number',
    'X-Page-Size'
  ],

  // Cache preflight for 1 day
  maxAge: 86400,

  // Handle pre-flight
  preflightContinue: false,

  // Send 200 on successful preflight
  optionsSuccessStatus: 200
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Protected API routes
app.get('/api/user', (req, res) => {
  res.json({ id: 1, name: 'John' });
});

app.post('/api/user', (req, res) => {
  res.json({ success: true, message: 'User created' });
});

// Admin only (extra protection)
app.delete('/api/admin/users/:id', (req, res) => {
  // Additional auth checks should happen here
  res.json({ success: true, message: 'User deleted' });
});

// Error handling
app.use((err, req, res, next) => {
  if (err.message === 'CORS not allowed') {
    return res.status(403).json({ error: 'CORS not allowed for this origin' });
  }
  res.status(500).json({ error: 'Server error' });
});

app.listen(3000, () => {
  console.log('Server running with CORS protection');
  console.log('Allowed origins:', origins);
});
```

## References

- MDN CORS: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- OWASP CORS: https://owasp.org/www-community/attacks/CORS
- CWE-532: Insertion of Sensitive Information into Log File: https://cwe.mitre.org/data/definitions/345.html
- Same-Origin Policy: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
- CORS Specification: https://fetch.spec.whatwg.org/#http-cors-protocol
