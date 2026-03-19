# API Security and Rate Limiting

## Definition

**Rate limiting** is a security mechanism that restricts the number of requests a client can make to an API within a specified time period. Without rate limiting, attackers can perform brute force attacks (testing many password combinations), credential stuffing (trying leaked credentials), OTP enumeration (guessing one-time passwords), or launch denial-of-service (DoS) attacks that exhaust server resources. Rate limiting protects your API by limiting the damage any single attacker can do and making automated attacks economically infeasible.

## Attack Types Without Rate Limiting

### 1. Brute Force Login Attack

```javascript
// ❌ VULNERABLE API: No rate limiting
POST /api/auth/login
{
  "username": "admin",
  "password": "attempt1"
}

// Response: 401 Unauthorized

// Attacker sends thousands of requests:
for (let i = 0; i < 100000; i++) {
  POST /api/auth/login
  {
    "username": "admin",
    "password": "password" + i
  }
  // Eventually finds correct password
}

// Or uses common passwords:
const commonPasswords = ['password', '123456', 'admin', 'letmein', ...];
commonPasswords.forEach(pwd => {
  // Try each password
});

// With 10,000 requests per second:
// Testing 500,000 passwords takes 50 seconds
// At 1 million passwords: ~100 seconds
// Most systems compromise in minutes
```

### 2. Credential Stuffing

```javascript
// ❌ VULNERABLE: No rate limiting
// Attacker has leaked username/password list from another breach
// Tests each credential against your service

const breachedCredentials = [
  { username: 'user1@example.com', password: 'Pass123!' },
  { username: 'user2@example.com', password: 'qwerty123' },
  // ... 10 million more credentials from previous breaches
];

breachedCredentials.forEach(cred => {
  fetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(cred)
  }).then(r => {
    if (r.status === 200) {
      // Credential works on this site!
      recordSuccessfulLogin(cred);
    }
  });
});

// Attacker can test 10 million credentials against your API
// Even if only 1% match users, that's 100,000 compromised accounts
```

### 3. OTP/SMS Code Enumeration

```javascript
// ❌ VULNERABLE: No rate limiting
// User requests OTP
POST /api/auth/request-otp
{ "email": "victim@example.com" }

// User receives SMS: code 123456

// Attacker immediately tries all 6-digit codes
for (let code = 0; code <= 999999; code++) {
  const otp = String(code).padStart(6, '0');
  fetch('/api/auth/verify-otp', {
    method: 'POST',
    body: JSON.stringify({
      email: 'victim@example.com',
      otp: otp
    })
  }).then(r => {
    if (r.status === 200) {
      console.log('Correct OTP:', otp);
      // Account compromised
    }
  });
}

// 6-digit code has 1,000,000 possibilities
// With 1000 requests/second: compromised in ~1000 seconds (~17 minutes)
// With 10,000 requests/second: compromised in ~100 seconds
```

### 4. API Key Enumeration

```javascript
// ❌ VULNERABLE: No rate limiting
// Attacker generates/guesses API keys
for (let i = 0; i < 1000000; i++) {
  const guessedKey = generateRandomKey(i);  // sk-1234567890...

  fetch('/api/users', {
    headers: {
      'Authorization': `Bearer ${guessedKey}`
    }
  }).then(r => {
    if (r.status === 200) {
      console.log('Valid API key found:', guessedKey);
      // Can now access entire API
    }
  });
}
```

### 5. Denial of Service (DoS)

```javascript
// ❌ VULNERABLE: No rate limiting
// Attacker floods API with requests
// Goal: Exhaust server resources, make service unavailable

const headers = {
  'User-Agent': 'Mozilla/5.0...',
  'Referer': 'https://example.com'
};

for (let i = 0; i < 100000; i++) {
  fetch('/api/expensive-operation', {
    headers,
    body: JSON.stringify({ data: 'x'.repeat(10000) })
  }).then(() => {
    // Don't wait for response, send next request immediately
  });
}

// Thousands of simultaneous requests
// Server CPU/memory exhausted
// Legitimate users get connection timeout
// Service unavailable
```

## Rate Limiting Strategies

### 1. Fixed Window Counter

```
Time slots:        |--1 min--|--1 min--|--1 min--|
User requests:     1  2  3  4  5  6  7  8  9  10
Allowed?           Y  Y  Y  Y  Y  Y  Y  Y  Y  Y
Then new window:   |--1 min--|--1 min--|--1 min--|
Reset counter      0                              0

Request 11 (after reset): Y
Request 12: Y
```

**Pseudocode:**
```
current_time = now()
key = "user:" + user_id + ":" + floor(current_time / 60)  // 1-minute bucket
count = redis.get(key)

if count is null:
  count = 1
  redis.set(key, 1, expiry=60)
else:
  count = count + 1
  redis.set(key, count)

if count > LIMIT (100 requests):
  return 429 Too Many Requests
else:
  allow request
```

**Problem:** Burst attacks at window boundaries
```
Minute 1: Requests 1-100 allowed
Minute 2: Counter resets at second 60
          Attacker sends 100 more requests immediately (second 60-61)
          At second 120, counter resets again
          Attacker sends another 100
          Total in 60 seconds: 200 requests (bypassed limit!)
```

### 2. Sliding Window Log

```
Requests tracked:    [time1][time2][time3]...[timeN]
New request arrives: Check if within last 60 seconds
                     If > 100 requests, reject

Oldest entry expires when:
current_time - oldest_entry_time > window_size
```

**Pseudocode:**
```
key = "user:" + user_id
current_time = now()
window_start = current_time - window_size (60 seconds)

// Remove expired entries
redis.zremrangebyscore(key, 0, window_start)

// Count requests in current window
count = redis.zcard(key)

if count >= LIMIT:
  return 429 Too Many Requests

// Add current request
redis.zadd(key, current_time, request_id)
redis.expire(key, window_size)  // Auto-cleanup
allow request
```

**Advantage:** No burst attack vulnerability
**Disadvantage:** Higher memory usage (tracks individual requests)

### 3. Token Bucket

```
Bucket capacity: 100 tokens
Refill rate: 10 tokens per minute

Time 0:00:
  Tokens in bucket: 100
  Request 1: Remove 1 token → 99 tokens
  Request 2: Remove 1 token → 98 tokens
  ...
  Request 100: Remove 1 token → 0 tokens
  Request 101: No tokens → REJECT (429)

Time 0:06 (6 seconds later):
  Tokens refilled: 6 seconds × (10 tokens/60 seconds) = 1 token
  Tokens in bucket: 1
  Request 102: Remove 1 token → 0 tokens
  Request 103: No tokens → REJECT

Time 0:60 (60 seconds later):
  Tokens refilled: 60 seconds × (10 tokens/60 seconds) = 10 tokens
  Tokens in bucket: 10 (capped at max 100)
```

**Pseudocode:**
```
key = "bucket:" + user_id
max_tokens = 100
refill_rate = 10 tokens per minute

last_refill = redis.hget(key, "last_refill")
tokens = redis.hget(key, "tokens")

if last_refill is null:
  tokens = max_tokens
else:
  time_passed = (now() - last_refill) seconds
  refilled = time_passed * (refill_rate / 60)
  tokens = min(max_tokens, tokens + refilled)

if tokens >= 1:  // Cost per request
  tokens = tokens - 1
  redis.hset(key, {
    tokens: tokens,
    last_refill: now()
  })
  allow request
else:
  return 429 Too Many Requests
```

**Advantage:**
- Smooth request distribution
- Allows bursts up to bucket capacity
- Most fair for users

## Implementing Rate Limiting in Express

### Using express-rate-limit

```bash
npm install express-rate-limit redis redis-client
```

```javascript
// ✅ SECURE: Express rate limiting setup
const express = require('express');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

const app = express();
const redisClient = redis.createClient();

// Basic rate limiter (memory-based, good for development)
const basicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // 100 requests per window
  message: 'Too many requests, please try again later',
  standardHeaders: true,      // Return rate limit info in headers
  legacyHeaders: false        // Disable X-RateLimit-* headers
});

// Strict limiter for sensitive endpoints
const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,    // 1 minute
  max: 5,                     // 5 requests per minute
  skipSuccessfulRequests: false,  // Count successful requests
  skipFailedRequests: false       // Count failed requests
});

// Very strict limiter for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,   // 15 minutes
  max: 5,                     // 5 login attempts per 15 min
  skipSuccessfulRequests: true,  // Reset on successful login
  message: 'Too many login attempts, please try again later',

  // Custom key generator (rate limit by email, not IP)
  keyGenerator: (req, res) => {
    return req.body.email || req.ip;
  }
});

// Redis-based limiter (for distributed systems)
const limiter = rateLimit({
  store: new RedisStore({
    client: redisClient,
    prefix: 'rl:'  // Redis key prefix
  }),
  windowMs: 15 * 60 * 1000,
  max: 100
});

// Apply to all routes
app.use(limiter);

// Apply to specific routes
app.get('/api/data', basicLimiter, (req, res) => {
  res.json({ data: 'ok' });
});

// Strict limit on sensitive endpoint
app.post('/api/download-report', strictLimiter, (req, res) => {
  // Generate and send report
  res.download('report.pdf');
});

// Login endpoint with very strict limit
app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { email, password } = req.body;

  // Verify credentials
  if (isValidCredentials(email, password)) {
    res.json({ token: generateToken(email) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Check rate limit status endpoint
app.get('/api/rate-limit-status', (req, res) => {
  res.json({
    limit: req.rateLimit.limit,
    current: req.rateLimit.current,
    remaining: req.rateLimit.limit - req.rateLimit.current
  });
});

app.listen(3000);
```

### Custom Rate Limiting

```javascript
// ✅ Implement custom rate limiting with more control
const rateLimit = (options = {}) => {
  const {
    windowMs = 60 * 1000,
    max = 100,
    message = 'Too many requests',
    keyGenerator = (req) => req.ip,
    skipSuccessfulRequests = false,
    skipFailedRequests = false,
    onLimitReached = null
  } = options;

  const requests = new Map();

  return (req, res, next) => {
    const key = keyGenerator(req);
    const now = Date.now();

    // Get or initialize request log
    if (!requests.has(key)) {
      requests.set(key, []);
    }

    const requestLog = requests.get(key);

    // Remove old entries outside window
    const windowStart = now - windowMs;
    const recentRequests = requestLog.filter(time => time > windowStart);

    // Check if limit exceeded
    if (recentRequests.length >= max) {
      if (onLimitReached) {
        onLimitReached(req, key);
      }

      res.status(429).json({
        error: message,
        retryAfter: Math.ceil((recentRequests[0] + windowMs - now) / 1000)
      });

      res.setHeader('Retry-After', Math.ceil((recentRequests[0] + windowMs - now) / 1000));
      return;
    }

    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', max - recentRequests.length - 1);
    res.setHeader('X-RateLimit-Reset', Math.ceil((recentRequests[0] + windowMs) / 1000));

    // On successful request, optionally reset counter
    const originalJson = res.json;
    res.json = function(data) {
      if (skipSuccessfulRequests && res.statusCode >= 200 && res.statusCode < 300) {
        requests.delete(key);
      }
      return originalJson.call(this, data);
    };

    // Add current request to log
    recentRequests.push(now);
    requests.set(key, recentRequests);

    // Cleanup old entries
    if (requests.size > 1000) {
      for (const [k, v] of requests.entries()) {
        if (v.every(time => time <= windowStart)) {
          requests.delete(k);
        }
      }
    }

    next();
  };
};

// Usage
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later',
  keyGenerator: (req) => req.body.email || req.ip,
  skipSuccessfulRequests: true,
  onLimitReached: (req, key) => {
    console.warn(`Login rate limit exceeded for: ${key}`);
    // Could send alert to security team
  }
});
```

## API Key Security

### Generating Secure API Keys

```javascript
// ✅ Generate cryptographically secure API keys
const crypto = require('crypto');

function generateAPIKey() {
  // Generate 32 random bytes (256 bits)
  const randomBytes = crypto.randomBytes(32);

  // Encode as hex or base64
  const apiKey = randomBytes.toString('hex');  // or base64

  return apiKey;  // Example: 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'
}

// Better: Use a prefix to identify key type
function generateAPIKey(prefix = 'sk') {
  const randomBytes = crypto.randomBytes(32);
  const randomPart = randomBytes.toString('hex');
  return `${prefix}_${randomPart}`;  // Example: 'sk_a1b2c3d4e5f6g7h8'
}

// Storage: Hash API key before storing in database
const crypto = require('crypto');

function hashAPIKey(apiKey) {
  return crypto
    .createHash('sha256')
    .update(apiKey)
    .digest('hex');
}

// When user creates API key:
const apiKey = generateAPIKey();
const hashedKey = hashAPIKey(apiKey);

// Store in database:
db.apiKeys.insert({
  userId: user.id,
  hashedKey: hashedKey,  // Store hash, not plaintext
  prefix: 'sk',
  createdAt: new Date(),
  lastUsed: null,
  rateLimit: 1000
});

// Return to user (only time they see it):
console.log('Your API Key:', apiKey);
console.log('Save it securely, you won\'t see it again');

// When user makes API request:
const apiKey = req.headers['x-api-key'];
const hashedKey = hashAPIKey(apiKey);

const keyRecord = db.apiKeys.findOne({ hashedKey });
if (keyRecord) {
  req.user = { id: keyRecord.userId };
  next();
} else {
  res.status(401).json({ error: 'Invalid API key' });
}
```

## Input Validation on API Endpoints

### Using express-validator

```bash
npm install express-validator
```

```javascript
const { body, query, validationResult } = require('express-validator');

const express = require('express');
const app = express();

// Middleware to validate POST body
app.post('/api/users',
  // Validation chain
  body('email')
    .isEmail()
    .normalizeEmail(),
  body('username')
    .isLength({ min: 3, max: 50 })
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username must be alphanumeric'),
  body('password')
    .isLength({ min: 12 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/),
  body('age')
    .optional()
    .isInt({ min: 0, max: 150 }),

  // Handler
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Process valid request
    const { email, username, password, age } = req.body;
    createUser(email, username, password, age);

    res.json({ success: true });
  }
);

// Validate query parameters
app.get('/api/users',
  query('page')
    .optional()
    .isInt({ min: 1 })
    .toInt(),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .toInt()
    .default(20),
  query('sort')
    .optional()
    .isIn(['asc', 'desc'])
    .default('asc'),

  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // Validated query parameters
    const { page = 1, limit = 20, sort = 'asc' } = req.query;
    const users = getUsers(page, limit, sort);

    res.json(users);
  }
);
```

### Using Zod for Schema Validation

```bash
npm install zod
```

```javascript
const { z } = require('zod');
const express = require('express');
const app = express();

// Define request schemas
const CreateUserSchema = z.object({
  email: z.string().email(),
  username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_]+$/),
  password: z.string().min(12).regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/),
  age: z.number().int().min(0).max(150).optional()
});

const QuerySchema = z.object({
  page: z.string().regex(/^\d+$/).transform(Number).optional(),
  limit: z.string().regex(/^\d+$/).transform(Number).optional()
});

app.post('/api/users', (req, res) => {
  try {
    const validatedData = CreateUserSchema.parse(req.body);
    // Process validatedData
    res.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ errors: error.errors });
    } else {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
});

app.get('/api/users', (req, res) => {
  try {
    const validatedQuery = QuerySchema.parse(req.query);
    // Process validatedQuery
    res.json([]);
  } catch (error) {
    if (error instanceof z.ZodError) {
      res.status(400).json({ errors: error.errors });
    }
  }
});
```

## Returning Appropriate HTTP Status Codes

```javascript
// ✅ Proper HTTP status code usage

// 200 OK - Request succeeded
app.get('/api/users', (req, res) => {
  res.status(200).json(users);  // or just res.json()
});

// 201 Created - Resource created
app.post('/api/users', (req, res) => {
  const user = createUser(req.body);
  res.status(201).json(user);
});

// 204 No Content - Success, no body
app.delete('/api/users/:id', (req, res) => {
  deleteUser(req.params.id);
  res.status(204).send();  // No body
});

// 400 Bad Request - Client error in request
app.post('/api/users', (req, res) => {
  if (!req.body.email) {
    res.status(400).json({ error: 'Email is required' });
  }
});

// 401 Unauthorized - Authentication required/failed
app.get('/api/profile', (req, res) => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
  }
});

// 403 Forbidden - Authenticated but not authorized
app.get('/api/admin/users', (req, res) => {
  if (req.user.role !== 'admin') {
    res.status(403).json({ error: 'Admin access required' });
  }
});

// 404 Not Found - Resource doesn't exist
app.get('/api/users/:id', (req, res) => {
  const user = db.getUser(req.params.id);
  if (!user) {
    res.status(404).json({ error: 'User not found' });
  }
});

// 429 Too Many Requests - Rate limit exceeded
app.use(rateLimit);
app.get('/api/data', (req, res) => {
  // Handled by rate limit middleware
  res.status(429).json({ error: 'Rate limit exceeded' });
});

// 500 Internal Server Error - Server error
app.get('/api/data', (req, res) => {
  try {
    const data = expensiveOperation();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 503 Service Unavailable - Server overloaded
if (serverLoad > 90) {
  res.status(503).json({ error: 'Service temporarily unavailable' });
}
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: No rate limiting, no validation
const express = require('express');
const app = express();

app.use(express.json());

// ❌ Login endpoint with NO rate limiting
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  // ❌ No input validation
  // Accepts any input

  const user = db.users.findOne({ username });

  if (user && user.password === password) {  // ❌ Plaintext comparison!
    res.json({ token: generateToken(user) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ❌ No protection against OTP enumeration
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  // ❌ No rate limiting
  // ❌ No input validation

  const isValid = verifyOTP(email, otp);

  if (isValid) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid OTP' });
  }
});

// ❌ API endpoint with no rate limiting
app.get('/api/expensive-operation', (req, res) => {
  // ❌ No rate limiting
  // ❌ Attacker can DoS
  const result = expensiveDatabaseQuery();
  res.json(result);
});

app.listen(3000);
```

## Secure Code Example

```javascript
// ✅ SECURE: Rate limiting, validation, proper auth
const express = require('express');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json());

// ✅ Rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 5,                    // 5 attempts per 15 min
  skipSuccessfulRequests: true,  // Reset on success
  message: 'Too many login attempts, please try again later',
  keyGenerator: (req) => req.body.email || req.ip,
  standardHeaders: true
});

// ✅ Rate limiting for sensitive operations
const sensitiveOperationLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,   // 1 minute
  max: 10,                   // 10 requests per minute
  message: 'Too many requests to this endpoint'
});

// ✅ Login with validation and rate limiting
app.post('/api/auth/login',
  loginLimiter,  // Apply rate limit first
  body('email')
    .isEmail()
    .normalizeEmail(),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters'),

  async (req, res) => {
    // ✅ Check validation
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { email, password } = req.body;

      // ✅ Constant-time comparison to prevent timing attacks
      const user = await db.users.findOne({ email });

      if (!user) {
        // ✅ Don't reveal if email exists
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // ✅ Use bcrypt for password verification
      const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);

      if (!isPasswordValid) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // ✅ Log successful authentication
      await db.auditLog.insert({
        userId: user.id,
        action: 'login',
        ip: req.ip,
        timestamp: new Date()
      });

      // ✅ Generate secure token
      const token = generateToken(user);

      res.json({
        token,
        user: { id: user.id, email: user.email }
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ✅ OTP verification with rate limiting and validation
app.post('/api/auth/verify-otp',
  sensitiveOperationLimiter,
  body('email').isEmail(),
  body('otp').isLength({ min: 6, max: 6 }).isNumeric(),

  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { email, otp } = req.body;

      // ✅ Use constant-time comparison for OTP
      const record = await db.otpCodes.findOne({ email });

      if (!record) {
        return res.status(401).json({ error: 'No OTP found for this email' });
      }

      // ✅ Check if OTP has expired (e.g., 5 minutes)
      if (Date.now() - record.createdAt > 5 * 60 * 1000) {
        await db.otpCodes.deleteOne({ email });
        return res.status(401).json({ error: 'OTP has expired' });
      }

      // ✅ Constant-time comparison
      const isValid = timingSafeEqual(otp, record.code);

      if (!isValid) {
        // ✅ Increment failed attempts
        record.attempts = (record.attempts || 0) + 1;

        if (record.attempts > 3) {
          // ✅ Lock after 3 failed attempts
          await db.otpCodes.deleteOne({ email });
          return res.status(429).json({ error: 'Too many failed OTP attempts' });
        }

        await record.save();
        return res.status(401).json({ error: 'Invalid OTP' });
      }

      // ✅ OTP verified
      await db.otpCodes.deleteOne({ email });

      const token = generateToken({ email });

      res.json({
        token,
        message: 'OTP verified successfully'
      });
    } catch (err) {
      console.error('OTP error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ✅ API endpoint with rate limiting
app.get('/api/expensive-operation',
  sensitiveOperationLimiter,
  authenticateToken,

  async (req, res) => {
    try {
      // ✅ Rate-limited, authenticated
      const result = await expensiveQuery(req.user.id);

      // ✅ Set cache headers
      res.setHeader('Cache-Control', 'private, max-age=300');

      res.json(result);
    } catch (err) {
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

// ✅ Helper: Constant-time comparison
function timingSafeEqual(a, b) {
  const crypto = require('crypto');
  try {
    return crypto.timingSafeEqual(
      Buffer.from(a),
      Buffer.from(b)
    );
  } catch (err) {
    return false;
  }
}

app.listen(3000);
```

## Mitigations and Best Practices

### 1. Implement Rate Limiting on All Public APIs
### 2. Use Stricter Limits for Sensitive Endpoints
### 3. Validate All Input Before Processing
### 4. Use Bcrypt/Argon2 for Password Hashing
### 5. Implement Account Lockout After Failed Attempts
### 6. Use HTTPS for All API Communication
### 7. Implement API Key Rotation
### 8. Monitor and Log API Activity
### 9. Return Generic Error Messages
### 10. Implement CORS Properly

## Summary

Rate limiting is essential for API security. Implement it using token bucket or sliding window algorithms, apply stricter limits to sensitive endpoints like login, validate all input, use proper authentication/hashing, return appropriate HTTP status codes, and monitor for abuse patterns. Protect against brute force, credential stuffing, OTP enumeration, and DoS attacks through comprehensive rate limiting and input validation strategies.
