# Security Logging and Monitoring (OWASP A09)

## Definition

**Security Logging and Monitoring** (OWASP A09:2021) refers to the inadequate logging, monitoring, and alerting of security events. Without proper logging and monitoring, breaches go undetected, attack patterns are invisible, and incident response is delayed. Effective security logging captures authentication attempts, access control failures, input validation errors, and unusual activity, while proper monitoring detects patterns that indicate active attacks or compromises.

## What to Log

### 1. Authentication Events

```javascript
// ✅ Log authentication attempts
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const clientIP = req.ip;
  const userAgent = req.get('User-Agent');

  const user = db.users.findOne({ email });

  if (!user) {
    // ✅ Log failed login
    logger.warn('Failed login: user not found', {
      email,
      ip: clientIP,
      userAgent,
      timestamp: new Date()
    });

    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const isValid = bcrypt.compareSync(password, user.passwordHash);

  if (!isValid) {
    // ✅ Log failed login with password mismatch
    logger.warn('Failed login: invalid password', {
      userId: user.id,
      email,
      ip: clientIP,
      timestamp: new Date()
    });

    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // ✅ Log successful login
  logger.info('User logged in', {
    userId: user.id,
    email,
    ip: clientIP,
    userAgent,
    timestamp: new Date()
  });

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);

  res.json({ token });
});
```

### 2. Access Control Failures

```javascript
// ✅ Log access control violations
app.delete('/api/users/:id',
  authenticateToken,
  (req, res) => {
    // ✅ Check authorization
    if (req.user.id !== req.params.id && req.user.role !== 'admin') {
      // ✅ Log unauthorized access attempt
      logger.warn('Unauthorized access attempt', {
        userId: req.user.id,
        attemptedResourceId: req.params.id,
        action: 'DELETE',
        ip: req.ip,
        timestamp: new Date()
      });

      return res.status(403).json({ error: 'Forbidden' });
    }

    // ✅ Log successful privileged action
    logger.info('User deleted', {
      deletedUserId: req.params.id,
      deletedBy: req.user.id,
      ip: req.ip,
      timestamp: new Date()
    });

    db.users.delete(req.params.id);

    res.json({ success: true });
  }
);
```

### 3. Input Validation Failures

```javascript
// ✅ Log validation failures
app.post('/api/users', (req, res) => {
  const { email, password } = req.body;

  // Validate email
  if (!isValidEmail(email)) {
    // ✅ Log validation failure
    logger.warn('Invalid email input', {
      email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date()
    });

    return res.status(400).json({ error: 'Invalid email' });
  }

  // Validate password
  if (!isStrongPassword(password)) {
    // ✅ Log weak password attempt
    logger.warn('Weak password input', {
      ip: req.ip,
      timestamp: new Date()
      // DON'T log the actual password!
    });

    return res.status(400).json({ error: 'Password too weak' });
  }

  // Continue with valid input...
});
```

### 4. Unusual Activity

```javascript
// ✅ Log suspicious patterns
app.get('/api/users/:id/data', (req, res) => {
  const user = db.users.findById(req.params.id);
  const clientIP = req.ip;

  // ✅ Monitor rapid requests from same IP
  const recentRequests = getRecentRequests(clientIP);
  if (recentRequests > 100) {
    logger.warn('Rapid requests from IP', {
      ip: clientIP,
      requestCount: recentRequests,
      timeWindow: '1 minute',
      timestamp: new Date()
    });

    // Could rate limit this IP
  }

  // ✅ Monitor access patterns
  if (isAnomalousAccessPattern(req.user.id, req.params.id)) {
    logger.warn('Anomalous access pattern', {
      userId: req.user.id,
      accessedResourceId: req.params.id,
      pattern: 'Sequential ID access',
      timestamp: new Date()
    });
  }

  // ✅ Monitor large data exports
  if (req.query.export === 'true' && user.dataSize > 1000000) {
    logger.warn('Large data export', {
      userId: req.user.id,
      dataSize: user.dataSize,
      ip: req.ip,
      timestamp: new Date()
    });
  }

  res.json(user);
});
```

## What NOT to Log

### Sensitive Data Never to Log

```javascript
// ❌ NEVER log passwords
logger.info('User registered', {
  username: user.username,
  password: user.password  // ❌ NEVER!
});

// ❌ NEVER log credit cards
logger.info('Payment processed', {
  creditCard: req.body.creditCard  // ❌ NEVER!
});

// ❌ NEVER log API keys
logger.info('API authenticated', {
  apiKey: req.headers['x-api-key']  // ❌ NEVER!
});

// ❌ NEVER log tokens
logger.info('User authenticated', {
  token: req.headers.authorization  // ❌ NEVER!
});

// ❌ NEVER log PII
logger.info('User created', {
  ssn: user.ssn,                // ❌ NEVER!
  dateOfBirth: user.dob,        // ❌ NEVER!
  medicalRecords: user.health   // ❌ NEVER!
});

// ✅ SAFE: Log non-sensitive identifiers
logger.info('User created', {
  userId: user.id,          // ✅ SAFE
  email: user.email,        // ✅ Usually SAFE (consider privacy)
  username: user.username   // ✅ SAFE
});
```

## Log Injection Attacks

### Vulnerable: Logging User Input

```javascript
// ❌ VULNERABLE: Logging unsanitized user input
app.post('/api/search', (req, res) => {
  const query = req.body.query;

  // ❌ Directly logging user input
  logger.info(`User searched: ${query}`);

  // Attacker sends:
  // { "query": "\nINFO: User authenticated as admin" }

  // Log output shows:
  // INFO: User searched:
  // INFO: User authenticated as admin
  // (log appears to show legitimate authentication)

  // In centralized logging, attacker manipulates logs:
  // { "query": "{\"severity\": \"CRITICAL\", \"message\": \"System compromised\"}" }

  // Result: Fake critical alert in log aggregator

  const results = search(query);

  res.json(results);
});
```

### Secure: Sanitized Logging

```javascript
// ✅ SECURE: Sanitize log input
function sanitizeForLogging(input) {
  return input
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t')
    .replace(/"/g, '\\"')
    .substring(0, 1000);  // Limit length
}

app.post('/api/search', (req, res) => {
  const query = req.body.query;
  const sanitized = sanitizeForLogging(query);

  // ✅ Safely log
  logger.info('User search', {
    query: sanitized,  // Sanitized
    ip: req.ip,
    timestamp: new Date()
  });

  const results = search(query);

  res.json(results);
});

// ✅ Structured logging (better)
logger.info('User search', {
  query: query.substring(0, 1000),  // Limit
  ip: req.ip,
  timestamp: new Date(),
  type: 'search_event'
});

// Structured logging is harder to inject into
```

## Centralized Logging

### ELK Stack (Elasticsearch, Logstash, Kibana)

```javascript
// ✅ SECURE: Send logs to centralized system
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    // Console for development
    new winston.transports.Console(),

    // File for persistence
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),

    // Elasticsearch for centralized logging
    new (require('winston-elasticsearch'))({
      level: 'info',
      clientOpts: { node: 'http://localhost:9200' },
      index: 'logs',
      transformer: (logData) => {
        return {
          '@timestamp': new Date().toISOString(),
          message: logData.message,
          severity: logData.level,
          fields: logData.meta
        };
      }
    })
  ]
});

// Usage
logger.info('Security event', {
  userId: user.id,
  action: 'login_success',
  ip: req.ip
});
```

### Datadog Integration

```javascript
// ✅ SECURE: Datadog for monitoring
const { StatsD } = require('node-dogstatsd').v2;

const dogstatsd = new StatsD({
  host: 'localhost',
  port: 8125
});

app.post('/api/login', (req, res) => {
  const start = Date.now();

  try {
    // ... authentication logic ...

    // ✅ Log successful authentication
    dogstatsd.increment('auth.success', ['endpoint:login']);

    logger.info('User login', {
      userId: user.id,
      ip: req.ip,
      success: true
    });
  } catch (err) {
    // ✅ Log failed authentication
    dogstatsd.increment('auth.failure', ['endpoint:login']);

    logger.warn('Failed login', {
      email: req.body.email,
      ip: req.ip,
      error: 'Invalid credentials'
    });
  } finally {
    const duration = Date.now() - start;
    dogstatsd.histogram('auth.duration', duration);
  }
});
```

## Alerting on Suspicious Activity

```javascript
// ✅ SECURE: Set up alerts
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const clientIP = req.ip;

  // Check for brute force attempts
  const failedAttempts = getFailedAttempts(email, clientIP);

  if (failedAttempts > 5) {
    // ✅ Alert security team
    await alertSecurityTeam({
      type: 'BRUTE_FORCE_ATTEMPT',
      email,
      ip: clientIP,
      failedAttempts,
      timestamp: new Date()
    });

    // ❌ Block further attempts
    res.status(429).json({ error: 'Too many failed attempts' });
    return;
  }

  // ... continue with authentication ...
});

// ✅ Monitor for privilege escalation
app.put('/api/users/:id/role',
  authenticateToken,
  async (req, res) => {
    const { role } = req.body;

    // Check if user is escalating own privileges
    if (req.user.id === req.params.id && role === 'admin') {
      // ✅ Critical alert
      await alertSecurityTeam({
        type: 'PRIVILEGE_ESCALATION_ATTEMPT',
        userId: req.user.id,
        ip: req.ip,
        attemptedRole: role,
        timestamp: new Date(),
        severity: 'CRITICAL'
      });

      // Deny the request
      res.status(403).json({ error: 'Cannot self-escalate' });
      return;
    }

    // ... continue with role change ...
  }
);

// ✅ Monitor for unusual data access
function monitorDataAccess(userId, resourceId, dataSize) {
  const baseline = getAccessBaseline(userId);

  if (dataSize > baseline * 10) {
    // ✅ Alert: unusual amount of data accessed
    alertSecurityTeam({
      type: 'UNUSUAL_DATA_ACCESS',
      userId,
      resourceId,
      dataSize,
      baselineSize: baseline,
      timestamp: new Date(),
      severity: 'HIGH'
    });
  }
}
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: Inadequate logging and monitoring
const express = require('express');

const app = express();
app.use(express.json());

// ❌ No logging setup
// ❌ No monitoring
// ❌ No alerting

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  // ❌ No login attempt logging
  // ❌ No IP tracking
  // ❌ No failure tracking

  const user = db.users.findOne({ email });

  if (!user || user.password !== password) {
    // ❌ No failed attempt logged
    res.status(401).json({ error: 'Invalid credentials' });
    return;
  }

  // ❌ No successful login logged
  // ❌ No token issuance logged
  const token = jwt.sign({ userId: user.id });

  res.json({ token });
});

app.delete('/api/users/:id', (req, res) => {
  // ❌ No access control logging
  // ❌ No authorization failure logging
  // ❌ No deletion logging

  db.users.delete(req.params.id);

  res.json({ success: true });
});

app.get('/api/export-all-data', (req, res) => {
  // ❌ No export logging
  // ❌ No unusual activity detection
  // ❌ No large data access alerts

  const allData = db.getAllData();

  res.json(allData);
});

// Problems:
// - No way to detect attack patterns
// - Breach discovered weeks/months later
// - No audit trail for forensics
// - No incident response capability
```

## Secure Code Example

```javascript
// ✅ SECURE: Comprehensive logging and monitoring
const express = require('express');
const winston = require('winston');
const { StatsD } = require('node-dogstatsd').v2;

const app = express();
app.use(express.json());

// ✅ Setup logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'auth-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

// ✅ Setup metrics
const dogstatsd = new StatsD({
  host: 'localhost',
  port: 8125
});

// ✅ Security event logging
function logSecurityEvent(type, data) {
  logger.warn('Security Event', {
    type,
    timestamp: new Date(),
    ...data
  });

  // Also send metric
  dogstatsd.increment(`security.event.${type}`);
}

// ✅ Comprehensive login logging
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const clientIP = req.ip;
  const userAgent = req.get('User-Agent');
  const startTime = Date.now();

  try {
    // ✅ Check for brute force
    const recentFailures = await redis.get(`login_failures:${email}`);
    const ipAttempts = await redis.get(`login_attempts:${clientIP}`);

    if (recentFailures > 10 || ipAttempts > 50) {
      // ✅ Log and alert
      logSecurityEvent('BRUTE_FORCE_DETECTED', {
        email,
        ip: clientIP,
        recentFailures,
        ipAttempts
      });

      // Alert security team
      await sendSecurityAlert({
        type: 'BRUTE_FORCE',
        email,
        ip: clientIP,
        severity: 'HIGH'
      });

      res.status(429).json({ error: 'Too many attempts' });
      return;
    }

    // ✅ Authenticate
    const user = db.users.findOne({ email });

    if (!user) {
      // ✅ Log failed attempt
      logSecurityEvent('LOGIN_FAILED_UNKNOWN_USER', {
        email: email.substring(0, 10) + '***',  // Partial email
        ip: clientIP,
        userAgent: userAgent?.substring(0, 50)
      });

      // Increment failure counter
      await redis.incr(`login_failures:${email}`);
      await redis.expire(`login_failures:${email}`, 3600);
      await redis.incr(`login_attempts:${clientIP}`);

      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    if (!bcrypt.compareSync(password, user.passwordHash)) {
      // ✅ Log failed login
      logSecurityEvent('LOGIN_FAILED_INVALID_PASSWORD', {
        userId: user.id,
        ip: clientIP
      });

      // Increment counters
      await redis.incr(`login_failures:${email}`);

      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // ✅ Successful login
    logSecurityEvent('LOGIN_SUCCESS', {
      userId: user.id,
      ip: clientIP,
      duration: Date.now() - startTime
    });

    // ✅ Send metric
    dogstatsd.increment('auth.success');
    dogstatsd.histogram('auth.duration', Date.now() - startTime);

    // Clear failure counters
    await redis.del(`login_failures:${email}`);

    // ✅ Generate token with audit trail
    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // ✅ Log token issuance
    logger.info('Token issued', {
      userId: user.id,
      expiresIn: '1h',
      ip: clientIP
    });

    res.json({ token });

  } catch (err) {
    logSecurityEvent('LOGIN_ERROR', {
      error: err.message,
      ip: clientIP
    });

    res.status(500).json({ error: 'Internal error' });
  }
});

// ✅ Protected endpoint with logging
app.delete('/api/users/:id',
  authenticateToken,
  async (req, res) => {
    // ✅ Check authorization
    if (req.user.id !== req.params.id && req.user.role !== 'admin') {
      // ✅ Log unauthorized attempt
      logSecurityEvent('UNAUTHORIZED_ACCESS', {
        userId: req.user.id,
        attemptedResourceId: req.params.id,
        action: 'DELETE_USER',
        ip: req.ip
      });

      return res.status(403).json({ error: 'Forbidden' });
    }

    // ✅ Log deletion
    logSecurityEvent('USER_DELETED', {
      deletedUserId: req.params.id,
      deletedBy: req.user.id,
      ip: req.ip
    });

    db.users.delete(req.params.id);

    res.json({ success: true });
  }
);

// ✅ Large export with monitoring
app.get('/api/export-data', authenticateToken, async (req, res) => {
  const dataSize = await calculateExportSize(req.user.id);

  // ✅ Alert on large export
  if (dataSize > 100000000) {  // 100MB
    logSecurityEvent('LARGE_DATA_EXPORT', {
      userId: req.user.id,
      dataSize,
      ip: req.ip
    });

    await sendSecurityAlert({
      type: 'LARGE_EXPORT',
      userId: req.user.id,
      size: dataSize
    });
  }

  // ✅ Log export
  logger.info('Data exported', {
    userId: req.user.id,
    size: dataSize,
    timestamp: new Date()
  });

  const data = db.exportUserData(req.user.id);

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="export.json"');

  res.json(data);
});

// ✅ Periodic alert check
setInterval(async () => {
  // Check for unusual patterns
  const suspiciousIPs = await identifySuspiciousIPs();
  const failedLoginPatterns = await identifyFailedLoginPatterns();

  if (suspiciousIPs.length > 0) {
    await sendSecurityAlert({
      type: 'SUSPICIOUS_IPS',
      ips: suspiciousIPs
    });
  }

  if (failedLoginPatterns.length > 0) {
    await sendSecurityAlert({
      type: 'FAILED_LOGIN_PATTERNS',
      patterns: failedLoginPatterns
    });
  }
}, 60000);  // Check every minute

app.listen(3000);
```

## Mitigations and Best Practices

### 1. Log Security-Relevant Events
- Authentication attempts (success and failure)
- Access control failures
- Input validation failures
- Privilege escalation
- Data export/access

### 2. Never Log Sensitive Data
- Passwords
- API keys
- Tokens
- Credit cards
- Personal health information

### 3. Use Structured Logging
- JSON format for easy parsing
- Consistent fields
- Searchable and filterable

### 4. Centralize Logs
- Don't rely on single server logs
- Use centralized logging (ELK, Datadog)
- Encrypt logs in transit and at rest

### 5. Set Up Alerting
- Brute force attempts
- Privilege escalation
- Unusual access patterns
- Large data exports

### 6. Retention and Archival
- Keep logs for audit purposes
- Archive old logs securely
- Follow regulatory requirements

## Summary

Security logging and monitoring are critical for detecting breaches and responding to incidents. Log all security-relevant events (authentication, access control, validation failures, unusual activity) while avoiding logging sensitive data. Use centralized logging systems, implement alerting for suspicious patterns, and maintain audit trails for incident forensics and compliance.
