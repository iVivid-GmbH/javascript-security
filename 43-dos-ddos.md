# Denial of Service (DoS) and Distributed Denial of Service (DDoS)

## Definition

**Denial of Service (DoS)** is an attack where an attacker makes a service unavailable to legitimate users. **Distributed Denial of Service (DDoS)** involves multiple systems launching attacks simultaneously. In the JavaScript/Node.js context, vulnerabilities include ReDoS (Regular Expression Denial of Service), XML bombs, algorithmic attacks, application-level DoS, and resource exhaustion. These attacks consume server resources (CPU, memory, bandwidth) faster than the application can serve legitimate requests.

## Denial of Service Attack Types

### 1. Regular Expression Denial of Service (ReDoS)

```javascript
// ❌ VULNERABLE: Regex with catastrophic backtracking
const vulnerable_regex = /^(a+)+$/;

// Input: "aaaaaaaaaaaaaaaaaaaaab" (22 characters)
// Regex engine tries all possible backtracking paths
// Computational complexity: O(2^n) - exponential!

vulnerable_regex.test("aaaaaaaaaaaaaaaaaaaaab");
// Takes seconds or minutes to fail
// During this time, CPU usage at 100%

// Real vulnerability example
const pattern = /^([a-zA-Z0-9_]*)*$/;  // Catastrophic backtracking

app.post('/api/validate', (req, res) => {
  const input = req.body.text;

  // ❌ Attacker sends 1000-character string
  if (pattern.test(input)) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }

  // This one request ties up CPU for seconds
  // Application becomes unresponsive
});

// Attack:
// POST /api/validate
// { "text": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab" }
// Server hangs
```

### 2. Billion Laughs (XML Bomb)

```javascript
// ❌ VULNERABLE: Parsing untrusted XML without limits
const xml2js = require('xml2js');

app.post('/api/import', (req, res) => {
  const parser = new xml2js.Parser();

  // ❌ No limits on entity expansion
  parser.parseString(req.body.xmlData, (err, result) => {
    if (err) return res.status(400).json({ error: 'Invalid XML' });

    res.json(result);
  });
});

// Attacker sends XML bomb:
const bomb = `
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<lolz>&lol5;</lolz>
`;

// Parser expands entities exponentially
// Memory usage: 100MB+ for small XML
// Parser crash or extreme slowness
```

### 3. Large Payload Attack

```javascript
// ❌ VULNERABLE: No size limits on uploads
app.post('/api/upload', (req, res) => {
  // ❌ Express default bodyParser has no limit
  // ❌ Or limit set too high

  const data = req.body;

  // Attacker sends:
  // 1. Huge JSON: 100MB+ payload
  // 2. Server loads entire payload into memory
  // 3. Memory usage spikes
  // 4. Other requests fail (OOM killer)
  // 5. Application crashes

  res.json({ received: true });
});
```

### 4. Algorithmic Complexity Attack

```javascript
// ❌ VULNERABLE: O(n^2) or worse algorithm
app.get('/api/search', (req, res) => {
  const query = req.query.q;

  // ❌ O(n^2) search
  const results = [];
  for (let i = 0; i < database.length; i++) {
    for (let j = 0; j < query.length; j++) {
      if (database[i].name.includes(query[j])) {
        results.push(database[i]);
      }
    }
  }

  // Attacker searches for 1000-character query
  // Loop iterations: database.length * query.length
  // If database has 10,000 items:
  // 10,000 * 1,000 = 10 million iterations
  // Server timeout

  res.json(results);
});
```

### 5. Slow Loris Attack

```javascript
// ❌ VULNERABLE: Slow, incomplete requests
// Attacker sends HTTP request very slowly
// Opens 1000s of connections
// Each connection sends data in drips

GET /api/data HTTP/1.1
Host: example.com
[pause 30 seconds]
User-Agent: [pause 30 seconds]
[pause 30 seconds]
[complete the request after 5 minutes]

// Application holds connection open
// Waits for complete request
// Server runs out of file descriptors
// New legitimate requests rejected
```

## Frontend-Specific DoS Risks

### ReDoS in User Input

```javascript
// ❌ VULNERABLE: User regex pattern
app.post('/api/pattern', (req, res) => {
  // ❌ User-supplied regex
  const userPattern = req.body.pattern;
  const userData = req.body.data;

  try {
    // ❌ Never compile user-supplied regex!
    const regex = new RegExp(userPattern);
    const result = regex.test(userData);

    res.json({ matches: result });
  } catch (err) {
    res.status(400).json({ error: 'Invalid regex' });
  }
});

// Attacker sends:
// pattern: "^(a+)+$"
// data: "aaaaaaaaaaaaaaaaaaaaab"
// Server hangs
```

## Mitigation: Prevention Strategies

### 1. Rate Limiting

```javascript
// Limit requests per IP/user
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100  // 100 requests per window
});

app.use(limiter);

// Stricter for expensive endpoints
const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 5
});

app.post('/api/regex-test', strictLimiter, (req, res) => {
  // ...
});
```

### 2. Request Size Limits

```javascript
// Limit body size
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb' }));

// Or per route
app.post('/api/upload', express.json({ limit: '10kb' }), (req, res) => {
  // ...
});
```

### 3. Timeout Settings

```javascript
// Set request timeout
app.use((req, res, next) => {
  req.setTimeout(5000);  // 5 second timeout
  next();
});

// Or per route
app.post('/api/regex-test', (req, res) => {
  // Set timeout for this request
  const timeout = setTimeout(() => {
    res.status(408).json({ error: 'Request timeout' });
  }, 5000);

  performExpensiveOperation().then(result => {
    clearTimeout(timeout);
    res.json(result);
  });
});
```

### 4. Regular Expression Safety

```javascript
// ✅ SAFE: Use proven regex library
const RE2 = require('re2');

app.post('/api/regex-test', (req, res) => {
  try {
    // RE2 guarantees linear time complexity
    // No catastrophic backtracking possible
    const regex = new RE2(req.body.pattern);
    const result = regex.test(req.body.data);

    res.json({ matches: result });
  } catch (err) {
    res.status(400).json({ error: 'Invalid regex' });
  }
});

// ✅ SAFE: Use simple string methods
// Instead of complex regex:
const pattern = req.body.pattern;
const data = req.body.data;

if (data.includes(pattern)) {
  // Simple, no DoS risk
}
```

### 5. Safe XML Parsing

```javascript
// ✅ SAFE: Disable entity expansion
const xml2js = require('xml2js');

const parser = new xml2js.Parser({
  // Disable XXE (XML External Entity)
  xmlMode: true,
  // Limit entity expansion
  maxDepth: 10,
  maxNodes: 1000
});

app.post('/api/import', (req, res) => {
  parser.parseString(req.body.xmlData, (err, result) => {
    if (err) return res.status(400).json({ error: 'Invalid XML' });

    res.json(result);
  });
});
```

### 6. Async Operation Limits

```javascript
// ✅ SAFE: Limit concurrent operations
const pLimit = require('p-limit');

const limit = pLimit(10);  // Max 10 concurrent operations

app.get('/api/process', async (req, res) => {
  const items = req.body.items;

  // Only process max 100 items
  if (items.length > 100) {
    return res.status(400).json({ error: 'Too many items' });
  }

  // Limit concurrency
  const promises = items.map(item =>
    limit(() => processItem(item))
  );

  const results = await Promise.all(promises);

  res.json(results);
});
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: Multiple DoS attack vectors
const express = require('express');
const xml2js = require('xml2js');

const app = express();

// ❌ No size limits
app.use(express.json());
app.use(express.text());

// ❌ No rate limiting

// ❌ Vulnerability 1: ReDoS
app.post('/api/validate', (req, res) => {
  const dangerous = /^(a+)+$/;  // Catastrophic backtracking

  // Attacker sends: "aaaaaaaaaaaaaaaaaaaaab"
  if (dangerous.test(req.body.input)) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
  // Server hangs
});

// ❌ Vulnerability 2: XML bomb
app.post('/api/import', (req, res) => {
  const parser = new xml2js.Parser();

  // No entity expansion limits
  parser.parseString(req.body.xml, (err, result) => {
    if (err) return res.status(400).json({ error: err.message });

    res.json(result);
  });
});

// ❌ Vulnerability 3: Algorithmic DoS
app.get('/api/search', (req, res) => {
  const query = req.query.q;
  const results = [];

  // O(n^2) algorithm
  for (let i = 0; i < 10000; i++) {
    for (let j = 0; j < query.length; j++) {
      if (database[i].name[j] === query[j]) {
        results.push(database[i]);
      }
    }
  }

  res.json(results);
});

// ❌ Vulnerability 4: User-supplied regex
app.post('/api/filter', (req, res) => {
  const userRegex = new RegExp(req.body.pattern);

  // Attacker provides malicious regex
  if (userRegex.test(req.body.data)) {
    res.json({ match: true });
  }
});

// ❌ Vulnerability 5: Slow requests
// No timeout settings
// Connection held open indefinitely

app.listen(3000);
```

## Secure Code Example

```javascript
// ✅ SECURE: Protected against DoS attacks
const express = require('express');
const rateLimit = require('express-rate-limit');
const xml2js = require('xml2js');
const RE2 = require('re2');

const app = express();

// ✅ Size limits
app.use(express.json({ limit: '1mb' }));
app.use(express.text({ limit: '1mb' }));

// ✅ Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use(limiter);

// ✅ Stricter rate limit for expensive operations
const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10
});

// ✅ Security 1: Safe regex with RE2
app.post('/api/validate',
  strictLimiter,
  express.json({ limit: '10kb' }),

  (req, res) => {
    try {
      // ✅ RE2 prevents catastrophic backtracking
      const regex = new RE2(req.body.pattern, 'i');

      // ✅ Set timeout
      const timeout = setTimeout(() => {
        res.status(408).json({ error: 'Request timeout' });
      }, 1000);

      const result = regex.test(req.body.input);

      clearTimeout(timeout);

      res.json({ valid: result });
    } catch (err) {
      res.status(400).json({ error: 'Invalid regex' });
    }
  }
);

// ✅ Security 2: Safe XML parsing
const xmlParser = new xml2js.Parser({
  // Prevent XXE
  strict: true,
  // Limit expansion
  maxDepth: 10,
  maxNodes: 1000
});

app.post('/api/import',
  strictLimiter,
  express.text({ limit: '5mb', type: 'application/xml' }),

  (req, res) => {
    xmlParser.parseString(req.body, (err, result) => {
      if (err) {
        return res.status(400).json({ error: 'Invalid XML' });
      }

      res.json(result);
    });
  }
);

// ✅ Security 3: Safe search with limits
app.get('/api/search', (req, res) => {
  const query = req.query.q;

  // ✅ Limit query length
  if (!query || query.length > 100) {
    return res.status(400).json({ error: 'Invalid query' });
  }

  // ✅ Use efficient algorithm
  const results = database.filter(item =>
    item.name.includes(query)  // O(n) instead of O(n^2)
  );

  // ✅ Limit results
  const limitedResults = results.slice(0, 100);

  res.json(limitedResults);
});

// ✅ Security 4: Strict pattern validation
app.post('/api/filter',
  strictLimiter,
  (req, res) => {
    const { pattern, data } = req.body;

    // ✅ Validate pattern
    if (!pattern || pattern.length > 50) {
      return res.status(400).json({ error: 'Invalid pattern' });
    }

    // ✅ Use safe regex (RE2)
    try {
      const regex = new RE2(pattern);
      const result = regex.test(data);

      res.json({ match: result });
    } catch (err) {
      res.status(400).json({ error: 'Invalid pattern' });
    }
  }
);

// ✅ Security 5: Request timeout
app.use((req, res, next) => {
  req.setTimeout(10000);  // 10 second timeout
  next();
});

// ✅ Security 6: Prevent slow loris
const slowDown = require('express-slow-down');

const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 100,
  delayMs: (hits) => hits * 100
});

app.use(speedLimiter);

app.listen(3000);
```

## Mitigation Checklist

```
✓ Implement rate limiting
✓ Set request/response size limits
✓ Set request timeout
✓ Disable unnecessary features
✓ Use safe regex libraries (RE2)
✓ Validate and sanitize input
✓ Implement async operation limits
✓ Monitor resource usage
✓ Use CDN with DDoS protection
✓ Implement request queuing
✓ Scale infrastructure (auto-scaling)
✓ Have incident response plan
```

## Summary

Prevent Denial of Service attacks through rate limiting, request size limits, timeout settings, safe regex libraries (RE2), proper XML configuration, limiting algorithmic complexity, and monitoring resource usage. At the infrastructure level, use CDN services with DDoS protection, implement load balancing, and set up auto-scaling to handle traffic spikes. Always validate and limit user input, especially for computationally expensive operations.
