# Server-Side Request Forgery (SSRF) in JavaScript/Node.js

## Definition

Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to trick a server into making HTTP requests to unintended destinations. An attacker can control where the server makes requests, potentially accessing internal resources, services, APIs, cloud metadata endpoints, or bypassing firewalls. SSRF occurs when user-controlled URLs or hostnames are used in server-side requests without proper validation.

## How SSRF Works

SSRF vulnerabilities occur when a server makes HTTP requests based on user input without proper validation. The server's requests have privileges that the attacker may not have directly, allowing them to:

1. **Access internal services** - Services only reachable from within the network
2. **Query cloud metadata** - AWS, GCP, Azure metadata endpoints
3. **Port scanning** - Discover open ports on internal network
4. **Access restricted APIs** - Services behind firewalls
5. **Exfiltrate data** - Retrieve sensitive information

### Attack Vectors

**Common SSRF vectors:**

1. **Webhook delivery** - User specifies URL for webhook callbacks
2. **Image processing** - User provides image URL to fetch and process
3. **PDF generation** - User provides URL to convert to PDF
4. **Link preview** - Website fetches open graph data from URL
5. **File download** - User specifies URL to download from
6. **API proxy** - Server proxies requests to user-specified URL

## Impact: Cloud Metadata Endpoint

Cloud providers expose metadata through internal HTTP endpoints:

### AWS Metadata Endpoint

```
http://169.254.169.254/latest/meta-data/
```

This endpoint is accessible only from EC2 instances and contains:
- IAM credentials (access key, secret key, session token)
- Instance metadata (ID, availability zone, security groups)
- User data scripts
- Network information

### Example AWS SSRF Attack

An attacker discovers the server can fetch URLs:

```
Normal usage:
GET /fetch?url=https://example.com

Attacker's request:
GET /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

Server response contains:
{
  "Code" : "Success",
  "LastUpdated" : "2023-01-15T12:34:56Z",
  "Type" : "AWS4",
  "AccessKeyId" : "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey" : "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token" : "AQoDYXdzEJr...",
  "Expiration" : "2023-01-15T18:34:56Z"
}

Now attacker has AWS credentials and can:
- Access S3 buckets
- Launch EC2 instances
- Modify security groups
- Access databases
```

### GCP Metadata Endpoint

```
http://metadata.google.internal/computeMetadata/v1/

Requires header:
Metadata-Flavor: Google

Contains:
- Service account credentials
- SSH keys
- Project ID
- Zone information
```

### Azure Metadata Endpoint

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01

Requires header:
Metadata:true

Contains:
- VM identity tokens
- Managed identity credentials
- User data
```

## Blind SSRF

Blind SSRF occurs when the server doesn't return the response, but still makes the request. This is still dangerous because:

1. **Port scanning** - Attacker can infer open ports from response times
2. **Service detection** - Specific error messages reveal running services
3. **Data exfiltration** - Data can be sent to attacker's server via URL parameters
4. **Resource exhaustion** - Attacker can cause DoS by requesting large files

## URL Validation Pitfalls

### Hostname Allowlist Bypass

```javascript
// VULNERABLE: Incomplete allowlist validation
const allowedHosts = ['api.example.com', 'cdn.example.com'];

function isAllowedHost(url) {
  const hostname = new URL(url).hostname;
  return allowedHosts.includes(hostname);
}

// Attack 1: DNS rebinding
// DNS entry: api.example.com -> first query returns 127.0.0.1
//                              -> second query returns attacker.com
// Server validates hostname (passes), then DNS resolves to attacker

// Attack 2: IP address bypasses hostname check
isAllowedHost('http://127.0.0.1:8080')  // Returns false (good)
isAllowedHost('http://2130706433')       // 127.0.0.1 in decimal format - may bypass!

// Attack 3: IPv6 loopback
isAllowedHost('http://[::1]:8080')       // IPv6 loopback - may bypass!

// Attack 4: Localhost variations
isAllowedHost('http://localhost:8080')   // Not in allowlist - bypassed!
isAllowedHost('http://127.0.0.1:8080')   // Not in allowlist - bypassed!
```

### DNS Rebinding

DNS rebinding is a sophisticated SSRF attack:

```
1. Attacker controls attacker.com domain
2. Attacker's site makes request to attacker.com
3. DNS resolution #1: attacker.com -> 93.184.216.34 (attacker's IP)
   - Server validates this is allowed
4. Between validation and actual request, attacker changes DNS
5. DNS resolution #2: attacker.com -> 192.168.1.1 (internal IP)
6. Server makes request to internal IP thinking it's attacker.com
7. Attacker gains access to internal resources
```

## Node.js Fetch-Based Vulnerable Example

```javascript
const express = require('express');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// VULNERABLE: No URL validation
app.post('/vulnerable/fetch-url', async (req, res) => {
  const { url } = req.body;

  try {
    // VULNERABLE: User-controlled URL
    const response = await fetch(url);
    const data = await response.text();
    res.json({ content: data });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABLE: Webhook delivery
app.post('/vulnerable/webhook', async (req, res) => {
  const { webhookUrl, data } = req.body;

  try {
    // VULNERABLE: Sending data to attacker-controlled URL
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABLE: Image processing
app.post('/vulnerable/process-image', async (req, res) => {
  const { imageUrl } = req.body;

  try {
    // VULNERABLE: Fetching image from user-specified URL
    const response = await fetch(imageUrl);
    const imageBuffer = await response.buffer();

    // Process image (resize, convert, etc.)
    // ... processing code ...

    res.type('image/jpeg').send(imageBuffer);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VULNERABLE: Open redirect via SSRF
app.post('/vulnerable/fetch-and-redirect', async (req, res) => {
  const { targetUrl } = req.body;

  try {
    const response = await fetch(targetUrl);
    const data = await response.text();
    res.send(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000);

// Attack examples:
// 1. POST /vulnerable/fetch-url with {"url": "http://169.254.169.254/latest/meta-data/iam/"}
// 2. POST /vulnerable/webhook with {"webhookUrl": "http://localhost:8080/admin", "data": {...}}
// 3. POST /vulnerable/process-image with {"imageUrl": "http://127.0.0.1:3000/api/secret"}
// 4. POST /vulnerable/fetch-and-redirect with {"targetUrl": "http://metadata.google.internal/"}
```

## Best Practices and Secure Implementation

### 1. URL Validation - Whitelist Approach

```javascript
const express = require('express');
const { URL } = require('url');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// Define allowed domains
const ALLOWED_DOMAINS = [
  'api.example.com',
  'cdn.example.com',
  'trusted-partner.com'
];

// Strict URL validation
function validateUrl(urlString) {
  try {
    const url = new URL(urlString);

    // 1. Check protocol
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('Invalid protocol');
    }

    // 2. Check hostname is allowed
    if (!ALLOWED_DOMAINS.includes(url.hostname)) {
      throw new Error('Hostname not allowed');
    }

    // 3. Resolve hostname to check for local IPs
    // This is a simplified check - in production use `dns.promises.resolve()`
    const blockedHosts = [
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      '::1',
      '169.254.169.254', // AWS metadata
      'metadata.google.internal', // GCP metadata
      '169.254.170.2', // Azure metadata
    ];

    if (blockedHosts.includes(url.hostname)) {
      throw new Error('Local/metadata address blocked');
    }

    return url;
  } catch (error) {
    throw new Error(`Invalid URL: ${error.message}`);
  }
}

// SECURE: Fetch with validation
app.post('/secure/fetch-url', async (req, res) => {
  const { url } = req.body;

  try {
    // Validate URL
    const validUrl = validateUrl(url);

    // Fetch with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(validUrl.toString(), {
      signal: controller.signal,
      timeout: 5000
    });

    clearTimeout(timeout);

    // Limit response size
    const MAX_SIZE = 1024 * 100; // 100KB
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_SIZE) {
      return res.status(400).json({ error: 'Response too large' });
    }

    const data = await response.text();
    res.json({ content: data });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

### 2. DNS Resolution Validation

```javascript
const express = require('express');
const { URL } = require('url');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// Blocked IP ranges (private networks)
const BLOCKED_IP_RANGES = [
  /^127\./, // 127.0.0.0/8 - Loopback
  /^10\./, // 10.0.0.0/8 - Private
  /^172\.(1[6-9]|2[0-9]|3[01])\./, // 172.16.0.0/12 - Private
  /^192\.168\./, // 192.168.0.0/16 - Private
  /^169\.254\./, // 169.254.0.0/16 - Link-local
  /^0\./, // 0.0.0.0/8
  /^255\.255\.255\.255/, // Broadcast
  /^::1/, // IPv6 loopback
  /^fc[0-9a-f]{2}:/i, // IPv6 private
  /^fe[89a-b][0-9a-f]:/i, // IPv6 link-local
];

function isBlockedIP(ip) {
  return BLOCKED_IP_RANGES.some(range => range.test(ip));
}

async function validateAndResolveUrl(urlString) {
  const url = new URL(urlString);

  // Check protocol
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Invalid protocol');
  }

  // Resolve hostname to IP
  try {
    const addresses = await dns.resolve4(url.hostname);

    // Check all resolved IPs are not blocked
    for (const ip of addresses) {
      if (isBlockedIP(ip)) {
        throw new Error(`Resolved to blocked IP: ${ip}`);
      }
    }

    return url;
  } catch (error) {
    throw new Error(`DNS resolution failed: ${error.message}`);
  }
}

// SECURE: Fetch with DNS validation
app.post('/secure/fetch-with-dns-check', async (req, res) => {
  const { url } = req.body;

  try {
    // Validate and resolve URL
    const validUrl = await validateAndResolveUrl(url);

    // Fetch
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(validUrl.toString(), {
      signal: controller.signal,
      timeout: 5000
    });

    clearTimeout(timeout);

    const data = await response.text();
    res.json({ content: data });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

### 3. Request Timeout and Size Limits

```javascript
const express = require('express');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// SECURE: Fetch with timeout and size limits
async function secureFetch(url) {
  const MAX_TIMEOUT = 5000; // 5 seconds
  const MAX_RESPONSE_SIZE = 1024 * 100; // 100KB

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), MAX_TIMEOUT);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      timeout: MAX_TIMEOUT
    });

    // Check content-length header
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_RESPONSE_SIZE) {
      throw new Error('Response size exceeds limit');
    }

    // Stream response and limit size
    let size = 0;
    let chunks = [];

    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > MAX_RESPONSE_SIZE) {
        throw new Error('Response size exceeds limit');
      }
      chunks.push(chunk);
    }

    return Buffer.concat(chunks).toString();
  } finally {
    clearTimeout(timeoutId);
  }
}

app.post('/secure/fetch', async (req, res) => {
  const { url } = req.body;

  try {
    const data = await secureFetch(url);
    res.json({ content: data });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

### 4. Webhook with URL Validation

```javascript
const express = require('express');
const { URL } = require('url');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// Allowed webhook domains
const ALLOWED_WEBHOOK_DOMAINS = [
  'webhook.example.com',
  'hooks.slack.com',
  'webhooks.github.com'
];

function validateWebhookUrl(urlString) {
  try {
    const url = new URL(urlString);

    // Must be HTTPS for webhooks
    if (url.protocol !== 'https:') {
      throw new Error('Webhooks must use HTTPS');
    }

    // Check domain is allowed
    if (!ALLOWED_WEBHOOK_DOMAINS.includes(url.hostname)) {
      throw new Error('Webhook domain not allowed');
    }

    // Block internal IPs
    const blockedPatterns = [
      /^127\./, /^10\./, /^172\./, /^192\.168\./, /^169\.254\./
    ];
    if (blockedPatterns.some(p => p.test(url.hostname))) {
      throw new Error('Internal addresses not allowed');
    }

    return url;
  } catch (error) {
    throw new Error(`Invalid webhook URL: ${error.message}`);
  }
}

// SECURE: Webhook delivery
app.post('/secure/webhook', async (req, res) => {
  const { webhookUrl, data, eventType } = req.body;

  try {
    // Validate webhook URL
    const url = validateWebhookUrl(webhookUrl);

    // Log webhook delivery attempt
    console.log(`Webhook delivery: ${eventType} to ${url.hostname}`);

    // Send webhook with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'MyApp-Webhook/1.0'
      },
      body: JSON.stringify({
        event: eventType,
        timestamp: new Date().toISOString(),
        data: data
      }),
      signal: controller.signal,
      timeout: 10000
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`Webhook returned status ${response.status}`);
    }

    res.json({ success: true, status: response.status });
  } catch (error) {
    console.error(`Webhook delivery failed: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

### 5. Image Processing with Validation

```javascript
const express = require('express');
const { URL } = require('url');
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// Allowed image domains
const ALLOWED_IMAGE_DOMAINS = [
  'images.example.com',
  'cdn.example.com',
  'imgur.com'
];

// MIME types allowed for images
const ALLOWED_IMAGE_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp'
];

async function validateAndFetchImage(urlString) {
  const url = new URL(urlString);

  // Validate protocol
  if (url.protocol !== 'https:') {
    throw new Error('Image URLs must use HTTPS');
  }

  // Validate domain
  if (!ALLOWED_IMAGE_DOMAINS.includes(url.hostname)) {
    throw new Error('Image domain not allowed');
  }

  // Fetch image
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(url.toString(), {
      signal: controller.signal,
      timeout: 10000
    });

    // Validate content-type
    const contentType = response.headers.get('content-type');
    if (!ALLOWED_IMAGE_TYPES.some(t => contentType.includes(t))) {
      throw new Error('Invalid image type');
    }

    // Validate content-length
    const contentLength = response.headers.get('content-length');
    const MAX_IMAGE_SIZE = 1024 * 1024 * 5; // 5MB
    if (contentLength && parseInt(contentLength) > MAX_IMAGE_SIZE) {
      throw new Error('Image too large');
    }

    // Stream with size limit
    let size = 0;
    let chunks = [];

    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > MAX_IMAGE_SIZE) {
        throw new Error('Image exceeds size limit');
      }
      chunks.push(chunk);
    }

    return Buffer.concat(chunks);
  } finally {
    clearTimeout(timeout);
  }
}

// SECURE: Image processing endpoint
app.post('/secure/process-image', async (req, res) => {
  const { imageUrl } = req.body;

  try {
    const imageBuffer = await validateAndFetchImage(imageUrl);

    // Process image (resize, convert, etc.)
    // Using a library like sharp
    // const processed = await sharp(imageBuffer).resize(800, 600).toBuffer();

    res.type('image/jpeg').send(imageBuffer);
  } catch (error) {
    console.error(`Image processing error: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

## Complete Secure Implementation

```javascript
const express = require('express');
const { URL } = require('url');
const dns = require('dns').promises;
const fetch = require('node-fetch');
const app = express();

app.use(express.json());

// Configuration
const ALLOWED_DOMAINS = [
  'api.example.com',
  'cdn.example.com',
  'trusted-partner.com'
];

const BLOCKED_IP_RANGES = [
  /^127\./, /^10\./, /^172\.(1[6-9]|2[0-9]|3[01])\./, /^192\.168\./,
  /^169\.254\./, /^0\./, /^255\.255\.255\.255/, /^::1/, /^fc[0-9a-f]{2}:/i
];

// Validation functions
function isBlockedIP(ip) {
  return BLOCKED_IP_RANGES.some(range => range.test(ip));
}

async function validateUrl(urlString) {
  const url = new URL(urlString);

  // Protocol validation
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Invalid protocol');
  }

  // Domain whitelist
  if (!ALLOWED_DOMAINS.includes(url.hostname)) {
    throw new Error('Domain not allowed');
  }

  // DNS resolution check
  try {
    const addresses = await dns.resolve4(url.hostname);
    for (const ip of addresses) {
      if (isBlockedIP(ip)) {
        throw new Error(`Resolved to blocked IP: ${ip}`);
      }
    }
  } catch (error) {
    throw new Error(`DNS resolution failed: ${error.message}`);
  }

  return url;
}

// Secure fetch with all protections
async function secureFetch(url) {
  const MAX_TIMEOUT = 5000;
  const MAX_SIZE = 1024 * 100; // 100KB

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), MAX_TIMEOUT);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      timeout: MAX_TIMEOUT
    });

    // Check size
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_SIZE) {
      throw new Error('Response too large');
    }

    // Stream with limit
    let size = 0;
    let chunks = [];
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > MAX_SIZE) throw new Error('Size exceeded');
      chunks.push(chunk);
    }

    return Buffer.concat(chunks).toString();
  } finally {
    clearTimeout(timeoutId);
  }
}

// Endpoint
app.post('/fetch', async (req, res) => {
  const { url } = req.body;

  try {
    const validUrl = await validateUrl(url);
    const data = await secureFetch(validUrl.toString());
    res.json({ content: data });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

## Best Practices Summary

1. **Use allowlist, not blocklist** - Explicitly allow domains
2. **Validate protocol** - Only allow http/https
3. **Resolve DNS and check IPs** - Prevent TOCTOU attacks
4. **Block internal IPs** - 127.0.0.1, 192.168.x.x, 10.x.x.x, 169.254.x.x
5. **Block metadata endpoints** - 169.254.169.254, metadata.google.internal
6. **Implement timeouts** - Prevent long-running requests
7. **Limit response size** - Prevent resource exhaustion
8. **Use HTTPS only** - For sensitive operations
9. **Monitor requests** - Log all SSRF attempts
10. **Regular security audits** - Test for SSRF vulnerabilities

## References

- OWASP SSRF: https://owasp.org/www-community/attacks/Server-Side_Request_Forgery
- CWE-918: Server-Side Request Forgery (SSRF): https://cwe.mitre.org/data/definitions/918.html
- AWS EC2 Metadata: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
- DNS Rebinding: https://en.wikipedia.org/wiki/DNS_rebinding
