# Subresource Integrity (SRI)

## Definition

**Subresource Integrity (SRI)** is a security feature that allows you to provide a cryptographic hash of an external resource (script or stylesheet) in the integrity attribute of the HTML tag. When a browser loads the resource, it verifies that the downloaded content matches the provided hash. If the content has been modified or corrupted (either maliciously or accidentally), the browser rejects the resource and does not execute it. SRI is a powerful defense against compromised CDNs, man-in-the-middle attacks, and supply chain attacks targeting third-party scripts and stylesheets.

## How SRI Works

### Step-by-Step Process

1. **Developer adds integrity attribute** with cryptographic hash
2. **Browser downloads** resource from CDN/server
3. **Browser computes hash** of the downloaded content
4. **Browser compares** computed hash with integrity attribute
5. **If match:** Browser uses the resource
6. **If mismatch:** Browser rejects and doesn't execute

### Hash Algorithms Supported

```
sha256  → 256-bit hash (32 bytes)
sha384  → 384-bit hash (48 bytes)
sha512  → 512-bit hash (64 bytes)
```

**Recommendation:** Use `sha384` as default (good security/performance balance)

### Integrity Attribute Format

```
integrity="[algorithm]-[base64-encoded-hash]"
integrity="sha384-ABC123DEF456"
```

Multiple hashes can be provided (fallback support):

```
integrity="sha384-ABC123DEF456 sha512-XYZ789GHI012"
```

Browser will accept if ANY hash matches (useful during hash algorithm transitions).

## Generating SRI Hashes

### Using Online Tool

```
https://www.srihash.org/

1. Paste CDN URL
2. Select hash algorithm (sha384 recommended)
3. Copy the generated integrity attribute
```

### Using npm Command

```bash
npm install -g sri

# Generate hash for any URL
sri https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js

# Output:
# sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG
```

### Using OpenSSL

```bash
# Download file and generate hash
curl -o library.js https://cdn.example.com/library.js

# Create hash
openssl dgst -sha384 -binary library.js | openssl enc -base64 -A

# Output: [base64-encoded-hash]

# Full integrity attribute
openssl dgst -sha384 -binary library.js | base64 | sed 's/^/sha384-/'
```

### Using Node.js

```javascript
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

async function generateSRI(url, algorithm = 'sha384') {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      const hash = crypto.createHash(algorithm);

      response.on('data', (chunk) => {
        hash.update(chunk);
      });

      response.on('end', () => {
        const digest = hash.digest('base64');
        resolve(`${algorithm}-${digest}`);
      });

      response.on('error', reject);
    });
  });
}

// Usage
generateSRI('https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js')
  .then(integrity => {
    console.log(`integrity="${integrity}"`);
  });
```

### Using npm script

```bash
# For local files
node -e "
const crypto = require('crypto');
const fs = require('fs');
const file = process.argv[1];
const data = fs.readFileSync(file);
const hash = crypto.createHash('sha384').update(data).digest('base64');
console.log(\`sha384-\${hash}\`);
" path/to/file.js
```

## Applying SRI to `<script>` Tags

### Basic SRI on External Script

```html
<!-- VULNERABLE: No integrity check -->
<script src="https://cdn.example.com/library.js"></script>

<!-- SECURE: With SRI -->
<script
  src="https://cdn.example.com/library.js"
  integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG"
  crossorigin="anonymous">
</script>
```

### Multiple Scripts with SRI

```html
<!DOCTYPE html>
<html>
<head>
  <!-- jQuery -->
  <script
    src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
    integrity="sha384-tsQFqpEReu7ZLhBV2VZlAu7zcOV+rXbYlF2cqB8txI/8aZajjp4Bqd+V6D5IgvKT"
    crossorigin="anonymous">
  </script>

  <!-- Bootstrap JS -->
  <script
    src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"
    integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP40uv4N1iDfW9oVHg6V8j+EvqvN8s"
    crossorigin="anonymous">
  </script>

  <!-- Custom analytics library -->
  <script
    src="/js/analytics.js"
    integrity="sha384-XYZ789DEF123GHI456JKL789MNO012PQR345STU678VWX901YZA234BCD567EFG">
  </script>
</head>
<body>
  <!-- Content -->
</body>
</html>
```

### SRI with Module Scripts

```html
<!-- SRI for ES modules -->
<script type="module"
  src="https://cdn.example.com/module.mjs"
  integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG">
</script>
```

## Applying SRI to `<link>` Tags

### External Stylesheets with SRI

```html
<!-- VULNERABLE: No integrity check -->
<link rel="stylesheet" href="https://cdn.example.com/style.css">

<!-- SECURE: With SRI -->
<link
  rel="stylesheet"
  href="https://cdn.example.com/style.css"
  integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG"
  crossorigin="anonymous">
```

### Multiple Stylesheets with SRI

```html
<head>
  <!-- Bootstrap CSS -->
  <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
    integrity="sha384-1BmE4kWBq78iYhFldwKuhfstenjYMLA+hwg1ROUciok7aJ0sx1/QbE0sB/gSvuuNLv3"
    crossorigin="anonymous">

  <!-- Font Awesome -->
  <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.0.0/css/all.min.css"
    integrity="sha384-3ercQjPL5rhdGHC6xqF2onLsQkB2y5W5j8q4y5Z5oUlZ0Y0000000000000000000000"
    crossorigin="anonymous">

  <!-- Custom stylesheet -->
  <link
    rel="stylesheet"
    href="/css/custom.css"
    integrity="sha384-DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG123ABC">
</head>
```

## The Crossorigin Attribute

The `crossorigin` attribute is **required** for SRI to work with cross-origin resources.

### Why Crossorigin is Needed

Without `crossorigin="anonymous"`:
- Browser applies same-origin policy
- Doesn't reveal detailed error messages
- SRI verification may not trigger properly

### Crossorigin Values

```html
<!-- Allow cross-origin request without credentials -->
<script
  src="https://cdn.example.com/script.js"
  integrity="sha384-ABC123..."
  crossorigin="anonymous">
</script>

<!-- Allow cross-origin request WITH credentials (cookies, auth) -->
<script
  src="https://cdn.example.com/script.js"
  integrity="sha384-ABC123..."
  crossorigin="use-credentials">
</script>
```

### Complete Example

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <!-- Bootstrap CSS with SRI and crossorigin -->
  <link
    rel="stylesheet"
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css"
    integrity="sha384-1BmE4kWBq78iYhFldwKuhfstenjYMLA+hwg1ROUciok7aJ0sx1/QbE0sB/gSvuuNLv3"
    crossorigin="anonymous">
</head>
<body>
  <div class="container">
    <h1>Secure Application with SRI</h1>
  </div>

  <!-- jQuery with SRI and crossorigin -->
  <script
    src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
    integrity="sha384-tsQFqpEReu7ZLhBV2VZlAu7zcOV+rXbYlF2cqB8txI/8aZajjp4Bqd+V6D5IgvKT"
    crossorigin="anonymous">
  </script>

  <!-- Bootstrap JS with SRI and crossorigin -->
  <script
    src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"
    integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP40uv4N1iDfW9oVHg6V8j+EvqvN8s"
    crossorigin="anonymous">
  </script>

  <!-- Custom script without crossorigin needed (same-origin) -->
  <script
    src="/js/app.js"
    integrity="sha384-XYZ789DEF123GHI456JKL789MNO012PQR345STU678VWX901YZA234BCD567EFG">
  </script>
</body>
</html>
```

## How the Browser Verifies

### Verification Algorithm

```
1. Parse HTML and identify resources with integrity attribute
2. Download resource from specified URL
3. Compute hash of downloaded content using specified algorithm
4. Compare computed hash with integrity attribute value
5. If hashes match:
   - Continue loading/executing resource
   - Fire load event
6. If hashes don't match:
   - Stop loading
   - Fire error event
   - Do NOT execute resource
   - Log security warning to console
```

### Browser Console Messages

**When SRI passes:**
```javascript
// No console warnings, resource loads normally
console.log('Resource loaded successfully');
```

**When SRI fails:**
```
Refused to apply style from 'https://cdn.example.com/style.css'
because its integrity doesn't match:
Expected sha384-ABC123...
Got sha384-XYZ789...
```

```
Refused to load the script 'https://cdn.example.com/script.js'
because the following Content Security Policy directive is violated:
script-src sha384-ABC123... 'self' https://cdn.example.com
```

## Limitations of SRI

### 1. Dynamic Content

```javascript
// ❌ SRI doesn't work for dynamic URLs
const CDN = 'https://cdn.example.com';
const version = '1.2.3';
const url = `${CDN}/lib-${version}.js`;

// Can't hardcode integrity for dynamic URLs
document.write(`<script src="${url}"></script>`);

// ✅ Alternative: Use Service Workers to verify
// ✅ Alternative: Verify on server-side before serving
```

### 2. First-Party Resources

```javascript
// ❌ SRI for same-origin resources is less critical
// (Server has full control over content)
<script src="/js/app.js" integrity="sha384-..."></script>

// ✅ Better: Ensure server itself is secure
// ✅ Benefit: Detects accidental corruption during download
```

### 3. API Responses

```javascript
// ❌ SRI doesn't apply to fetch API responses
fetch('https://api.example.com/data')
  .then(r => r.json())
  .then(data => {
    // No integrity verification for API data
  });

// ✅ Alternative: Verify response signature on client
// ✅ Alternative: Use signed/authenticated APIs (JWT, signatures)
```

### 4. Hash Algorithm Transitions

```javascript
// SRI uses specific algorithms
// If hash algorithm becomes weak, need to update all attributes
// Browser supports multiple hashes, but still requires update

// ✅ Keep track of hash algorithm strength
// ✅ Plan for SHA-256 deprecation (if needed)
```

## Combining SRI with CSP

### Content Security Policy + SRI

```html
<head>
  <!-- CSP restricts what scripts can load -->
  <meta http-equiv="Content-Security-Policy"
    content="script-src 'self' https://cdn.jsdelivr.net https://cdn.example.com sha384-ABC123...">

  <!-- SRI ensures the script hasn't been tampered with -->
  <script
    src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
    integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG"
    crossorigin="anonymous">
  </script>
</head>
```

### Defense-in-Depth with SRI + CSP

```javascript
/**
 * Layer 1: CSP - Controls where scripts can come from
 * Layer 2: SRI - Ensures loaded scripts haven't been modified
 * Layer 3: HTTPS - Encrypts in-transit
 * Layer 4: CORS - Prevents cross-site requests to API
 */

// Server sets CSP header
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "script-src 'self' https://cdn.jsdelivr.net sha384-ABC123..."
  );
  next();
});

// HTML includes SRI
const html = `
<!DOCTYPE html>
<html>
<head>
  <script
    src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
    integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG"
    crossorigin="anonymous">
  </script>
</head>
</html>
`;
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: server.js (no SRI protection)
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>My Application</title>

      <!-- ❌ No SRI - vulnerable to CDN compromise -->
      <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css">

      <!-- ❌ No SRI - vulnerable to supply chain attack -->
      <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>

      <!-- ❌ No SRI - no protection if CDN is compromised -->
      <script src="https://analytics.example.com/track.js"></script>
    </head>
    <body>
      <h1>Welcome</h1>
      <p>This application doesn't use SRI, so external resources can be tampered with</p>
    </body>
    </html>
  `;
  res.send(html);
});

app.listen(3000);
```

**Attack Scenario:**

```
1. Attacker compromises cdn.jsdelivr.net
2. Attacker replaces bootstrap.min.css with malicious version
3. Attacker injects JavaScript in the CSS (via expression() or similar)
4. When victim visits website, malicious CSS loads
5. Victim's browser executes injected scripts
6. Attacker steals credentials, session tokens, etc.

With SRI:
1. Attacker compromises CDN
2. Attacker modifies file
3. Browser computes hash of modified file
4. Computed hash doesn't match integrity attribute
5. Browser rejects the file
6. Victim is protected
```

## Secure Code Example

```javascript
// ✅ SECURE: server.js with SRI protection
const express = require('express');
const helmet = require('helmet');
const app = express();

// Apply security headers
app.use(helmet());

// Define resources with their SRI hashes
const EXTERNAL_RESOURCES = {
  bootstrap_css: {
    url: 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css',
    integrity: 'sha384-1BmE4kWBq78iYhFldwKuhfstenjYMLA+hwg1ROUciok7aJ0sx1/QbE0sB/gSvuuNLv3',
    crossorigin: 'anonymous'
  },
  jquery: {
    url: 'https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js',
    integrity: 'sha384-tsQFqpEReu7ZLhBV2VZlAu7zcOV+rXbYlF2cqB8txI/8aZajjp4Bqd+V6D5IgvKT',
    crossorigin: 'anonymous'
  },
  bootstrap_js: {
    url: 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js',
    integrity: 'sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP40uv4N1iDfW9oVHg6V8j+EvqvN8s',
    crossorigin: 'anonymous'
  },
  analytics: {
    url: 'https://analytics.company.com/track.js',
    integrity: 'sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG',
    crossorigin: 'anonymous'
  }
};

app.get('/', (req, res) => {
  const { bootstrap_css, jquery, bootstrap_js, analytics } = EXTERNAL_RESOURCES;

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Secure Application with SRI</title>

      <!-- ✅ SECURE: Bootstrap CSS with SRI -->
      <link
        rel="stylesheet"
        href="${bootstrap_css.url}"
        integrity="${bootstrap_css.integrity}"
        crossorigin="${bootstrap_css.crossorigin}">
    </head>
    <body>
      <div class="container">
        <h1>Welcome to Secure Application</h1>
        <p>All external resources are protected with Subresource Integrity</p>
      </div>

      <!-- ✅ SECURE: jQuery with SRI -->
      <script
        src="${jquery.url}"
        integrity="${jquery.integrity}"
        crossorigin="${jquery.crossorigin}">
      </script>

      <!-- ✅ SECURE: Bootstrap JS with SRI -->
      <script
        src="${bootstrap_js.url}"
        integrity="${bootstrap_js.integrity}"
        crossorigin="${bootstrap_js.crossorigin}">
      </script>

      <!-- ✅ SECURE: Analytics with SRI -->
      <script
        src="${analytics.url}"
        integrity="${analytics.integrity}"
        crossorigin="${analytics.crossorigin}">
      </script>

      <!-- ✅ SECURE: Inline script to handle SRI failures -->
      <script>
        // Monitor for SRI integrity failures
        window.addEventListener('error', (event) => {
          if (event.message && event.message.includes('integrity')) {
            console.error('SRI INTEGRITY VIOLATION DETECTED');
            console.error('Resource may have been tampered with:', event.filename);
            // Could notify monitoring service
            fetch('/api/security-event', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                type: 'SRI_FAILURE',
                url: event.filename,
                timestamp: new Date().toISOString()
              })
            });
          }
        });
      </script>
    </body>
    </html>
  `;
  res.send(html);
});

// Serve local JavaScript with SRI hash
app.get('/js/app.js', (req, res) => {
  const crypto = require('crypto');
  const fs = require('fs');

  const script = fs.readFileSync('./public/js/app.js');
  const hash = crypto.createHash('sha384').update(script).digest('base64');
  const integrity = `sha384-${hash}`;

  // Include SRI hash as response header for verification
  res.setHeader('X-SRI-Hash', integrity);
  res.setHeader('Content-Type', 'application/javascript');
  res.send(script);
});

// API to get SRI hashes for client-side script loading
app.get('/api/sri-hashes', (req, res) => {
  res.json(EXTERNAL_RESOURCES);
});

app.listen(3000);
```

## Mitigations and Best Practices

### 1. Generate and Document All SRI Hashes

```javascript
// sri-config.js - Central repository of all SRI hashes
module.exports = {
  scripts: {
    jquery: {
      version: '3.6.0',
      url: 'https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js',
      integrity: 'sha384-tsQFqpEReu7ZLhBV2VZlAu7zcOV+rXbYlF2cqB8txI/8aZajjp4Bqd+V6D5IgvKT'
    },
    lodash: {
      version: '4.17.21',
      url: 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js',
      integrity: 'sha384-ABC123...'
    }
  },
  styles: {
    bootstrap: {
      version: '5.1.3',
      url: 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css',
      integrity: 'sha384-1BmE4kWBq78...'
    }
  }
};
```

### 2. Use npm sri Tool for Generation

```bash
# Install globally
npm install -g sri

# Generate hash for URL
sri https://cdn.example.com/script.js

# Save to file
sri https://cdn.example.com/script.js > sri-hashes.txt

# Create bash script to generate all hashes
#!/bin/bash
# generate-sri.sh

echo "Generating SRI hashes..."
sri https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js
sri https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css
sri https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js
```

### 3. Automate SRI Hash Updates

```javascript
// build/generate-sri.js
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');

const resources = [
  { name: 'jquery', url: 'https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js' },
  { name: 'bootstrap_css', url: 'https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css' }
];

async function generateSRIs() {
  const results = {};

  for (const resource of resources) {
    const hash = await getSRI(resource.url);
    results[resource.name] = {
      url: resource.url,
      integrity: hash
    };
  }

  fs.writeFileSync('sri-config.json', JSON.stringify(results, null, 2));
  console.log('✓ SRI hashes generated');
}

function getSRI(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      const hash = crypto.createHash('sha384');
      response.on('data', chunk => hash.update(chunk));
      response.on('end', () => {
        resolve(`sha384-${hash.digest('base64')}`);
      });
      response.on('error', reject);
    });
  });
}

generateSRIs().catch(console.error);
```

### 4. Monitor SRI Failures

```javascript
// Client-side monitoring
document.addEventListener('error', (event) => {
  if (event.message && event.message.includes('integrity')) {
    // Log SRI failure
    console.error('SRI Integrity Check Failed:', {
      url: event.filename,
      message: event.message,
      timestamp: new Date().toISOString()
    });

    // Send to monitoring service
    navigator.sendBeacon('/api/security-events', JSON.stringify({
      type: 'SRI_FAILURE',
      url: event.filename,
      userAgent: navigator.userAgent
    }));
  }
});
```

### 5. Use Always HTTPS

```html
<!-- SRI is less effective over HTTP -->
<!-- Upgrade insecure requests -->

<meta http-equiv="Content-Security-Policy"
  content="upgrade-insecure-requests">

<!-- Or server-side HSTS -->
<!-- Strict-Transport-Security: max-age=31536000; includeSubDomains -->
```

### 6. Combine with Content Security Policy

```html
<head>
  <!-- CSP allows scripts from specific origins with SRI hashes -->
  <meta http-equiv="Content-Security-Policy"
    content="script-src 'self' https://cdn.jsdelivr.net sha384-ABC123...">

  <!-- Actual script with matching SRI hash -->
  <script
    src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
    integrity="sha384-ABC123..."
    crossorigin="anonymous">
  </script>
</head>
```

### 7. Test SRI Implementation

```javascript
// Test that SRI validation works
// Create intentionally mismatched hash to verify rejection

function testSRIValidation() {
  const script = document.createElement('script');
  script.src = 'https://cdn.example.com/test.js';

  // Intentionally wrong hash to test validation
  script.integrity = 'sha384-WRONG_HASH_123456789';

  // Should fire error event
  script.onerror = () => {
    console.log('✓ SRI validation working: rejected mismatched hash');
  };

  script.onload = () => {
    console.error('✗ SRI validation NOT working: loaded despite wrong hash');
  };

  document.head.appendChild(script);
}
```

### 8. Version Lock External Dependencies

```json
{
  "externalDependencies": {
    "jquery": {
      "version": "3.6.0",
      "url": "https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js",
      "integrity": "sha384-tsQFqpEReu7ZLhBV2VZlAu7zcOV+rXbYlF2cqB8txI/8aZajjp4Bqd+V6D5IgvKT",
      "updated": "2021-12-15"
    }
  }
}
```

### 9. Respond to SRI Failures Gracefully

```javascript
// Fallback behavior when SRI fails
<script>
  function loadBackupScript(url) {
    const script = document.createElement('script');
    script.src = url;
    script.onload = () => {
      console.warn('Loaded backup script from:', url);
    };
    script.onerror = () => {
      console.error('Failed to load backup script');
      // Disable functionality that depends on this script
      alert('Unable to load required resources. Please refresh the page.');
    };
    document.head.appendChild(script);
  }

  // If primary CDN fails due to SRI, try backup
  window.addEventListener('error', (event) => {
    if (event.message && event.message.includes('integrity')) {
      loadBackupScript('/local-backup/jquery.min.js');
    }
  });
</script>
```

### 10. Create SRI Checklist

```markdown
# SRI Implementation Checklist

- [ ] All external `<script>` tags have integrity attributes
- [ ] All external `<link>` tags have integrity attributes
- [ ] All integrity attributes use sha384 algorithm
- [ ] All cross-origin scripts have crossorigin="anonymous"
- [ ] Hashes are stored in version control
- [ ] SRI generation is automated in build process
- [ ] CSP policy aligns with SRI hashes
- [ ] Monitoring for SRI failures is in place
- [ ] HTTPS is enforced for all resources
- [ ] SRI update procedure is documented
```

## Summary

Subresource Integrity is a critical security feature for protecting against compromised CDNs and supply chain attacks targeting external scripts and stylesheets. By computing cryptographic hashes of external resources and verifying them before execution, you ensure that only authorized, unmodified code runs on your page. Combine SRI with Content Security Policy, HTTPS enforcement, and proper CORS configuration for comprehensive protection against third-party resource tampering.
