---
theme: default
title: JavaScript & Frontend Security
titleTemplate: '%s - JS Security Reference'
description: A complete reference of crucial JavaScript, frontend, and frontend-backend-communication security concepts
author: Torsten Zielke
keywords: security, javascript, frontend, XSS, CSRF, CORS, JWT, OWASP
highlighter: shiki
lineNumbers: true
drawings:
  persist: false
transition: slide-left
mdc: true
colorSchema: dark
favicon: 'https://em-content.zobj.net/source/twitter/376/locked_1f512.png'
fonts:
  sans: 'Inter'
  mono: 'Fira Code'
---

# JavaScript & Frontend Security

### A Complete Developer Reference

45 essential concepts from client-side attacks to backend communication security

<div class="mt-8 text-gray-400 text-sm">
  OWASP Top 10 · XSS · CSRF · JWT · CORS · CSP · Supply Chain · and much more
</div>

<div class="abs-br m-6 text-sm text-gray-500">
  Press <kbd>Space</kbd> to advance
</div>

---
layout: default
---

# What This Covers

<div class="grid grid-cols-3 gap-4 mt-4 text-sm">
  <div class="bg-red-900/30 border border-red-700 rounded p-3">
    <div class="font-bold text-red-400 mb-2">🔴 Client-Side Attacks</div>
    <div class="text-gray-300">XSS · Clickjacking · Prototype Pollution · DOM Clobbering · eval() · Open Redirects · ReDoS · Insecure Storage</div>
  </div>
  <div class="bg-orange-900/30 border border-orange-700 rounded p-3">
    <div class="font-bold text-orange-400 mb-2">🟠 Injection</div>
    <div class="text-gray-300">SQL Injection · NoSQL Injection · Command Injection · Template Injection</div>
  </div>
  <div class="bg-yellow-900/30 border border-yellow-700 rounded p-3">
    <div class="font-bold text-yellow-400 mb-2">🟡 Cross-Origin</div>
    <div class="text-gray-300">CSRF · CORS Misconfiguration · SSRF</div>
  </div>
  <div class="bg-green-900/30 border border-green-700 rounded p-3">
    <div class="font-bold text-green-400 mb-2">🟢 Auth & Access</div>
    <div class="text-gray-300">Broken Access Control · Auth Failures · JWT · OAuth/OIDC · Session Management · IDOR</div>
  </div>
  <div class="bg-blue-900/30 border border-blue-700 rounded p-3">
    <div class="font-bold text-blue-400 mb-2">🔵 Transport</div>
    <div class="text-gray-300">HTTPS/TLS · HSTS · MitM · WebSocket Security · Web Crypto API · Cache Poisoning</div>
  </div>
  <div class="bg-purple-900/30 border border-purple-700 rounded p-3">
    <div class="font-bold text-purple-400 mb-2">🟣 Headers & Policies</div>
    <div class="text-gray-300">CSP · Secure Cookies · Referrer Policy · Permissions Policy · MIME Sniffing</div>
  </div>
  <div class="bg-gray-800 border border-gray-600 rounded p-3">
    <div class="font-bold text-gray-300 mb-2">⚫ Supply Chain</div>
    <div class="text-gray-300">Supply Chain Attacks · SRI · Outdated Components · Third-Party Scripts</div>
  </div>
  <div class="bg-amber-900/30 border border-amber-700 rounded p-3">
    <div class="font-bold text-amber-400 mb-2">🔶 API & Backend</div>
    <div class="text-gray-300">Rate Limiting · Crypto Failures · Misconfiguration · Mass Assignment · Deserialization</div>
  </div>
  <div class="bg-cyan-900/30 border border-cyan-700 rounded p-3">
    <div class="font-bold text-cyan-400 mb-2">🔷 Availability</div>
    <div class="text-gray-300">DoS / DDoS · Security Logging · Insecure Design</div>
  </div>
</div>

---
layout: section
---

# 🔴 Client-Side Attack Vectors
> *"The web browser is the most hostile software development environment imaginable."*
> - Douglas Crockford

---

# 01 - Cross-Site Scripting (XSS)

**Attackers inject malicious scripts into trusted web pages that execute in the victim's browser.**

<div class="grid grid-cols-2 gap-6 mt-4">
<div>

### 3 Types
- **Stored XSS** - Script saved in DB, served to all visitors
- **Reflected XSS** - Script in URL, reflected back in response
- **DOM-based XSS** - Client-side JS processes attacker input

### Attack Goal
- Steal session cookies / tokens
- Keylogging, form hijacking
- Redirect to phishing sites
- Full account takeover

</div>
<div>

```html
<!-- ❌ Vulnerable -->
<div id="output"></div>
<script>
  // User input reflected unsanitized
  document.getElementById('output').innerHTML
    = location.search; // XSS!
</script>

<!-- ✅ Secure -->
<script>
  const el = document.getElementById('output');
  el.textContent = location.search; // safe
  // OR use DOMPurify:
  el.innerHTML = DOMPurify.sanitize(userInput);
</script>
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./01-xss-cross-site-scripting.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">01-xss-cross-site-scripting.md</a></div>

---

# 02 - Clickjacking

**A transparent iframe overlays a legitimate site, tricking users into clicking UI they can't see.**

<div class="grid grid-cols-2 gap-6 mt-4">
<div>

### How It Works
1. Attacker embeds target site in transparent `<iframe>`
2. Positions malicious button under victim's cursor
3. User thinks they click "Win a Prize!" - actually clicks "Delete Account"

### Variants
- **UI Redressing** - fake overlays on real UI
- **Likejacking** - tricking Facebook likes
- **Cursorjacking** - fake cursor position

</div>
<div>

```bash
# ✅ Prevention - HTTP Headers

# Block all framing:
X-Frame-Options: DENY

# Allow only same origin:
X-Frame-Options: SAMEORIGIN

# Modern CSP equivalent:
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'

# Allow specific domain:
Content-Security-Policy:
  frame-ancestors https://trusted.example.com
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./02-clickjacking.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">02-clickjacking.md</a></div>

---

# 03 - Prototype Pollution

**Attackers inject properties into `Object.prototype`, altering every object in the application.**

<div class="grid grid-cols-2 gap-6 mt-4">
<div>

### The Attack
```js
// ❌ Vulnerable deep merge
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);
    } else {
      target[key] = source[key]; // DANGEROUS: all objects now have this key
    }
  }
}
// Attacker sends:
merge({}, JSON.parse(
  '{"__proto__":{"isAdmin":true}}'
));
// Now ALL objects have isAdmin: true!
```

</div>
<div>

### ✅ Prevention
```js
// Use Object.create(null) - no prototype
const safe = Object.create(null);

// Freeze the prototype
Object.freeze(Object.prototype);

// Use Maps instead of plain objects
const map = new Map();

// Validate keys before assignment
const ALLOWED = new Set(['name', 'email']);
if (!ALLOWED.has(key)) throw new Error();

// Use safe merge libraries with
// prototype pollution protection
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./03-prototype-pollution.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">03-prototype-pollution.md</a></div>

---

# 04–08 - More Client-Side Threats

<div class="grid grid-cols-2 gap-4 text-sm mt-2">
<div class="space-y-3">

**04 · DOM Clobbering**
HTML `id`/`name` attributes overwrite JS global variables, enabling script injection when apps read unsafe DOM properties.
```html
<!-- Overwrites window.config -->
<a id="config" href="javascript:alert(1)">
```

**05 · eval() & Dynamic Code Execution**
`eval()`, `new Function(str)`, `setTimeout(str)` with user-controlled strings execute arbitrary code. Use `JSON.parse()` and named functions instead.

**06 · Insecure Client-Side Storage**
Tokens in `localStorage` are readable by any JS on the page. Prefer `HttpOnly` cookies for sensitive data. Never store passwords or private keys client-side.

</div>
<div class="space-y-3">

**07 · ReDoS (Regex DoS)**
Catastrophically backtracking regex patterns freeze the JS engine on crafted input. Avoid nested quantifiers: `/(\w+)+$/` → use linear-time alternatives.

**08 · Open Redirects**
`?redirect=https://evil.com` used to send victims to phishing sites while appearing to originate from a trusted domain. Always whitelist redirect destinations.

```js
// ❌ Vulnerable
res.redirect(req.query.next);

// ✅ Secure
const ALLOWED = ['/', '/dashboard'];
const next = req.query.next;
res.redirect(ALLOWED.includes(next)
  ? next : '/');
```

</div>
</div>

---

## 46 · Micro-Frontend (MFE) Security

<div class="grid grid-cols-2 gap-6">
<div>

**The risk:** Module Federation remotes run with full host-app trust. A compromised remote reads shared tokens, makes credentialed API calls, and modifies the DOM.

```js
// ❌ Blindly loading a remote
remotes: {
  checkout: 'checkout@https://cdn.partner.com/remoteEntry.js'
  // No SRI, no origin allowlist
}

// ✅ Validate remote integrity
remotes: {
  checkout: `promise new Promise((res, rej) =>
    loadRemote('checkout', KNOWN_HASH, res, rej)
  )`
}
```

</div>
<div>

**Defences:**
- Pin remote bundle hash in CI; fail build on mismatch
- Never pass auth tokens to remotes - share only non-sensitive state
- Sandbox untrusted remotes in `<iframe>` with `allow` policy
- Apply a strict CSP scoped to each remote's origin
- Audit `shared:` config - accidentally shared `react` or `lodash` can be hijacked

</div>
</div>

---

## 48 · Framework Security (React / Vue / Angular)

<div class="grid grid-cols-2 gap-6">
<div>

**Framework XSS pitfalls:**

```jsx
// ❌ React - raw HTML injection
<div dangerouslySetInnerHTML={{ __html: userBio }} />

// ❌ Vue - v-html with user content
<div v-html="userComment"></div>

// ❌ Angular - bypassing sanitizer
this.safe = this.san.bypassSecurityTrustHtml(input);

// ❌ Next.js SSR - string interpolation into HTML
`<div>${req.query.name}</div>` // XSS via SSR
```

</div>
<div>

**Safe patterns:**

```jsx
// ✅ React - sanitise before injecting
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{
  __html: DOMPurify.sanitize(userBio)
}} />

// ✅ Vue - text binding is always safe
<p>{{ userComment }}</p>

// ✅ Angular sanitizer is safe by default
// Only bypass if content comes from your own CMS

// ✅ Next.js - pass data through props, not HTML strings
export async function getServerSideProps({ query }) {
  return { props: { name: query.name } }; // escaped by React
}
```

</div>
</div>

---
layout: section
---

# 🟠 Injection Attacks
> *"All user input is evil until proven otherwise."*
> - Michael Howard

---

# 09 - SQL Injection

**Unsanitized user input embedded in SQL queries allows attackers to read, modify, or destroy database data.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### The Attack
```js
// ❌ Vulnerable - string concatenation
const query = `SELECT * FROM users
  WHERE email = '${req.body.email}'`;

// Attacker sends: ' OR '1'='1
// Resulting query:
// SELECT * FROM users WHERE email = ''
// OR '1'='1'  ← returns ALL rows!

// Even worse - dropping tables:
// '; DROP TABLE users; --
```

</div>
<div>

### ✅ Parameterized Queries
```js
// pg (PostgreSQL)
const result = await pool.query(
  'SELECT * FROM users WHERE email = $1',
  [req.body.email]  // safe - never concatenated
);

// mysql2
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE email = ?',
  [req.body.email]
);

// Prisma ORM - safe by default
const user = await prisma.user.findUnique({
  where: { email: req.body.email }
});
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./09-sql-injection.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">09-sql-injection.md</a></div>

---

# 10–13 - More Injection Types

<div class="grid grid-cols-2 gap-4 text-sm mt-2">
<div class="space-y-3">

**10 · NoSQL Injection**
MongoDB operators (`$where`, `$gt`, `$or`) injected via JSON bodies bypass authentication or exfiltrate data.
```js
// ❌ Attacker sends: {"password": {"$gt": ""}}
// ✅ Use Joi/Zod schema validation
// ✅ Use mongo-sanitize on req.body
```

**11 · Command Injection**
User input passed to `child_process.exec()` can execute arbitrary OS commands via shell metacharacters (`;`, `&&`, `|`).
```js
// ❌ exec(`ping ${userInput}`)
// ✅ execFile('ping', [userInput])
//    - no shell, args are safe
```

</div>
<div class="space-y-3">

**13 · HTML / Template Injection**
- **Client-side**: User input in template literals → XSS
- **Server-side (SSTI)**: User input in Handlebars/EJS/Pug templates can achieve **Remote Code Execution**
```js
// ❌ EJS - RCE via template injection
// ✅ Never pass user input as template string
// ✅ Use auto-escaping, sanitize all variables
// ✅ Avoid res.render with user-supplied views
```

</div>
</div>

---
layout: section
---

# 🟡 Cross-Origin & Request Forgery
> *"Trust is a vulnerability. Verify everything."*
> - Security Engineering Principle

---

# 14 - CSRF (Cross-Site Request Forgery)

**A malicious site tricks the victim's authenticated browser into making unwanted requests to another site.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### How It Works
```html
<!-- evil.com - victim visits this page -->
<!-- Browser auto-sends bank.com cookies! -->
<form action="https://bank.com/transfer"
      method="POST" id="csrf">
  <input name="amount" value="10000">
  <input name="to" value="attacker">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### Defenses
1. **CSRF Tokens** - random value in form + header
2. **`SameSite=Strict`** cookie attribute
3. **`SameSite=Lax`** (default in modern browsers)
4. **Double Submit Cookie** pattern
5. **Custom request headers** (CORS preflight)

</div>
<div>

```js
// ✅ Express CSRF token middleware
const csrf = require('csurf');
app.use(csrf({ cookie: true }));

// ✅ SameSite cookie (Node.js)
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict' // best protection
});

// ✅ Verify Origin header on state changes
app.use((req, res, next) => {
  if (['POST','PUT','DELETE'].includes(req.method)) {
    const origin = req.get('Origin');
    if (origin !== 'https://yourapp.com') {
      return res.status(403).end();
    }
  }
  next();
});
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./14-csrf.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">14-csrf.md</a></div>

---

# 15 - CORS Misconfiguration

**Overly permissive CORS headers expose APIs to unauthorized cross-origin access.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### Dangerous Misconfigs
```js
// ❌ Wildcard + credentials - NEVER do this
app.use(cors({
  origin: '*',
  credentials: true // INVALID - browser rejects
}));

// ❌ Blindly reflecting Origin header
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin',
    req.headers.origin); // any origin allowed!
  res.header('Access-Control-Allow-Credentials',
    'true');
  next();
});

// ❌ Trusting 'null' origin
// (sandbox iframes send null - attackers exploit this)
```

</div>
<div>

```js
// ✅ Explicit allowlist
const ALLOWED_ORIGINS = [
  'https://app.example.com',
  'https://admin.example.com'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./15-cors.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">15-cors.md</a></div>

---

# 16 - SSRF (Server-Side Request Forgery)

**The server fetches an attacker-specified URL, enabling access to internal services or cloud metadata.**

<div class="grid grid-cols-2 gap-6 mt-4">
<div>

### High-Value Targets
```
# AWS metadata endpoint
http://169.254.169.254/latest/meta-data/
  → IAM credentials, instance identity

# Internal services
http://localhost:6379/  → Redis
http://localhost:27017/ → MongoDB
http://10.0.0.1/admin  → Internal admin panel

# Cloud provider metadata
http://metadata.google.internal/
http://169.254.169.254/ (AWS, Azure, GCP)
```

### Blind SSRF
Attacker triggers requests without seeing responses - uses timing or out-of-band DNS callbacks to confirm.

</div>
<div>

```js
// ❌ Vulnerable - user-controlled URL
app.post('/fetch-image', async (req, res) => {
  const { url } = req.body;
  const data = await fetch(url); // SSRF!
  res.send(data);
});

// ✅ Secure - allowlist + DNS validation
const { URL } = require('url');
const dns = require('dns').promises;

async function isSafeUrl(urlStr) {
  const url = new URL(urlStr);
  // Only allow https and known domains
  if (url.protocol !== 'https:') return false;
  const ALLOWED = ['cdn.example.com', 'api.example.com'];
  if (!ALLOWED.includes(url.hostname)) return false;
  // Resolve DNS - block private IPs
  const addrs = await dns.resolve4(url.hostname);
  return !addrs.some(isPrivateIP);
}
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./16-ssrf.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">16-ssrf.md</a></div>

---
layout: section
---

# 🟢 Authentication & Authorization
> *"Security is not a product, but a process."*
> - Bruce Schneier

---

# 17 - Broken Access Control

**Users act outside their intended permissions - the #1 OWASP 2021 risk, found in 94% of apps tested.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### Common Failures
- Accessing another user's data (IDOR)
- Reaching admin endpoints without admin role
- Bypassing access checks by changing URL
- Viewing hidden resources by guessing paths
- JWT with role claims tampered client-side

```js
// ❌ Trust role from JWT payload directly
// Attacker modifies payload: {"role":"admin"}
// Then re-signs with weak or leaked secret
app.get('/admin', (req, res) => {
  const { role } = decodeJWT(req.token);
  if (role === 'admin') res.send(adminData);
});
```

</div>
<div>

```js
// ✅ Enforce permissions server-side
// ALWAYS verify signature AND authorization

const authMiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  try {
    // Verify signature with strong secret
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // Look up permissions from DB - don't trust claims
    const user = await User.findById(payload.sub);
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

const requireRole = (role) => (req, res, next) => {
  if (req.user?.role !== role) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
};

app.get('/admin', authMiddleware, requireRole('admin'), handler);
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./17-broken-access-control.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">17-broken-access-control.md</a> · <a href="./22-idor.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">22-idor.md</a></div>

---

# 18 - Authentication Failures

**Weak credential handling and broken session management allow attackers to compromise user accounts. OWASP A07.**

<div class="grid grid-cols-2 gap-4 text-sm mt-3">
<div class="space-y-3">

### What Goes Wrong
- Passwords hashed with MD5/SHA1 (crackable in seconds)
- No MFA - single factor is single point of failure
- No account lockout → brute force succeeds
- Sessions not invalidated on logout
- Predictable / short session IDs
- Password reset tokens that never expire

### Key Mitigations
- `bcrypt`/`Argon2` with cost factor ≥ 12
- TOTP-based MFA (`speakeasy` / `otplib`)
- Rate-limit + lockout on login endpoint
- Breach detection via HaveIBeenPwned API

</div>
<div>

```js
// ✅ Password hashing (bcrypt)
const bcrypt = require('bcryptjs');
const COST = 12; // work factor
const hash = await bcrypt.hash(password, COST);
const ok   = await bcrypt.compare(password, hash);

// ✅ MFA with TOTP
const speakeasy = require('speakeasy');
const secret = speakeasy.generateSecret({ length: 20 });
// Store secret.base32 for user, show QR code once

const valid = speakeasy.totp.verify({
  secret: user.totpSecret,
  encoding: 'base32',
  token: req.body.totpCode,
  window: 1  // allow ±30s clock drift
});

// ✅ HaveIBeenPwned check at registration
const { pwnedPassword } = require('hibp');
const count = await pwnedPassword(password);
if (count > 0) throw new Error('Password found in breach data');
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./18-authentication-failures.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">18-authentication-failures.md</a></div>

---

# 19 - JWT Security

**JSON Web Tokens can be misconfigured in many ways - each leading to forged tokens and account takeover.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### Critical Vulnerabilities

**`alg: none` Attack**
```js
// Attacker forges header:
// { "alg": "none", "typ": "JWT" }
// No signature needed - some libraries accept!
```

**Algorithm Confusion (RS256 → HS256)**
```text
Server uses RS256 (asymmetric).
Attacker switches to HS256 and signs
with the PUBLIC key as HMAC secret.
Vulnerable libraries accept it!
```

**Weak Secret**
```text
HS256 with short/guessable secret
→ brute-forceable with hashcat in seconds
```

</div>
<div>

```js
// ✅ Secure JWT implementation
const jwt = require('jsonwebtoken');

// Sign - strong secret, short expiry
const token = jwt.sign(
  { sub: user.id, role: user.role },
  process.env.JWT_SECRET, // min 256-bit random
  {
    expiresIn: '15m',      // short-lived
    algorithm: 'HS256'     // explicit algorithm
  }
);

// Verify - always specify algorithm explicitly
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'] // reject alg:none + confusion
});

// Never store sensitive data in payload
// (it's Base64-encoded, NOT encrypted)
// Use HttpOnly cookie for storage, not localStorage
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./19-jwt-security.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">19-jwt-security.md</a></div>

---

# 20–22 - OAuth, Sessions & IDOR

<div class="grid grid-cols-2 gap-4 text-sm mt-2">
<div class="space-y-3">

**20 · OAuth 2.0 & OIDC Security**
- Always use **Authorization Code + PKCE** flow
- Validate `state` parameter to prevent CSRF
- Validate `redirect_uri` against registered list - never use wildcards
- Validate ID token: `iss`, `aud`, `exp`, `nonce`
- Never use Implicit flow (tokens in URL fragment!)

**22 · IDOR - Insecure Direct Object References**
Always verify resource ownership, not just authentication:
```js
// ✅ Check ownership, not just authentication
const doc = await Doc.findOne({
  _id: req.params.id,
  userId: req.user.id  // ← critical check
});
if (!doc) return res.status(404).end();
```

</div>
<div class="space-y-3">

**21 · Session Management**
```js
// ✅ Secure express-session config
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,        // HTTPS only
    sameSite: 'strict',
    maxAge: 30 * 60 * 1000 // 30 min
  }
}));

// Regenerate session ID on login (prevents session fixation)
req.session.regenerate((err) => {
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

// Destroy session on logout
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});
```

</div>
</div>

---
layout: section
---

# 🔵 Transport & Network Security
> *"In the digital world, a secure channel is the foundation of all trust."*
> - Transport Layer Security Principle

---

# 23–27 - Transport Security

<div class="grid grid-cols-2 gap-4 text-sm mt-2">
<div class="space-y-3">

**23 · HTTPS & TLS**
Encrypts all data in transit. Minimum TLS 1.2, prefer TLS 1.3. Mixed content (HTTP resources on HTTPS page) leaks data and breaks security.
```js
// Force HTTPS in Express
app.use((req, res, next) => {
  if (!req.secure) {
    return res.redirect(301,
      `https://${req.headers.host}${req.url}`);
  }
  next();
});
```

**24 · HSTS (HTTP Strict Transport Security)**
Forces browser to use HTTPS only, even if user types HTTP. Prevents SSL stripping attacks.
```bash
Strict-Transport-Security:
  max-age=31536000; includeSubDomains; preload
```

**25 · Man-in-the-Middle (MitM)**
Attacker intercepts traffic on untrusted networks (public WiFi, ARP spoofing). TLS + HSTS + cert validation prevent this.

</div>
<div class="space-y-3">

**27 · WebSocket Security**
```js
// ✅ Validate Origin on upgrade
const wss = new WebSocketServer({
  server,
  verifyClient: ({ origin }, cb) => {
    const allowed = ['https://yourapp.com'];
    cb(allowed.includes(origin), 403, 'Forbidden');
  }
});

// ✅ Authenticate via first message (not URL params)
ws.on('message', async (data) => {
  const msg = JSON.parse(data);
  if (!ws.authenticated) {
    const user = await verifyToken(msg.token);
    ws.authenticated = true;
    ws.user = user;
  }
  // validate all messages with Zod/Joi
});
```

</div>
</div>

---

## 47 · Client-Side Cryptography & Web Crypto API

<div class="grid grid-cols-2 gap-6">
<div>

**❌ Common mistakes:**

```js
// ❌ Using Math.random for keys
const key = Math.random().toString(36);

// ❌ AES-CBC with same IV every time
const enc = crypto.subtle.encrypt(
  { name: 'AES-CBC', iv: FIXED_IV }, key, data
);

// ❌ Storing keys in localStorage
localStorage.setItem('key', exportedKey);

// ❌ PBKDF2 with too few iterations
{ name: 'PBKDF2', iterations: 1000 }
```

</div>
<div>

**✅ Correct patterns:**

```js
// ✅ Secure key derivation (600k iterations)
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt,
    iterations: 600_000, hash: 'SHA-256' },
  baseKey,
  { name: 'AES-GCM', length: 256 },
  false, ['encrypt', 'decrypt']
);
// ✅ Random IV for every encryption
const iv = crypto.getRandomValues(new Uint8Array(12));
await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

// ✅ Non-extractable keys stored in IndexedDB
// ✅ Never do crypto client-side for server-side secrets
```

</div>
</div>

---

## 49 · Web Cache Poisoning & Cache Deception

<div class="grid grid-cols-2 gap-6">
<div>

**Attack - Unkeyed header injection:**

```http
GET / HTTP/1.1
Host: app.com
X-Forwarded-Host: attacker.com
```
Server reflects `X-Forwarded-Host` into response → CDN caches it for all users → every visitor receives content pointing to `attacker.com`.

**Cache deception:** `GET /profile/secret.css` - CDN caches private profile page because it looks like a static asset.

</div>
<div>

**Defences:**

```nginx
# ✅ Normalise / strip unkeyed headers at edge
proxy_set_header X-Forwarded-Host $host;

# ✅ Private responses must never be cached
Cache-Control: no-store, private

# ✅ Vary on headers that affect response
Vary: Accept-Language, Accept-Encoding
```

- Audit CDN cache rules - block caching on auth paths
- Never reflect request headers into response HTML unvalidated
- Enable `X-Cache-Status` in staging to surface poisonable paths
- Use path-based cache rules, not extension-based

</div>
</div>

---
layout: section
---

# 🟣 HTTP Security Headers & Browser Policies
> *"Defense in depth means never relying on a single line of defense."*
> - NIST Security Principle

---

# 28 - Content Security Policy (CSP)

**Whitelist trusted sources for scripts, styles, and media - the most powerful XSS defense.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### Key Directives
```
default-src 'self'          - fallback for all types
script-src 'self' 'nonce-{n}' - scripts only from origin
                               + inlines with matching nonce
style-src 'self' 'unsafe-inline'
img-src 'self' data: https:
connect-src 'self' https://api.example.com
frame-ancestors 'none'      - prevents clickjacking
form-action 'self'          - where forms can submit
upgrade-insecure-requests   - auto-upgrade HTTP→HTTPS
```

### Strict CSP with Nonces (best practice)
```html
<!-- Server generates random nonce per request -->
<script nonce="r@nd0m-n0nc3">
  // This inline script is allowed
</script>
```

</div>
<div>

```js
// ✅ Helmet.js CSP for Express
const helmet = require('helmet');

app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      (req, res) => `'nonce-${res.locals.nonce}'`
    ],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'", "https://api.example.com"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: [],
  },
  reportOnly: false, // true for testing
}));

// Test with Report-Only first:
// Content-Security-Policy-Report-Only: ...
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./28-content-security-policy.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">28-content-security-policy.md</a></div>

---

# 29–32 - More Security Headers

<div class="grid grid-cols-2 gap-4 text-sm mt-2">
<div class="space-y-3">

**29 · Secure Cookie Attributes**
```js
res.cookie('session', value, {
  httpOnly: true,   // no JS access (XSS safe)
  secure: true,     // HTTPS only
  sameSite: 'Strict', // no cross-site sending
  maxAge: 1800000,  // 30 min
  path: '/',
  domain: 'example.com'
});
```

**30 · Referrer Policy**
Prevents sensitive URL params from leaking to third-party servers via the `Referer` header.
```bash
Referrer-Policy: strict-origin-when-cross-origin
```
Sends full path for same-origin, only origin for cross-origin, nothing for HTTP→HTTPS downgrade.

</div>
<div class="space-y-3">

**31 · Permissions Policy**
Restrict browser APIs for your page and embedded iframes.
```bash
Permissions-Policy:
  camera=(),
  microphone=(),
  geolocation=(self),
  fullscreen=(self),
  payment=()
```

**32 · X-Content-Type-Options (MIME Sniffing)**
Prevents browsers from guessing content type, stopping polyglot file attacks.
```bash
X-Content-Type-Options: nosniff
```

**Full Helmet.js Setup (one line)**
```js
app.use(helmet());
// Sets: X-Content-Type-Options, X-Frame-Options,
// HSTS, X-XSS-Protection, Referrer-Policy, etc.
```

</div>
</div>

---
layout: section
---

# ⚫ Supply Chain & Dependency Security
> *"A chain is only as strong as its weakest link - and you didn't write most of your code."*
> - Supply Chain Security Principle

---

# 33 - Supply Chain Attacks

**Attackers compromise widely-used npm packages, injecting malicious code into millions of apps.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### Real-World Incidents
| Year | Package | Impact |
|------|---------|--------|
| 2018 | `event-stream` | Crypto wallet theft |
| 2022 | `colors`/`faker` | Deliberate sabotage |
| 2024 | `polyfill.io` | 150K sites compromised |
| 2025 | `chalk`, `debug`, `ansi-styles` | 2.6B weekly downloads hit |

### Attack Vectors
- Compromised maintainer accounts
- Typosquatting (`lodahs` vs `lodash`)
- Dependency confusion (private pkg name on npm)
- Malicious `postinstall` scripts

</div>
<div>

```bash
# ✅ Audit dependencies
npm audit
npm audit fix

# ✅ Use lock files - commit them!
# package-lock.json / yarn.lock / pnpm-lock.yaml

# ✅ Pin exact versions for critical deps
# "lodash": "4.17.21" not "^4.17.21"

# ✅ Automated scanning
# - Dependabot (GitHub)
# - Snyk (snyk.io)
# - Socket.dev (supply chain focused)
# - OWASP Dependency Check

# ✅ Set npm strict mode
npm config set ignore-scripts true
# Review scripts before install

# ✅ Use SRI for CDN scripts (next slide)
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./33-supply-chain-attacks.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">33-supply-chain-attacks.md</a> · <a href="./35-vulnerable-outdated-components.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">35-vulnerable-outdated-components.md</a></div>

---

# 34 - Subresource Integrity (SRI)

**Browser verifies CDN-loaded resources haven't been tampered with via cryptographic hashes.**

<div class="grid grid-cols-2 gap-6 mt-4">
<div>

### How It Works
1. Generate SHA hash of the resource
2. Add `integrity` attribute to `<script>`/`<link>`
3. Browser fetches resource, computes hash
4. If hashes don't match → **resource blocked**

```bash
# Generate SRI hash
openssl dgst -sha384 -binary \
  jquery.min.js | openssl base64 -A
# → sha384-abc123...

# Or use online tool:
# https://www.srihash.org/
```

</div>
<div>

```html
<!-- ✅ Script with SRI -->
<script
  src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
  integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk"
  crossorigin="anonymous">
</script>

<!-- ✅ Stylesheet with SRI -->
<link
  rel="stylesheet"
  href="https://cdn.example.com/styles.css"
  integrity="sha256-abc123..."
  crossorigin="anonymous">
```

```js
// ✅ CSP + SRI combination
// require-sri-for blocks resources without SRI:
Content-Security-Policy:
  require-sri-for script style;
  script-src https://trusted-cdn.com
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./34-subresource-integrity.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">34-subresource-integrity.md</a></div>

---

# 35 & 36 - Outdated Components & Third-Party Scripts

<div class="grid grid-cols-2 gap-4 text-sm mt-3">
<div class="space-y-3">

**35 · Vulnerable & Outdated Components (OWASP A06)**

Using libraries with known CVEs exposes apps to exploits that have already been patched.

```bash
# Find vulnerabilities in your dependencies
npm audit

# Auto-fix safe/patch-level upgrades
npm audit fix

# Check a specific package
npx snyk test

# View outdated packages
npm outdated
```

- Enable **Dependabot** or **Renovate** for automated PRs
- Pin exact versions for critical security packages
- Check transitive deps - your `node_modules` tree matters
- Integrate `npm audit` into CI/CD - fail builds on high severity

</div>
<div class="space-y-3">

**36 · Third-Party Script Security**

Analytics tags, chat widgets, and ad scripts run with full page privilege - **one compromised vendor = XSS on your site**.

```html
<!-- ❌ Unlimited trust to third-party -->
<script src="https://analytics.vendor.com/track.js"></script>

<!-- ✅ SRI hash - blocks tampered versions -->
<script
  src="https://analytics.vendor.com/track.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous">
</script>

<!-- ✅ Sandbox third-party widgets in iframes -->
<iframe
  src="https://widget.vendor.com/chat"
  sandbox="allow-scripts allow-same-origin"
  referrerpolicy="no-referrer">
</iframe>
```

Restrict via CSP: `script-src 'self' https://analytics.vendor.com`

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./35-vulnerable-outdated-components.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">35-vulnerable-outdated-components.md</a> · <a href="./36-third-party-scripts.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">36-third-party-scripts.md</a></div>

---
layout: section
---

# 🔶 API & Backend Communication Security
> *"Never trust the client. Never trust the network. Validate everything server-side."*
> - API Security Best Practice

---

# 37 - API Security & Rate Limiting

**APIs without rate limiting are vulnerable to brute force, credential stuffing, and DoS.**

<div class="grid grid-cols-2 gap-6 mt-3">
<div>

### Attack Types Without Rate Limiting
- **Brute Force** - try all passwords
- **Credential Stuffing** - breach data + known passwords
- **OTP Enumeration** - try all 6-digit codes
- **Scraping** - mass data extraction
- **DoS** - overwhelm with requests

### Rate Limit Strategies
- **Fixed Window** - 100 req per 15 min
- **Sliding Window** - smoothed over time
- **Token Bucket** - burst-friendly
- **Leaky Bucket** - constant rate output

</div>
<div>

```js
// ✅ express-rate-limit
const rateLimit = require('express-rate-limit');

// General API limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
});

// Stricter limit for auth endpoints
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,  // only 5 attempts per 15 min
  skipSuccessfulRequests: true
});

app.use('/api/', apiLimiter);
app.post('/auth/login', loginLimiter, loginHandler);

// ✅ Validate all inputs (Zod)
const schema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128)
});
```

</div>
</div>

<div class="mt-2 text-xs text-gray-400">📄 Deep dive: <a href="./37-api-security-rate-limiting.md" target="_blank" class="text-blue-400 underline decoration-dotted hover:text-blue-300">37-api-security-rate-limiting.md</a></div>

---

# 38–42 - Backend Security Concepts

<div class="grid grid-cols-2 gap-4 text-sm mt-2">
<div class="space-y-2">

**38 · Cryptographic Failures (OWASP A02)**
- Always use `bcrypt`/`Argon2` for passwords (NOT MD5/SHA1)
- Store secrets in env vars / vaults - never in code
- Enforce HTTPS - never transmit sensitive data over HTTP
- Use AES-256-GCM for data at rest encryption
- Never log tokens, passwords, or PII

**39 · Security Misconfiguration (OWASP A05)**
- Disable debug mode and stack traces in production
- Remove default credentials and sample apps
- Set all security headers (use `helmet`)
- Restrict HTTP methods to what's needed
- Close unnecessary open ports/services
- Lock down S3/cloud storage permissions

</div>
<div class="space-y-2">

**40 · Software & Data Integrity (OWASP A08)**
- Verify update signatures before applying
- Protect CI/CD pipeline - use pinned action versions
- Use lock files and dependency provenance

**41 · Insecure Deserialization**
```js
// ❌ NEVER eval user-provided JSON
eval('(' + userInput + ')');

// ✅ Always use JSON.parse - it's safe
const data = JSON.parse(userInput);

// ✅ Validate schema after parsing
const schema = z.object({ id: z.number() });
const safe = schema.parse(data);
```

**42 · Mass Assignment**
```js
// ❌ Blind spread of req.body
await User.update({ ...req.body });
// ✅ Explicit field allowlist
const { name, email } = req.body;
await User.update({ name, email });
```

</div>
</div>

---
layout: section
---

# 🔷 Availability & Monitoring
> *"The question is not if you will be attacked, but when - and whether you'll know."*
> - Security Operations Principle

---

# 43–45 - Availability & Design

<div class="grid grid-cols-2 gap-4 text-sm mt-2">
<div class="space-y-3">

**43 · DoS & DDoS**

Application-layer DoS risks in Node.js:
```js
// ❌ No payload size limit
app.use(express.json());

// ✅ Limit payload size
app.use(express.json({ limit: '100kb' }));

// ❌ Vulnerable regex (ReDoS)
/^(a+)+$/.test(userInput);

// ✅ Set request timeouts
server.setTimeout(5000);
```

Mitigation layers: CDN (Cloudflare) → WAF → Rate Limiting → App-level validation

**44 · Security Logging & Monitoring (OWASP A09)**

What to log: auth events, access control failures, input validation rejections, unusual activity patterns

What NOT to log: passwords, tokens, full credit card numbers, PII in plain text

Use structured logging: Winston / Pino → centralized ELK / Datadog

</div>
<div class="space-y-3">

**45 · Insecure Design (OWASP A04)**

Design flaws can't be fixed with patches - must be addressed at architecture level.

**STRIDE Threat Model**

| Threat | Example |
|--------|---------|
| **S**poofing | Fake login page |
| **T**ampering | Modified JWT payload |
| **R**epudiation | No audit logs |
| **I**nfo Disclosure | Stack traces in prod |
| **D**enial of Service | No rate limiting |
| **E**levation of Privilege | IDOR to admin data |

**Secure Design Principles**
- Least Privilege - minimum permissions needed
- Defense in Depth - multiple security layers
- Fail Secure - errors → denied, not open
- Separation of Concerns - compartmentalize trust

</div>
</div>

---
layout: default
---

# 📋 OWASP Top 10:2021 - Quick Reference

<div class="grid grid-cols-2 gap-4 mt-4 text-sm">
<div>

| Rank | Vulnerability | Key Defense |
|------|--------------|-------------|
| **A01** | Broken Access Control | Server-side authz on every route |
| **A02** | Cryptographic Failures | HTTPS, bcrypt, secrets in vault |
| **A03** | Injection | Parameterized queries, sanitize |
| **A04** | Insecure Design | Threat modeling, STRIDE |
| **A05** | Security Misconfiguration | Helmet, disable debug, lock env |

</div>
<div>

| Rank | Vulnerability | Key Defense |
|------|--------------|-------------|
| **A06** | Vulnerable Components | npm audit, Dependabot, pin deps |
| **A07** | Auth Failures | bcrypt, MFA, session rotation |
| **A08** | Integrity Failures | SRI, signed releases, lock files |
| **A09** | Logging Failures | Structured logs, alert on anomaly |
| **A10** | SSRF | URL allowlists, block private IPs |

</div>
</div>

<div class="mt-6 bg-gray-800 rounded p-4 text-sm">

**Essential npm packages for Express security:**
```bash
npm install helmet cors express-rate-limit csurf bcryptjs jsonwebtoken zod joi dompurify mongo-sanitize
```

</div>

---
layout: default
---

# ✅ Security Checklist - Ship Confidently

<div class="grid grid-cols-3 gap-4 mt-4 text-xs">
<div class="bg-gray-800 rounded p-3">
<div class="font-bold text-red-400 mb-2">Client-Side</div>

- [ ] Sanitize all HTML output (DOMPurify)
- [ ] Never use `innerHTML` with user data
- [ ] Avoid `eval()` and `new Function()`
- [ ] Set `X-Frame-Options: DENY`
- [ ] Implement strict CSP with nonces
- [ ] No secrets in frontend code
- [ ] Tokens in HttpOnly cookies, not localStorage
- [ ] SRI on all CDN resources
- [ ] Validate all regex patterns for ReDoS

</div>
<div class="bg-gray-800 rounded p-3">
<div class="font-bold text-yellow-400 mb-2">Auth & API</div>

- [ ] Use parameterized queries only
- [ ] bcrypt/Argon2 for passwords (cost ≥ 12)
- [ ] JWT: explicit alg, short expiry, strong secret
- [ ] OAuth: PKCE, validate state + redirect_uri
- [ ] Rate limit all auth endpoints (max 5/15min)
- [ ] Session: regenerate on login, destroy on logout
- [ ] CORS: explicit allowlist, never wildcard+creds
- [ ] Verify resource ownership (IDOR check)
- [ ] Limit request body size

</div>
<div class="bg-gray-800 rounded p-3">
<div class="font-bold text-blue-400 mb-2">Transport & Ops</div>

- [ ] HTTPS enforced everywhere
- [ ] HSTS with preload
- [ ] All security headers set (Helmet.js)
- [ ] SameSite=Strict on session cookies
- [ ] npm audit in CI/CD pipeline
- [ ] Dependabot or Renovate enabled
- [ ] No secrets in source control (.env in .gitignore)
- [ ] Structured logging - no PII in logs
- [ ] Error pages don't leak stack traces
- [ ] Threat model before each major feature

</div>
</div>

---
layout: center
class: text-center
---

# Stay Curious. Stay Secure.

<div class="mt-6 text-gray-300">
  45 concepts covered - each with its own deep-dive markdown file.
</div>

<div class="grid grid-cols-3 gap-6 mt-8 text-sm text-left">
<div>

**Research Further**
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)

</div>
<div>

**Tooling**
- [Snyk](https://snyk.io) - dependency scanning
- [Socket.dev](https://socket.dev) - supply chain
- [Helmet.js](https://helmetjs.github.io) - security headers
- [DOMPurify](https://github.com/cure53/DOMPurify) - XSS sanitization

</div>
<div>

**Standards**
- OWASP ASVS (Verification Standard)
- NIST SP 800-63 (Auth Guidelines)
- RFC 7519 (JWT)
- RFC 6749 (OAuth 2.0)
- RFC 8414 (PKCE)

</div>
</div>

<div class="mt-10 text-gray-500 text-xs">
  JS & Frontend Security Reference · 2025 · All 45 concept files in this repository
</div>
