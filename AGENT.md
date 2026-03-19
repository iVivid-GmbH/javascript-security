# AGENT.md — JavaScript & Frontend Security Agent Guide

This file gives AI agents the context, priorities, and step-by-step instructions needed to audit, triage, and remediate the most critical security issues in a JavaScript/frontend codebase.

---

## Repository Overview

This repository is a **JavaScript & Frontend Security Reference** covering 45 security concepts across 9 categories. The concepts are documented in individual markdown files (`01-xss-cross-site-scripting.md` … `45-insecure-design.md`) and presented via a Reveal.js 2D slide deck (`slides.html`).

When an agent is asked to "handle security issues" or "audit this codebase", follow the workflow below.

---

## Agent Workflow

### Step 1 — Discover & Inventory

Run the following to understand what you're working with:

```bash
# List all source files (JS, TS, HTML, CSS)
find . -type f \( -name "*.js" -o -name "*.ts" -o -name "*.jsx" -o -name "*.tsx" -o -name "*.html" \) \
  | grep -v node_modules | grep -v dist

# Check for a lockfile to audit dependencies
ls package-lock.json yarn.lock pnpm-lock.yaml 2>/dev/null

# Run npm audit
npm audit --json 2>/dev/null | jq '.vulnerabilities | to_entries[] | {name: .key, severity: .value.severity, via: .value.via[0]}'
```

---

### Step 2 — Automated Static Analysis

Run these checks in order. Each produces actionable output.

#### 2a. Dependency vulnerabilities
```bash
npm audit --audit-level=moderate
# Fix automatically where safe:
npm audit fix
# For breaking changes, review manually:
npm audit fix --dry-run --force
```

#### 2b. Secrets / credential leaks
```bash
# Scan for hardcoded secrets (requires trufflehog or gitleaks)
trufflehog filesystem . --only-verified 2>/dev/null \
  || gitleaks detect --source . --no-git 2>/dev/null \
  || grep -rn --include="*.{js,ts,env,json,yml,yaml,html}" \
       -E "(api[_-]?key|secret|password|token|credential)\s*[=:]\s*['\"][^'\"]{8,}" \
       . | grep -v node_modules | grep -v ".min."
```

#### 2c. XSS sinks — dangerous DOM patterns
```bash
grep -rn --include="*.{js,ts,jsx,tsx,html}" \
  -E "(innerHTML|outerHTML|document\.write|insertAdjacentHTML|dangerouslySetInnerHTML|eval\(|setTimeout\(|setInterval\(|new Function\()" \
  . | grep -v node_modules | grep -v ".min." | grep -v ".test."
```

#### 2d. Unsafe URL handling / open redirect
```bash
grep -rn --include="*.{js,ts,jsx,tsx}" \
  -E "(location\.href\s*=|location\.replace\(|window\.open\(|href\s*=\s*[^'\"]*req|redirect\()" \
  . | grep -v node_modules
```

#### 2e. Prototype pollution risks
```bash
grep -rn --include="*.{js,ts}" \
  -E "(__proto__|constructor\[|Object\.assign\(|merge\(|extend\(|deepMerge\()" \
  . | grep -v node_modules
```

#### 2f. Insecure cookie configuration
```bash
grep -rn --include="*.{js,ts}" \
  -E "res\.cookie\(|document\.cookie\s*=" \
  . | grep -v node_modules
# Flag any cookie missing: httpOnly, secure, sameSite
```

#### 2g. Missing/weak CSP in HTML files
```bash
grep -rn --include="*.html" \
  -E "Content-Security-Policy|<meta[^>]+http-equiv" \
  . | grep -v node_modules
# No output = no CSP configured → HIGH priority finding
```

#### 2h. CORS misconfiguration
```bash
grep -rn --include="*.{js,ts}" \
  -E "Access-Control-Allow-Origin.*\*|origin:\s*['\"]?\*" \
  . | grep -v node_modules
```

#### 2i. JWT handling issues
```bash
grep -rn --include="*.{js,ts}" \
  -E "jwt\.verify|jwt\.decode|algorithm.*none|alg.*none|HS256.*secret" \
  . | grep -v node_modules
```

---

### Step 3 — Prioritise Findings

Score each finding using this matrix:

| Severity | CVSS Score | Examples | Action |
|----------|-----------|---------|--------|
| **Critical** | 9.0–10.0 | RCE via eval, hardcoded secrets, SQLi | Fix immediately, block deploy |
| **High** | 7.0–8.9 | XSS, CSRF, broken auth, open redirect | Fix before next release |
| **Medium** | 4.0–6.9 | Missing CSP, insecure cookies, CORS * | Fix in current sprint |
| **Low** | 0.1–3.9 | Missing security headers, verbose errors | Fix in backlog |
| **Info** | — | Outdated deps (no known CVE), code style | Track, no urgency |

**Top 10 issues to remediate first (by real-world impact):**

1. **Hardcoded secrets / API keys** — immediate credential rotation + fix
2. **XSS via innerHTML / dangerouslySetInnerHTML** — sanitise or use textContent
3. **eval() / new Function() with user input** — remove entirely
4. **npm dependencies with Critical/High CVEs** — `npm audit fix` or pin patched version
5. **No Content-Security-Policy** — add strict CSP header
6. **Wildcard CORS (`Access-Control-Allow-Origin: *`)** — restrict to explicit origins
7. **Insecure cookies** (missing `HttpOnly`, `Secure`, `SameSite=Strict`) — add all three
8. **Missing CSRF protection** on state-changing endpoints — add CSRF tokens or SameSite cookies
9. **JWT algorithm confusion** (`alg: none` or secret in client code) — enforce HS256/RS256 server-side
10. **Open redirect** via unvalidated `redirect` param — validate against allowlist

---

### Step 4 — Remediation Patterns

#### Fix XSS
```js
// ❌ Vulnerable
element.innerHTML = userInput;

// ✅ Safe — text only
element.textContent = userInput;

// ✅ Safe — HTML needed: sanitise first
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

#### Fix insecure cookies
```js
// ❌ Missing flags
res.cookie('session', token);

// ✅ All flags set
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'Strict',
  maxAge: 3600000,
  path: '/',
});
```

#### Fix wildcard CORS
```js
// ❌ Accepts any origin
app.use(cors({ origin: '*' }));

// ✅ Explicit allowlist
const ALLOWED_ORIGINS = ['https://app.example.com'];
app.use(cors({
  origin: (origin, cb) =>
    ALLOWED_ORIGINS.includes(origin) ? cb(null, true) : cb(new Error('CORS blocked')),
  credentials: true,
}));
```

#### Add Content-Security-Policy
```html
<!-- In HTML <head> -->
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none';">
```

Or via server header (preferred):
```js
// Express + Helmet
import helmet from 'helmet';
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'none'"],
    upgradeInsecureRequests: [],
  },
}));
```

#### Rotate leaked secrets
```bash
# 1. Immediately revoke the leaked key in the provider dashboard
# 2. Remove from codebase
git filter-repo --path-glob '*.env' --invert-paths   # strip from history
# 3. Add to .gitignore
echo ".env" >> .gitignore
echo ".env.local" >> .gitignore
# 4. Use environment variables or a secrets manager instead
```

---

### Step 5 — Verify Fixes

After applying remediation, re-run the checks from Step 2 and confirm:

```bash
# Re-run npm audit — expect 0 high/critical
npm audit --audit-level=high

# Re-check XSS sinks — expect 0 matches
grep -rn --include="*.{js,ts,html}" "innerHTML\s*=" . | grep -v node_modules | grep -v ".test."

# Confirm CSP exists
grep -rn "Content-Security-Policy" . | grep -v node_modules
```

---

### Step 6 — Produce a Security Report

Create a `security-report.md` in the repo root with the following structure:

```markdown
# Security Audit Report — <date>

## Summary
- Files scanned: N
- Total findings: N
- Critical: N | High: N | Medium: N | Low: N

## Findings

### [CRITICAL] Hardcoded API key in src/config.js
**File:** `src/config.js:42`
**Impact:** Full account takeover, data breach
**Remediation:** Remove key, rotate credential, use env variable
**Status:** [ ] Open / [x] Fixed

...

## Dependency Vulnerabilities
| Package | Installed | CVE | Severity | Fix |
|---------|-----------|-----|----------|-----|
| ...     | ...       | ... | ...      | ... |

## Verified Clean
- [x] No secrets in source
- [x] npm audit: 0 high/critical
- [x] CSP header present
- [x] Cookies: HttpOnly + Secure + SameSite
```

---

## Concept Reference Index

Each numbered file in this repo is a deep-dive reference for that security concept. When investigating a finding, read the matching file for full explanation, attack scenarios, and mitigations:

| Finding Type | Reference File |
|-------------|---------------|
| XSS | `01-xss-cross-site-scripting.md` |
| Clickjacking | `02-clickjacking.md` |
| Prototype Pollution | `03-prototype-pollution.md` |
| DOM Clobbering | `04-dom-clobbering.md` |
| ReDoS | `05-redos.md` |
| SQL Injection | `06-sql-injection.md` |
| NoSQL Injection | `07-nosql-injection.md` |
| Command Injection | `08-command-injection.md` |
| LDAP Injection | `09-ldap-injection.md` |
| SSTI | `10-template-injection-ssti.md` |
| CSRF | `11-csrf.md` |
| CORS Misconfiguration | `12-cors-misconfiguration.md` |
| SSRF | `13-ssrf.md` |
| JWT Vulnerabilities | `14-jwt-vulnerabilities.md` |
| OAuth/OIDC | `15-oauth-oidc-vulnerabilities.md` |
| Broken Access Control | `16-broken-access-control.md` |
| IDOR | `17-idor.md` |
| Session Management | `18-session-management.md` |
| HTTPS/TLS | `19-https-tls.md` |
| HSTS | `20-hsts.md` |
| MitM | `21-mitm-attacks.md` |
| Certificate Pinning | `22-certificate-pinning.md` |
| WebSockets | `23-websocket-security.md` |
| CSP | `24-content-security-policy.md` |
| Secure Cookies | `25-secure-cookies.md` |
| Referrer Policy | `26-referrer-policy.md` |
| MIME Sniffing | `27-mime-sniffing.md` |
| Clickjacking Headers | `28-clickjacking-x-frame-options.md` |
| Supply Chain | `29-supply-chain-attacks.md` |
| SRI | `30-subresource-integrity.md` |
| Outdated Components / 3rd-party | `31-outdated-components-third-party-scripts.md` |
| Rate Limiting | `32-rate-limiting.md` |
| Cryptographic Failures | `33-cryptographic-failures.md` |
| Mass Assignment | `34-mass-assignment.md` |
| GraphQL Security | `35-graphql-security.md` |
| DoS/DDoS | `36-dos-ddos.md` |
| Security Logging | `37-security-logging-monitoring.md` |
| Insecure Design | `38-insecure-design.md` |

---

## Useful One-Liners for Agents

```bash
# Count distinct security-sensitive patterns
grep -rn --include="*.{js,ts}" "innerHTML\|eval(\|document\.write\|new Function(" \
  . | grep -v node_modules | wc -l

# Find all external script sources loaded in HTML
grep -rn --include="*.html" 'src="http' . | grep -v node_modules

# Check for SRI on CDN scripts
grep -rn --include="*.html" '<script' . | grep -v integrity

# Detect sensitive fields without input validation
grep -rn --include="*.{js,ts}" \
  -E "(req\.body\.|req\.query\.|req\.params\.)(password|token|secret|key|ssn|dob|creditcard)" \
  . | grep -v node_modules

# List all npm packages and their licenses
npx license-checker --summary 2>/dev/null | head -40
```

---

*This file is part of the JavaScript & Frontend Security Reference. Update it as new vulnerability classes emerge or new automated tools become available.*
