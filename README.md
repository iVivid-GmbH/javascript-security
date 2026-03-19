# JavaScript & Frontend Security — Complete Reference

> A comprehensive, research-ready overview of crucial security concepts for JavaScript/frontend development and frontend-backend communication. Each concept below links to a dedicated deep-dive file with explanations, examples, and mitigations.

---

## How to Use This Reference

Each entry includes a one-to-two sentence summary. Click the link to open the detailed file for that concept, which contains: a full explanation, how attacks work, code examples (vulnerable vs. secure), and best-practice mitigations.

---

## 🔴 Category 1 — Client-Side / Frontend Attack Vectors

| # | Concept | Summary |
|---|---------|---------|
| 01 | [Cross-Site Scripting (XSS)](./01-xss-cross-site-scripting.md) | Attackers inject malicious scripts into trusted web pages, running in the victim's browser to steal data or hijack sessions. Comes in three forms: Stored, Reflected, and DOM-based. |
| 02 | [Clickjacking](./02-clickjacking.md) | A malicious page overlays a transparent iframe over a legitimate site, tricking users into clicking UI elements they can't see. Prevented with `X-Frame-Options` and CSP `frame-ancestors`. |
| 03 | [Prototype Pollution](./03-prototype-pollution.md) | Attackers inject properties into JavaScript's `Object.prototype`, altering the behavior of all objects in the app — often leading to XSS or remote code execution. |
| 04 | [DOM Clobbering](./04-dom-clobbering.md) | HTML elements with `id` or `name` attributes can overwrite global JavaScript variables, enabling script injection in apps that do unsafe DOM reads. |
| 05 | [eval() & Dynamic Code Execution](./05-eval-dynamic-code-execution.md) | Using `eval()`, `setTimeout(string)`, or `new Function(string)` with user-controlled input allows arbitrary code execution in the browser. |
| 06 | [Insecure Data Storage (Client-Side)](./06-insecure-data-storage.md) | Storing sensitive tokens or PII in `localStorage`, `sessionStorage`, or insecure cookies exposes them to XSS theft. HttpOnly cookies and short-lived tokens are safer alternatives. |
| 07 | [ReDoS — Regular Expression DoS](./07-redos.md) | Poorly written regex patterns with catastrophic backtracking can freeze a JavaScript engine when fed crafted input, causing denial of service. |
| 08 | [Open Redirects](./08-open-redirects.md) | A URL parameter controls where the app redirects users; attackers exploit this to send victims to phishing sites while appearing to come from a trusted domain. |

---

## 🟠 Category 2 — Injection Attacks

| # | Concept | Summary |
|---|---------|---------|
| 09 | [SQL Injection](./09-sql-injection.md) | Unsanitized user input is embedded in SQL queries, allowing attackers to read, modify, or delete database data. Parameterized queries and ORMs eliminate this risk. |
| 10 | [NoSQL Injection](./10-nosql-injection.md) | Similar to SQL injection but targeting document databases (MongoDB, etc.) via JSON operators like `$where` or `$gt` injected in request bodies. |
| 11 | [Command Injection](./11-command-injection.md) | User input passed to OS shell commands (Node.js `exec`, `spawn`) can execute arbitrary system commands if not properly escaped. |
| 12 | [LDAP Injection](./12-ldap-injection.md) | Unsanitized input inserted into LDAP queries can bypass authentication or expose directory data. |
| 13 | [HTML & Template Injection](./13-html-template-injection.md) | Untrusted input rendered directly into HTML templates (server-side or client-side) can lead to XSS or, in server-side template engines, full remote code execution (SSTI). |

---

## 🟡 Category 3 — Cross-Origin & Request Forgery

| # | Concept | Summary |
|---|---------|---------|
| 14 | [CSRF — Cross-Site Request Forgery](./14-csrf.md) | A malicious site tricks the victim's authenticated browser into making state-changing requests to another site. Mitigated with CSRF tokens and `SameSite` cookie attributes. |
| 15 | [CORS — Cross-Origin Resource Sharing](./15-cors.md) | Browser policy that restricts cross-origin HTTP requests; misconfigured CORS headers (e.g., `Access-Control-Allow-Origin: *` with credentials) expose APIs to unauthorized access. |
| 16 | [Server-Side Request Forgery (SSRF)](./16-ssrf.md) | The server is tricked into making HTTP requests to internal services on the attacker's behalf, potentially exposing cloud metadata endpoints or internal APIs. |

---

## 🟢 Category 4 — Authentication & Authorization

| # | Concept | Summary |
|---|---------|---------|
| 17 | [Broken Access Control](./17-broken-access-control.md) | The #1 OWASP risk: users can act outside their intended permissions — accessing other users' data, admin endpoints, or unpublished resources. |
| 18 | [Identification & Authentication Failures](./18-authentication-failures.md) | Weak passwords, missing MFA, insecure credential storage, and broken session management allow attackers to compromise user accounts. |
| 19 | [JWT Security](./19-jwt-security.md) | JSON Web Tokens can be misconfigured (e.g., `alg: none` attacks, weak secrets, missing expiry) allowing forged tokens and session hijacking. |
| 20 | [OAuth 2.0 & OpenID Connect Security](./20-oauth-oidc-security.md) | OAuth flows can be exploited via authorization code interception, open redirects in redirect_uri, token leakage, and PKCE bypass if not implemented correctly. |
| 21 | [Session Management](./21-session-management.md) | Predictable session IDs, missing session invalidation on logout, and session fixation attacks allow attackers to impersonate authenticated users. |
| 22 | [Insecure Direct Object References (IDOR)](./22-idor.md) | APIs that expose internal object IDs (e.g., `/api/invoice/1234`) without verifying ownership let attackers access or modify other users' data. |

---

## 🔵 Category 5 — Transport & Network Security

| # | Concept | Summary |
|---|---------|---------|
| 23 | [HTTPS & TLS](./23-https-tls.md) | Encrypts data in transit between browser and server; without it, network attackers can read or modify all traffic (man-in-the-middle). |
| 24 | [HTTP Strict Transport Security (HSTS)](./24-hsts.md) | An HTTP header that forces browsers to use HTTPS only for a domain, preventing SSL stripping and downgrade attacks. |
| 25 | [Man-in-the-Middle (MitM) Attacks](./25-man-in-the-middle.md) | An attacker positions themselves between client and server to intercept or alter communications; prevented by TLS, HSTS, and certificate validation. |
| 26 | [Certificate Pinning](./26-certificate-pinning.md) | The app trusts only specific certificates or public keys for a domain, preventing attacks using fraudulently issued certificates. |
| 27 | [WebSocket Security](./27-websocket-security.md) | WebSocket connections bypass some browser security policies; they require origin validation, authentication tokens, and protection against message injection. |

---

## 🟣 Category 6 — HTTP Security Headers & Browser Policies

| # | Concept | Summary |
|---|---------|---------|
| 28 | [Content Security Policy (CSP)](./28-content-security-policy.md) | An HTTP response header that whitelists trusted sources for scripts, styles, and media, dramatically reducing XSS attack surface. |
| 29 | [Secure Cookie Attributes](./29-secure-cookie-attributes.md) | `HttpOnly` prevents JS access, `Secure` enforces HTTPS-only transmission, and `SameSite` prevents cookies from being sent on cross-site requests. |
| 30 | [Referrer Policy](./30-referrer-policy.md) | Controls how much URL information is sent in the `Referer` header when navigating, preventing leakage of sensitive URL parameters to third parties. |
| 31 | [Permissions Policy (Feature Policy)](./31-permissions-policy.md) | An HTTP header that restricts which browser features (camera, geolocation, fullscreen) can be used by a page and its iframes. |
| 32 | [X-Content-Type-Options & MIME Sniffing](./32-mime-sniffing.md) | The `X-Content-Type-Options: nosniff` header prevents browsers from MIME-sniffing responses, stopping certain content injection attacks. |

---

## ⚫ Category 7 — Supply Chain & Dependency Security

| # | Concept | Summary |
|---|---------|---------|
| 33 | [Supply Chain Attacks](./33-supply-chain-attacks.md) | Attackers compromise widely used npm packages or CDN assets, injecting malicious code that runs in every app consuming that dependency. |
| 34 | [Subresource Integrity (SRI)](./34-subresource-integrity.md) | A browser mechanism that verifies CDN-loaded scripts or stylesheets haven't been tampered with by comparing cryptographic hashes. |
| 35 | [Vulnerable & Outdated Components](./35-vulnerable-outdated-components.md) | Using libraries with known CVEs (outdated npm packages, frameworks) exposes applications to exploits that have already been patched upstream. |
| 36 | [Third-Party Script Security](./36-third-party-scripts.md) | Analytics tags, chat widgets, and ad scripts run with full page privileges; a compromised third-party script is as dangerous as a direct XSS attack. |

---

## 🔶 Category 8 — API & Backend Communication Security

| # | Concept | Summary |
|---|---------|---------|
| 37 | [API Security & Rate Limiting](./37-api-security-rate-limiting.md) | APIs without rate limiting are vulnerable to brute force, credential stuffing, and DoS attacks; proper throttling and input validation are essential. |
| 38 | [Cryptographic Failures](./38-cryptographic-failures.md) | Transmitting or storing sensitive data without strong encryption (e.g., MD5 passwords, HTTP-only APIs, hardcoded secrets) exposes it to theft. |
| 39 | [Security Misconfiguration](./39-security-misconfiguration.md) | Default credentials, verbose error messages, open cloud storage buckets, and unnecessary services enabled in production are common misconfigurations. |
| 40 | [Software & Data Integrity Failures](./40-software-data-integrity-failures.md) | Auto-updating without signature verification, deserializing untrusted data, and CI/CD pipeline compromises allow attackers to execute arbitrary code. |
| 41 | [Insecure Deserialization](./41-insecure-deserialization.md) | Deserializing attacker-controlled data (JSON, XML, binary) without validation can lead to object injection, privilege escalation, or remote code execution. |
| 42 | [Mass Assignment](./42-mass-assignment.md) | Automatically binding request body fields to data model properties without whitelisting allows attackers to set fields like `isAdmin: true`. |

---

## 🔷 Category 9 — Availability & Monitoring

| # | Concept | Summary |
|---|---------|---------|
| 43 | [DoS & DDoS Attacks](./43-dos-ddos.md) | Overwhelming a server or client with traffic or expensive operations to make a service unavailable; mitigated with rate limiting, CDNs, and WAFs. |
| 44 | [Security Logging & Monitoring Failures](./44-security-logging-monitoring.md) | Without proper logging of authentication events, errors, and suspicious activity, breaches go undetected; logging must itself be tamper-resistant. |
| 45 | [Insecure Design](./45-insecure-design.md) | Security flaws baked into architecture (missing threat modeling, no defense in depth) that cannot be fixed by implementation patches alone. |

---

## 📋 Quick Reference — OWASP Top 10:2021 Mapping

| OWASP Rank | Name | Covered In |
|------------|------|-----------|
| A01 | Broken Access Control | [#17](./17-broken-access-control.md), [#22](./22-idor.md) |
| A02 | Cryptographic Failures | [#38](./38-cryptographic-failures.md), [#23](./23-https-tls.md) |
| A03 | Injection | [#01](./01-xss-cross-site-scripting.md), [#09](./09-sql-injection.md), [#10](./10-nosql-injection.md), [#11](./11-command-injection.md) |
| A04 | Insecure Design | [#45](./45-insecure-design.md) |
| A05 | Security Misconfiguration | [#39](./39-security-misconfiguration.md), [#15](./15-cors.md) |
| A06 | Vulnerable & Outdated Components | [#35](./35-vulnerable-outdated-components.md) |
| A07 | Identification & Authentication Failures | [#18](./18-authentication-failures.md), [#19](./19-jwt-security.md), [#21](./21-session-management.md) |
| A08 | Software & Data Integrity Failures | [#40](./40-software-data-integrity-failures.md), [#33](./33-supply-chain-attacks.md) |
| A09 | Security Logging & Monitoring Failures | [#44](./44-security-logging-monitoring.md) |
| A10 | Server-Side Request Forgery (SSRF) | [#16](./16-ssrf.md) |

---

*Sources: [OWASP Top 10](https://owasp.org/www-project-top-ten/) · [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security) · [PortSwigger Web Security Academy](https://portswigger.net/web-security) · [FreeCodeCamp JS Security](https://www.freecodecamp.org/news/how-to-secure-javascript-applications/) · [Capture The Bug – Modern Frontend Security](https://capturethebug.xyz/Blogs/Modern-Frontend-Security-Protecting-Your-Application-Beyond-XSS-and-CSRF-in-2025)*
