# HSTS - HTTP Strict Transport Security

## Definition

HTTP Strict Transport Security (HSTS) is an HTTP response header that instructs browsers to:

1. Always connect to the server using HTTPS (not HTTP)
2. Reject any attempt to connect via HTTP
3. Remember this preference for a specified time period

HSTS essentially says: "For the next N seconds, always talk to me over HTTPS. If you see an HTTP request, reject it immediately before trying to connect."

The header is: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

Without HSTS, a user's first visit to a site might be vulnerable to SSL stripping attacks. HSTS protects subsequent visits by preventing any HTTP connection attempts.

## SSL Stripping Attack

### How the Attack Works

SSL stripping (also called protocol downgrade attack) is a Man-in-the-Middle (MitM) technique that removes the "S" from HTTPS, downgrading the connection to HTTP. Here's the process:

```
1. Victim intends to visit https://bank.example.com
2. Victim types: bank.example.com (without https://)
3. Browser defaults to HTTP: http://bank.example.com
4. Victim's request passes through attacker's network (public WiFi)

5. Attacker intercepts HTTP request
6. Attacker proxies the request to HTTPS:
   Attacker → HTTPS → bank.example.com (encrypted)
7. Bank responds over HTTPS with login page
8. Attacker strips HTTPS and responds to victim over HTTP:
   Victim ← HTTP ← Attacker ← HTTPS ← Bank

9. Victim sees login form, thinks connection is secure
10. Victim enters username and password
11. Password is transmitted in plaintext (HTTP)
12. Attacker captures password

13. Attacker can now log in to victim's bank account
```

### Why It Works

- Users often omit "https://" when typing URLs
- Without HSTS, browsers allow HTTP connections
- The attacker can convincingly proxy to the real server
- HTTPS warning doesn't appear because the victim is using HTTP
- Victim's password is transmitted in plaintext

## How HSTS Prevents SSL Stripping

Once a browser receives an HSTS header, subsequent connections are automatically upgraded to HTTPS:

```
First Visit (without HSTS protection):
1. Victim types: bank.example.com
2. Browser defaults to HTTP
3. Attacker can SSL strip (as shown above)

First Response (with HSTS):
Bank sets header: Strict-Transport-Security: max-age=31536000
Browser stores: "bank.example.com requires HTTPS for 31536000 seconds"

Second Visit (with HSTS protection):
1. Victim types: bank.example.com
2. Browser checks stored HSTS entries
3. Browser finds: "bank.example.com requires HTTPS"
4. Browser IMMEDIATELY upgrades to: https://bank.example.com
5. Browser rejects any HTTP response from the server
6. Attacker cannot SSL strip because browser won't accept HTTP
```

This prevents SSL stripping on all subsequent connections for the duration specified by max-age.

## The Strict-Transport-Security Header Syntax

The header takes the following format:

```
Strict-Transport-Security: <directive>[; <directive>]
```

### Directive: max-age

Specifies how long (in seconds) the browser should enforce HTTPS for this domain.

```
max-age=31536000    # 1 year (31,536,000 seconds)
max-age=10886400    # ~4 months
max-age=63072000    # 2 years
```

Once max-age expires, the browser will accept HTTP connections again until a new HSTS header is received.

### Directive: includeSubDomains

When present, HSTS applies to all subdomains of the specified domain.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains

// Applies to:
https://example.com
https://www.example.com
https://api.example.com
https://cdn.example.com
// etc.
```

Without includeSubDomains, HSTS only applies to the exact domain that set the header.

### Directive: preload

When present, indicates the domain is eligible for inclusion in the HSTS preload list. This is a hardcoded list in browsers of domains that require HTTPS.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

To be eligible for the preload list, you must:
- Set max-age to at least 31536000 (1 year)
- Include includeSubDomains
- Include preload
- Have valid HTTPS with a trusted certificate
- Register at https://hstspreload.org/

### Complete Example

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

This tells the browser:
- Use HTTPS for the next 2 years
- Apply to all subdomains
- This domain is in the preload list
- All browsers will enforce HTTPS even for first visits

## HSTS Preload List

The HSTS preload list is a hardcoded list of domains that require HTTPS, included in browsers like Chrome, Firefox, Safari, and Edge. It's maintained at https://hstspreload.org/.

### Why Preload Lists Matter

Without the preload list:
```
First visit to bank.example.com → HTTP → SSL stripping possible
Second visit to bank.example.com → HTTPS (from HSTS) → Safe
```

With the preload list:
```
First visit to bank.example.com → HTTPS (hardcoded in browser) → No SSL stripping
Second visit to bank.example.com → HTTPS (from HSTS) → Safe
```

The preload list eliminates the "first visit" vulnerability for critical domains like banks.

### Submitting to the Preload List

1. Set the HSTS header correctly:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

2. Verify with HTTPS (no errors):
- Certificate must be valid
- Must use a supported CA (not self-signed)
- No mixed content or insecure dependencies

3. Visit https://hstspreload.org/
4. Enter your domain
5. Pass all checks (may take days or weeks for review)
6. Your domain is added to the list
7. Next browser update includes your domain

## How to Enable HSTS in Express/Node.js

### Using Helmet Middleware (Recommended)

```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Enable HSTS with Helmet
app.use(helmet.hsts({
  maxAge: 31536000,          // 1 year in seconds
  includeSubDomains: true,   // Apply to subdomains
  preload: true              // Eligible for preload list
}));

app.get('/', (req, res) => {
  res.send('HSTS enabled!');
});

app.listen(3000);
```

This sets the header on every response automatically.

### Manual Header Setting

```javascript
const express = require('express');
const app = express();

// Manually set HSTS header on all responses
app.use((req, res, next) => {
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  next();
});

app.get('/', (req, res) => {
  res.send('HSTS enabled!');
});

app.listen(3000);
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    # HSTS header
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Rest of configuration...
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}
```

### Apache Configuration

```apache
# In .htaccess or Apache config
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
</IfModule>

# Redirect HTTP to HTTPS
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```

## Caveats and Limitations

### First Visit Vulnerability

Even with HSTS, the very first visit to a domain is vulnerable to SSL stripping if the user types the domain without https://:

```
User's first ever visit to bank.example.com:
1. Browser has no HSTS entry (first visit)
2. User types: bank.example.com (no https://)
3. Browser defaults to HTTP
4. Attacker can SSL strip

After first response with HSTS header:
Browser stores: "bank.example.com requires HTTPS"
All subsequent visits are protected
```

**Mitigation**: Register for the HSTS preload list so the domain is hardcoded in browsers.

### Domain Migration Issues

If you migrate from one domain to another, HSTS can cause problems:

```
Old domain: oldsite.example.com (with HSTS set to 2 years)
New domain: newsite.example.com

User tries to visit oldsite.example.com:
1. Browser has HSTS entry for oldsite.example.com
2. Browser tries HTTPS: https://oldsite.example.com
3. Server is down or redirects to HTTP
4. Browser refuses HTTP connection (HSTS prevents it)
5. User sees error: "Connection refused"
6. User cannot access the redirect to newsite.example.com
```

**Mitigation**:
- Set max-age to a reasonable value (not too long)
- When redirecting, ensure HTTPS is available
- Gradually transition users to new domain

### Subdomain Issues

With includeSubDomains, all subdomains are affected:

```
Main domain: example.com (HSTS with includeSubDomains)
Subdomain: oldapi.example.com (no longer available)

User tries to visit oldapi.example.com:
1. Browser enforces HTTPS (due to parent domain's HSTS)
2. oldapi subdomain doesn't have a valid HTTPS certificate
3. Connection fails
4. User sees error
```

**Mitigation**:
- Ensure all subdomains support HTTPS before enabling includeSubDomains
- Use separate HSTS headers for subdomains if needed

### HSTS Timeout Issues

Once set, HSTS cannot be easily removed:

```
Domain sets: max-age=63072000 (2 years)
Later, domain tries to remove HSTS by setting:
max-age=0

Problem:
- You must serve this response over HTTPS (HSTS prevents HTTP)
- If HTTPS infrastructure fails, browsers still enforce HSTS
- Users cannot access the site
```

**Mitigation**:
- Start with a reasonable max-age (not too long)
- Only set HSTS when confident
- Have a solid HTTPS infrastructure
- Monitor certificate renewal

## Best Practices

1. **Always set HSTS**: Even if you think your users will use HTTPS, set the header
2. **Start with a shorter max-age**: Use 1 month (2592000 seconds) initially, increase to 1 year (31536000) once stable
3. **Include includeSubDomains**: Protect all subdomains, but ensure they all support HTTPS
4. **Test thoroughly before preload**: Use https://hstspreload.org/ to test your domain
5. **Register for preload list**: Protect even first-time visitors
6. **Monitor HSTS issues**: Track users who encounter HSTS errors
7. **Plan for domain migration**: If changing domains, set shorter max-age values
8. **Ensure HTTPS is stable**: HSTS breaks the site if HTTPS fails
9. **Use Helmet or similar**: Avoid manual header setting, use middleware
10. **Combine with other headers**: HSTS works best alongside CSP, X-Frame-Options, etc.
11. **Test across browsers**: Verify HSTS behavior in Chrome, Firefox, Safari, Edge
12. **Use report-uri for testing**: Consider Content-Security-Policy-Report-Only before enforcing
13. **Document your HSTS policy**: Team members should understand max-age and implications
14. **Plan certificate renewal**: Automate renewal to prevent HSTS from breaking the site
15. **Consider gradual rollout**: Enable HSTS for a percentage of users, monitor, then enable globally
