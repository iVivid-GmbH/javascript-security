# HTTPS and TLS Security

## Definition

HTTPS (HTTP Secure) is HTTP layered on top of TLS/SSL (Transport Layer Security/Secure Sockets Layer), creating an encrypted and authenticated communication channel. TLS is the cryptographic protocol that handles:

- **Encryption**: Data is encrypted so only the client and server can read it
- **Authentication**: Verification that you're communicating with the legitimate server (not an attacker)
- **Integrity**: Assurance that data hasn't been modified in transit
- **Perfect Forward Secrecy (PFS)**: Even if the server's private key is compromised, past session keys remain secure

TLS has replaced the older SSL protocol. SSL 3.0 and earlier versions are deprecated due to security vulnerabilities. TLS 1.0 and 1.1 are also deprecated. Modern applications should use TLS 1.2 minimum, with TLS 1.3 preferred.

## What TLS Does

### Encryption

Data transmitted between client and server is encrypted using symmetric cryptography (typically AES-256). This prevents eavesdropping:

```
Without TLS:
Client → "password=secret123" → [Network] → "password=secret123" (visible to attacker)

With TLS:
Client → "password=secret123" → [TLS Encryption] → "k7f#j2@k9x$8" (encrypted)
         → [Network] → "k7f#j2@k9x$8" (unreadable to attacker)
```

### Authentication

The server presents a digital certificate signed by a Certificate Authority (CA). This proves:

- The server is who it claims to be
- The domain ownership is verified
- The certificate is legitimate and not revoked

```
TLS Handshake:
1. Client requests server's certificate
2. Server sends certificate (public key + identity + CA signature)
3. Client verifies certificate signature using CA's public key
4. If valid, client trusts this is the legitimate server
5. Client and server establish encrypted connection
```

### Integrity

Message Authentication Codes (MACs) ensure data hasn't been tampered with:

```
Client sends: "Transfer $1000 to account 5678"
+ TLS MAC (hash of message + secret key)

Server receives and verifies:
- Recomputes MAC
- Compares to received MAC
- If they match, data wasn't modified
```

### Perfect Forward Secrecy (PFS)

With PFS, each session has its own unique encryption key. If the server's long-term private key is compromised, past sessions remain secure because they used different keys:

```
Session 1 (Jan 1): Uses key K1 (derived from server's private key + ephemeral key)
Session 2 (Jan 2): Uses key K2 (derived from server's private key + different ephemeral key)

Server's private key compromised on Jan 3:
- Can't decrypt Session 1 (K1 never stored)
- Can't decrypt Session 2 (K2 never stored)
- Future sessions using new ephemeral keys are also safe
```

## TLS Handshake Overview

The TLS handshake is the initial negotiation process that establishes a secure connection:

```
1. CLIENT HELLO
   Client → Server:
   - TLS version supported
   - Cipher suites supported
   - Random number (client_random)
   - Compression methods

2. SERVER HELLO
   Server → Client:
   - Selected TLS version
   - Selected cipher suite
   - Random number (server_random)
   - Session ID (for resumption)

3. SERVER CERTIFICATE
   Server → Client:
   - Server's X.509 certificate
   - Contains server's public key
   - Signed by a Certificate Authority

4. SERVER KEY EXCHANGE (for certain cipher suites)
   Server → Client:
   - Ephemeral public key (for PFS)
   - Signature of all previous handshake messages

5. CLIENT KEY EXCHANGE
   Client → Server:
   - Ephemeral public key (or pre-master secret encrypted with server's public key)

6. CHANGE CIPHER SPEC
   Both sides → Each other:
   - Indicates switching to encrypted communication
   - Using negotiated cipher suite

7. FINISHED
   Both sides → Each other:
   - MAC of all handshake messages (proves handshake wasn't tampered with)
   - All subsequent messages encrypted with negotiated keys

Result: Secure, encrypted channel established
        Both sides verified each other's identity (server definitely, client optionally)
```

## Dangers of HTTP (Unencrypted)

### Man-in-the-Middle (MitM) Attacks

Without HTTPS, attackers on the network can intercept all traffic:

```
User on public WiFi:
1. Victim connects to "FreeWifi" access point (controlled by attacker)
2. Victim browses HTTP website
3. Attacker uses packet capture (Wireshark) to see all traffic
4. Attacker steals: usernames, passwords, session cookies, personal data
5. Attacker can modify responses (inject malware, JavaScript, ads)
```

### Eavesdropping

All data transmitted in plaintext can be read by anyone on the network:

```
HTTP request: GET /api/bank/balance?account=12345&pin=1234
Visible to: ISP, router operators, WiFi users, network administrators, etc.
```

### Session Cookie Theft

Session cookies transmitted over HTTP are trivial to steal:

```
HTTP response:
Set-Cookie: sessionid=abc123def456ghi789jk

Attacker intercepts and uses:
Cookie: sessionid=abc123def456ghi789jk

Attacker is now impersonating the user
```

### Injection Attacks

Without HTTPS, attackers can modify responses on the fly:

```
Original HTML:
<script src="https://trusted-cdn.com/app.js"></script>

Attacker modifies response:
<script src="http://attacker.com/malware.js"></script>

User's browser executes attacker's malware
```

### DNS Spoofing

Attackers can redirect traffic to a fake server:

```
1. Victim requests example.com
2. Attacker intercepts DNS request
3. Attacker returns IP of fake server (with SSL certificate for fake domain)
4. Without HTTPS, victim wouldn't notice
5. With HTTPS, certificate doesn't match domain, browser warns user
```

## Mixed Content Issues

Mixed content occurs when an HTTPS page loads resources (images, scripts, CSS) over HTTP. This is a critical vulnerability because:

1. **Passive mixed content** (images, CSS): Can be modified by attacker, causing visual changes or injection
2. **Active mixed content** (scripts, stylesheets that execute code): Attacker can completely control page behavior, steal data, perform actions

### Example of Mixed Content Vulnerability

```html
<!-- Page loaded over HTTPS -->
<html>
  <head>
    <!-- VULNERABLE: Script loaded over HTTP -->
    <script src="http://example.com/app.js"></script>
  </head>
  <body>
    <!-- VULNERABLE: Image loaded over HTTP -->
    <img src="http://cdn.example.com/logo.png" />
  </body>
</html>
```

An attacker can:
- Replace `app.js` with malicious code
- Replace image with injected content

### Fixing Mixed Content

```html
<!-- SECURE: All resources over HTTPS -->
<html>
  <head>
    <script src="https://example.com/app.js"></script>
  </head>
  <body>
    <img src="https://cdn.example.com/logo.png" />
  </body>
</html>
```

Or use protocol-relative URLs:

```html
<!-- Works over both HTTPS and HTTP (but prefer HTTPS) -->
<script src="//example.com/app.js"></script>
```

## TLS Version Requirements

### TLS 1.0 and 1.1 (Deprecated)

- Contains known vulnerabilities
- Subject to attacks like BEAST, POODLE
- Should never be used in production
- Most browsers will remove support soon

### TLS 1.2 (Minimum Required)

- Widely supported across clients and servers
- Generally secure with proper cipher suite selection
- Recommended minimum for all new applications

### TLS 1.3 (Preferred)

- Latest version (RFC 8446)
- Faster handshakes (1-RTT instead of 2-RTT)
- Simpler, removes obsolete features
- Better security properties
- Improving browser and server support

### Configuration Example: Enforcing TLS 1.2+

```javascript
// Node.js HTTPS server
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('private-key.pem'),
  cert: fs.readFileSync('certificate.pem'),
  minVersion: 'TLSv1.2', // Reject TLS 1.1 and lower
  maxVersion: 'TLSv1.3', // Allow up to TLS 1.3
  // Explicitly enabled cipher suites (TLS 1.2 compatible)
  ciphers: [
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305',
    'ECDHE-RSA-CHACHA20-POLY1305'
  ].join(':')
};

const server = https.createServer(options, app);
```

## Cipher Suite Selection

A cipher suite specifies the algorithms used for:
- Key exchange (ECDHE, RSA, etc.)
- Encryption (AES-256-GCM, ChaCha20, etc.)
- Authentication/integrity (SHA256, POLY1305, etc.)

### Good Cipher Suites (Modern)

```
ECDHE-ECDSA-AES256-GCM-SHA384      Modern, fast, secure
ECDHE-RSA-AES256-GCM-SHA384        Most compatible
ECDHE-ECDSA-CHACHA20-POLY1305      Alternative, good mobile performance
ECDHE-RSA-CHACHA20-POLY1305        Alternative, good mobile performance
```

### Weak Cipher Suites (Avoid)

```
DES, 3DES                           Weak encryption
MD5, RC4                            Weak hashing/encryption
RSA (key exchange)                  No perfect forward secrecy
NULL ciphers                        No encryption (deprecated)
```

### Cipher Suite Order

The server should prefer strong ciphers and disable weak ones:

```javascript
const options = {
  // Prioritize modern, secure ciphers
  ciphers: [
    // TLS 1.3 cipher suites (don't specify, they're enforced)
    'ECDHE-ECDSA-AES256-GCM-SHA384',   // TLS 1.2
    'ECDHE-RSA-AES256-GCM-SHA384',     // TLS 1.2
    'ECDHE-ECDSA-CHACHA20-POLY1305',   // TLS 1.2
    'ECDHE-RSA-CHACHA20-POLY1305'      // TLS 1.2
  ].join(':'),
  // Disable weak ciphers
  honorCipherOrder: true // Server chooses cipher, not client
};
```

## Certificate Management

### What is an SSL/TLS Certificate?

A certificate is a digital document containing:
- Server's public key
- Server's domain name
- Certificate Authority's digital signature
- Validity dates
- Certificate chain (for cross-signing)

### Let's Encrypt (Free Certificates)

Let's Encrypt provides free, automated certificate issuance:

```bash
# Install Certbot
apt-get install certbot python3-certbot-nginx

# Obtain certificate for domain
certbot certonly --standalone -d example.com -d www.example.com

# Automatic renewal (runs daily via cron)
certbot renew --quiet

# Certificates stored in:
# /etc/letsencrypt/live/example.com/
```

### Certificate Chain

Certificates are signed by Certificate Authorities in a chain:

```
Root CA (self-signed, in browser's trust store)
└── Intermediate CA (signed by Root CA)
    └── Server Certificate (signed by Intermediate CA)

Browser verifies chain:
1. Does CA signature match server cert's hash? ✓
2. Does intermediate signature match root CA cert? ✓
3. Is root CA in browser's trust store? ✓
4. Is domain on certificate? ✓
→ Certificate is valid, trust server
```

### Certificate Pinning

For extra security, applications can pin to specific certificates or public keys (covered in detail in a separate section):

```javascript
const https = require('https');
const crypto = require('crypto');

// Pin specific certificate public key
const pinnedPublicKey = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

https.get('https://api.example.com', (res) => {
  const cert = res.socket.getPeerCertificate();
  const publicKeyDer = cert.pubkey;
  const publicKeyHash = crypto
    .createHash('sha256')
    .update(publicKeyDer)
    .digest('base64');

  if (publicKeyHash !== pinnedPublicKey) {
    throw new Error('Certificate pinning failed!');
  }
});
```

## Forcing HTTPS in Node.js/Express

### Redirect HTTP to HTTPS

```javascript
const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');

const app = express();

// Middleware to redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (req.secure) {
    // Already HTTPS
    next();
  } else {
    // Redirect to HTTPS
    res.redirect(`https://${req.header('host')}${req.url}`);
  }
});

// HTTPS options
const httpsOptions = {
  key: fs.readFileSync('private-key.pem'),
  cert: fs.readFileSync('certificate.pem')
};

// Create HTTPS server
https.createServer(httpsOptions, app).listen(443);

// Create HTTP server for redirects
http.createServer((req, res) => {
  res.writeHead(301, { 'Location': `https://${req.headers.host}${req.url}` });
  res.end();
}).listen(80);
```

### Using Helmet Middleware

```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Helmet sets security headers including HSTS
app.use(helmet());

// HSTS header forces HTTPS for future connections
app.use(helmet.hsts({
  maxAge: 31536000,           // 1 year in seconds
  includeSubDomains: true,
  preload: true               // Eligible for HSTS preload list
}));

// Redirect HTTP to HTTPS
app.use((req, res, next) => {
  if (!req.secure) {
    return res.redirect(`https://${req.header('host')}${req.url}`);
  }
  next();
});
```

### Nginx Configuration

```nginx
# Redirect all HTTP traffic to HTTPS
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    # Certificate and key
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS header
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Rest of configuration
    location / {
        proxy_pass http://localhost:3000;
    }
}
```

## Best Practices

1. **Always use HTTPS**: Never transmit sensitive data over HTTP
2. **Use TLS 1.2 minimum**: Disable TLS 1.0, 1.1, and SSL 3.0
3. **Prefer TLS 1.3**: Use TLS 1.3 where supported for better security and performance
4. **Select strong cipher suites**: Use ECDHE-based suites with AES-256-GCM or ChaCha20-Poly1305
5. **Enable Perfect Forward Secrecy (PFS)**: Use ephemeral keys in key exchange
6. **Obtain certificates from legitimate CAs**: Use Let's Encrypt for free, automated certificates
7. **Keep certificates valid**: Monitor expiration dates and renew before expiry
8. **Implement HSTS**: Force HTTPS for all future connections with the Strict-Transport-Security header
9. **Avoid mixed content**: Load all resources (scripts, images, CSS) over HTTPS
10. **Use certificate pinning for critical APIs**: Pin to specific certificates or public keys
11. **Validate certificates**: Always verify certificate chain and domain names
12. **Monitor certificate transparency logs**: Watch for unauthorized certificate issuance
13. **Use certificate status checking**: Implement OCSP stapling to check certificate revocation
14. **Disable older TLS versions on all servers**: HTTP, SMTP, database connections, etc.
15. **Test TLS configuration**: Use tools like testssl.sh or SSLLabs to verify your configuration
