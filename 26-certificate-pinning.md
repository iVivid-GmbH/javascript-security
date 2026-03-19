# Certificate Pinning and Trust Management

## Definition

Certificate pinning is a security technique where an application cryptographically verifies that the server's certificate (or public key) matches a specific expected value that was pinned into the application. Instead of relying solely on the Certificate Authority (CA) system, the application trusts only specific certificates or public keys.

There are three main types of pinning:

1. **Leaf certificate pinning**: Pin to the end-entity certificate used by the server
2. **Intermediate CA certificate pinning**: Pin to the CA that signs the end-entity certificate
3. **Public key pinning**: Pin to the public key extracted from a certificate

Pinning provides an additional layer of security against:
- Compromised Certificate Authorities
- Rogue certificates issued by legitimate CAs
- Man-in-the-Middle attacks using fraudulent but "valid" certificates
- Network compromises

## Why Certificate Authorities Can Be Compromised

### The DigiNotar Incident (2011)

DigiNotar was a Dutch Certificate Authority that was compromised by attackers. The attacker issued fraudulent certificates for major domains including:
- google.com
- yahoo.com
- facebook.com
- skype.com
- microsoft.com

The attack worked like this:

```
1. Attacker gained unauthorized access to DigiNotar's systems
2. Attacker used DigiNotar's private key to issue fraudulent certificates
3. DigiNotar, as a trusted CA, signed these forged certificates
4. Browsers trusted these certificates (DigiNotar was in browser's trust store)
5. Attacker could now perform MITM attacks on any of these services
6. Users would connect to attacker's server, thinking they're on legitimate site
7. Certificate appeared valid (signed by trusted CA, domain matched)

Impact:
- Attackers impersonated Google, Yahoo, Facebook, etc.
- Users were compromised without knowing it
- Attack wasn't detected until later

Result:
- DigiNotar was shut down
- All DigiNotar certificates were revoked
- Incident led to development of pinning and Certificate Transparency
```

### Other CA Compromises

Several other CAs have been compromised:
- **GlobalSign**: Private key compromise (2015)
- **COMODO**: Hacked by attackers (2011)
- **StartCom**: Revoked from browsers due to practices (2016)
- **China's CAs**: Suspected issuance of unauthorized certificates

Each compromise showed that trusting CAs alone is insufficient for high-security applications.

## What Pinning Does

Pinning restricts trust to specific certificates or keys, bypassing the CA system for that domain:

```
Without Pinning (normal TLS):
1. Browser gets certificate for bank.example.com
2. Browser checks: Is it signed by a trusted CA? YES
3. Browser checks: Does domain match? YES
4. Browser trusts it

Problem: If any trusted CA is compromised, attacker can issue fake certificate
         Browser would trust the fake certificate

With Pinning:
1. Application (or browser) has pinned certificate/public key for bank.example.com
2. Browser gets certificate for bank.example.com
3. Browser checks: Is it signed by a trusted CA? YES
4. Browser checks: Does domain match? YES
5. Browser checks: Does it match pinned certificate/key? NO
6. Browser rejects connection (certificate mismatch)

Result: Even if attacker has a valid certificate from compromised CA, it won't match pin
        Attacker cannot perform MITM even with "valid" certificate
```

## HPKP (HTTP Public Key Pinning) - Deprecated

### What HPKP Was

HPKP was an HTTP header that allowed servers to tell browsers which public keys were legitimate:

```
Public-Key-Pins: pin-sha256="AAAAAAAAAAAAAAAA="; pin-sha256="BBBBBBBBBBBBBBBB="; max-age=2592000
```

The browser would pin these public keys and reject any certificate that didn't use one of these pinned keys.

### Why HPKP Was Problematic

1. **Operational Difficulty**:
   ```
   If you lose your private key, you must rotate to a new key.
   But all browsers have the old key pinned.
   Users get connection refused errors.
   Recovery requires waiting for max-age to expire.
   ```

2. **Backup Key Management**:
   ```
   You must have a backup key pinned in case of key compromise.
   Managing multiple keys across infrastructure is complex.
   ```

3. **Pinning Failures**:
   ```
   If you misconfigure pinning, you lock users out.
   Misconfiguration: pin-sha256="WRONG_KEY=" max-age=63072000
   Users can't access site for 2 years.
   ```

4. **max-age Issues**:
   ```
   Short max-age (e.g., 1 day): Pinning is ineffective
   Long max-age (e.g., 2 years): Misconfiguration locks out users
   No good middle ground.
   ```

5. **Browser Support Declining**:
   ```
   Chrome removed HPKP support
   Firefox removed HPKP support
   Safari never fully supported it
   Edge never fully supported it
   ```

6. **Report-Only Mode Issues**:
   ```
   Testing with report-only didn't catch all misconfigurations
   Some issues only appeared in enforce mode.
   ```

### HPKP Deprecation

HPKP has been deprecated by the W3C and removed from major browsers. It's no longer recommended. Google recommends using:
- Certificate Transparency logs
- CAA records
- Certificate pinning via application code (for mobile apps)

## Modern Alternatives to HPKP

### Certificate Transparency (CT) Logs

Certificate Transparency requires CAs to log all issued certificates in publicly auditable logs:

```
1. CA issues certificate for your domain
2. CA must submit certificate to CT logs
3. Certificate gets a Signed Certificate Timestamp (SCT)
4. Browser verifies SCT in certificate
5. Browser can audit CT logs to detect unauthorized certificates

Benefits:
- Unauthorized certificates are logged and discoverable
- Organizations can monitor CT logs for their domains
- No key management burden
- Works across all CAs
```

Monitoring CT logs for your domain:

```bash
# Use services like:
# https://crt.sh/ - Search and monitor certificates
# https://certspotter.com/ - Email alerts for issued certificates
# https://censys.io/ - Certificate monitoring

# Example: Watch for certificates issued for your domain
curl -s "https://crt.sh/?q=example.com&output=json" | jq
```

### CAA DNS Records

Certification Authority Authorization (CAA) DNS records restrict which CAs can issue certificates for your domain:

```
# Only allow Let's Encrypt and DigiCert to issue certificates
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 issue "digicert.com"

# If attacker compromises other CA, they cannot issue valid certificate for example.com
# DNS lookup fails, CA cannot issue
```

Setting up CAA records:

```bash
# Add CAA records in your DNS provider
# Zone file example:
example.com.  3600  IN  CAA  0 issue "letsencrypt.org"
example.com.  3600  IN  CAA  0 issue "digicert.com"
example.com.  3600  IN  CAA  0 iodef "mailto:security@example.com"

# Verify:
dig +short CAA example.com
```

### Application-Level Certificate Pinning

For critical applications (especially APIs), implement pinning in your code:

```javascript
// Pin to specific certificate public key
const https = require('https');
const crypto = require('crypto');

const pinnedKeys = [
  'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // Current key
  'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='  // Backup key
];

function validateCertificate(socket) {
  const cert = socket.getPeerCertificate();
  const publicKeyDer = cert.pubkey;
  const publicKeyHash = crypto
    .createHash('sha256')
    .update(publicKeyDer)
    .digest('base64');

  const pinHash = `sha256/${publicKeyHash}`;

  if (!pinnedKeys.includes(pinHash)) {
    throw new Error(`Certificate pinning failed! Got ${pinHash}`);
  }
}

https.get('https://api.example.com', (res) => {
  validateCertificate(res.socket);
  // Connection is valid, use response
});
```

### Application-Level Policy Framework (ACME)

Use ACME (Automated Certificate Management Environment) with pinning:

```javascript
// Pin using certificate chain
const https = require('https');

const options = {
  cert: fs.readFileSync('cert.pem'),
  key: fs.readFileSync('key.pem'),
  // Pin to intermediate CA certificate
  ca: [
    fs.readFileSync('intermediate.pem'),
    fs.readFileSync('backup_intermediate.pem')
  ]
};

https.createServer(options, app).listen(443);
```

## How Pinning Works in Mobile Apps vs Browsers

### Mobile Apps (Native Implementation)

Mobile apps have direct control over networking, allowing sophisticated pinning:

```swift
// iOS Example - Certificate pinning with backup
class CertificatePinning {
  let pinnedCertificates = [
    // Current certificate
    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    // Backup certificate
    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
  ]

  func validateCertificate(_ challenge: URLAuthenticationChallenge) -> Bool {
    guard let cert = challenge.protectionSpace.serverTrust?.certificate else {
      return false
    }

    let publicKey = SecCertificateCopyPublicKey(cert)
    let hash = sha256(publicKey)

    return pinnedCertificates.contains(hash)
  }
}
```

Advantages:
- Direct control over certificate validation
- Can pin to multiple keys (current + backup)
- Can rotate keys without forcing app update
- Can fail gracefully if pinned certificate isn't valid

Disadvantages:
- Must update app to change pinned keys
- App update distribution takes time
- Can lock users out if not careful

### Browsers

Browsers now support limited pinning through:

1. **Certificate Transparency (CT)**: Built into modern browsers
2. **Public Key Pinning Extension (PKPX)**: Experimental, limited support
3. **DNS CAA**: Server-side restriction, not browser-enforced

Browsers generally don't support client-side pinning because:
- HTTP headers are unencrypted and can be spoofed
- Pinning to specific certificates would require frequent updates
- Risk of locking users out
- CA system with Certificate Transparency is preferred

## Best Practices

### For APIs and Backend Services

1. **Implement certificate pinning**: Pin to your server's certificate or public key
2. **Have backup keys**: Pin to both current and next certificate
3. **Plan key rotation**: Establish procedure for rotating pinned keys
4. **Test thoroughly**: Verify pinning doesn't block legitimate traffic
5. **Monitor certificate logs**: Check Certificate Transparency logs for your domain
6. **Use CAA records**: Restrict which CAs can issue certificates
7. **Implement monitoring**: Alert on certificate validation failures
8. **Document procedures**: Keep team informed of pinning strategy

### For Web Applications

1. **Use HTTPS with strong certificates**: TLS 1.2+ with modern ciphers
2. **Monitor Certificate Transparency logs**: Detect unauthorized certificates
3. **Set up CAA records**: Restrict certificate issuance
4. **Use HSTS**: Prevent SSL stripping
5. **Validate certificates**: Never disable certificate validation
6. **Consider CSP (Content Security Policy)**: Additional layer of protection
7. **Use subresource integrity (SRI)**: For external scripts and stylesheets

### For Mobile Apps

1. **Implement certificate pinning**: Pin to multiple keys (current + backups)
2. **Plan for certificate rotation**: Have procedure for updating pinned keys
3. **Fail securely**: Don't ignore pinning failures
4. **Monitor errors**: Track pinning validation failures
5. **Use TOFU (Trust On First Use)**: For non-critical connections
6. **Test certificate rotation**: Simulate certificate change scenarios
7. **Document pin rotation process**: Team should understand procedures

### Certificate Rotation Strategy

```
Phase 1 (Weeks 1-2):
- Generate new certificate key pair
- Pin both old and new certificate in app
- Deploy updated app
- Some users update immediately

Phase 2 (Weeks 2-4):
- Deploy new certificate on server
- Old certificate still pinned as backup
- Any user with updated app connects to new cert
- Users with old app still connect to old cert (which is still running)

Phase 3 (Weeks 4-8):
- Wait for most users to update app
- Ensure new certificate is trusted by all updated clients

Phase 4 (Weeks 8+):
- Once confident most users have updated
- Retire old certificate
- Only new certificate pinned in next app version
```

### Key Takeaway

While HPKP is deprecated, certificate pinning via application code remains valuable for:
- APIs with fixed endpoints
- Critical security operations
- Systems where you control both client and server
- Applications that cannot rely on browser certificate handling

For websites, Certificate Transparency + CAA records provides sufficient protection without the operational burden of pinning.
