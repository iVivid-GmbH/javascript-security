# Cryptographic Failures (OWASP A02)

## Definition

**Cryptographic Failures** (OWASP A02:2021) refers to the inadequate protection of sensitive data through improper use or absence of cryptography. This includes data transmitted over the network without encryption, data stored in plaintext in databases, weak cryptographic algorithms, hardcoded secrets in source code, and incorrect implementation of encryption/hashing. Cryptographic failures expose user data to theft, manipulation, and misuse. The consequences include identity theft, financial fraud, unauthorized access, and regulatory violations (GDPR, HIPAA, PCI-DSS).

## Data in Transit: HTTP vs HTTPS

### HTTP: Unencrypted Communication

```
Client Request:
GET /api/user/profile HTTP/1.1
Authorization: Bearer abc123token
Host: example.com

Network:
- Attacker can intercept request
- See authentication token clearly
- See all user data in response
- Modify request in-flight
- Inject code into response
```

### HTTPS: Encrypted Communication

```
Client Request (Encrypted):
TLS 1.3 encrypted data...
[contents hidden from attacker]

Benefits:
- Encryption prevents eavesdropping
- Authentication verifies server identity
- Integrity prevents tampering
- Forward secrecy protects past sessions
```

### Vulnerable Code: HTTP

```javascript
// ❌ VULNERABLE: HTTP protocol
const express = require('express');
const app = express();

app.get('/api/user/profile', (req, res) => {
  // Data transmitted in plaintext over HTTP
  res.json({
    userId: '12345',
    email: 'user@example.com',
    password: 'SecurePass123!'  // ❌ Even if encrypted in DB, exposed in transit!
  });
});

// Attack scenario:
// 1. User visits http://example.com
// 2. Attacker on same WiFi (coffee shop)
// 3. Attacker runs: tcpdump -i wlan0 'tcp port 80'
// 4. Attacker sees all data in plaintext
```

### Secure Code: HTTPS

```javascript
// ✅ SECURE: HTTPS protocol
const https = require('https');
const fs = require('fs');
const express = require('express');

const options = {
  key: fs.readFileSync('private-key.pem'),
  cert: fs.readFileSync('certificate.pem')
};

const app = express();

app.get('/api/user/profile', (req, res) => {
  res.json({
    userId: '12345',
    email: 'user@example.com'
  });
});

https.createServer(options, app).listen(443);

// Also: Redirect HTTP to HTTPS
const httpApp = express();
httpApp.use((req, res) => {
  res.redirect(301, `https://${req.host}${req.url}`);
});
http.createServer(httpApp).listen(80);
```

## Data at Rest: Storage Security

### Plaintext Storage (Vulnerable)

```javascript
// ❌ VULNERABLE: Passwords stored in plaintext
const db = require('sqlite3');

db.run('CREATE TABLE users (id INTEGER, email TEXT, password TEXT)');

app.post('/register', (req, res) => {
  const { email, password } = req.body;

  // ❌ VULNERABLE: Storing plaintext password
  db.run(
    'INSERT INTO users (email, password) VALUES (?, ?)',
    [email, password]  // Password stored as-is!
  );

  res.json({ success: true });
});

// If database is breached:
// SELECT * FROM users;
// email          | password
// user@ex.com    | SecurePass123!
// admin@ex.com   | AdminPassword

// All passwords immediately compromised
```

### Properly Hashed Passwords (Secure)

```javascript
// ✅ SECURE: Using bcrypt for password hashing
const bcrypt = require('bcrypt');

app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // ✅ Hash password with bcrypt
  const saltRounds = 12;  // Computational cost
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  db.run(
    'INSERT INTO users (email, password_hash) VALUES (?, ?)',
    [email, hashedPassword]  // Hash stored, not password
  );

  res.json({ success: true });
});

// If database is breached:
// SELECT * FROM users;
// email          | password_hash
// user@ex.com    | $2b$12$dXjsSn...  (cannot be reversed)
// admin@ex.com   | $2b$12$bHsQaV...  (cannot be reversed)

// Passwords are still protected
```

## Weak Cryptographic Algorithms

### Vulnerable: MD5 and SHA1 for Passwords

```javascript
// ❌ VULNERABLE: Using MD5 for password hashing
const crypto = require('crypto');

function hashPassword(password) {
  // MD5 is cryptographically broken
  return crypto.createHash('md5').update(password).digest('hex');
}

// Problems with MD5:
// 1. Fast to compute (good for attackers, bad for defense)
// 2. Rainbow tables available online
// 3. Hash collisions demonstrated
// 4. Precomputed for all common passwords

// Attack:
// User password: "password123"
// MD5 hash: 482c811da5d5b4bc6d497ffa98491e38
// Search online: hash instantly maps to "password123"
```

### Vulnerable: SHA1 for Passwords

```javascript
// ❌ VULNERABLE: Using SHA1 for passwords
crypto.createHash('sha1').update(password).digest('hex');

// SHA1 problems:
// 1. Still too fast for password hashing
// 2. Collision attacks possible
// 3. No salt by default
// 4. No computational work factor

const hashedPassword = crypto
  .createHash('sha1')
  .update(password)
  .digest('hex');

// Result: user "password123" → 482c811da5d5b4bc6d497ffa98491e38
// Same hash every time (no salt!)
// If two users use same password, hashes are identical
```

### Vulnerable: ECB Mode for Encryption

```javascript
// ❌ VULNERABLE: Using ECB (Electronic Codebook) mode
const crypto = require('crypto');

function encryptDataECB(data, key) {
  const cipher = crypto.createCipher('aes-128-ecb', key);
  return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// ECB Problems:
// 1. Same plaintext block → same ciphertext block
// 2. Reveals patterns in data
// 3. Deterministic (no randomness)

// Example:
const data1 = 'AAAABBBBAAAABBBB';
const encrypted1 = encryptDataECB(data1, key);
// Result: 'AAAAAAAABBBBBBBB' (pattern visible!)

// If attacker knows plaintext structure:
// Can partially decrypt without knowing key
```

### Secure: Bcrypt, Argon2, Scrypt

```javascript
// ✅ SECURE: Bcrypt with proper work factor
const bcrypt = require('bcrypt');

async function hashPassword(password) {
  // Computational cost factor
  // Higher = slower = better against brute force
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// ✅ SECURE: Argon2 (memory-hard function)
const argon2 = require('argon2');

async function hashPassword(password) {
  return await argon2.hash(password, {
    type: argon2.argon2id,  // Latest type
    memoryCost: 2**16,       // 64 MB memory
    timeCost: 3,             // 3 iterations
    parallelism: 1
  });
}

async function verifyPassword(password, hash) {
  return await argon2.verify(hash, password);
}

// ✅ SECURE: Scrypt
const crypto = require('crypto');

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, 'salt', 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey.toString('hex'));
    });
  });
}
```

### Secure: Encryption with Proper Mode

```javascript
// ✅ SECURE: CBC or GCM mode with IV
const crypto = require('crypto');

function encryptData(data, encryptionKey) {
  // Generate random IV each time
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',  // GCM mode (authenticated encryption)
    encryptionKey,
    iv
  );

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Get authentication tag
  const authTag = cipher.getAuthTag();

  // Return IV + authTag + encrypted data
  return {
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    encrypted: encrypted
  };
}

function decryptData(encryptedData, decryptionKey) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    decryptionKey,
    Buffer.from(encryptedData.iv, 'hex')
  );

  // Set auth tag before decryption
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
```

## Hardcoded Secrets in Source Code

### Vulnerable: Secrets in Code

```javascript
// ❌ VULNERABLE: Secrets in source code
const express = require('express');
const app = express();

// ❌ Database password hardcoded
const dbPassword = 'super_secret_db_pass_2024';

// ❌ API key hardcoded
const apiKey = 'sk-1234567890abcdef1234567890';

// ❌ Private key hardcoded
const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCA...
-----END PRIVATE KEY-----`;

// ❌ JWT secret hardcoded
const jwtSecret = 'super_secret_jwt_key_123';

// ❌ Third-party API credentials
const stripeKey = 'sk_live_abc123...';

// Problems:
// 1. Secrets visible in source code
// 2. Secrets committed to Git history
// 3. Visible in GitHub repositories
// 4. Anyone with repo access has secrets
// 5. Exposed if repository breached

// Can be found:
// - grep -r "sk_" .
// - git log -S "secret"
// - GitHub search: sk_ filename:package.json
```

### Secure: Environment Variables

```javascript
// ✅ SECURE: Use environment variables
const express = require('express');
const app = express();

// Load from environment
const dbPassword = process.env.DATABASE_PASSWORD;
const apiKey = process.env.API_KEY;
const privateKey = process.env.PRIVATE_KEY;
const jwtSecret = process.env.JWT_SECRET;

// .env file (not committed to Git)
// DATABASE_PASSWORD=super_secret_db_pass_2024
// API_KEY=sk-1234567890abcdef1234567890
// JWT_SECRET=super_secret_jwt_key_123

// .gitignore
// .env
// .env.local
// *.key
// *.pem

// Usage in code
if (!process.env.DATABASE_PASSWORD) {
  throw new Error('DATABASE_PASSWORD environment variable is required');
}

const dbPassword = process.env.DATABASE_PASSWORD;
```

### Secure: Secrets Management

```javascript
// ✅ SECURE: Using AWS Secrets Manager
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager();

async function getSecret(secretName) {
  try {
    const response = await secretsManager.getSecretValue({
      SecretId: secretName
    }).promise();

    if (response.SecretString) {
      return JSON.parse(response.SecretString);
    } else {
      return response.SecretBinary;
    }
  } catch (error) {
    console.error('Error retrieving secret:', error);
    throw error;
  }
}

// Usage
const dbPassword = await getSecret('prod/database/password');
const apiKey = await getSecret('prod/api/key');

// ✅ SECURE: Using HashiCorp Vault
const vault = require('node-vault');

const client = vault({
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN
});

async function getSecret(path) {
  const secret = await client.read(path);
  return secret.data.data;  // Return secret value
}

// Usage
const secrets = await getSecret('secret/prod/database');
```

## Sensitive Data in Logs

### Vulnerable: Logging Sensitive Data

```javascript
// ❌ VULNERABLE: Logging sensitive information
const express = require('express');
const app = express();

// ❌ Logs entire request including passwords
app.use((req, res, next) => {
  console.log('Request:', req.body);  // NEVER log bodies containing passwords!
  next();
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // ❌ Logging password
  console.log(`User ${email} attempting login with password ${password}`);

  // ❌ Logging entire user object
  const user = db.findUser(email);
  console.log('User found:', user);  // May contain private data

  res.json({ success: true });
});

// Problems:
// 1. Passwords visible in application logs
// 2. Logs stored on disk unencrypted
// 3. Log aggregation services see passwords
// 4. Multiple copies: app logs, syslog, ELK stack, backups
// 5. If logs breached, all passwords exposed

// Log files may be viewed by:
// - Support staff
// - Security team
// - Accidentally shared with third parties
// - Stored in backup without proper encryption
```

### Secure: Filtering Sensitive Data

```javascript
// ✅ SECURE: Filter sensitive data before logging
const express = require('express');
const app = express();

// Create logger that filters sensitive fields
function createSafeLogger() {
  const sensitiveFields = [
    'password',
    'pin',
    'ssn',
    'creditCard',
    'cvv',
    'apiKey',
    'token',
    'secret',
    'bearerToken'
  ];

  return {
    log: (message, data = {}) => {
      // Clone and redact
      const safe = JSON.parse(JSON.stringify(data));

      sensitiveFields.forEach(field => {
        if (safe[field]) {
          safe[field] = '***REDACTED***';
        }
      });

      console.log(message, safe);
    }
  };
}

const logger = createSafeLogger();

app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // ✅ Logs without password
  logger.log('Login attempt for:', { email, password });
  // Output: Login attempt for: { email: 'user@ex.com', password: '***REDACTED***' }

  // ✅ Don't log sensitive user fields
  const user = db.findUser(email);
  if (user) {
    // Only log non-sensitive fields
    logger.log('User found:', {
      userId: user.id,
      email: user.email,
      lastLogin: user.lastLogin
      // DO NOT include: passwordHash, apiKeys, etc.
    });
  }

  res.json({ success: true });
});
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: Multiple cryptographic failures
const express = require('express');
const crypto = require('crypto');
const db = require('sqlite3');

const app = express();
app.use(express.json());

// ❌ VULNERABILITY 1: HTTP only (no HTTPS)
app.listen(3000);  // No HTTPS!

// ❌ VULNERABILITY 2: Weak password hashing
function hashPassword(password) {
  // MD5 is broken, no salt, too fast
  return crypto.createHash('md5').update(password).digest('hex');
}

// ❌ VULNERABILITY 3: Plaintext storage of API keys
const thirdPartyApiKey = 'sk-1234567890abcdef1234567890';

// ❌ VULNERABILITY 4: Hardcoded secrets
const jwtSecret = 'super_secret_key_hardcoded_in_source';
const dbPassword = 'database_password_in_code';

// ❌ VULNERABILITY 5: Using ECB mode (deterministic)
function encryptCreditCard(card, key) {
  const cipher = crypto.createCipher('aes-128-ecb', key);
  return cipher.update(card, 'utf8', 'hex') + cipher.final('hex');
}

// ❌ VULNERABILITY 6: Passwords stored in plaintext
app.post('/register', (req, res) => {
  const { email, password } = req.body;

  // Password stored as-is, not hashed
  db.run(
    'INSERT INTO users (email, password, creditCard) VALUES (?, ?, ?)',
    [
      email,
      password,  // ❌ PLAINTEXT PASSWORD!
      req.body.creditCard  // ❌ Plaintext credit card!
    ]
  );

  res.json({ success: true });
});

// ❌ VULNERABILITY 7: Sensitive data in logs
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // ❌ Logs everything including password
  console.log('Login attempt:', JSON.stringify(req.body));

  const user = db.getUser(email);

  if (user && user.password === password) {  // ❌ MD5 comparison
    res.json({ token: generateToken(user) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ❌ VULNERABILITY 8: Sensitive data in response
app.get('/api/user/:id', (req, res) => {
  const user = db.getUser(req.params.id);

  // Returns everything, including hash and API keys
  res.json(user);  // ❌ Exposes sensitive fields
});

function generateToken(user) {
  // ❌ Using weak algorithm, no expiration
  return crypto
    .createHash('sha1')
    .update(user.id + jwtSecret)
    .digest('hex');
}
```

## Secure Code Example

```javascript
// ✅ SECURE: Proper cryptography
const express = require('express');
const https = require('https');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

require('dotenv').config();  // Load environment variables

const app = express();
app.use(express.json());

// ✅ VULNERABILITY 1: HTTPS only
const options = {
  key: fs.readFileSync(process.env.PRIVATE_KEY_PATH),
  cert: fs.readFileSync(process.env.CERT_PATH)
};

https.createServer(options, app).listen(443);

// ✅ VULNERABILITY 2: Strong password hashing
async function hashPassword(password) {
  const saltRounds = 12;  // Computational cost
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// ✅ VULNERABILITY 3: Secrets from environment
const thirdPartyApiKey = process.env.THIRD_PARTY_API_KEY;

// ✅ VULNERABILITY 4: Secrets not hardcoded
const jwtSecret = process.env.JWT_SECRET;
const dbPassword = process.env.DATABASE_PASSWORD;

if (!jwtSecret || !dbPassword) {
  throw new Error('Missing required environment variables');
}

// ✅ VULNERABILITY 5: Proper encryption with GCM mode
function encryptCreditCard(card, encryptionKey) {
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(encryptionKey, 'hex'),
    iv
  );

  let encrypted = cipher.update(card, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    encrypted
  };
}

// ✅ VULNERABILITY 6: Password hashing before storage
app.post('/register', async (req, res) => {
  const { email, password, creditCard } = req.body;

  try {
    // ✅ Hash password
    const hashedPassword = await hashPassword(password);

    // ✅ Encrypt credit card
    const encryptedCard = encryptCreditCard(
      creditCard,
      process.env.ENCRYPTION_KEY
    );

    // ✅ Store encrypted/hashed data
    db.run(
      'INSERT INTO users (email, password_hash, credit_card_iv, credit_card_tag, credit_card_encrypted) VALUES (?, ?, ?, ?, ?)',
      [
        email,
        hashedPassword,
        encryptedCard.iv,
        encryptedCard.authTag,
        encryptedCard.encrypted
      ]
    );

    res.json({ success: true });
  } catch (err) {
    console.error('Registration error');  // ✅ Don't log details
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ✅ VULNERABILITY 7: Filter sensitive data in logs
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // ✅ Don't log password
  console.log(`Login attempt from ${email}`);  // Only email, not password

  try {
    const user = db.getUser(email);

    if (!user) {
      // ✅ Generic error message (timing attack resistant)
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // ✅ Use bcrypt for comparison
    const isValid = await verifyPassword(password, user.password_hash);

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // ✅ Generate proper JWT with expiration
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      jwtSecret,
      { expiresIn: '1h' }  // Token expires in 1 hour
    );

    res.json({ token });
  } catch (err) {
    console.error('Login error');  // ✅ Generic log
    res.status(500).json({ error: 'Login failed' });
  }
});

// ✅ VULNERABILITY 8: Don't expose sensitive data
app.get('/api/user/:id', authenticateToken, (req, res) => {
  const user = db.getUser(req.params.id);

  // ✅ Only return necessary, non-sensitive fields
  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    createdAt: user.createdAt
    // DO NOT include: password_hash, credit card data, API keys
  });
});

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = decoded;
    next();
  });
}

app.listen(443);
```

## Mitigations and Best Practices

### 1. Use HTTPS Everywhere
### 2. Hash Passwords with bcrypt/Argon2
### 3. Don't Store Plaintext Sensitive Data
### 4. Use Strong Encryption (AES-256-GCM)
### 5. Never Hardcode Secrets
### 6. Use Environment Variables or Vaults
### 7. Filter Sensitive Data in Logs
### 8. Encrypt Data at Rest
### 9. Implement Key Rotation
### 10. Use Standard Libraries, Not Custom Crypto

## Summary

Protect sensitive data through strong encryption for transit (HTTPS) and rest (AES-256-GCM), proper password hashing (bcrypt/Argon2), and secure secret management (environment variables/vaults). Never log sensitive data, never hardcode secrets, and always use authenticated encryption for stored sensitive data.
