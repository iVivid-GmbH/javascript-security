# Prototype Pollution

## Definition

Prototype pollution is a security vulnerability in JavaScript where an attacker can inject arbitrary properties into an object's prototype chain. Because JavaScript objects inherit properties from their prototypes, poisoning the prototype allows the attacker to influence the behavior of all objects in the application, potentially leading to property injection, XSS attacks, Remote Code Execution (RCE), or Denial of Service.

The vulnerability occurs when application code merges or extends untrusted user input into objects without properly validating or sanitizing the input for special properties like `__proto__`, `constructor`, or `prototype`.

---

## JavaScript Prototype Chain Basics

Understanding the prototype chain is essential to grasping prototype pollution.

```javascript
// Every JavaScript object has a prototype
const obj = {};

// Access the prototype
console.log(Object.getPrototypeOf(obj)); // Returns Object.prototype
console.log(obj.__proto__);             // Also returns Object.prototype

// All objects inherit from Object.prototype
const user = { name: 'Alice' };
console.log(user.toString()); // Inherited from Object.prototype

// Creating a property on Object.prototype affects ALL objects
Object.prototype.isAdmin = false;
console.log(user.isAdmin);    // true (if user had isAdmin: true)
console.log({}.isAdmin);      // false (polluted default)

// The prototype chain lookup:
// user.name -> user object itself -> user.__proto__ -> user.__proto__.__proto__ -> null
```

### How Prototype Inheritance Works

```javascript
// Prototype chain visualization
const animal = { type: 'animal' };
const dog = Object.create(animal);
dog.breed = 'Golden Retriever';

console.log(dog.breed);  // 'Golden Retriever' (own property)
console.log(dog.type);   // 'animal' (inherited from prototype)

// Setting a property on the prototype affects the entire chain
animal.age = 5;
console.log(dog.age);    // 5 (now inherited)

// Every instance shares the same prototype object
const cat = Object.create(animal);
console.log(cat.age);    // 5 (same prototype)
```

---

## How Prototype Pollution Works

### Vulnerability via `__proto__`

The `__proto__` property is a special accessor that allows direct access to an object's prototype.

```javascript
// Vulnerable merge function
function merge(target, source) {
  for (let key in source) {
    if (source.hasOwnProperty(key)) {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker's payload in source
const attacker = {
  '__proto__': {
    isAdmin: true
  }
};

const user = { name: 'Alice' };
merge(user, attacker);

console.log(user.__proto__.isAdmin);     // true
console.log(({}).isAdmin);              // true - POLLUTED!

// Now any new object will have isAdmin: true by default
const newUser = {};
console.log(newUser.isAdmin);           // true (inherited from polluted prototype)
```

### Vulnerability via `constructor.prototype`

```javascript
// Another way to access Object.prototype
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];
  }
  return target;
}

// Attacker's payload
const attacker = {
  'constructor': {
    'prototype': {
      'isAdmin': true
    }
  }
};

const user = { name: 'Alice' };
merge(user, attacker);

// Now Object.prototype is polluted
console.log(({}).isAdmin);     // true
```

### Complex Nested Prototype Pollution

```javascript
// Deeply nested object merge
function deepMerge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) {
        target[key] = {};
      }
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Attacker provides JSON in request
const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
const config = { debug: false };
deepMerge(config, userInput);

// Object.prototype is now polluted
console.log({}.isAdmin); // true
```

---

## Real Vulnerable Code Examples

### Example 1: Vulnerable Merge in Express Route

```javascript
// Express backend - VULNERABLE
const express = require('express');
const app = express();

app.use(express.json());

// Simple merge function without protection
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}

app.post('/api/update-settings', (req, res) => {
  const userSettings = {
    theme: 'light',
    notifications: true
  };

  // Merging user-provided JSON directly
  merge(userSettings, req.body);

  // Attacker sends: {"__proto__": {"isAdmin": true}}
  // Now all objects have isAdmin: true

  res.json({ success: true, settings: userSettings });
});

// Authorization check - BYPASSED
app.post('/api/admin-action', (req, res) => {
  const user = { name: 'Alice', isAdmin: false };

  if (user.isAdmin) {
    // This is now true if prototype was polluted!
    performAdminAction();
    res.json({ success: true });
  } else {
    res.status(403).json({ error: 'Forbidden' });
  }
});
```

**Attack:**
```bash
# Attacker sends this request
curl -X POST http://localhost:3000/api/update-settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"isAdmin": true}}'

# Then accesses admin endpoints successfully
curl -X POST http://localhost:3000/api/admin-action
```

### Example 2: Vulnerable lodash `_.extend()`

```javascript
// Using lodash (before version 4.17.11) - VULNERABLE
const _ = require('lodash');

const userDefaults = {
  email: 'user@example.com',
  role: 'user'
};

function applyUserConfig(user, config) {
  return _.extend(userDefaults, config);
}

// Attacker provides config
const attackerConfig = {
  '__proto__': {
    'role': 'admin'
  }
};

const result = applyUserConfig({}, attackerConfig);

// All new objects now have admin role
const newUser = {};
console.log(newUser.role);  // 'admin' - POLLUTED!
```

### Example 3: Vulnerable Constructor-based Pollution

```javascript
// Vulnerable object assignment
function applySettings(target, settings) {
  for (let [key, value] of Object.entries(settings)) {
    if (typeof value === 'object' && value !== null) {
      if (!target[key]) {
        target[key] = {};
      }
      // Recursive assignment without protection
      applySettings(target[key], value);
    } else {
      target[key] = value;
    }
  }
}

const config = {};

// Attacker sends
const userInput = {
  'constructor': {
    'prototype': {
      'apiUrl': 'https://attacker.com/evil-api'
    }
  }
};

applySettings(config, userInput);

// Now all objects route to attacker's API
const request = {};
console.log(request.apiUrl); // 'https://attacker.com/evil-api'
```

---

## Impact of Prototype Pollution

### 1. Authentication/Authorization Bypass

```javascript
// Before attack
const user = { name: 'Alice', isAdmin: false };
if (user.isAdmin) {
  // Doesn't execute
}

// After prototype pollution
// Attacker pollutes __proto__ with isAdmin: true
// Now:
const user = { name: 'Alice', isAdmin: false };
if (user.isAdmin) {
  // EXECUTES! Authorization bypassed
}
```

### 2. XSS (Cross-Site Scripting)

```javascript
// Application code that renders objects
function renderPage(config) {
  document.body.innerHTML = `
    <div onclick="${config.handleClick}">Click me</div>
  `;
}

// Normal config
const config = { theme: 'dark' };
renderPage(config); // Safe

// After pollution attack
// Attacker pollutes: __proto__ = { handleClick: "alert('XSS')" }
const config = { theme: 'dark' };
// config.handleClick is now "alert('XSS')" from prototype
renderPage(config);
// Results in: <div onclick="alert('XSS')">Click me</div>
// XSS vulnerability!
```

### 3. RCE (Remote Code Execution) - Conditional

```javascript
// If application uses eval or Function constructor on config values
const config = {};

// After pollution
// Attacker pollutes: __proto__ = { code: "require('fs').rmdir('/')" }
const func = new Function(config.code);
func(); // EXECUTES ATTACKER CODE!

// Or with Node.js child_process
if (config.useShell) {
  require('child_process').exec('rm -rf /'); // Potential RCE
}
```

### 4. DoS (Denial of Service)

```javascript
// Pollution with circular references
// Attacker pollutes: __proto__ = { self: __proto__ }

// Application code with infinite loop detection failure
function serializeObject(obj, visited = new Set()) {
  if (visited.has(obj)) return '[Circular]';
  visited.add(obj);

  let result = {};
  for (const key in obj) {
    if (obj.hasOwnProperty(key)) { // Only own properties
      result[key] = serializeObject(obj[key], visited);
    }
  }
  return result;
}

// But with pollution, obj.self might traverse the polluted prototype
// Causing infinite recursion or excessive memory usage
```

---

## Secure Code Examples

### 1. Filter Out Dangerous Keys

```javascript
// Secure merge function
function safeMerge(target, source) {
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];

  for (const key in source) {
    if (dangerousKeys.includes(key)) {
      // Skip dangerous keys
      continue;
    }
    if (source.hasOwnProperty(key)) {
      target[key] = source[key];
    }
  }
  return target;
}

// Usage
const user = {};
const userInput = {
  '__proto__': { isAdmin: true },
  'name': 'Alice'
};

safeMerge(user, userInput);
console.log(user.name);       // 'Alice'
console.log(user.__proto__);  // Not polluted
console.log({}.isAdmin);      // undefined (safe)
```

### 2. Use Object.create(null) for Untrusted Data

```javascript
// Objects created with Object.create(null) have no prototype
const safeConfig = Object.create(null);

// Attempting to pollute has no effect
safeConfig.__proto__ = { isAdmin: true };
safeConfig.constructor = { prototype: { isAdmin: true } };

// These don't pollute Object.prototype
console.log({}.isAdmin); // undefined

// But note: these objects lack standard methods
safeConfig.toString(); // TypeError: safeConfig.toString is not a function

// Solution: only use for data, not for objects needing methods
```

### 3. Object.freeze to Prevent Modification

```javascript
// Freeze Object.prototype to prevent pollution
Object.freeze(Object.prototype);

// Now attempts to pollute fail silently (in non-strict mode)
try {
  Object.prototype.isAdmin = true;
  // Fails silently in non-strict mode
  // TypeError in strict mode
} catch (e) {
  console.error('Pollution attempt blocked:', e);
}

console.log({}.isAdmin); // undefined (safe)

// Also freeze Array.prototype, Function.prototype, etc.
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);
```

### 4. Use Map Instead of Objects for Untrusted Data

```javascript
// Maps are immune to prototype pollution
const userPreferences = new Map();

// User provides data
const userInput = {
  '__proto__': { isAdmin: true },
  'theme': 'dark'
};

// Store in Map
for (const [key, value] of Object.entries(userInput)) {
  userPreferences.set(key, value);
}

// __proto__ is stored as a regular key, not a property
console.log(userPreferences.get('__proto__'));  // { isAdmin: true }
console.log({}.isAdmin);                        // undefined (safe)
```

### 5. Deep Clone with Protection

```javascript
// Secure deep merge
function secureDeepMerge(target, source) {
  const dangerousKeys = [
    '__proto__',
    'constructor',
    'prototype',
    'constructor.prototype'
  ];

  for (const key in source) {
    if (dangerousKeys.includes(key)) {
      continue; // Skip dangerous keys
    }

    if (
      typeof source[key] === 'object' &&
      source[key] !== null &&
      !Array.isArray(source[key])
    ) {
      // Recursively merge objects
      if (!target[key] || typeof target[key] !== 'object') {
        target[key] = {};
      }
      secureDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }

  return target;
}

const config = { database: { host: 'localhost' } };
const userInput = {
  'database': { port: 5432 },
  '__proto__': { isAdmin: true }
};

secureDeepMerge(config, userInput);
console.log(config.database); // { host: 'localhost', port: 5432 }
console.log({}.isAdmin);      // undefined (safe)
```

### 6. Use Libraries with Prototype Pollution Fixes

```javascript
// lodash 4.17.11+ is safe
const _ = require('lodash');

const userDefaults = { role: 'user' };
const userInput = { '__proto__': { role: 'admin' } };

const result = _.merge(userDefaults, userInput);
// Safe: lodash filters dangerous keys

// Or use Object.assign (shallow merge only)
const result2 = Object.assign({}, userDefaults, userInput);
// Still safe because Object.assign doesn't traverse __proto__
```

---

## Prevention Best Practices Checklist

1. **Avoid Recursive Merging of Untrusted Input**
   - If you must merge, filter dangerous keys first
   - Use allowlists instead of blocklists

2. **Filter Dangerous Property Names**
   ```javascript
   const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
   const isSafe = !dangerousKeys.includes(key);
   ```

3. **Use Object.create(null) for Untrusted Data**
   - Objects without prototypes can't be polluted
   - Remember they lack standard methods like toString()

4. **Freeze Built-in Prototypes**
   ```javascript
   Object.freeze(Object.prototype);
   Object.freeze(Array.prototype);
   Object.freeze(Function.prototype);
   ```

5. **Use Maps Instead of Objects**
   - Maps treat all keys as regular data
   - Immune to prototype pollution
   - Downside: less convenient than object property access

6. **Use Well-Maintained Libraries**
   - Keep lodash, npm packages updated
   - Check known vulnerabilities in your dependencies
   - Use `npm audit` regularly

7. **Input Validation and Sanitization**
   - Validate that input matches expected structure
   - Use schema validation libraries (Joi, Zod, Yup)
   - Reject unexpected properties

8. **Avoid Dangerous APIs**
   - Don't use `eval()` on config values
   - Don't use `new Function()` on config values
   - Don't use object properties in sensitive security decisions without validation

9. **Security Testing**
   - Test your merge/extend functions with payload:
     ```javascript
     { '__proto__': { testProp: 'polluted' } }
     { 'constructor': { 'prototype': { testProp: 'polluted' } } }
     ```
   - Verify that testProp doesn't appear on new objects

10. **Dependency Scanning**
    ```bash
    npm audit
    npm outdated
    # Check for known prototype pollution CVEs
    ```

---

## CVE Example: lodash Prototype Pollution (CVE-2018-16487)

**Affected Versions**: lodash <= 4.17.10

**Vulnerability**:
```javascript
const _ = require('lodash'); // <= 4.17.10

const payload = {
  '__proto__': {
    'isAdmin': true
  }
};

const user = {};
_.defaultsDeep(user, payload);

// Result: all objects now have isAdmin: true
console.log({}.isAdmin); // true
```

**Fix**: Upgrade to lodash 4.17.11 or later, which sanitizes dangerous keys.

**Lesson**: Even trusted libraries can have prototype pollution vulnerabilities. Keep dependencies updated.

---

## Detection Tools

```bash
# Check for prototype pollution vulnerabilities
npm audit

# Use eslint plugin to detect problematic patterns
npm install --save-dev eslint-plugin-security

# Manual testing with objects
const obj = {};
merge(obj, {'__proto__': {'test': 'polluted'}});
if ({}.test === 'polluted') {
  console.error('VULNERABLE: Prototype pollution detected');
}
```

---

## Related Reading

- OWASP: Prototype Pollution
- CWE-1321: Improperly Controlled Modification of Object Prototype Attributes
- Prototype Pollution Attack by Olivier Arteau (2018)
- lodash CVE-2018-16487: Prototype Pollution via _.defaultsDeep
- Node.js Security Best Practices
