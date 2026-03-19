# NoSQL Injection

## Definition

NoSQL Injection is a vulnerability that occurs when untrusted user input is used to construct NoSQL queries without proper validation, sanitization, or parameterization. Unlike SQL databases, NoSQL databases like MongoDB, CouchDB, and others use different query formats (JSON, JavaScript objects, etc.), making injection attacks possible in different ways.

An attacker can inject operator objects or modify query logic by injecting malicious JSON/JavaScript to bypass authentication, extract data, modify documents, or execute arbitrary code.

---

## How NoSQL Injection Works

### MongoDB Operator Injection

```javascript
// Normal query
db.users.findOne({ username: 'alice', password: 'pass123' });

// If password comes from user input without validation
// User provides: { $gt: '' }
// Query becomes:
db.users.findOne({ username: 'alice', password: { $gt: '' } });

// The $gt operator means "greater than"
// Empty string < any string, so this ALWAYS matches
// Authentication bypassed!
```

### Query Operator Reference

```javascript
// MongoDB operators that can be exploited:
{$gt: value}       // Greater than
{$gte: value}      // Greater than or equal
{$lt: value}       // Less than
{$lte: value}      // Less than or equal
{$ne: value}       // Not equal
{$eq: value}       // Equal
{$in: [values]}    // In array
{$nin: [values]}   // Not in array
{$or: [queries]}   // OR operation
{$and: [queries]}  // AND operation
{$regex: pattern}  // Regular expression
{$where: code}     // JavaScript execution (DANGEROUS)
{$exists: bool}    // Field exists
{$type: type}      // Field type check
```

---

## Authentication Bypass with NoSQL Injection

### Vulnerability 1: Direct Operator Injection

```javascript
// VULNERABLE: Naive query with user input
const username = req.body.username;
const password = req.body.password;

// Query construction without validation
db.users.findOne({
  username: username,
  password: password
});

// If user sends JSON: { "username": "admin", "password": { "$ne": "" } }
// Query becomes:
db.users.findOne({
  username: "admin",
  password: { "$ne": "" }  // Not equal to empty string
});

// This matches any user with non-empty password
// Attacker logs in as admin without knowing password!
```

### Vulnerability 2: JavaScript-based Injection

```javascript
// VULNERABLE: Using eval or $where operator
const query = {
  $where: `this.username == '${username}' && this.password == '${password}'`
};

db.users.findOne(query);

// Attacker sends: username = "admin'; return true; //"
// Query becomes:
db.users.findOne({
  $where: `this.username == 'admin'; return true; //' && this.password == '...'`
});

// Injected code executes: return true
// Always matches!
```

### Vulnerability 3: OR Injection

```javascript
// VULNERABLE: Username/password check
const username = req.body.username;
const password = req.body.password;

db.users.findOne({
  username: username,
  password: password
});

// Attacker sends JSON:
// { "username": { "$or": [{ }, { "role": "admin" }] }, "password": { "$or": [{ }] } }

// Query becomes:
db.users.findOne({
  username: { "$or": [{ }, { "role": "admin" }] },
  password: { "$or": [{ }] }
});

// Empty objects match everything
// Returns first user (usually admin)
```

---

## Real Vulnerable Code Examples

### Example 1: Express + MongoDB Authentication

```javascript
// VULNERABLE: Direct query with user input
const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();

app.use(express.json());

const client = new MongoClient('mongodb://localhost:27017');

async function vulnerableLogin(req, res) {
  try {
    const db = client.db('myapp');
    const usersCollection = db.collection('users');

    const username = req.body.username; // User input
    const password = req.body.password; // User input

    // VULNERABLE: Direct query construction
    const user = await usersCollection.findOne({
      username: username,
      password: password
    });

    if (user) {
      req.session.userId = user._id;
      res.json({ success: true, user: user });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: error.message }); // DANGEROUS: Leaks error details
  }
}

app.post('/login', vulnerableLogin);

// Attack 1: Operator injection
// username: admin
// password: { "$ne": "" }
// JSON sent: { "username": "admin", "password": { "$ne": "" } }

// Attack 2: OR injection
// username: { "$or": [{ }, { "role": "admin" }] }
// password: { "$or": [{ }] }

// Attack 3: Regex injection
// username: { "$regex": "^admin" }
// password: { "$ne": "" }
```

### Example 2: Query Building with String Concatenation

```javascript
// VULNERABLE: Mongoose with string concatenation
const User = require('./models/User');

app.post('/search', async (req, res) => {
  const searchTerm = req.query.q;

  // VULNERABLE: Building regex from user input
  try {
    // Attacker-controlled regex pattern
    const query = new RegExp(searchTerm);
    const users = await User.find({
      $or: [
        { username: { $regex: query } },
        { email: { $regex: query } }
      ]
    });

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Attack:
// searchTerm: '(.*)*'
// This creates a ReDoS vulnerable regex
// Server hangs

// Or:
// searchTerm: '.*'
// Returns all users due to loose regex
```

### Example 3: Unsafe Mongoose Query

```javascript
// VULNERABLE: Mongoose with eval-like behavior
app.get('/user/:id', async (req, res) => {
  const userId = req.params.id;

  // VULNERABLE: If userId contains special chars
  try {
    const user = await User.findById(userId);
    // ObjectId validation missing
    // If userId = { $ne: null }, could bypass checks

    res.json(user);
  } catch (error) {
    res.json({ error: error.message });
  }
});

// Better approach: Parse and validate ID
```

### Example 4: CouchDB Map/Reduce Injection

```javascript
// VULNERABLE: CouchDB map function injection
app.post('/query', (req, res) => {
  const mapFunction = req.body.map; // User input!

  // DANGEROUS: Executing user-provided code
  const designDoc = {
    _id: '_design/custom',
    views: {
      custom: {
        map: mapFunction // User-controlled JavaScript!
      }
    }
  };

  // User can inject arbitrary code
  // This executes on the database server
});

// Attack:
// mapFunction: "function(doc) { /* attacker's code */ }"
// Attacker gains database access
```

---

## NoSQL Injection in Different Databases

### MongoDB Injection Patterns

```javascript
// Standard NoSQL Injection
{ username: 'admin', password: { $gt: '' } }

// OR injection
{ $or: [{ username: 'admin' }, { password: 'any' }] }

// NIN injection
{ username: { $nin: ['admin', 'root'] } }

// Regex injection
{ username: { $regex: '^admin' } }

// Exists injection
{ username: { $exists: true }, password: { $exists: true } }

// Type injection
{ username: { $type: 'string' } }
```

### DynamoDB Injection (AWS)

```javascript
// DynamoDB uses slightly different syntax but same principle
// AttributeNames and AttributeValues can be injected

// VULNERABLE: Building expressions from user input
const params = {
  TableName: 'Users',
  FilterExpression: 'username = :username AND password = :password',
  ExpressionAttributeValues: {
    ':username': req.body.username,
    ':password': req.body.password
  }
};

// This is relatively safe if expressions are fixed
// But vulnerable if FilterExpression is user-provided
```

---

## Secure Alternatives

### Solution 1: Input Validation and Type Checking

```javascript
// SECURE: Validate input types before querying
app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Type checking - ensure inputs are strings
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input types' });
  }

  // Length validation
  if (username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Invalid username length' });
  }

  if (password.length < 8 || password.length > 100) {
    return res.status(400).json({ error: 'Invalid password length' });
  }

  // Pattern validation
  if (!/^[a-zA-Z0-9_]+$/.test(username)) {
    return res.status(400).json({ error: 'Invalid username characters' });
  }

  // Now safe to use in query
  const user = await User.findOne({
    username: username,
    password: password
  });

  if (user) {
    req.session.userId = user._id;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```

### Solution 2: Schema Validation with Joi/Zod

```javascript
// SECURE: Validate input against schema
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const loginSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(50)
    .required(),
  password: Joi.string()
    .min(8)
    .max(100)
    .required()
});

app.post('/login', async (req, res) => {
  // Validate input against schema
  const { error, value } = loginSchema.validate(req.body);

  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }

  // Now value contains validated, safe data
  const user = await User.findOne({
    username: value.username,
    password: value.password
  });

  if (user) {
    req.session.userId = user._id;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Using Zod (TypeScript-friendly)
const { z } = require('zod');

const LoginSchema = z.object({
  username: z.string().alphanumeric().min(3).max(50),
  password: z.string().min(8).max(100)
});

const validatedData = LoginSchema.parse(req.body); // Throws if invalid
```

### Solution 3: Mongoose Schema Validation

```javascript
// SECURE: Mongoose schema enforces structure
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    match: /^[a-zA-Z0-9_]+$/, // Regex validation
    minlength: 3,
    maxlength: 50
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    maxlength: 100
  },
  email: {
    type: String,
    required: true,
    match: /.+\@.+\..+/ // Email format
  }
});

const User = mongoose.model('User', userSchema);

app.post('/login', async (req, res) => {
  try {
    // Mongoose automatically validates types
    const user = await User.findOne({
      username: req.body.username,
      password: req.body.password
    });

    if (user) {
      req.session.userId = user._id;
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    // Validation error caught by Mongoose
    res.status(400).json({ error: 'Invalid input' });
  }
});
```

### Solution 4: MongoDB Driver Security Features

```javascript
// SECURE: Using MongoDB driver safely
const { MongoClient } = require('mongodb');

const client = new MongoClient('mongodb://localhost:27017');

async function secureLogin(username, password) {
  const db = client.db('myapp');
  const users = db.collection('users');

  // ✓ SAFE: Direct object, no concatenation
  const user = await users.findOne({
    username: String(username), // Explicit type conversion
    password: String(password)
  });

  return user;
}

// If you need regex search, be careful:
async function safeSearch(searchTerm) {
  const db = client.db('myapp');
  const users = db.collection('users');

  // Escape special regex characters
  const escapedTerm = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // Now safe to use in regex
  const users = await users.find({
    username: {
      $regex: `^${escapedTerm}`,
      $options: 'i' // Case-insensitive
    }
  }).toArray();

  return users;
}
```

### Solution 5: Sanitize Library

```javascript
// SECURE: Using mongo-sanitize library
const mongoSanitize = require('mongo-sanitize');

app.use(mongoSanitize()); // Middleware - automatically sanitizes input

app.post('/login', async (req, res) => {
  // mongo-sanitize removes $ and . from object keys
  // Prevents injection attacks

  const user = await User.findOne({
    username: req.body.username, // Already sanitized by middleware
    password: req.body.password
  });

  if (user) {
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// What sanitization does:
// Input: { "$ne": "password" }
// After sanitize: { "ne": "password" }
// $ is removed, operator doesn't work anymore
```

### Solution 6: Whitelist/Allowlist Validation

```javascript
// SECURE: Only allow specific query structures
const ALLOWED_SORT_FIELDS = ['username', 'email', 'created_at'];
const ALLOWED_OPERATORS = { asc: 1, desc: -1 };

app.get('/users', async (req, res) => {
  const sortField = req.query.sort_by || 'created_at';
  const sortOrder = req.query.order || 'asc';

  // Validate against whitelist
  if (!ALLOWED_SORT_FIELDS.includes(sortField)) {
    return res.status(400).json({ error: 'Invalid sort field' });
  }

  if (!ALLOWED_OPERATORS[sortOrder]) {
    return res.status(400).json({ error: 'Invalid sort order' });
  }

  // Build query with validated values only
  const query = {};
  query[sortField] = ALLOWED_OPERATORS[sortOrder];

  const users = await User.find().sort(query);
  res.json(users);
});
```

---

## Error Message Leakage Prevention

### VULNERABLE: Detailed Error Messages

```javascript
app.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({
      username: req.body.username,
      password: req.body.password
    });
    // ...
  } catch (error) {
    // DANGEROUS: Leaks MongoDB error details
    res.status(500).json({
      error: error.message, // "Invalid query operator $gt", etc.
      stack: error.stack,    // Full stack trace!
      originalError: error
    });
  }
});
```

### SECURE: Generic Error Messages

```javascript
app.post('/login', async (req, res) => {
  try {
    // Validate input first (prevents many NoSQL injection attempts)
    if (typeof req.body.username !== 'string') {
      return res.status(400).json({ error: 'Invalid input' });
    }

    const user = await User.findOne({
      username: req.body.username,
      password: req.body.password
    });

    if (user) {
      req.session.userId = user._id;
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    // ✓ SECURE: Generic error message
    console.error('Login error:', error); // Log server-side only
    res.status(500).json({ error: 'An error occurred' });
  }
});
```

---

## Best Practices Checklist

1. **Never Trust User Input**
   - Always validate type
   - Always validate length
   - Always validate format

2. **Use Schema Validation**
   ```javascript
   // Joi, Zod, or Mongoose schemas
   // Automatic type checking and validation
   ```

3. **Input Type Checking**
   ```javascript
   // ✓ SAFE: Type checking
   if (typeof username !== 'string') {
     return res.status(400).json({ error: 'Invalid type' });
   }

   // ✗ DANGEROUS: No type checking
   db.users.findOne({ username: username });
   ```

4. **Avoid User-Controlled Field Names**
   - Don't let users specify sort fields without validation
   - Don't let users specify projection fields without validation

5. **Sanitize Input**
   - Use mongo-sanitize library
   - Remove $ and . from user input
   - Escape special characters

6. **Use Allowlists**
   - For sort fields
   - For filter fields
   - For projection fields
   - For operators

7. **Avoid $where Operator**
   ```javascript
   // ✗ DANGEROUS: JavaScript execution
   db.users.find({ $where: userInput });

   // Use regular operators instead
   db.users.find({ username: { $regex: pattern } });
   ```

8. **Disable Server-Side JavaScript Execution**
   - MongoDB: Disable in security configurations
   - CouchDB: Use appropriate access controls

9. **Use ORM/Schema Validation**
   - Mongoose: Type and validation enforcement
   - Sequelize: Query building safety
   - Prisma: Type-safe database access

10. **Log and Monitor**
    - Log failed login attempts
    - Alert on suspicious query patterns
    - Monitor for injection attempts

11. **Error Handling**
    - Don't expose MongoDB error messages
    - Return generic error messages to users
    - Log detailed errors server-side

12. **Code Review**
    - Review all database queries
    - Check for user input in queries
    - Validate against injection patterns

---

## Testing for NoSQL Injection

```javascript
// Common test payloads
const testPayloads = [
  // Operator injection
  { $ne: '' },
  { $gt: '' },
  { $lt: '' },
  { $regex: '.*' },
  { $in: [''] },
  { $nin: [] },
  { $exists: true },

  // OR injection
  { $or: [{ }, { }] },
  { $or: [{ foo: 'bar' }] },

  // Complex payloads
  { $or: [{ username: { $ne: null } }] },
  { $or: [{ username: { $regex: '.*' } }] },

  // String-based injection (for vulnerable code)
  "' || '1'=='1",
  "'; return true; //",
];

// Test function
function testForVulnerability(inputValue) {
  try {
    // Try to query with injection payload
    db.users.findOne({
      username: 'admin',
      password: inputValue
    });

    // Check if unexpected results returned
    // If injection succeeded, would return results
  } catch (error) {
    // Validation error = good sign
    console.log('Blocked:', error.message);
  }
}

testPayloads.forEach(testForVulnerability);
```

---

## Real-World Vulnerabilities

- **CouchDB Injection**: Map/reduce functions executed unsafely
- **MongoDB Injection**: Various applications vulnerable to operator injection
- **Express + MongoDB**: Many tutorials show vulnerable patterns
- **Firebase**: Vulnerable if data is trusted without validation

---

## Related Reading

- OWASP: NoSQL Injection
- CWE-943: Improper Neutralization of Special Elements in Data Query Logic
- MongoDB Security Best Practices
- OWASP NoSQL Injection Cheat Sheet
- PortSwigger: NoSQL Injection
- mongo-sanitize Documentation
