# LDAP Injection in JavaScript/Node.js

## Definition

LDAP (Lightweight Directory Access Protocol) Injection is a security vulnerability that occurs when user-controlled input is concatenated into LDAP filter queries without proper escaping or validation. Similar to SQL injection, LDAP injection allows attackers to manipulate LDAP queries to bypass authentication, extract unauthorized data, or modify directory entries.

## How LDAP Queries Work

LDAP is used to query directory services, commonly for user authentication, contact lookups, and access control. LDAP queries use a filter syntax with specific operators and special characters.

### Basic LDAP Filter Structure

```
(&(uid=john)(objectClass=person))
```

Components:
- **`&`** - AND operator
- **`()`** - Filter grouping
- **`uid=john`** - Attribute matching (attribute = value)
- **`objectClass=person`** - Object class matching

### Common LDAP Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `=` | Equals | `(cn=John)` |
| `~=` | Approximately equals | `(cn~=Jon)` |
| `>=` | Greater than or equal | `(age>=18)` |
| `<=` | Less than or equal | `(age<=65)` |
| `&` | AND | `(&(cn=John)(uid=jdoe))` |
| `\|` | OR | `(\|(cn=John)(cn=Jane))` |
| `!` | NOT | `(!(cn=John))` |
| `*` | Wildcard | `(cn=J*)` |

## How User Input Injection Enables Attacks

LDAP injection occurs when user input is directly concatenated into LDAP filters, allowing attackers to inject special characters that alter query logic.

### Attack Vectors

**Special characters with meaning in LDAP:**
- `*` (asterisk) - Wildcard matching any characters
- `(` and `)` (parentheses) - Grouping and filter operators
- `&` and `|` (ampersand, pipe) - Logical operators
- `!` (exclamation) - Negation operator
- `\` (backslash) - Escape character

### Authentication Bypass Example

**Normal LDAP authentication filter:**
```
(&(uid=john)(userPassword=secret123))
```

**Vulnerable code concatenates user input:**
```javascript
const username = req.body.username; // User input
const password = req.body.password; // User input
const filter = `(&(uid=${username})(userPassword=${password}))`;
```

**Attack payload:**
- **Username:** `admin)(|(uid=*`
- **Password:** `anything`

**Resulting filter:**
```
(&(uid=admin)(|(uid=*)(userPassword=anything))
```

**Result:** Filter matches if uid is admin OR if uid matches anything (always true) - authentication bypassed!

**Another attack payload:**
- **Username:** `*`
- **Password:** `*`

**Resulting filter:**
```
(&(uid=*)(userPassword=*))
```

**Result:** Matches any user with any password - authentication bypassed!

### Data Extraction Example

An attacker can also enumerate data:

**Original filter:**
```
(&(cn=john)(objectClass=person))
```

**Attack payload to enumerate all users:**
- User input: `*`

**Resulting filter:**
```
(&(cn=*)(objectClass=person))
```

**Result:** Returns all people in directory

## Example Attack String

Common LDAP injection attack strings:

```
# Authentication bypass - wildcard
*

# Authentication bypass - always true OR condition
*)(&

# Authentication bypass - comment-like syntax
*))(&(|(uid=*

# Data enumeration
admin)(|(cn=*

# Filter bypassing
*))(&(uid=*

# Nested filter injection
*)(|(cn=*))(&(uid=*
```

## Vulnerable Node.js LDAP Authentication Code

```javascript
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.use(express.json());

// VULNERABLE: LDAP client setup
const client = ldap.createClient({
  url: 'ldap://ldap.example.com:389'
});

// VULNERABLE: Direct user input concatenation
app.post('/vulnerable/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // VULNERABLE: User input directly concatenated into LDAP filter
  const filter = `(&(uid=${username})(userPassword=${password}))`;

  client.bind(filter, password, (err) => {
    if (!err) {
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ error: 'Login failed' });
    }
  });
});

// VULNERABLE: Search with user input
app.post('/vulnerable/search', (req, res) => {
  const searchTerm = req.body.search;

  // VULNERABLE: User input directly concatenated
  const filter = `(cn=${searchTerm})`;

  const opts = {
    filter: filter,
    scope: 'sub',
    attributes: ['cn', 'mail', 'telephoneNumber', 'sn']
  };

  client.search('dc=example,dc=com', opts, (err, res2) => {
    if (err) return res.status(500).json({ error: err.message });

    const results = [];
    res2.on('searchEntry', (entry) => {
      results.push(entry.object);
    });

    res2.on('end', () => {
      res.json(results);
    });
  });
});

// VULNERABLE: User enumeration
app.post('/vulnerable/find-user', (req, res) => {
  const email = req.body.email;

  // VULNERABLE: Email directly concatenated
  const filter = `(mail=${email})`;

  const opts = {
    filter: filter,
    scope: 'sub',
    attributes: ['uid', 'cn', 'mail']
  };

  client.search('dc=example,dc=com', opts, (err, res2) => {
    if (err) return res.status(500).json({ error: err.message });

    let found = false;
    res2.on('searchEntry', (entry) => {
      found = true;
      res.json({ exists: true, user: entry.object });
    });

    res2.on('end', () => {
      if (!found) {
        res.json({ exists: false });
      }
    });
  });
});

app.listen(3000);

// Attack examples:
// 1. POST /vulnerable/login with {"username": "admin*)(&", "password": "anything"}
// 2. POST /vulnerable/login with {"username": "*", "password": "*"}
// 3. POST /vulnerable/search with {"search": "*"}
// 4. POST /vulnerable/find-user with {"email": "*"}
```

## Secure LDAP Implementation

### Option 1: Proper Escaping

```javascript
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.use(express.json());

const client = ldap.createClient({
  url: 'ldap://ldap.example.com:389'
});

// SECURE: LDAP filter escaping function
function escapeLDAPFilter(input) {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }

  // LDAP filter escape characters
  const escapeMap = {
    '*': '\\2a',  // Asterisk
    '(': '\\28',  // Left paren
    ')': '\\29',  // Right paren
    '\\': '\\5c', // Backslash
    '\x00': '\\00' // Null character
  };

  return input.replace(/[*()\\[\x00]/g, (char) => escapeMap[char]);
}

// SECURE: Login with escaped input
app.post('/secure/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Validate input format
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input type' });
  }

  // Escape user input
  const escapedUsername = escapeLDAPFilter(username);
  const escapedPassword = escapeLDAPFilter(password);

  // SECURE: Build filter with escaped input
  const filter = `(&(uid=${escapedUsername})(userPassword=${escapedPassword}))`;

  client.bind(filter, password, (err) => {
    if (!err) {
      res.json({ success: true, message: 'Login successful' });
    } else {
      res.status(401).json({ error: 'Login failed' });
    }
  });
});

// SECURE: Search with escaped input
app.post('/secure/search', (req, res) => {
  const searchTerm = req.body.search;

  if (!searchTerm || typeof searchTerm !== 'string') {
    return res.status(400).json({ error: 'Invalid search term' });
  }

  if (searchTerm.length > 255) {
    return res.status(400).json({ error: 'Search term too long' });
  }

  // SECURE: Escape the search input
  const escapedTerm = escapeLDAPFilter(searchTerm);
  const filter = `(cn=${escapedTerm})`;

  const opts = {
    filter: filter,
    scope: 'sub',
    attributes: ['cn', 'mail', 'telephoneNumber', 'sn'],
    sizeLimit: 100 // Limit results
  };

  client.search('dc=example,dc=com', opts, (err, res2) => {
    if (err) return res.status(500).json({ error: 'Search failed' });

    const results = [];
    res2.on('searchEntry', (entry) => {
      results.push(entry.object);
    });

    res2.on('end', () => {
      res.json(results);
    });
  });
});

app.listen(3000);
```

### Option 2: Using ldapjs with Safe Filter API

Modern LDAP libraries provide safe filter construction APIs:

```javascript
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.use(express.json());

const client = ldap.createClient({
  url: 'ldap://ldap.example.com:389'
});

// SECURE: Using ldapjs filter builder (if available)
app.post('/secure/login-modern', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || !password) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  // Using parameterized filter construction
  // Instead of string concatenation
  const filter = ldap.filters.AndFilter({
    filters: [
      ldap.filters.EqualityFilter({
        attribute: 'uid',
        value: username  // Automatically escaped
      }),
      ldap.filters.EqualityFilter({
        attribute: 'userPassword',
        value: password  // Automatically escaped
      })
    ]
  });

  client.bind(filter.toString(), password, (err) => {
    if (!err) {
      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Login failed' });
    }
  });
});

// SECURE: Safe search
app.post('/secure/search-modern', (req, res) => {
  const searchTerm = req.body.search;

  if (!searchTerm || typeof searchTerm !== 'string' || searchTerm.length > 255) {
    return res.status(400).json({ error: 'Invalid search term' });
  }

  // Using filter builder with automatic escaping
  const filter = ldap.filters.EqualityFilter({
    attribute: 'cn',
    value: searchTerm  // Automatically escaped
  });

  const opts = {
    filter: filter.toString(),
    scope: 'sub',
    attributes: ['cn', 'mail', 'telephoneNumber', 'sn'],
    sizeLimit: 100
  };

  client.search('dc=example,dc=com', opts, (err, res2) => {
    if (err) return res.status(500).json({ error: 'Search failed' });

    const results = [];
    res2.on('searchEntry', (entry) => {
      results.push(entry.object);
    });

    res2.on('end', () => {
      res.json(results);
    });
  });
});

app.listen(3000);
```

### Option 3: Parameterized Queries with Filter Constants

```javascript
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.use(express.json());

const client = ldap.createClient({
  url: 'ldap://ldap.example.com:389'
});

// SECURE: Filter template with validation
function createAuthFilter(username, password) {
  // Strict validation before use
  if (!/^[a-zA-Z0-9._@-]+$/.test(username)) {
    throw new Error('Invalid username format');
  }

  if (username.length > 128) {
    throw new Error('Username too long');
  }

  // Use filter builder instead of string concatenation
  return new ldap.filters.AndFilter({
    filters: [
      new ldap.filters.EqualityFilter({
        attribute: 'uid',
        value: username
      }),
      new ldap.filters.EqualityFilter({
        attribute: 'userPassword',
        value: password
      })
    ]
  });
}

app.post('/secure/login-validated', (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;

    const filter = createAuthFilter(username, password);

    client.bind(filter.toString(), password, (err) => {
      if (!err) {
        res.json({ success: true });
      } else {
        res.status(401).json({ error: 'Login failed' });
      }
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(3000);
```

## Secure Alternatives and Best Practices

### 1. Use Dedicated LDAP Client Libraries

Modern LDAP libraries abstract away filter construction:

```javascript
// Using the active-directory library
const ActiveDirectory = require('active-directory');

const config = {
  url: 'ldap://dc.example.com:389',
  baseDN: 'dc=example,dc=com',
  username: 'admin@example.com',
  password: 'password'
};

const ad = new ActiveDirectory(config);

// The library handles escaping automatically
ad.authenticate(username, password, (err, auth) => {
  if (auth) {
    console.log('Authenticated!');
  } else {
    console.log('Authentication failed!');
  }
});
```

### 2. Whitelist Input Validation

```javascript
// Only allow specific username formats
function validateUsername(username) {
  // Allow only alphanumeric, dot, dash, underscore
  const valid = /^[a-zA-Z0-9._-]+$/.test(username);
  const maxLength = username.length <= 128;
  return valid && maxLength;
}

// Only allow specific email formats
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
}
```

### 3. Implement Account Lockout

```javascript
// Prevent brute force attacks
const failedAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

function isAccountLocked(username) {
  const attempts = failedAttempts.get(username);
  if (!attempts) return false;

  if (Date.now() - attempts.lastAttempt > LOCKOUT_TIME) {
    failedAttempts.delete(username);
    return false;
  }

  return attempts.count >= MAX_ATTEMPTS;
}

function recordFailedAttempt(username) {
  const attempts = failedAttempts.get(username) || { count: 0 };
  attempts.count++;
  attempts.lastAttempt = Date.now();
  failedAttempts.set(username, attempts);
}

function clearFailedAttempts(username) {
  failedAttempts.delete(username);
}
```

### 4. Limit Search Results

```javascript
const opts = {
  filter: filter,
  scope: 'sub',
  attributes: ['cn', 'mail'], // Only return needed attributes
  sizeLimit: 100, // Maximum 100 results
  timeLimit: 5    // Maximum 5 seconds
};
```

### 5. Use TLS/SSL for LDAP Connection

```javascript
const client = ldap.createClient({
  url: 'ldaps://ldap.example.com:636', // Use LDAPS
  tlsOptions: {
    rejectUnauthorized: true
  }
});
```

## Complete Secure Implementation Example

```javascript
const express = require('express');
const ldap = require('ldapjs');
const app = express();

app.use(express.json());

// LDAP client with TLS
const client = ldap.createClient({
  url: 'ldaps://ldap.example.com:636',
  tlsOptions: {
    rejectUnauthorized: true
  }
});

// Escape function
function escapeLDAPFilter(input) {
  if (typeof input !== 'string') throw new Error('Must be string');
  return input.replace(/[*()\\[\x00]/g, (char) => {
    const escapeMap = {
      '*': '\\2a', '(': '\\28', ')': '\\29', '\\': '\\5c', '\x00': '\\00'
    };
    return escapeMap[char];
  });
}

// Validation
function validateUsername(username) {
  const valid = /^[a-zA-Z0-9._-]+$/.test(username);
  return valid && username.length > 0 && username.length <= 128;
}

// Login with all protections
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Validate inputs
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  if (!validateUsername(username)) {
    return res.status(400).json({ error: 'Invalid username format' });
  }

  if (password.length > 128) {
    return res.status(400).json({ error: 'Password too long' });
  }

  // Escape inputs
  const escapedUsername = escapeLDAPFilter(username);
  const filter = `(&(uid=${escapedUsername})(objectClass=person))`;

  // Bind with user credentials
  const userDN = `uid=${escapedUsername},ou=people,dc=example,dc=com`;

  client.bind(userDN, password, (err) => {
    if (!err) {
      res.json({ success: true, username });
    } else {
      res.status(401).json({ error: 'Authentication failed' });
    }
  });
});

app.listen(3000);
```

## Best Practices Summary

1. **Always escape LDAP filter special characters** - Use escaping functions for all user input
2. **Use LDAP filter builder libraries** - Leverage libraries that abstract filter construction
3. **Validate input format** - Use whitelisting for expected formats (usernames, emails)
4. **Implement length limits** - Prevent overly long input
5. **Use TLS/SSL for LDAP** - Encrypt credentials in transit
6. **Limit query results** - Set sizeLimit and timeLimit in search options
7. **Use parameterized searches** - Prefer filter builders over string concatenation
8. **Implement rate limiting** - Prevent brute force and enumeration attacks
9. **Log authentication attempts** - Monitor for suspicious activity
10. **Review directory ACLs** - Ensure LDAP service account has minimal necessary permissions
11. **Use dedicated LDAP libraries** - Modern libraries handle security better than manual queries
12. **Regular security audits** - Test LDAP implementations for injection vulnerabilities

## References

- OWASP LDAP Injection: https://owasp.org/www-community/attacks/LDAP_Injection
- CWE-90: Improper Neutralization of Special Elements used in an LDAP Query: https://cwe.mitre.org/data/definitions/90.html
- ldapjs Documentation: http://ldapjs.org/
- LDAP Filter Escaping RFC 4515: https://tools.ietf.org/html/rfc4515
