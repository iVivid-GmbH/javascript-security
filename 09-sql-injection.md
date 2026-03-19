# SQL Injection

## Definition

SQL Injection is a critical vulnerability that occurs when untrusted user input is concatenated into SQL queries without proper sanitization or parameterization. An attacker can inject arbitrary SQL code to manipulate the query logic, potentially reading, modifying, or deleting database data, bypassing authentication, or executing arbitrary database commands.

The vulnerability exists because SQL is interpreted as both data and code. If user input reaches the database engine, it can alter the query's structure and behavior.

---

## How SQL Injection Works

### Basic SQL Injection Mechanics

```sql
-- Normal query
SELECT * FROM users WHERE username = 'alice' AND password = 'pass123';

-- Injected query - if password comes from user input
password = ' OR '1'='1
-- Becomes:
SELECT * FROM users WHERE username = 'alice' AND password = '' OR '1'='1';
-- The '1'='1' is always true, bypassing password check!

-- All users are returned
```

### Attack Scenario: Authentication Bypass

```javascript
// VULNERABLE Node.js/Express code
const mysql = require('mysql');

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // DANGEROUS: Direct string concatenation
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  connection.query(query, (error, results) => {
    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});

// Attack:
// username: ' OR '1'='1' --
// password: anything
// Query becomes:
// SELECT * FROM users WHERE username = '' OR '1'='1' --' AND password = '...'
// The -- comments out the password check
// Returns all users, authentication bypassed!
```

---

## Types of SQL Injection

### Type 1: Classic SQL Injection

Direct insertion of SQL code into queries.

```javascript
// VULNERABLE
const query = `SELECT * FROM users WHERE id = ${userId}`;
// If userId = "1 OR 1=1"
// Query becomes: SELECT * FROM users WHERE id = 1 OR 1=1
// Returns all users instead of specific user
```

### Type 2: Blind SQL Injection

Data is not directly displayed, but application behavior changes based on query result.

```javascript
// VULNERABLE: Information leaked through timing/behavior
const query = `SELECT * FROM users WHERE username = '${username}'`;
connection.query(query, (error, results) => {
  const userExists = results.length > 0;
  // True/False leaks through response time or message differences
});

// Attack:
// username = "admin' AND SUBSTRING(password,1,1)='a'--"
// If password starts with 'a', query takes longer/returns true
// Attacker can guess password character by character
```

### Type 3: Time-Based Blind SQL Injection

```javascript
// VULNERABLE: Attacker uses delay to infer information
const query = `SELECT * FROM users WHERE username = '${username}'`;
// username = "' OR IF(1=1, SLEEP(5), 0)--"
// If condition is true, query sleeps 5 seconds
// Attacker detects delay, knows condition was true
```

### Type 4: Out-of-Band SQL Injection

Data is exfiltrated through a side channel (DNS, HTTP).

```javascript
// VULNERABLE: SQL Server with out-of-band exfiltration
// Query = "SELECT * FROM users WHERE id = 1 AND (SELECT COUNT(*) FROM users WHERE password LIKE 'a%') > 0"
// Database makes HTTP request or DNS query to attacker's server with data
// Works in some databases (SQL Server, Oracle) not in MySQL
```

---

## Real Vulnerable Code Examples

### Example 1: Login Form SQL Injection

```javascript
// Express.js - VULNERABLE
const mysql = require('mysql');
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'myapp'
});

app.post('/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // DANGEROUS: String concatenation
  const query = `
    SELECT id, email, role FROM users
    WHERE email = '${email}' AND password = MD5('${password}')
  `;

  console.log('Query:', query); // Debug log leaks query structure

  connection.query(query, (error, results) => {
    if (error) throw error;

    if (results.length > 0) {
      const user = results[0];
      req.session.userId = user.id;
      req.session.role = user.role;

      res.json({ success: true, message: 'Logged in' });
    } else {
      res.status(401).json({ error: 'Invalid email or password' });
    }
  });
});

// Attack 1: Authentication bypass
// email: ' OR '1'='1' --
// password: (anything)
// Query: SELECT ... WHERE email = '' OR '1'='1' --' AND password = ...
// Returns first user (usually admin)

// Attack 2: Admin login bypass
// email: admin' --
// password: (anything)
// Query: SELECT ... WHERE email = 'admin' --' AND password = ...
// Logs in as admin without password

// Attack 3: Extract all users
// email: ' UNION SELECT id, email, password FROM users --
// Query becomes: SELECT id, email, role FROM users WHERE email = '' UNION SELECT id, email, password FROM users --
// Returns all user passwords!
```

### Example 2: Search Functionality SQL Injection

```javascript
// VULNERABLE: Search feature
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  const limit = req.query.limit || 10;

  // DANGEROUS: Concatenation
  const query = `
    SELECT id, title, description FROM products
    WHERE title LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'
    LIMIT ${limit}
  `;

  connection.query(query, (error, results) => {
    res.json(results);
  });
});

// Attack 1: Extract database structure
// searchTerm: ' OR '1'='1
// Returns all products

// Attack 2: UNION-based extraction
// searchTerm: ' UNION SELECT 1, user(), version() --
// Returns database user and version

// Attack 3: Stacked queries (if supported)
// searchTerm: '; DROP TABLE products; --
// Deletes the products table!

// Attack 4: Limit bypass
// limit: 1 UNION SELECT id, password, email FROM users LIMIT 999999
// Returns all user data
```

### Example 3: Order By SQL Injection

```javascript
// VULNERABLE: Sorting
app.get('/products', (req, res) => {
  const sortBy = req.query.sort || 'price';

  // DANGEROUS: Column name concatenation
  const query = `
    SELECT id, title, price FROM products
    ORDER BY ${sortBy} ASC
  `;

  connection.query(query, (error, results) => {
    res.json(results);
  });
});

// Attack:
// sort: (SELECT COUNT(*) FROM users) --
// Executes subquery, attacker learns number of users
// sort: id; DELETE FROM products; --
// Deletes all products
```

### Example 4: Error-Based SQL Injection

```javascript
// VULNERABLE: Error messages reveal information
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // DANGEROUS
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  connection.query(query, (error, results) => {
    if (error) {
      // DANGEROUS: Detailed error message leaked
      res.status(500).json({ error: error.message });
    } else {
      res.json(results[0]);
    }
  });
});

// Attack:
// id: 1 AND (SELECT 1 FROM users WHERE EXTRACTVALUE(1, CONCAT('~', (SELECT password FROM users LIMIT 1))))
// Error message: "XPATH syntax error: '~..password_value..'"
// Attacker learns the password from error!

// Or simpler:
// id: 1' AND 1=0 UNION SELECT version(), user(), database()--
// Error reveals database version, user, and name
```

---

## Secure Alternatives

### Solution 1: Parameterized Queries (Prepared Statements)

```javascript
// SECURE: Using parameterized queries with mysql2/promise
const mysql = require('mysql2/promise');

app.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    const connection = await mysql.createConnection({
      host: 'localhost',
      user: 'root',
      password: 'password',
      database: 'myapp'
    });

    // ✓ SECURE: Parameterized query
    const query = `
      SELECT id, email, role FROM users
      WHERE email = ? AND password = MD5(?)
    `;

    // Placeholders (?) are filled with parameters
    // User input is never interpreted as SQL code
    const [rows] = await connection.execute(query, [email, password]);

    if (rows.length > 0) {
      const user = rows[0];
      req.session.userId = user.id;
      req.session.role = user.role;

      res.json({ success: true });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }

    connection.end();
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Attack attempt: email: ' OR '1'='1' --
// Treated as literal string, not SQL
// Query: SELECT ... WHERE email = ' OR '1'='1' -- AND password = ...
// No user with that exact email exists, authentication fails ✓ SAFE
```

### Solution 2: Prepared Statements with Different Drivers

```javascript
// Using pg (PostgreSQL)
const { Pool } = require('pg');
const pool = new Pool();

app.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    // ✓ SECURE: Parameterized query
    const result = await pool.query(
      'SELECT id, email, role FROM users WHERE email = $1 AND password = crypt($2, password)',
      [email, password]
    );

    if (result.rows.length > 0) {
      res.json({ success: true, user: result.rows[0] });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Using sqlite3
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database(':memory:');

app.post('/login', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // ✓ SECURE: Parameterized query
  db.get(
    'SELECT id, email FROM users WHERE email = ? AND password = ?',
    [email, password],
    (err, row) => {
      if (err) {
        res.status(500).json({ error: 'Database error' });
      } else if (row) {
        res.json({ success: true, user: row });
      } else {
        res.status(401).json({ error: 'Invalid credentials' });
      }
    }
  );
});
```

### Solution 3: Object-Relational Mapping (ORM)

```javascript
// Using Sequelize ORM - handles parameterization automatically
const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize('database', 'user', 'password');

const User = sequelize.define('User', {
  email: DataTypes.STRING,
  password: DataTypes.STRING
});

app.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    // ✓ SECURE: ORM handles parameterization
    const user = await User.findOne({
      where: {
        email: email,
        password: password
      }
    });

    if (user) {
      res.json({ success: true, user: user });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});

// Using Prisma ORM
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

app.post('/login', async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    // ✓ SECURE: Prisma parameterizes automatically
    const user = await prisma.user.findUnique({
      where: { email: email }
    });

    if (user && user.password === password) {
      res.json({ success: true, user: user });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Database error' });
  }
});
```

### Solution 4: Input Validation and Allowlisting

```javascript
// SECURE: Validate and allowlist
app.get('/products', (req, res) => {
  const sortBy = req.query.sort || 'price';

  // Whitelist of allowed columns
  const allowedColumns = ['id', 'title', 'price', 'created_at'];

  // Validate that sort parameter is in the allowlist
  if (!allowedColumns.includes(sortBy)) {
    return res.status(400).json({ error: 'Invalid sort column' });
  }

  // Now safe to use in query
  const query = `SELECT id, title, price FROM products ORDER BY ?? ASC`;

  // Using ?? for identifier escaping (column names)
  connection.query(query, [sortBy], (error, results) => {
    res.json(results);
  });
});
```

### Solution 5: Escaping (Last Resort, Not Recommended)

```javascript
// LESS SECURE: Manual escaping (only if parameterization unavailable)
const mysql = require('mysql');

const email = mysql.escape(req.body.email); // Escapes special characters
const password = mysql.escape(req.body.password);

const query = `
  SELECT * FROM users
  WHERE email = ${email} AND password = ${password}
`;

// This is safer than concatenation, but parameterization is better
// mysql.escape() adds quotes and escapes single quotes
// ' becomes \'

// Risk: Escaping bypasses still possible with certain character sets
// Use parameterization instead whenever possible
```

---

## Error Message Leakage Prevention

### VULNERABLE: Detailed Errors

```javascript
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;

  connection.query(query, (error, results) => {
    if (error) {
      // DANGEROUS: Leaks database structure and SQL syntax
      res.status(500).json({
        error: error.message, // "XPATH syntax error...", "Unclosed string...", etc.
        code: error.code,      // SQL_SYNTAX_ERROR, etc.
        sql: query             // NEVER log the query!
      });
    } else {
      res.json(results);
    }
  });
});
```

### SECURE: Generic Error Messages

```javascript
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ?`;

  connection.execute(query, [userId], (error, results) => {
    if (error) {
      // ✓ SECURE: Generic message, detailed error logged server-side only
      console.error('Database error:', error); // Log on server, never in response
      res.status(500).json({ error: 'An error occurred' });
    } else {
      res.json(results);
    }
  });
});

// Server logs have full details for debugging
// Client never learns database structure or query details
```

---

## SQL Injection Detection and Testing

### Manual Testing Patterns

```javascript
// Test inputs that reveal SQL injection
const testInputs = [
  "'",                          // Basic quote
  "' OR '1'='1",               // Classic bypass
  "' OR '1'='1' --",           // Comment-based bypass
  "' OR 1=1 --",               // Numeric bypass
  "admin'--",                   // Truncation
  "' UNION SELECT NULL--",      // UNION injection
  "1' AND '1'='1",             // AND-based
  "1' AND SLEEP(5)--",         // Time-based blind
  "1' AND (SELECT COUNT(*) FROM users)--", // Information extraction
];

testInputs.forEach(input => {
  console.log('Testing:', input);
  // Check if query behavior changes
});
```

### Automated Testing with Tools

```bash
# SQLMap: Automated SQL injection testing
sqlmap -u "http://example.com/search?q=test" --dbs

# Burp Suite: Manual testing with payload generator

# OWASP ZAP: Automated scanning

# NoSQLMap: For NoSQL databases
```

---

## Best Practices Checklist

1. **Always Use Parameterized Queries**
   ```javascript
   // ✓ ALWAYS
   connection.query('SELECT * FROM users WHERE id = ?', [userId]);

   // ✗ NEVER
   connection.query(`SELECT * FROM users WHERE id = ${userId}`);
   ```

2. **Use ORMs When Possible**
   - Sequelize, Prisma, TypeORM
   - Automatic parameterization
   - Less error-prone

3. **Input Validation**
   - Validate data type (int for IDs, email for emails)
   - Validate length and format
   - Use allowlists for dynamic parts (columns, ORDER BY)

4. **Never Concatenate User Input**
   - Into SQL queries
   - Into database commands
   - Into connection strings

5. **Use Prepared Statements**
   - Compile query once with placeholders
   - Execute multiple times with different parameters
   - Parameter binding happens in client library, never database

6. **Escape Identifiers Separately**
   ```javascript
   // Column names need different escaping than values
   // Use ?? for identifiers, ? for values
   connection.query('SELECT * FROM ?? WHERE id = ?', [columnName, userId]);
   ```

7. **Prevent Error Message Leakage**
   - Log errors server-side only
   - Return generic messages to client
   - Never include query details in responses

8. **Principle of Least Privilege**
   - Database user for application has minimal permissions
   - Separate read-only user for reporting
   - No DROP or ALTER permissions

9. **Use Stored Procedures Carefully**
   ```javascript
   // ✓ SAFE: Stored procedure with parameters
   connection.query('CALL authenticate(?, ?)', [email, password]);

   // ✗ DANGEROUS: Stored procedure with concatenation
   // Don't do this inside the procedure either!
   connection.query(`CALL authenticate('${email}', '${password}')`);
   ```

10. **Monitor and Log**
    - Log database queries for audit
    - Alert on suspicious patterns
    - Monitor for unusual SQL syntax

11. **Use WAF (Web Application Firewall)**
    - ModSecurity
    - Cloudflare WAF
    - AWS WAF
    - Catches common injection patterns

12. **Regular Security Testing**
    - Penetration testing
    - Code review
    - Automated scanning
    - Bug bounty programs

---

## SQL Injection vs. Proper Parameterization

| Aspect | Vulnerable | Secure |
|--------|-----------|--------|
| **Query** | `SELECT * FROM users WHERE id = ${id}` | `SELECT * FROM users WHERE id = ?` |
| **Binding** | At query time (concatenation) | At execution time (client library) |
| **Input** | `1' OR '1'='1` | Treated as literal string `1' OR '1'='1` |
| **Error Risk** | High - any user input is dangerous | Low - parameterization automatic |
| **Performance** | Repeated parsing of different queries | Query pre-compiled, reused |
| **Escaping** | Manual, error-prone | Automatic by client library |

---

## Real-World SQL Injection Breaches

- **Sony Pictures (2014)**: SQL injection led to major data breach
- **Ashley Madison (2015)**: SQL injection exposed millions of accounts
- **Equifax (2017)**: Apache Struts vulnerability leading to SQL injection
- **TalkTalk (2015)**: SQL injection compromised customer data

---

## Related Reading

- OWASP: SQL Injection
- CWE-89: SQL Injection
- OWASP Top 10: A1 - Injection
- RFC 3986: URI Generic Syntax
- OWASP SQL Injection Prevention Cheat Sheet
- PortSwigger: SQL Injection Tutorial
