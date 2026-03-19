# WebSocket Security

## Definition

WebSocket is a protocol that enables bidirectional communication between a client and server over a single, persistent TCP connection. Unlike HTTP (request-response), WebSocket maintains an open connection allowing both client and server to send messages at any time.

WebSocket URLs:
- `ws://example.com/socket` (unencrypted)
- `wss://example.com/socket` (encrypted, recommended)

While WebSocket is powerful for real-time applications, it introduces unique security challenges:
- No automatic CSRF protection (no CSRF token in message body)
- No automatic origin validation
- Potential for connection hijacking if not properly authenticated
- DoS vulnerability via large messages or connection flooding

## How WebSockets Differ from HTTP

### No Automatic Origin Checks

HTTP includes automatic origin validation:

```
HTTP Request:
GET /api/data HTTP/1.1
Host: bank.example.com
Origin: https://attacker.example.com

Browser enforces CORS:
If bank.example.com doesn't allow https://attacker.example.com
Request is blocked (browser rejects response)
```

WebSocket does NOT have automatic origin validation:

```
WebSocket Request:
GET /socket HTTP/1.1
Host: bank.example.com
Origin: https://attacker.example.com
Upgrade: websocket

Server MUST manually check Origin header
If server doesn't validate, connection is established
Attacker can now send messages via WebSocket
```

### No CSRF Token Sent Automatically

HTTP forms include CSRF tokens:

```html
<!-- Form includes CSRF token -->
<form method="POST" action="/api/transfer">
  <input type="hidden" name="csrf_token" value="abc123...">
  <input type="text" name="amount">
</form>
```

WebSocket messages do NOT include CSRF tokens:

```javascript
// WebSocket message - no automatic token
ws.send(JSON.stringify({
  action: 'transfer',
  amount: 1000,
  to: 'attacker@example.com'
  // No CSRF token unless explicitly added
}));
```

This requires application-level CSRF protection.

## Origin Validation on the Server

### Vulnerable: No Origin Check

```javascript
const WebSocket = require('ws');
const http = require('http');
const express = require('express');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// VULNERABLE: No origin validation
wss.on('connection', (ws, req) => {
  console.log('Client connected');
  // Accept connection from any origin

  ws.on('message', (message) => {
    // Process message from any origin
    const data = JSON.parse(message);
    handleTransaction(data);
  });
});

server.listen(3000);
```

An attacker can:

```html
<!-- Attacker's website (attacker.com) -->
<script>
  const ws = new WebSocket('wss://bank.example.com/socket');

  ws.onopen = () => {
    // Send message to victim's bank
    ws.send(JSON.stringify({
      action: 'transfer',
      amount: 10000,
      to: 'attacker@example.com'
    }));
  };

  ws.onmessage = (event) => {
    console.log('Response:', event.data);
  };
</script>
```

If user visits attacker.com while logged into bank.example.com:
1. Browser still has session cookie for bank.example.com
2. WebSocket connection includes cookie (authentication)
3. Attacker's JavaScript sends transaction message
4. Bank processes it (no origin validation)
5. Money is transferred to attacker

### Secure: Origin Validation

```javascript
const WebSocket = require('ws');
const http = require('http');
const express = require('express');

const app = express();
const server = http.createServer(app);

// SECURE: Configure WebSocket with origin validation
const wss = new WebSocket.Server({
  server,
  // Validate origin before accepting connection
  verifyClient: (info, callback) => {
    const origin = info.origin;
    const allowedOrigins = [
      'https://bank.example.com',
      'https://www.bank.example.com'
    ];

    if (allowedOrigins.includes(origin)) {
      callback(true); // Accept connection
    } else {
      console.warn(`Rejected WebSocket from origin: ${origin}`);
      callback(false, 401, 'Unauthorized origin'); // Reject connection
    }
  }
});

wss.on('connection', (ws, req) => {
  console.log('Client connected from:', req.headers.origin);

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      // Now safe to process - origin validated
      handleTransaction(data);
    } catch (error) {
      ws.send(JSON.stringify({ error: 'Invalid message' }));
    }
  });

  ws.on('close', () => {
    console.log('Client disconnected');
  });

  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

app.get('/', (req, res) => {
  res.send('Bank Application');
});

server.listen(3000);
```

### Dynamic Origin Validation

For applications with multiple allowed origins:

```javascript
const wss = new WebSocket.Server({
  server,
  verifyClient: (info, callback) => {
    const origin = info.origin;

    // Check against database of allowed origins
    db.origins.findOne({ origin }, (err, doc) => {
      if (err) {
        return callback(false, 500, 'Server error');
      }

      if (doc && doc.allowed) {
        callback(true);
      } else {
        callback(false, 403, 'Origin not allowed');
      }
    });
  }
});
```

## Authentication Over WebSocket

### Pitfall 1: Query Parameters (Insecure)

```javascript
// INSECURE: Token in URL is visible and logged
const ws = new WebSocket('wss://api.example.com/socket?token=abc123...');

// Problem:
// - Token visible in browser address bar
// - Token visible in browser history
// - Token visible in server logs
// - Token visible in proxy/firewall logs
```

### Pitfall 2: Cookie Without Validation (Insecure)

```javascript
// INSECURE: Assuming cookie is enough
wss.on('connection', (ws, req) => {
  // Don't just assume req.user exists because of cookie
  // Cookies can be CSRF'd - must validate origin
  const user = req.user; // May not be authenticated yet
});
```

### Secure: Send Token in First Message

```javascript
// CLIENT SIDE: Secure approach
const ws = new WebSocket('wss://api.example.com/socket');

ws.onopen = () => {
  // Send authentication in first message (not URL)
  const token = localStorage.getItem('auth_token');
  ws.send(JSON.stringify({
    type: 'auth',
    token: token
  }));
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.type === 'auth_response') {
    if (data.success) {
      console.log('Authenticated');
      // Now safe to send other messages
    } else {
      console.error('Authentication failed');
      ws.close();
    }
  }
};

// SERVER SIDE: Validate token and origin
wss.on('connection', (ws, req) => {
  // Validate origin first
  const origin = req.headers.origin;
  if (!isAllowedOrigin(origin)) {
    ws.close(1008, 'Unauthorized origin');
    return;
  }

  // Flag as unauthenticated until auth message received
  ws.isAuthenticated = false;
  let authTimeout = setTimeout(() => {
    if (!ws.isAuthenticated) {
      ws.close(1008, 'Authentication timeout');
    }
  }, 5000); // Must authenticate within 5 seconds

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      // First message must be authentication
      if (!ws.isAuthenticated) {
        if (data.type !== 'auth') {
          ws.close(1008, 'Must authenticate first');
          return;
        }

        // Verify token
        const user = verifyToken(data.token);
        if (!user) {
          ws.send(JSON.stringify({
            type: 'auth_response',
            success: false,
            message: 'Invalid token'
          }));
          ws.close(1008, 'Invalid token');
          return;
        }

        // Authenticated
        clearTimeout(authTimeout);
        ws.isAuthenticated = true;
        ws.user = user;

        ws.send(JSON.stringify({
          type: 'auth_response',
          success: true,
          user: user.username
        }));
        return;
      }

      // Process authenticated messages
      handleMessage(ws, data);
    } catch (error) {
      ws.send(JSON.stringify({ error: 'Invalid message format' }));
    }
  });
});
```

## Message Validation and Sanitization

### Vulnerable: No Validation

```javascript
// VULNERABLE: Trusting client input
wss.on('connection', (ws, req) => {
  ws.on('message', (message) => {
    const data = JSON.parse(message);

    // Dangerous: No validation
    db.messages.create({
      userId: data.userId,
      content: data.content,
      timestamp: data.timestamp // Client controls timestamp!
    });

    // Broadcast to all users
    broadcast(data);
  });
});
```

Attacker can:
- Set arbitrary userId (impersonate other users)
- Inject HTML/JavaScript in content (XSS)
- Set arbitrary timestamps (mislead others about message time)
- Send oversized messages (DoS)

### Secure: Validation and Sanitization

```javascript
const DOMPurify = require('isomorphic-dompurify');
const joi = require('joi');

// Define message schema
const messageSchema = joi.object({
  content: joi.string().trim().max(5000).required(),
  // Only send what server needs, not what client sends
  // Don't accept userId, timestamp - server provides these
});

wss.on('connection', (ws, req) => {
  if (!ws.isAuthenticated) {
    return;
  }

  ws.on('message', (message) => {
    try {
      let data;

      // Parse safely
      try {
        data = JSON.parse(message);
      } catch {
        return ws.send(JSON.stringify({ error: 'Invalid JSON' }));
      }

      // Validate schema
      const { error, value } = messageSchema.validate(data);
      if (error) {
        return ws.send(JSON.stringify({
          error: 'Validation failed',
          details: error.details[0].message
        }));
      }

      // Sanitize user input
      const sanitizedContent = DOMPurify.sanitize(value.content);

      // Server provides these, not client
      const messageRecord = {
        userId: ws.user.id,
        content: sanitizedContent,
        timestamp: new Date(),
        socketId: ws.id
      };

      // Store and broadcast
      db.messages.create(messageRecord);
      broadcast(messageRecord);
    } catch (error) {
      ws.send(JSON.stringify({ error: 'Server error' }));
    }
  });
});
```

## WSS (WebSocket Secure) Requirement

### Vulnerable: Unencrypted WebSocket

```
ws://api.example.com/socket  ← INSECURE
```

Without encryption:
- All messages are plaintext on the network
- Attacker can eavesdrop on messages
- Attacker can modify messages in transit
- Perfect for MITM attacks

### Secure: Encrypted WebSocket

```
wss://api.example.com/socket  ← SECURE
```

Use TLS encryption just like HTTPS.

### Implementation

```javascript
const WebSocket = require('ws');
const https = require('https');
const fs = require('fs');

const httpsServer = https.createServer({
  cert: fs.readFileSync('cert.pem'),
  key: fs.readFileSync('key.pem')
});

const wss = new WebSocket.Server({
  server: httpsServer,
  verifyClient: (info, callback) => {
    // Validate origin
    const allowedOrigins = ['https://example.com'];
    if (allowedOrigins.includes(info.origin)) {
      callback(true);
    } else {
      callback(false, 403, 'Forbidden');
    }
  }
});

httpsServer.listen(443);
```

## DoS via Large Messages or Connection Flooding

### DoS Attack 1: Large Message Flooding

```javascript
// Attacker sends huge messages
const ws = new WebSocket('wss://api.example.com/socket');

// Send 1MB messages repeatedly
const bigMessage = 'x'.repeat(1024 * 1024);
for (let i = 0; i < 1000; i++) {
  ws.send(bigMessage);
  // Server runs out of memory, crashes
}
```

### DoS Attack 2: Connection Flooding

```javascript
// Attacker opens thousands of connections
for (let i = 0; i < 10000; i++) {
  const ws = new WebSocket('wss://api.example.com/socket');
  // Don't authenticate, just hold connections open
  // Server resources exhausted
}
```

### Protection: Message Size and Rate Limiting

```javascript
const WebSocket = require('ws');
const express = require('express');
const http = require('http');

const app = express();
const server = http.createServer(app);

// Configure max message size
const wss = new WebSocket.Server({
  server,
  maxPayload: 64 * 1024, // 64 KB max per message
  verifyClient: (info, callback) => {
    // Validate origin
    const allowedOrigins = ['https://example.com'];
    if (allowedOrigins.includes(info.origin)) {
      callback(true);
    } else {
      callback(false, 403, 'Forbidden');
    }
  }
});

// Rate limiting per connection
const connectionLimits = new Map();

wss.on('connection', (ws, req) => {
  const clientId = req.socket.remoteAddress;

  // Initialize rate limiter for this client
  connectionLimits.set(clientId, {
    messageCount: 0,
    resetTime: Date.now() + 60000 // 1 minute window
  });

  ws.on('message', (message) => {
    // Check rate limit
    const limit = connectionLimits.get(clientId);

    if (Date.now() > limit.resetTime) {
      // Reset window
      limit.messageCount = 0;
      limit.resetTime = Date.now() + 60000;
    }

    limit.messageCount++;

    // Allow max 100 messages per minute
    if (limit.messageCount > 100) {
      ws.close(1008, 'Rate limit exceeded');
      connectionLimits.delete(clientId);
      return;
    }

    // Process message
    handleMessage(ws, message);
  });

  ws.on('close', () => {
    connectionLimits.delete(clientId);
  });
});

// Limit concurrent connections per IP
const connectionCounts = new Map();

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  const count = (connectionCounts.get(clientIp) || 0) + 1;

  if (count > 50) { // Max 50 connections per IP
    ws.close(1008, 'Too many connections');
    return;
  }

  connectionCounts.set(clientIp, count);

  ws.on('close', () => {
    connectionCounts.set(clientIp, Math.max(0, count - 1));
  });
});

server.listen(443);
```

## Best Practices

1. **Always use WSS (encrypted WebSocket)**: Never use unencrypted ws:// for sensitive data
2. **Validate origin headers**: Implement strict origin checking
3. **Authenticate before processing messages**: Require auth in first message, timeout if not received
4. **Don't pass tokens in URL**: Use message body or secure cookies
5. **Validate all messages**: Implement strict schema validation
6. **Sanitize user input**: Prevent XSS and injection attacks
7. **Implement rate limiting**: Prevent DoS via message flooding
8. **Limit message sizes**: Prevent memory exhaustion
9. **Limit concurrent connections**: Prevent connection flooding DoS
10. **Never trust client-provided IDs**: Always use authenticated user's ID from session
11. **Implement proper error handling**: Don't leak sensitive information in error messages
12. **Monitor WebSocket connections**: Track unusual patterns
13. **Use HTTPS for initial connection**: API discovery and authentication should be HTTPS
14. **Implement heartbeats**: Detect stale connections
15. **Test WebSocket security**: Include WebSocket-specific security tests in CI/CD
