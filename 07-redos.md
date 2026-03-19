# ReDoS: Regular Expression Denial of Service

## Definition

ReDoS (Regular Expression Denial of Service) is a vulnerability where a specially crafted input causes a regular expression to take an exponentially long time to execute, consuming CPU resources and effectively denying service to legitimate users.

The vulnerability occurs when a regex engine uses catastrophic backtracking, where the regex engine tries every possible combination of patterns when matching against input, leading to exponential time complexity instead of the expected linear or polynomial complexity.

A single malicious input can cause a regex to hang for seconds, minutes, or even indefinitely, blocking execution and potentially crashing the application or service.

---

## How Regex Backtracking Works

### Normal Regex Matching

```javascript
// Simple regex - no backtracking issues
const regex = /^abc$/;

// Matches: "abc"
// Doesn't match: "abd"

// The engine:
// 1. Try to match 'a' at position 0 - success
// 2. Try to match 'b' at position 1 - success
// 3. Try to match 'c' at position 2 - success
// 4. End of string - match successful
```

### Backtracking Basics

```javascript
// Regex with backtracking
const regex = /^(a+)+b$/;

// Matches: "aaab"
const result1 = regex.test("aaab"); // true - fast

// Testing against non-matching input triggers backtracking
// const result2 = regex.test("aaac"); // SLOW!

// Why it's slow:
// The regex engine:
// 1. (a+) matches "aaa"
// 2. The outer (a+)+ tries to match more "a"s
// 3. No more "a"s to match
// 4. Outer group backtracks, tries (a+) with "aa"
// 5. Tries to match "b" - doesn't match "a"
// 6. Backtracks again, tries (a+) with "a"
// 7. Tries to match "b" - doesn't match "a"
// 8. No match found
// 9. Repeats for every possible combination - EXPONENTIAL TIME!
```

### Visualization of Backtracking

```javascript
// Vulnerable pattern: (a+)+b
// Input: "aaaaaaaaaaaaaaaaaaaaaaaac" (20 a's and a c)

// The regex engine tries:
// 1. (a+)+ matches all 20 a's
// 2. Looks for 'b' at position 20 - finds 'c' instead - backtrack

// 3. (a+) matches 19 a's, outer (a+)+ tries to match 1 more
// 4. That 1 'a' is already consumed by first group - backtrack

// 5. Try different split: (a+) matches 18 a's, rest for outer group
// ... and so on for every possible split ...

// Result: 2^20 = ~1,000,000 attempts for just 20 a's!
// With 30 a's: 2^30 = ~1,000,000,000 attempts
// Input becomes larger = exponential explosion
```

---

## Vulnerable Regex Patterns

### Pattern 1: Nested Quantifiers

```javascript
// VULNERABLE: Nested quantifiers with alternation
const vulnerable1 = /^(a+)+$/;
const vulnerable2 = /^(a*)*$/;
const vulnerable3 = /^(a+)*$/;

// All trigger catastrophic backtracking on non-matching input
// Input: "aaaaaaaaaaaaaaaaaaaaaaaab"
vulnerable1.test("aaaaaaaaaaaaaaaaaaaaaaaab"); // EXTREMELY SLOW!
```

### Pattern 2: Alternation with Overlap

```javascript
// VULNERABLE: Alternation where patterns overlap
const vulnerable4 = /^(a|a)*$/;
const vulnerable5 = /^(a|ab)*$/;
const vulnerable6 = /^(a|ba)*$/;

// When input doesn't match, engine tries all combinations
vulnerable4.test("aaaaaaaaaaaaaaaaaaaaaaaaaac"); // SLOW!

// The patterns overlap:
// 'a' matches
// 'a' followed by '' matches
// Both are valid options, engine explores all paths
```

### Pattern 3: Multiple Optional Groups

```javascript
// VULNERABLE: Multiple optional/repeating groups
const vulnerable7 = /^(a?){n}$/; // where n is large
const vulnerable8 = /^.*a.*a.*a.*b$/;
const vulnerable9 = /^(x+x+)+y$/;

// Input that almost matches triggers all combinations
vulnerable7.test("aaaaaaaaaaaaaaaaaaaaaaaaaac"); // SLOW!
```

### Pattern 4: Branching with Repeats

```javascript
// VULNERABLE: Branches combined with repeats
const vulnerable10 = /^(x|xx)+$/;
const vulnerable11 = /^(a|ab)+$/;

// Input: "xxxxxxxxxxxxxxxxxxxxxxx"
// Engine tries all ways to split the input:
// x|xx|x|xx|x|xx... OR
// x|x|x|x|x|x...
// Each combination is valid, exponential paths

vulnerable10.test("xxxxxxxxxxxxxxxxxxxxxxx"); // SLOW!
```

### Pattern 5: Real-World Examples

```javascript
// Email validation - VULNERABLE
const badEmail = /^([a-zA-Z0-9]+)*@example\.com$/;
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaaab@example.com"
// Non-matching character causes exponential backtracking

// URL validation - VULNERABLE
const badURL = /^(https?:\/\/)*(.*)*\.com$/;
// Can cause ReDoS on malformed URLs

// Date validation - VULNERABLE
const badDate = /^(\d+)(\d+)*(\d+)*$/;
// Can cause ReDoS with long strings of digits

// Whitespace handling - VULNERABLE
const badTrim = /^(\s)*(\s)*$/;
// Can cause ReDoS with long whitespace strings
```

---

## Real Vulnerable Code Examples

### Example 1: User Input Validation

```javascript
// VULNERABLE: Email validation with ReDoS-prone regex
const emailRegex = /^([a-zA-Z0-9._-])+@([a-zA-Z0-9._-])+\.([a-zA-Z0-9_-])+$/;

app.post('/api/register', (req, res) => {
  const email = req.body.email;

  // Vulnerable validation
  if (emailRegex.test(email)) {
    // Register user
  } else {
    res.status(400).json({ error: 'Invalid email' });
  }

  // Attack input: aaaaaaaaaaaaaaaaaaaaaaaaaaa!@example.com
  // The regex engine gets stuck, blocking the request
  // Application becomes unresponsive
});
```

### Example 2: Input Sanitization

```javascript
// VULNERABLE: HTML tag removal with ReDoS-prone regex
const htmlRegex = /^.*(<[a-zA-Z]+[^>]*>)*.*$/;

function removeHTMLTags(input) {
  if (htmlRegex.test(input)) {
    return input.replace(htmlRegex, '');
  }
  return '';
}

// Attack input: Long string without closing tags
const malicious = 'a'.repeat(30) + '<div>';
removeHTMLTags(malicious); // FREEZES!
```

### Example 3: URL Validation

```javascript
// VULNERABLE: URL parsing with ReDoS-prone regex
const urlRegex = /^((https?:\/\/)?(www\.)?[a-zA-Z0-9._-]+)*(\.[a-zA-Z0-9]+)*$/;

function validateURL(url) {
  // Validation hangs on malformed input
  return urlRegex.test(url); // VULNERABLE
}

const malicious = 'http://' + 'a'.repeat(50) + '!';
validateURL(malicious); // FREEZES!
```

### Example 4: Search and Replace

```javascript
// VULNERABLE: Search with ReDoS-prone regex
const searchRegex = /^(a|ab)+c$/;

function searchContent(query) {
  return documentContent.match(searchRegex);
}

// Attack input: No 'c' at the end, causes ReDoS
const malicious = 'a'.repeat(30) + 'd';
searchContent(malicious); // FREEZES!
```

---

## Impact of ReDoS

### Impact 1: CPU Exhaustion

```javascript
// Single malicious request can consume 100% CPU
const vulnerable = /^(a+)+b$/;

// Main thread blocked, no other requests processed
// setTimeout callbacks don't execute
// User interface becomes unresponsive
vulnerable.test('a'.repeat(50) + 'c');
```

### Impact 2: Denial of Service

```javascript
// Attacker sends multiple malicious inputs
for (let i = 0; i < 1000; i++) {
  // Each request freezes the server for several seconds
  fetch('/api/validate', {
    body: JSON.stringify({
      input: 'a'.repeat(30) + 'invalid'
    })
  });
}

// Server becomes unresponsive to legitimate requests
```

### Impact 3: Application Crash

```javascript
// Timeout/crash after prolonged backtracking
const vulnerable = /^(a+)*b$/;

try {
  vulnerable.test('a'.repeat(100) + 'c');
  // Takes too long, JavaScript runtime kills execution
  // Application crashes
} catch (e) {
  // Might catch error or crash ungracefully
}
```

---

## Safe Regex Alternatives

### Alternative 1: Use Simpler Regex

```javascript
// VULNERABLE: Nested quantifiers
const vulnerable = /^(a+)+$/;

// SAFE: Simpler pattern without nested quantifiers
const safe = /^a+$/;

// SAFE: Avoid overlapping alternations
const vulnerable2 = /^(a|ab)*$/;
const safe2 = /^(ab|a)*$/;
```

### Alternative 2: Flatten Quantifiers

```javascript
// VULNERABLE: Nested quantifiers
const vulnerable = /^(a+)+$/;

// SAFE: Flatten to single quantifier
const safe = /^a+$/;

// VULNERABLE: (x+x+)+
const vulnerable2 = /^(x+x+)+$/;

// SAFE: Simplify
const safe2 = /^(xx)+$/; // or just /^xx*$/
```

### Alternative 3: Use Possessive Quantifiers (When Supported)

```javascript
// JavaScript doesn't support possessive quantifiers natively
// But some JavaScript regex implementations and TypeScript do:

// VULNERABLE: (a+)+
const vulnerable = /^(a+)+$/;

// SAFE with possessive quantifier (not standard JS):
// const safe = /^(a+)+$/; // Not available in JS

// JavaScript alternative: Use atomic grouping (limited support)
```

### Alternative 4: Use Built-in String Methods

```javascript
// VULNERABLE: Complex regex for simple tasks
const vulnerable = /^([a-zA-Z0-9._-])+@([a-zA-Z0-9._-])+$/;

// SAFE: String methods (simple validation)
function simpleEmailCheck(email) {
  return email.includes('@') && email.length > 5;
}

// SAFE: Use proper email validation library
const emailValidator = require('email-validator');
const isValid = emailValidator.validate(email);
```

### Alternative 5: Use Libraries for Common Tasks

```javascript
// Email validation
const validator = require('validator');
const isEmail = validator.isEmail(email); // ✓ Safe

// URL validation
const isURL = validator.isURL(url); // ✓ Safe

// IP address validation
const isIP = validator.isIP(ip); // ✓ Safe

// These libraries use carefully tested, ReDoS-safe patterns
```

### Alternative 6: Input Length Limits

```javascript
// VULNERABLE: Potentially ReDoS-prone regex
const vulnerable = /^(a|ab)*$/;

function validateInput(input) {
  // Add length check before regex
  if (input.length > 100) {
    return false;
  }

  // Now regex is less likely to cause issues
  return vulnerable.test(input);
}

// This doesn't fix the vulnerability but limits impact
```

### Alternative 7: Timeout for Regex Execution

```javascript
// Wrap regex in a timeout (workaround, not ideal)
function testWithTimeout(regex, input, timeoutMs = 1000) {
  return new Promise((resolve) => {
    let completed = false;

    const worker = new Worker('regex-worker.js');
    worker.onmessage = (e) => {
      completed = true;
      resolve(e.data);
    };

    worker.postMessage({ regex: regex.source, input });

    // Kill worker if it takes too long
    setTimeout(() => {
      if (!completed) {
        worker.terminate();
        resolve(false); // Assume invalid
      }
    }, timeoutMs);
  });
}

// Usage
const result = await testWithTimeout(
  /^(a+)+$/,
  'a'.repeat(50) + 'b',
  1000
);
```

---

## Detecting ReDoS Vulnerabilities

### Manual Testing

```javascript
// Test 1: Find patterns with nested quantifiers
const patterns = [
  /^(a+)+$/,      // ❌ (a+)+
  /^(a*)*$/,      // ❌ (a*)*
  /^(a+)*$/,      // ❌ (a+)*
  /^(a|a)*$/,     // ❌ (a|a)*
  /^(a|ab)*$/,    // ⚠️ Alternation with overlap
  /^a+$/          // ✓ Safe
];

// Test 2: Measure execution time
function testRegexPerformance(regex, input) {
  const start = performance.now();
  const result = regex.test(input);
  const duration = performance.now() - start;

  console.log(`Regex test took ${duration}ms`);

  if (duration > 100) {
    console.warn('POSSIBLE ReDoS VULNERABILITY!');
  }

  return result;
}

// Test with increasingly long input
const testInput = 'a'.repeat(20) + 'x'; // Doesn't match
testRegexPerformance(/^(a+)+b$/, testInput); // Will be slow
```

### Tools for Detection

```bash
# safe-regex: Detects ReDoS-prone patterns
npm install safe-regex
```

```javascript
const safe = require('safe-regex');

console.log(safe(/^(a+)+$/));      // false - VULNERABLE
console.log(safe(/^(a|ab)*$/));    // false - VULNERABLE
console.log(safe(/^a+$/));         // true - SAFE
console.log(safe(/^[a-z]+$/));     // true - SAFE
```

### Using safe-regex Programmatically

```javascript
const safe = require('safe-regex');

// Validate regexes at build time
const regexPatterns = [
  /^(a+)+$/,
  /^[a-z]+$/,
  /^(a|ab)*$/
];

regexPatterns.forEach((regex, index) => {
  if (!safe(regex)) {
    console.error(`Pattern ${index} is vulnerable to ReDoS`);
    process.exit(1);
  }
});

console.log('All regex patterns are safe!');
```

---

## Best Practices Checklist

1. **Avoid Nested Quantifiers**
   ```javascript
   // ❌ VULNERABLE
   /^(a+)+$/

   // ✓ SAFE
   /^a+$/
   ```

2. **Avoid Overlapping Alternations**
   ```javascript
   // ❌ VULNERABLE
   /^(a|ab)*$/

   // ✓ SAFE
   /^(ab|a)*$/ // More specific pattern first
   ```

3. **Flatten Quantifiers**
   ```javascript
   // ❌ VULNERABLE
   /^(a*)*$/

   // ✓ SAFE
   /^a*$/
   ```

4. **Use Built-in String Methods for Simple Tasks**
   ```javascript
   // ❌ VULNERABLE regex
   /^[a-z]+[.][a-z]+$/

   // ✓ SAFE: String method
   input.includes('.')
   ```

5. **Use Established Libraries**
   ```javascript
   // ❌ Rolling your own regex
   /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/

   // ✓ Use validator library
   const validator = require('validator');
   validator.isEmail(email);
   ```

6. **Limit Input Length**
   ```javascript
   function validateInput(input, maxLength = 100) {
     if (input.length > maxLength) {
       return false;
     }
     return regex.test(input);
   }
   ```

7. **Use Safe-Regex to Check Your Patterns**
   ```bash
   npm install safe-regex
   ```

   ```javascript
   const safe = require('safe-regex');
   if (!safe(myRegex)) {
     throw new Error('Regex might be vulnerable to ReDoS');
   }
   ```

8. **Test Regex Performance**
   ```javascript
   function measureRegex(regex, input) {
     const start = performance.now();
     regex.test(input);
     const duration = performance.now() - start;
     return duration;
   }

   const slowTime = measureRegex(/^(a+)+$/, 'a'.repeat(25) + 'b');
   if (slowTime > 100) {
     console.warn('Regex is too slow');
   }
   ```

9. **Code Review**
   - Review all regex patterns before merging
   - Check for nested quantifiers
   - Check for overlapping alternations
   - Test with non-matching inputs

10. **Monitor in Production**
    - Log regex execution times
    - Alert on slow regex matches
    - Monitor CPU usage
    - Rate-limit input validation

11. **Documentation**
    - Document why each regex is safe
    - Include performance notes
    - Link to validation resources

12. **Use TypeScript with Strict Regex Checking**
    ```typescript
    // Some TypeScript plugins can check regex patterns
    // Look for 'typescript-eslint' with regex rules
    ```

---

## Real-World Impacts

- **2016 Node.js vulnerability**: ReDoS in debug library affected many applications
- **CloudFlare WAF**: ReDoS vulnerability in ModSecurity rules
- **Email validation libraries**: Multiple versions vulnerable to ReDoS
- **Ruby on Rails**: ReDoS in default MIME type checking regex
- **jQuery**: ReDoS vulnerabilities in selector parsing

---

## Related Reading

- OWASP: Regular Expression Denial of Service (ReDoS)
- CWE-1333: Inefficient Regular Expression Complexity
- safe-regex GitHub: https://github.com/substack/safe-regex
- vuln-regex-detector: Tool for finding vulnerable patterns
- Regular Expressions – Stop doing it wrong! (High-Performance Talk)
- RFC 5987: Internationalized Encoding for HTTP Headers
