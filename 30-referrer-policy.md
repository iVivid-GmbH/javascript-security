# Referrer-Policy

## Definition

The Referrer-Policy HTTP header controls how much referrer information is shared when a user navigates away from your page or requests external resources. The Referer header (note: misspelled in HTTP spec) contains the URL of the page that initiated the request, which can leak sensitive information.

A comprehensive Referrer-Policy prevents:
- Leaking sensitive URL parameters in the Referer header
- Exposing internal URL structures
- Revealing user navigation patterns
- Sharing session tokens or other sensitive data embedded in URLs

## What the Referer Header Leaks

### Leaking Sensitive URL Parameters

```
Current page (bank.example.com):
https://bank.example.com/accounts/12345/statements?year=2025&month=3&token=abc123xyz

User clicks link to external site (attacker.com):
<a href="https://attacker.com/innocuous-page">Click here</a>

Referer header sent to attacker.com:
Referer: https://bank.example.com/accounts/12345/statements?year=2025&month=3&token=abc123xyz

Attacker sees:
- Account number: 12345
- Year and month parameters
- Session/auth token: abc123xyz
- All from the Referer header!

Attacker can:
- Use token to access the account
- Analyze user's banking behavior
- Share account number with other attackers
```

### Leaking Internal Paths

```
Page on internal company site:
https://internal.company.com/employees/john-doe/salary-review

User clicks link to external training provider:
<a href="https://training-provider.com/course">Learning resources</a>

Referer sent:
Referer: https://internal.company.com/employees/john-doe/salary-review

External training provider learns:
- Employee directory structure
- Specific employee name
- Salary review information
- Potentially confidential information
```

### Leaking Session Tokens in URLs

```
Page with session token in URL (bad practice):
https://shop.example.com/checkout?session=abc123def456ghi789

User clicks social media share button that links externally:
<a href="https://facebook.com/share?url=https://shop.example.com/checkout?session=abc123def456ghi789">

Referer sent:
Referer: https://shop.example.com/checkout?session=abc123def456ghi789

Social media platform (or government intercepting traffic) sees:
- Full session token
- User's shopping session
- Ability to hijack the session
```

### Leaking User Navigation Patterns

```
Analytics domain tracks user across sites:
1. User on site-a.com (page about medical conditions)
   Clicks: <img src="https://tracker.example.com/track">
   Referer: https://site-a.com/conditions/heart-disease

2. User on site-b.com (insurance company)
   Clicks: <img src="https://tracker.example.com/track">
   Referer: https://site-b.com/insurance

3. User on site-c.com (pharmacy)
   Clicks: <img src="https://tracker.example.com/track">
   Referer: https://site-c.com/products

Tracker correlates:
- Medical condition searches
- Insurance shopping
- Pharmacy visits
- Complete health profile (privacy violation)
```

## The Referrer-Policy Header Values Explained

### no-referrer

**Behavior**: Never send any Referer header

```
Referrer-Policy: no-referrer

Current page: https://bank.example.com/accounts/12345/statements?token=secret

User navigates to: https://external.com

Referer header sent: (none)
```

**When to use:**
- Maximum privacy for users
- Sensitive information commonly in URLs
- Privacy-focused organizations

**Trade-offs:**
- Some analytics tools rely on Referer
- Referrer information lost for legitimate analytics
- Website can't see where traffic came from

### no-referrer-when-downgrade (Default in older browsers)

**Behavior**: Send Referer only when navigating from HTTPS to HTTPS. Don't send when going from HTTPS to HTTP (downgrade).

```
Referrer-Policy: no-referrer-when-downgrade

From HTTPS to HTTPS:
https://bank.example.com → https://external.com
Referer: https://bank.example.com ✓ (sent)

From HTTPS to HTTP:
https://bank.example.com → http://external.com
Referer: (not sent) ✗ (downgrade to unencrypted)
```

**Purpose**: Don't leak HTTPS URLs to unencrypted HTTP connections

**When to use:**
- Default conservative behavior
- When you want most referrer information available for analytics
- But refuse to downgrade to HTTP

**Trade-offs:**
- Still leaks sensitive information if destination is HTTPS
- Doesn't help if transitioning between two HTTPS sites

### same-origin

**Behavior**: Send Referer only for same-origin requests. Nothing for cross-origin.

```
Referrer-Policy: same-origin

Current origin: https://bank.example.com
Clicking link on bank.example.com to bank.example.com:
Referer: https://bank.example.com ✓ (same origin)

Clicking link on bank.example.com to external.com:
Referer: (not sent) ✗ (cross-origin)
```

**Purpose**: Prevent leaking information to external sites

**When to use:**
- Most websites should use this
- Protects privacy while maintaining analytics within your site
- Prevents cross-site information leakage

**Trade-offs:**
- External referrer tracking won't work (third-party analytics)
- Partner sites won't know traffic came from you

### strict-origin

**Behavior**: Send only the origin (scheme + domain + port), never the full URL path.

```
Referrer-Policy: strict-origin

From: https://bank.example.com/accounts/12345/statements?token=secret
To: https://external.com

Referer sent: https://bank.example.com (only origin, no path or query!)
```

**Purpose**: Allow referrer tracking but strip sensitive URL parts

**When to use:**
- Want basic referrer information but protect sensitive details
- Analytics needs to know which site traffic came from
- Can't use full URL because of sensitive parameters

**Trade-offs:**
- Still leaks origin information
- Doesn't prevent HTTPS to HTTP downgrade (use strict-origin-when-cross-origin)

### strict-origin-when-cross-origin

**Behavior**: Send origin for cross-origin HTTPS requests. Send full URL for same-origin.

```
Referrer-Policy: strict-origin-when-cross-origin

Same-origin request (bank.example.com to bank.example.com):
From: https://bank.example.com/accounts/12345
To: https://bank.example.com/transfer
Referer: https://bank.example.com/accounts/12345 ✓ (full URL)

Cross-origin HTTPS:
From: https://bank.example.com/accounts/12345/statements?token=secret
To: https://external.com
Referer: https://bank.example.com (only origin) ✓ (no path/query)

Cross-origin HTTPS to HTTP (downgrade):
From: https://bank.example.com/accounts/12345
To: http://external.com
Referer: (not sent) ✓ (no downgrade)
```

**Purpose**: Reasonable balance of privacy and functionality

**When to use:**
- Default for modern browsers if no policy set
- Recommended for most websites
- Good balance between privacy and analytics needs

## Setting via HTTP Header vs HTML Meta Tag vs referrerpolicy Attribute

### HTTP Header (Recommended)

Set on every response:

```
Referrer-Policy: strict-origin-when-cross-origin
```

**Pros:**
- Applies to all resources
- Consistent enforcement
- Highest priority if conflicts exist

**Implementation:**

```javascript
const express = require('express');
const app = express();

// Set header on all responses
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

app.get('/', (req, res) => {
  res.send('Page with referrer policy');
});
```

### HTML Meta Tag

Set in the `<head>` of the page:

```html
<!DOCTYPE html>
<html>
  <head>
    <meta name="referrer" content="strict-origin-when-cross-origin">
  </head>
  <body>
    <!-- Content -->
  </body>
</html>
```

**Pros:**
- Can be set per-page
- Useful if you can't set headers (static hosting)

**Cons:**
- Only applies to the current page
- Can be overridden by individual elements
- Not available for cross-origin subresources

**Implementation:**

```javascript
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta name="referrer" content="strict-origin-when-cross-origin">
      </head>
      <body>
        <h1>Page with referrer policy</h1>
      </body>
    </html>
  `);
});
```

### referrerpolicy Attribute on Elements

Set on individual links or images:

```html
<!-- Link-specific policy -->
<a href="https://external.com" referrerpolicy="no-referrer">External Link</a>

<!-- Image-specific policy -->
<img src="https://external.com/image.png" referrerpolicy="no-referrer" alt="Image">

<!-- Iframe-specific policy -->
<iframe src="https://external.com/embed" referrerpolicy="no-referrer"></iframe>

<!-- Form-specific policy -->
<form action="https://external.com/submit" referrerpolicy="no-referrer">
  <input type="text" name="data">
  <button>Submit</button>
</form>
```

**Pros:**
- Fine-grained control per element
- Useful for specific sensitive links

**Cons:**
- Must apply to every relevant element
- Easy to miss sensitive links
- More maintenance

**Hierarchy of policies** (when multiple are set):

```
Element-level (referrerpolicy attribute) > Meta tag > HTTP header

// If element has referrerpolicy, it overrides page/header policies
// If element has no policy, use meta tag policy
// If no meta tag, use HTTP header policy
```

## Best Practices

### For Most Websites

```javascript
// Set default policy on all pages
const express = require('express');
const app = express();

app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// OR use Helmet.js
const helmet = require('helmet');
app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));
```

### For Privacy-Focused Sites

```javascript
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});
```

### For Analytics-Heavy Sites (Still Protecting Privacy)

```javascript
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});
```

## Practical Implications

### Third-Party Analytics

```
With: Referrer-Policy: strict-origin-when-cross-origin

Analytics vendor tracking your users:
<img src="https://analytics.com/track?event=pageview">

Will see:
Referer: https://yoursite.com (only origin, no path)

Cannot see:
- Specific pages users visited
- Query parameters
- User behavior details
```

### Partner Websites

```
With: Referrer-Policy: strict-origin-when-cross-origin

Affiliate link to partner:
<a href="https://partner-store.com/products">Shop Now</a>

Partner sees:
Referer: https://yoursite.com (knows traffic came from you)

Cannot see:
- What page they came from
- User personal information in URLs
```

### Internal Navigation

```
With: Referrer-Policy: strict-origin-when-cross-origin

Internal links within your site:
From: https://yoursite.com/admin/secret-page
To: https://yoursite.com/admin/settings

Admin dashboard sees:
Referer: https://yoursite.com/admin/secret-page (full URL)

Allows analytics on internal navigation while protecting external sharing
```

## Implementation Checklist

1. **Set HTTP header**: Apply to all responses via middleware
2. **Test in browser devtools**: Verify Network tab shows correct Referer
3. **Test cross-origin navigation**: Verify Referer is properly restricted
4. **Document your choice**: Team should understand the policy
5. **Consider your analytics needs**: Ensure policy doesn't break analytics
6. **Test with real users**: Verify no functionality breaks
7. **Monitor analytics data**: Ensure you still get useful information
8. **Review regularly**: Update policy if requirements change
9. **Use Helmet.js or similar**: Don't manage headers manually
10. **Document for partners**: Let analytics vendors know your policy

## Summary Table

| Policy | Same-origin | Cross-origin HTTPS | Cross-origin HTTP |
|--------|-------------|-------------------|-------------------|
| **no-referrer** | Nothing | Nothing | Nothing |
| **no-referrer-when-downgrade** | Full URL | Full URL | Nothing |
| **same-origin** | Full URL | Nothing | Nothing |
| **strict-origin** | Origin | Origin | Origin |
| **strict-origin-when-cross-origin** | Full URL | Origin | Nothing |

**Recommended**: `strict-origin-when-cross-origin` (default in modern browsers)

- Provides analytics via origin
- Protects sensitive URL parameters from external sites
- Prevents HTTPS to HTTP downgrade leakage
- Good balance of privacy and functionality
