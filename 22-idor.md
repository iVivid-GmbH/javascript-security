# IDOR - Insecure Direct Object References

## Definition

Insecure Direct Object References (IDOR) is a vulnerability where an application exposes direct references to objects (database records, files, etc.) in a way that allows an attacker to access unauthorized resources by manipulating those references. The vulnerability occurs when the application fails to properly verify that the user has authorization to access a specific object before returning it.

IDOR is fundamentally an authorization vulnerability, not an authentication vulnerability. The user is authenticated (logged in), but they shouldn't have permission to access certain resources based on their role or relationship to the data.

## How IDOR Works

The attack involves three steps:

1. **Identify the direct reference**: User notices the application uses predictable identifiers (e.g., `userId=123`, `documentId=456`)
2. **Manipulate the reference**: Attacker changes the identifier to access other users' resources (e.g., `userId=124`, `userId=125`)
3. **Bypass authorization check**: The server returns the resource without verifying the requester has permission

## Horizontal vs Vertical Privilege Escalation via IDOR

### Horizontal Privilege Escalation (Lateral)

Accessing resources belonging to other users **at the same privilege level**. For example:

- User A accesses User B's documents by changing the user ID in the URL
- Customer accesses another customer's order history
- Employee views another employee's payroll information (both are employees)

This is the most common form of IDOR.

### Vertical Privilege Escalation

Accessing resources or functionality that should be restricted to **higher privilege users**. For example:

- Regular user accesses admin-only reports
- Customer accesses internal company financial data
- User without payment permission directly calls the payment processing API

Both are critical vulnerabilities, though vertical privilege escalation is often more severe.

## REST API Examples

### Example 1: GET Request for User Documents

```
GET /api/users/1234/documents HTTP/1.1
Host: app.example.com
Authorization: Bearer token_for_user_5678
```

This endpoint should only return documents for user 5678, but if it doesn't check authorization, it will return documents for any user ID in the URL. An attacker can simply change `1234` to other values.

### Example 2: Direct Resource Access

```
GET /api/invoices/789 HTTP/1.1
Host: app.example.com
Authorization: Bearer token_for_user_5678
```

The `invoices/789` reference is direct. If the server doesn't verify that user 5678 is the owner of invoice 789, any authenticated user can access it.

### Example 3: Nested Resource

```
GET /api/organizations/10/users/300/settings HTTP/1.1
Host: app.example.com
Authorization: Bearer token_for_admin_user
```

Even nested routes are vulnerable if authorization isn't properly checked at each level.

## How to Exploit IDOR

### Changing Numeric IDs

The simplest exploitation technique:

```bash
# Legitimate request for your own profile
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://api.example.com/api/users/5678

# Attacker's exploitation attempt (changing the ID)
curl -H "Authorization: Bearer ATTACKER_TOKEN" \
  https://api.example.com/api/users/5679

curl -H "Authorization: Bearer ATTACKER_TOKEN" \
  https://api.example.com/api/users/5680

# Attacker repeats with different IDs (possibly automated)
```

If the application doesn't check authorization, both requests return sensitive data about those users.

### Guessing UUIDs

While UUIDs are harder to guess than sequential IDs, they're not impossible:

1. **Collect multiple UUIDs**: If the application exposes UUIDs in API responses or HTTP headers
2. **Pattern analysis**: Some UUID generation isn't truly random (may be time-based UUIDs)
3. **Brute forcing**: With enough requests and computing power, UUIDs can be brute forced (especially v1 UUIDs)
4. **Information leakage**: Sometimes UUIDs appear in email confirmations, referrer headers, logs, etc.

Example attack:

```javascript
// If you notice UUIDs follow a pattern or can be enumerated
// Attacker obtains a known UUID: a7c2f4e1-9b8d-4c7f-8e3a-2d1b5f9c6a8e

// Try nearby UUIDs (if time-based v1 UUIDs are used)
const attackUrls = [
  'https://api.example.com/api/documents/a7c2f4e1-9b8d-4c7f-8e3a-2d1b5f9c6a8e',
  'https://api.example.com/api/documents/a7c2f4e1-9b8d-4c7f-8e3a-2d1b5f9c6a8f',
  'https://api.example.com/api/documents/a7c2f4e1-9b8d-4c7f-8e3a-2d1b5f9c6a90'
];

// Fetch each and see if they return valid documents
```

## Object-Level Authorization Checks

The fix to IDOR is straightforward: implement proper authorization checks at the object level. The principle is:

**Before returning an object, verify the current user has permission to access that specific object.**

## Vulnerable Code Example

```javascript
const express = require('express');
const app = express();

// Middleware that only checks authentication, not authorization
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    // Verify token and set req.user
    req.user = verifyToken(token);
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
};

app.use(authenticate);

// VULNERABLE: No authorization check
app.get('/api/users/:userId/documents', (req, res) => {
  const { userId } = req.params;

  // Simply fetch and return without checking if req.user owns the documents
  const documents = db.documents.find({ ownerId: userId });
  res.json(documents);
  // PROBLEM: Any authenticated user can access any user's documents
});

// VULNERABLE: No ownership verification
app.get('/api/invoices/:invoiceId', (req, res) => {
  const { invoiceId } = req.params;

  const invoice = db.invoices.findById(invoiceId);
  if (!invoice) {
    return res.status(404).send('Not found');
  }

  // Returns invoice without checking if req.user is the owner
  res.json(invoice);
});

// VULNERABLE: Trusting client-supplied user ID
app.post('/api/orders', (req, res) => {
  const { userId, items, total } = req.body;

  // CRITICAL FLAW: Attacker can set userId to any value
  const order = db.orders.create({
    userId: userId, // Should be req.user.id
    items: items,
    total: total,
    createdAt: new Date()
  });

  res.status(201).json(order);
});

// VULNERABLE: Horizontal privilege escalation in settings update
app.put('/api/users/:userId/settings', (req, res) => {
  const { userId } = req.params;
  const { theme, language, notifications } = req.body;

  // No check that req.user.id === userId
  const updated = db.users.findByIdAndUpdate(userId, {
    theme,
    language,
    notifications
  });

  res.json(updated);
});
```

## Secure Code Example

```javascript
const express = require('express');
const app = express();

// Middleware that checks authentication
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (token) {
    req.user = verifyToken(token);
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
};

app.use(authenticate);

// SECURE: Authorization check at object level
app.get('/api/users/:userId/documents', (req, res) => {
  const { userId } = req.params;
  const currentUserId = req.user.id;

  // Verify ownership before returning documents
  if (parseInt(userId) !== currentUserId && !req.user.isAdmin) {
    return res.status(403).send('Forbidden');
  }

  const documents = db.documents.find({ ownerId: parseInt(userId) });
  res.json(documents);
});

// SECURE: Verify ownership before returning resource
app.get('/api/invoices/:invoiceId', (req, res) => {
  const { invoiceId } = req.params;
  const currentUserId = req.user.id;

  const invoice = db.invoices.findById(invoiceId);
  if (!invoice) {
    return res.status(404).send('Not found');
  }

  // Authorization check: verify user owns or has permission for this invoice
  if (invoice.ownerId !== currentUserId && !isUserAdmin(currentUserId)) {
    return res.status(403).send('Forbidden');
  }

  res.json(invoice);
});

// SECURE: Use authenticated user ID, never trust client
app.post('/api/orders', (req, res) => {
  const { items, total } = req.body;
  const userId = req.user.id; // Use authenticated user, not from request body

  // Additional validation
  if (!items || items.length === 0) {
    return res.status(400).send('Invalid items');
  }

  const order = db.orders.create({
    userId: userId, // Secured: uses req.user.id
    items: items,
    total: total,
    createdAt: new Date()
  });

  res.status(201).json(order);
});

// SECURE: Verify ownership before allowing update
app.put('/api/users/:userId/settings', (req, res) => {
  const { userId } = req.params;
  const currentUserId = req.user.id;
  const { theme, language, notifications } = req.body;

  // Authorization check
  if (parseInt(userId) !== currentUserId && !req.user.isAdmin) {
    return res.status(403).send('Forbidden');
  }

  const updated = db.users.findByIdAndUpdate(parseInt(userId), {
    theme,
    language,
    notifications
  });

  res.json(updated);
});

// SECURE: Generic middleware for checking resource ownership
const checkResourceOwnership = (resourceModel) => {
  return async (req, res, next) => {
    const { id } = req.params;
    const currentUserId = req.user.id;

    const resource = await resourceModel.findById(id);
    if (!resource) {
      return res.status(404).send('Not found');
    }

    if (resource.ownerId !== currentUserId && !req.user.isAdmin) {
      return res.status(403).send('Forbidden');
    }

    req.resource = resource;
    next();
  };
};

// Use the middleware
app.get('/api/documents/:id',
  checkResourceOwnership(db.documents),
  (req, res) => {
    res.json(req.resource);
  }
);
```

## Resource Ownership Validation in Node.js/Express Middleware

A reusable approach is to create middleware that enforces ownership checks:

```javascript
// Middleware factory for ownership validation
const requireOwnership = (resourceGetter) => {
  return async (req, res, next) => {
    try {
      const { id } = req.params;
      const userId = req.user.id;

      // Get the resource
      const resource = await resourceGetter(id);
      if (!resource) {
        return res.status(404).send('Resource not found');
      }

      // Check ownership (or admin status)
      const isOwner = resource.userId === userId || resource.ownerId === userId;
      const isAdmin = req.user.role === 'admin';

      if (!isOwner && !isAdmin) {
        return res.status(403).send('Forbidden: You do not have access to this resource');
      }

      // Attach resource to request for use in route handler
      req.resource = resource;
      next();
    } catch (error) {
      res.status(500).send('Server error');
    }
  };
};

// Usage examples:
app.get('/api/posts/:id',
  requireOwnership(async (id) => db.posts.findById(id)),
  (req, res) => {
    res.json(req.resource);
  }
);

app.delete('/api/comments/:id',
  requireOwnership(async (id) => db.comments.findById(id)),
  (req, res) => {
    db.comments.deleteOne({ _id: req.resource._id });
    res.status(204).send();
  }
);

// For more complex authorization logic
const requireResourceAccess = (resourceGetter, authorizer) => {
  return async (req, res, next) => {
    try {
      const { id } = req.params;
      const resource = await resourceGetter(id);

      if (!resource) {
        return res.status(404).send('Not found');
      }

      // Use custom authorizer function
      const hasAccess = await authorizer(req.user, resource);
      if (!hasAccess) {
        return res.status(403).send('Forbidden');
      }

      req.resource = resource;
      next();
    } catch (error) {
      res.status(500).send('Server error');
    }
  };
};

// Usage with custom authorization logic
app.get('/api/projects/:id',
  requireResourceAccess(
    async (id) => db.projects.findById(id),
    async (user, project) => {
      // Check if user is owner or team member
      return user.id === project.ownerId ||
             project.teamMembers.includes(user.id);
    }
  ),
  (req, res) => {
    res.json(req.resource);
  }
);
```

## Using UUIDs vs Sequential IDs

### Sequential IDs

**Pros:**
- Easier to work with in development
- Smaller database indexes
- Human-readable

**Cons:**
- Easy to enumerate (predict next/previous IDs)
- Vulnerable to IDOR if authorization isn't checked
- Information leakage (number of resources, growth rate)

### UUIDs (v4 - Randomly Generated)

**Pros:**
- Cryptographically random, hard to predict
- Globally unique without coordination
- No enumeration risk
- Better privacy (harder to count resources)

**Cons:**
- Larger storage and network overhead (36 characters vs 10-20 for numeric)
- Slightly harder to debug
- Index performance may be slightly slower

### Example: Converting to UUIDs

```javascript
const { v4: uuidv4 } = require('uuid');

// Generate UUID for new resource
app.post('/api/documents', (req, res) => {
  const document = {
    id: uuidv4(), // Use UUID instead of auto-incrementing ID
    title: req.body.title,
    content: req.body.content,
    ownerId: req.user.id,
    createdAt: new Date()
  };

  db.documents.create(document);
  res.status(201).json(document);
});

// Access resource by UUID
app.get('/api/documents/:id', (req, res) => {
  const { id } = req.params;

  // UUID format validation
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(id)) {
    return res.status(400).send('Invalid ID format');
  }

  const document = db.documents.findById(id);
  if (!document) {
    return res.status(404).send('Not found');
  }

  // Still verify ownership
  if (document.ownerId !== req.user.id && !req.user.isAdmin) {
    return res.status(403).send('Forbidden');
  }

  res.json(document);
});
```

### Best of Both Worlds: Hybrid Approach

Use UUIDs for external-facing IDs and numeric IDs for internal operations:

```javascript
app.post('/api/documents', (req, res) => {
  const document = {
    externalId: uuidv4(), // UUID for API responses and external use
    internalId: autoIncrement, // Numeric ID for internal database operations
    title: req.body.title,
    ownerId: req.user.id
  };

  db.documents.create(document);
  res.status(201).json({
    id: document.externalId, // Only expose UUID
    title: document.title
  });
});

// Lookup by external UUID
app.get('/api/documents/:externalId', (req, res) => {
  const document = db.documents.findOne({ externalId: req.params.externalId });
  // ... rest of handler
});
```

## Best Practices

1. **Always check authorization at the object level**: Before returning or modifying any resource, verify the user has permission
2. **Use UUIDs or hashes instead of sequential IDs**: Reduces enumeration risks
3. **Never trust user-supplied IDs**: Always use the authenticated user's ID from the session/token
4. **Implement role-based access control (RBAC)**: Define clear permissions for each role
5. **Check both object ownership and relationships**: For nested resources, verify access at each level
6. **Use middleware for consistent checks**: Create reusable middleware to prevent authorization bypasses
7. **Log authorization failures**: Monitor for suspicious access patterns
8. **Fail securely**: Return 403 Forbidden, not 404 Not Found (404 confirms existence)
9. **Test IDOR thoroughly**: Attempt to access other users' resources in security testing
10. **Use API security tools**: Automated tools can scan for IDOR vulnerabilities
11. **Implement resource isolation**: Ensure your queries naturally filter by the authenticated user
12. **Document authorization rules**: Make it clear who can access what resources
13. **Use parameterized queries**: Prevent SQL injection that could bypass authorization
14. **Audit and monitor access**: Log who accessed what and when, for forensic analysis
15. **Keep resources private by default**: Require explicit permission grants rather than assuming public access
