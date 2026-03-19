# Mass Assignment Vulnerabilities

## Definition

**Mass assignment** (also called over-posting or auto-binding) is a vulnerability where an application automatically binds request data to model properties without proper filtering. This allows attackers to set fields that shouldn't be modifiable, such as setting their own role to "admin", changing prices, or escalating their privileges. The vulnerability arises when frameworks or ORMs automatically map all request parameters to model fields without an allowlist of permitted properties.

## How Mass Assignment Works

### Vulnerable Pattern: Auto-Binding All Properties

```javascript
// ❌ VULNERABLE: Express + raw object assignment
app.post('/api/users', (req, res) => {
  // Directly assigning request body to user object
  const user = req.body;

  // If req.body = {
  //   name: "John",
  //   email: "john@example.com",
  //   password: "hashedpass",
  //   isAdmin: true,          ← Attacker added this
  //   role: "admin",          ← Attacker added this
  //   isSuspended: false      ← Attacker added this
  // }

  db.users.insert(user);  // All properties inserted!

  res.json({ success: true });
});
```

### Vulnerable Pattern: Mongoose without Field Restrictions

```javascript
// ❌ VULNERABLE: Mongoose without field whitelisting
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: { type: String, enum: ['user', 'admin'] },
  isVerified: Boolean,
  isAdmin: Boolean
});

const User = mongoose.model('User', userSchema);

app.post('/api/users', async (req, res) => {
  // ❌ All properties from req.body automatically bound
  const user = new User(req.body);

  // Attacker POST:
  // {
  //   "name": "attacker",
  //   "email": "attacker@example.com",
  //   "password": "pass123",
  //   "role": "admin",         ← Should not be setable
  //   "isAdmin": true,         ← Should not be setable
  //   "isVerified": true       ← Should not be setable by user
  // }

  // All fields get set, attacker is admin!
  await user.save();

  res.json({ user });
});
```

### Vulnerable Pattern: Express + Direct Assignment

```javascript
// ❌ VULNERABLE: Object.assign with user input
app.put('/api/users/:id', (req, res) => {
  const user = db.users.findById(req.params.id);

  // ❌ Merging all properties
  Object.assign(user, req.body);

  // Attacker sends:
  // {
  //   "name": "newname",
  //   "email": "newemail@example.com",
  //   "role": "admin",         ← Attacker escalates privilege
  //   "isAdmin": true,         ← Attacker escalates privilege
  //   "paymentStatus": "paid", ← Attacker marks self as paid
  //   "creditLimit": 9999      ← Attacker sets high credit limit
  // }

  db.users.update(user);

  res.json({ user });
});
```

## Real-World Attack Examples

### E-Commerce Price Manipulation

```javascript
// ❌ VULNERABLE: Price can be set by attacker
const productSchema = {
  name: String,
  description: String,
  price: Number,          // Should not be user-settable!
  discount: Number,       // Should not be user-settable!
  stock: Number,          // Should not be user-settable!
  isFeatured: Boolean     // Should not be user-settable!
};

app.post('/api/products', (req, res) => {
  // ❌ Direct assignment
  const product = new Product(req.body);

  // Attacker creates product with:
  // {
  //   "name": "iPhone",
  //   "description": "Latest iPhone",
  //   "price": 0.01,          ← Instead of $999
  //   "discount": 99,         ← 99% discount
  //   "stock": 1000000,       ← Unlimited stock
  //   "isFeatured": true      ← Free featured listing
  // }

  await product.save();

  res.json({ product });
});
```

### User Privilege Escalation

```javascript
// ❌ VULNERABLE: Roles can be set by attacker
app.post('/api/users/register', (req, res) => {
  // ❌ All properties assignable
  const user = new User(req.body);

  // Attacker registers with:
  // {
  //   "username": "attacker",
  //   "email": "attacker@example.com",
  //   "password": "pass123",
  //   "role": "admin",         ← Should be "user"
  //   "permissions": ["read", "write", "delete"],  ← Should be []
  //   "isAdmin": true,         ← Should be false
  //   "isModerator": true      ← Should be false
  // }

  // Attacker gains admin access without earning it

  await user.save();

  res.json({ user });
});
```

### Payment/Account Status Manipulation

```javascript
// ❌ VULNERABLE: Payment status modifiable by user
app.post('/api/orders', (req, res) => {
  // ❌ Status fields assignable
  const order = new Order(req.body);

  // Attacker creates order with:
  // {
  //   "items": [...],
  //   "totalPrice": 9999,      ← Should be calculated
  //   "paymentStatus": "paid", ← Should be "pending"
  //   "shippingAddress": "attacker's address",
  //   "discountCode": "VIP50", ← Attacker gives self discount
  //   "isExpedited": true      ← Free expedited shipping
  // }

  // Order created with fake payment status
  // Attacker receives shipped goods without paying

  await order.save();

  res.json({ order });
});
```

## Vulnerable Code Example

```javascript
// ❌ VULNERABLE: Mass assignment in Express with Mongoose
const express = require('express');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());

// ❌ Schema allows many fields
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  passwordHash: String,
  firstName: String,
  lastName: String,
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  isAdmin: Boolean,
  isModerator: Boolean,
  permissions: [String],
  isVerified: Boolean,
  isActive: Boolean,
  accountType: { type: String, enum: ['free', 'premium', 'enterprise'] },
  premiumExpiration: Date,
  apiKey: String
});

const User = mongoose.model('User', userSchema);

// ❌ Registration allows all fields
app.post('/api/register', async (req, res) => {
  try {
    // ❌ Direct assignment from request body
    const user = new User(req.body);

    // Attacker sends:
    // {
    //   "username": "hacker",
    //   "email": "hacker@example.com",
    //   "passwordHash": "$2b$12$...",
    //   "role": "admin",          ← Escalation
    //   "isAdmin": true,          ← Escalation
    //   "isModerator": true,      ← Escalation
    //   "permissions": ["*"],     ← All permissions
    //   "isVerified": true,       ← Verify self
    //   "accountType": "enterprise", ← Free premium account
    //   "apiKey": "secret-key"    ← Self-generated API key
    // }

    await user.save();

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role  // Now "admin"!
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ❌ Update allows all fields
app.put('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    // ❌ Object.assign with unrestricted fields
    Object.assign(user, req.body);

    // Even authenticated users can:
    // 1. Change role from "user" to "admin"
    // 2. Verify themselves without email confirmation
    // 3. Upgrade to premium without payment
    // 4. Generate API keys

    await user.save();

    res.json({ success: true, user });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ❌ Create product allows price manipulation
const productSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,        // ❌ Can be set by attacker
  cost: Number,         // ❌ Should not be visible
  discount: Number,     // ❌ Can be set by attacker
  stock: Number,        // ❌ Can be inflated
  isFeatured: Boolean,  // ❌ Can be set for free
  createdBy: String
});

const Product = mongoose.model('Product', productSchema);

app.post('/api/products', async (req, res) => {
  try {
    // ❌ All fields assignable
    const product = new Product(req.body);

    // Attacker creates:
    // {
    //   "name": "item",
    //   "price": 0.01,        ← Instead of $100
    //   "discount": 99,       ← Instead of 0
    //   "stock": 999999,      ← Instead of 10
    //   "isFeatured": true    ← Free feature
    // }

    await product.save();

    res.json({ success: true, product });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(3000);
```

## Secure Code Examples

### Allowlist Approach with Mongoose

```javascript
// ✅ SECURE: Allowlist fields for mass assignment
const express = require('express');
const mongoose = require('mongoose');

const app = express();
app.use(express.json());

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  passwordHash: String,
  firstName: String,
  lastName: String,
  role: { type: String, enum: ['user', 'moderator', 'admin'], default: 'user' },
  isVerified: Boolean,
  accountType: { type: String, enum: ['free', 'premium'], default: 'free' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// ✅ SECURE: Filter allowed fields
function filterAllowedFields(input, allowedFields) {
  const filtered = {};
  allowedFields.forEach(field => {
    if (field in input) {
      filtered[field] = input[field];
    }
  });
  return filtered;
}

// ✅ SECURE: Registration with allowlist
app.post('/api/register', async (req, res) => {
  try {
    // ✅ Only allow specific fields
    const allowedFields = ['username', 'email', 'firstName', 'lastName'];
    const userData = filterAllowedFields(req.body, allowedFields);

    // Validate required fields
    if (!userData.username || !userData.email) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // ✅ Don't accept role from user
    userData.role = 'user';  // Default role

    // ✅ Don't accept verification from user
    userData.isVerified = false;  // Must verify email

    // ✅ Don't accept account type
    userData.accountType = 'free';  // Default to free

    const user = new User(userData);
    await user.save();

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role  // Always 'user'
      }
    });
  } catch (err) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

// ✅ SECURE: Update with allowlist
app.put('/api/users/:id', async (req, res) => {
  try {
    // ✅ Only allow updating profile fields
    const allowedFields = ['firstName', 'lastName', 'email'];
    const updates = filterAllowedFields(req.body, allowedFields);

    const user = await User.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    );

    // ✅ Role, verification, account type cannot be changed by user

    res.json({ success: true, user });
  } catch (err) {
    res.status(400).json({ error: 'Update failed' });
  }
});

// ✅ SECURE: Separate endpoint for admin role changes
app.put('/api/users/:id/role', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    // ✅ Require authentication and admin privilege
    const { role } = req.body;

    if (!['user', 'moderator', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role' });
    }

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    );

    // ✅ Log privilege escalation
    console.log(`Admin ${req.user.id} changed ${req.params.id} role to ${role}`);

    res.json({ success: true, user });
  } catch (err) {
    res.status(400).json({ error: 'Role update failed' });
  }
});

// ✅ SECURE: Products with field restrictions
const productSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  stock: Number,
  isFeatured: Boolean,
  createdBy: String
});

const Product = mongoose.model('Product', productSchema);

app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    // ✅ Admin-only endpoint
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin only' });
    }

    // ✅ Only allow specific fields
    const allowedFields = ['name', 'description', 'price', 'stock'];
    const productData = filterAllowedFields(req.body, allowedFields);

    // ✅ System-set fields
    productData.isFeatured = false;  // Not set by user
    productData.createdBy = req.user.id;  // From authenticated user

    const product = new Product(productData);
    await product.save();

    res.json({ success: true, product });
  } catch (err) {
    res.status(400).json({ error: 'Product creation failed' });
  }
});

// ✅ Middleware for auth
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

function authorizeAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}
```

### Using Lodash pick/omit

```javascript
// ✅ SECURE: Using lodash for field filtering
const _ = require('lodash');

app.put('/api/users/:id', async (req, res) => {
  try {
    // ✅ Pick only allowed fields
    const updates = _.pick(req.body, ['firstName', 'lastName', 'email']);

    const user = await User.findByIdAndUpdate(req.params.id, updates);

    res.json({ success: true, user });
  } catch (err) {
    res.status(400).json({ error: 'Update failed' });
  }
});

app.post('/api/products', async (req, res) => {
  try {
    // ✅ Omit dangerous fields
    const productData = _.omit(req.body, ['cost', 'margin', 'supplier', 'internalNotes']);

    // Or more secure: pick only what's allowed
    const productData = _.pick(req.body, ['name', 'description', 'price', 'stock']);

    const product = new Product(productData);
    await product.save();

    res.json({ success: true, product });
  } catch (err) {
    res.status(400).json({ error: 'Creation failed' });
  }
});
```

### Mongoose select() and Strict Mode

```javascript
// ✅ SECURE: Mongoose strict mode rejects unknown fields
userSchema.set('strict', true);  // ❌ Ignores unknown fields
userSchema.set('strict', 'throw');  // ✅ Throws error on unknown fields

// ✅ SECURE: Use Mongoose select
app.put('/api/users/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);

    // ✅ Explicitly set only allowed fields
    if ('firstName' in req.body) user.firstName = req.body.firstName;
    if ('lastName' in req.body) user.lastName = req.body.lastName;
    if ('email' in req.body) user.email = req.body.email;

    // ✅ Never set role, permissions, or other sensitive fields

    await user.save();

    res.json({ success: true, user });
  } catch (err) {
    res.status(400).json({ error: 'Update failed' });
  }
});
```

## Mitigations and Best Practices

### 1. Use Allowlist Approach

```javascript
const allowedFields = ['name', 'email', 'phone'];
const filtered = {};
allowedFields.forEach(field => {
  if (field in input) filtered[field] = input[field];
});
```

### 2. Don't Use Object.assign with User Input

```javascript
// ❌ BAD
Object.assign(user, req.body);

// ✅ GOOD
user.name = req.body.name;
user.email = req.body.email;
```

### 3. Separate Endpoints for Privilege Changes

```javascript
// Regular update
PUT /api/users/:id  // Name, email only

// Privilege update (admin only)
PUT /api/users/:id/role  // Role, permissions
```

### 4. Use Mongoose Strict Mode

```javascript
schema.set('strict', true);  // Ignore unknown fields
schema.set('strict', 'throw');  // Throw on unknown fields
```

### 5. Log Privilege Escalation

```javascript
if (oldRole !== newRole) {
  logger.warn(`Privilege escalation: ${userId} ${oldRole} → ${newRole}`);
}
```

### 6. Validate Against Schema

```javascript
const schema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email()
});

const { error, value } = schema.validate(req.body);
```

## Summary

Mass assignment vulnerabilities allow attackers to set fields they shouldn't be able to modify. Prevent them by using an allowlist approach, explicitly defining which fields are modifiable by users, creating separate endpoints for privilege changes, using strict validation, and never directly assigning request bodies to model objects. Always treat role changes, account verification, and payment status as sensitive operations requiring separate endpoints and authorization checks.
