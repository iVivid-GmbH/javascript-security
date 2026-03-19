# 47 · Client-Side Cryptography & Web Crypto API

## What It Is

The Web Crypto API (`window.crypto.subtle`) provides native, standardized cryptographic operations in browsers: AES encryption, HMAC/HKDF key derivation, RSA signatures, ECDSA, and more. Unlike older approaches (OpenSSL.js, TweetNaCl.js), Web Crypto runs in the browser's security context with hardware acceleration and is resistant to timing attacks. However, "client-side crypto" is notoriously misused: developers use `Math.random()` for key generation, store keys in `localStorage`, implement ECB mode, derive keys from weak passwords without proper salt/iterations, or skip authentication entirely. The API is also useless against many real threats: a compromised JavaScript context means an attacker can intercept plaintext before encryption or after decryption, read keys from `IndexedDB`, and monitor all cryptographic operations.

Client-side crypto is appropriate for end-to-end encryption (E2EE), protecting data at rest before sending to a server, and encrypting sensitive fields in transit. It is inappropriate as a substitute for TLS, for protecting authentication tokens, or as a general security mechanism when the JavaScript is not trusted.

## Why It Matters

Cryptographic mistakes are permanent: once data is encrypted with a weak key or broken algorithm, it typically cannot be recovered. The Web Crypto API abstracts complexity and prevents developers from directly implementing algorithms (good), but the surrounding code—key generation, derivation, storage, usage—is still error-prone. A key derived with weak PBKDF2 parameters (`iterations: 1000` instead of `100,000+`) is vulnerable to brute force. A key stored in `localStorage` is readable by any XSS. An AES key used in ECB mode exposes patterns in the plaintext. A function that encrypts user data but never authenticates the ciphertext is vulnerable to tampering. These mistakes often go undetected until a breach occurs.

## Attack Scenarios

1. **Weak Key Derivation from Passwords**: An app encrypts notes client-side using PBKDF2 with a password. The developer uses `iterations: 1000` (default) instead of `600,000+` because they worry about slow UX. An attacker steals the encrypted database and password hash. Using a GPU-accelerated dictionary attack, they test 1 billion passwords per second and recover users' plaintext notes within hours. If `iterations` had been 600,000, the attack would take months.

2. **ECB Mode Pattern Leakage**: A healthcare app encrypts patient SSNs client-side using AES-ECB. The same SSN always encrypts to the same ciphertext, allowing an attacker to correlate encrypted records and infer which patients share the same SSN. This is the classic ECB penguin problem: patterns in plaintext map to patterns in ciphertext. ECB is never secure for more than one block of data.

3. **Unauthenticated Encryption and Tampering**: A financial app encrypts transaction records in the browser and sends them to a server for storage. The encryption uses AES-CTR (a stream cipher) with no authentication tag. An attacker intercepts a transaction record, flips a few ciphertext bytes (which XORs plaintext bits), and re-uploads it. The server decrypts and stores the tampered transaction without detecting the modification. The tamper-resistant solution is AES-GCM, which authenticates the ciphertext and rejects tampered data.

## Vulnerable Code

```javascript
// utils/crypto-weak.ts - Common Web Crypto mistakes
import crypto from 'crypto';

// Mistake 1: Math.random for key generation
function generateWeakKey() {
  const key = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    key[i] = Math.floor(Math.random() * 256); // Predictable, not cryptographically secure
  }
  return key;
}

// Mistake 2: Weak PBKDF2 parameters
async function deriveKeyFromPassword(
  password: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 1000, // Too low! GPU-crackable in seconds
      hash: 'SHA-256',
    },
    baseKey,
    256
  );

  return crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-CBC' }, // Mistake 3: CBC with a reused/hardcoded IV leaks patterns
    false,
    ['encrypt', 'decrypt']
  );
  // Note: AES-ECB is not available in the Web Crypto API at all —
  // AES-CBC with a fixed IV is the closest equivalent vulnerability.
}

// Mistake 4: No authentication, stream cipher
async function encryptData(
  data: string,
  key: CryptoKey
): Promise<string> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(16)); // IV used but no auth tag

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-CTR', // Stream cipher, no authentication
      counter: iv,
      length: 128,
    },
    key,
    encoder.encode(data)
  );

  // Just concatenate IV and ciphertext - attacker can flip bits
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...combined)); // Base64 encode
}

// Mistake 5: Store key in localStorage
async function storeKey(key: CryptoKey) {
  const exported = await crypto.subtle.exportKey('raw', key);
  localStorage.setItem(
    'encryption_key',
    btoa(String.fromCharCode(...new Uint8Array(exported)))
  );
}

// Mistake 6: Decrypt without verifying authenticity
async function decryptData(encrypted: string, key: CryptoKey): Promise<string> {
  const combined = Uint8Array.from(
    atob(encrypted),
    (c) => c.charCodeAt(0)
  );
  const iv = combined.slice(0, 16);
  const ciphertext = combined.slice(16);

  // No integrity check; tampered data decrypts to garbage silently
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-CTR',
      counter: iv,
      length: 128,
    },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}
```

## Secure Code

```javascript
// utils/crypto-secure.ts - Correct Web Crypto patterns
import crypto from 'crypto';

interface EncryptedData {
  ciphertext: string; // base64
  iv: string; // base64
  authTag: string; // base64
  salt?: string; // base64, if key derived from password
}

// Correct: Cryptographically secure random bytes
function generateSecureKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32)); // Uses CSPRNG
}

// Correct: Strong PBKDF2 parameters (600k iterations, SHA-256)
async function deriveKeyFromPassword(
  password: string,
  salt?: Uint8Array
): Promise<{ key: CryptoKey; salt: Uint8Array }> {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  // Use a fresh salt if not provided
  const finalSalt = salt || crypto.getRandomValues(new Uint8Array(32));

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: finalSalt,
      iterations: 600000, // Slow enough to resist GPU attacks
      hash: 'SHA-256',
    },
    passwordKey,
    256 // 32 bytes for AES-256
  );

  const key = await crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-GCM' }, // Correct: authenticated encryption
    false,
    ['encrypt', 'decrypt']
  );

  return { key, salt: finalSalt };
}

// Correct: AES-GCM with authenticated encryption
async function encryptData(
  data: string,
  key: CryptoKey
): Promise<EncryptedData> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce for GCM

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128, // 16-byte auth tag
    },
    key,
    encoder.encode(data)
  );

  // GCM returns ciphertext + auth tag together
  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
    iv: btoa(String.fromCharCode(...iv)),
    authTag: '', // Auth tag is included in encrypted output
  };
}

// Correct: Decrypt and verify authentication
async function decryptData(
  encryptedData: EncryptedData,
  key: CryptoKey
): Promise<string> {
  const ciphertext = Uint8Array.from(atob(encryptedData.ciphertext), (c) =>
    c.charCodeAt(0)
  );
  const iv = Uint8Array.from(atob(encryptedData.iv), (c) => c.charCodeAt(0));

  try {
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128,
      },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    // AES-GCM throws if auth tag is invalid
    throw new Error('Decryption failed: ciphertext may be tampered');
  }
}

// Correct: Store key in IndexedDB with 'private' visibility
async function storeKeySecurely(
  key: CryptoKey,
  keyName: string
): Promise<void> {
  const db = await openDB();
  const tx = db.transaction('keys', 'readwrite');
  const store = tx.objectStore('keys');

  // IndexedDB supports CryptoKey objects natively
  await store.put({ name: keyName, key: key, timestamp: Date.now() });
}

// Correct: Retrieve key from IndexedDB (never localStorage)
async function retrieveKeySecurely(keyName: string): Promise<CryptoKey | null> {
  const db = await openDB();
  const tx = db.transaction('keys', 'readonly');
  const store = tx.objectStore('keys');
  const result = await store.get(keyName);

  return result?.key || null;
}

// Helper: Open IndexedDB
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('SecureCrypto', 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore('keys', { keyPath: 'name' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
```

## Mitigations

- **Use AES-GCM instead of AES-CTR, AES-CBC, or especially AES-ECB**: AES-GCM provides both confidentiality and authenticity in a single operation. Reject any proposal to use ECB mode (no IV, patterns leak) or unauthenticated stream ciphers. Require an authentication tag (typically 128 bits) and fail decryption immediately if it doesn't verify.

- **Set PBKDF2 iterations to at least 600,000 and use Argon2 where supported**: Use `iterations: 600000` or higher for PBKDF2, and prefer Argon2id (available via libraries like `@noble/hashes` for Node/Deno context) for password-based key derivation. Include a random salt (32 bytes) unique to each password and store it alongside the ciphertext.

- **Generate cryptographic keys and nonces with `crypto.getRandomValues()`**, never `Math.random()`, `Math.random() * 0xFF`, or predictable seeds: `Math.random()` is seeded by system time and is predictable. Always use `crypto.getRandomValues(new Uint8Array(...))` for cryptographic material, IVs, salts, and nonces.

- **Store keys in IndexedDB or sessionStorage, never `localStorage`**: `localStorage` is synchronous, same-origin readable, and survives tab closure. Use `IndexedDB` for persistent key storage (survives browser restart but not user logout) or `sessionStorage` (cleared on tab close). Never export keys to base64/JSON strings in `localStorage`.

- **Use random IVs/nonces for every encryption operation; never reuse or hardcode**: For AES-GCM, use a fresh 96-bit (12-byte) nonce per message. Reusing a nonce with the same key breaks GCM's security. Use `crypto.getRandomValues(new Uint8Array(12))` for each operation and include the nonce in the transmitted ciphertext (it is not secret).

- **Authenticate the ciphertext before decryption; fail fast on auth tag mismatch**: AES-GCM throws an error during decryption if the auth tag is invalid, preventing silent decryption of tampered data. Always catch and handle decryption errors; never fall back to returning plaintext or partial results.

- **Recognize the limits of client-side crypto: it does not protect data while JavaScript is running**: If the JavaScript context is compromised (XSS), an attacker can read plaintext before encryption, keys from `IndexedDB`, and intercept all cryptographic operations. Client-side crypto is not a substitute for TLS or authentication. Use it only for end-to-end encryption where the server cannot read the data, or for encrypting sensitive fields before transmission.

## References

- [Web Crypto API - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [OWASP: Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [RFC 3394: AES Key Wrap Algorithm](https://tools.ietf.org/html/rfc3394)
- [NIST Password Guidelines (SP 800-63B)](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems (Kocher)](https://www.paulkocher.com/TimingAttacks.html)
