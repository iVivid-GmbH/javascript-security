# 49 · Web Cache Poisoning & Cache Deception

## What It Is

Web cache poisoning (also called cache pollution) occurs when an attacker injects malicious content into a cache so that legitimate users receive the poisoned response. Modern web architectures use caches at multiple layers: CDNs (Cloudflare, Fastly, AWS CloudFront, Vercel Edge), reverse proxies (nginx, Varnish), browser cache, and application-level caches. The cache key determines what requests map to what cached responses. If the cache key is improperly constructed—by including request headers that user can control (like `X-Forwarded-Host`, `X-Forwarded-Scheme`, `User-Agent`, `Accept-Language`) but the response is cached as if the header was fixed—an attacker can poison the cache by crafting requests that result in their malicious response being stored for all future users.

Related to cache poisoning is cache deception: an attacker tricks the cache into storing a private response (containing authentication tokens, session data, or personalized content) as if it were public, allowing the attacker to access it. Cache deception often exploits path normalization differences between the cache and origin server or HTTP request smuggling vulnerabilities.

## Why It Matters

Cache poisoning affects all users of a website simultaneously. A single malicious request can poison a cache and serve XSS payloads, malware redirects, or phishing pages to thousands of legitimate users until the cache entry expires or is manually purged. Because the poisoned response is served from the cache (CDN edge), the attack is extremely fast and hard to trace back to the origin. Cache keys often include headers that developers assume are immutable but users can control: a frontend framework might send `X-Requested-With: XMLHttpRequest` or `X-API-Version`, and a naive cache might include these in the key, allowing header-based poisoning.

Cache deception is particularly dangerous for private data. If an attacker can trick the cache into storing a user's session token or authentication cookie, they can then retrieve it from the cache without authentication. The bug is often subtle: the cache and origin disagree on whether a request is cacheable, or the cache key excludes parameters that should be included.

## Attack Scenarios

1. **CDN Cache Poisoning via X-Forwarded-Host Header**: A web application is hosted on `example.com` and served through a CDN (e.g., Cloudflare). The application has an `og:url` meta tag that uses the request Host header: `<meta property="og:url" content="https://${req.headers.host}/..." />`. The CDN caches the response and includes the Host header in the cache key. An attacker sends a request with `Host: attacker.com` (they control attacker.com's DNS or forge the header). The application renders the og:url as `https://attacker.com/...`, and the CDN caches this response. When a legitimate user visits `example.com`, the CDN returns the cached response with og:url pointing to attacker.com. Sharing the link on social media embeds the attacker's URL.

2. **Cache Deception via Path Normalization**: A web app has an endpoint `/api/profile` that returns the logged-in user's data (includes session token). The cache is configured to cache static assets but not API responses, based on path: if the path ends with `.js`, `.css`, `.png`, etc., it's cacheable. An attacker requests `/api/profile.png` (path normalization: the server strips `.png` as an invalid extension and serves `/api/profile`). The cache sees the path ends with `.png` and caches the response. Later, the attacker requests the same URL and receives the cached profile data (including session token) without authentication.

3. **Fat GET Attack via Query String Injection**: A search endpoint `/search?q=users` renders results and is cacheable. An attacker sends a request `/search?q=users&__proto__[innerHTML]=<img%20src=x%20onerror=alert(1)>` (exploiting a framework bug or custom query parameter that gets into the response). If the cache key includes the full query string but the application only uses the `q` parameter, the cache stores a response for a different cache key. However, if the cache key is based only on `/search` without distinguishing query parameters, the poisoned response is cached for all `/search` requests. Legitimate users searching for "users" receive XSS.

## Vulnerable Code

```javascript
// Example 1: Express app with unkeyed header in response
import express, { Request, Response } from 'express';

const app = express();
const cache: Record<string, string> = {}; // Simple in-memory cache

// Middleware: Simple cache based on path only (vulnerable)
function cacheMiddleware(req: Request, res: Response, next: Function) {
  const cacheKey = req.path; // Cache key does NOT include Host header
  const cached = cache[cacheKey];
  if (cached) {
    res.set('X-Cache', 'HIT');
    res.send(cached);
    return;
  }

  // Intercept res.send to cache the response
  const originalSend = res.send;
  res.send = function (data: string) {
    // Cache all responses, regardless of headers
    cache[cacheKey] = data;
    res.set('X-Cache', 'MISS');
    return originalSend.call(this, data);
  };

  next();
}

app.use(cacheMiddleware);

// Vulnerable endpoint: Uses request Host header in response
app.get('/share', (req: Request, res: Response) => {
  const hostHeader = req.get('Host') || 'example.com'; // Attacker can control this
  const userAgent = req.get('User-Agent') || 'Unknown'; // Also attacker-controlled

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta property="og:url" content="https://${hostHeader}/share" />
      <meta property="og:title" content="Check this out!" />
      <meta property="User-Agent" content="${userAgent}" />
    </head>
    <body>
      <h1>Shared Page</h1>
      <p>Served from: ${hostHeader}</p>
      <p>User Agent: ${userAgent}</p>
    </body>
    </html>
  `;

  res.set('Cache-Control', 'public, max-age=3600'); // Cacheable!
  res.send(html);
});

// Vulnerable endpoint: Path-based cache decision
app.get('/api/profile', (req: Request, res: Response) => {
  // Private user data (should NEVER be cached)
  const userData = {
    username: 'john_doe',
    email: 'john@example.com',
    sessionToken: 'secret-session-abc123',
  };

  // Cache decision based on whether path looks like static asset
  const isCacheable = /\.(js|css|png|jpg|jpeg|gif|svg)$/i.test(req.path);

  if (!isCacheable) {
    res.set('Cache-Control', 'private, no-cache, no-store');
  } else {
    res.set('Cache-Control', 'public, max-age=86400'); // Cached forever!
  }

  res.json(userData);
});

// Example 2: CDN-level cache key configuration (Nginx/Varnish)
// Varnish VCL (vulnerable configuration)
vcl 4.1;

backend default {
  .host = "origin.example.com";
  .port = "443";
}

sub vcl_hash {
  # Cache key based on URL only
  hash_data(req.url);

  # BUG: If req.url is "/api/profile.png", normalize it
  if (req.url ~ "\.png$") {
    hash_data("static-asset"); // Different hash for static assets
  }

  # But server-side removes .png and serves /api/profile anyway!
  # Cache and origin disagree on cache key.
}

sub vcl_recv {
  # Vulnerable: Cache all requests
  if (req.method == "GET") {
    return (hash);
  }
}

// Example 3: Query string cache poisoning
app.get('/search', (req: Request, res: Response) => {
  const query = req.query.q as string;

  // Cache key does not include full query string
  const cacheKey = req.path; // Missing query parameters!

  // But response includes user input
  const html = `
    <html>
    <head>
      <title>Search Results for: ${query}</title>
    </head>
    <body>
      <h1>Results for: ${query}</h1>
      <p>Found ${Math.floor(Math.random() * 100)} results</p>
    </body>
    </html>
  `;

  res.set('Cache-Control', 'public, max-age=3600');
  res.set('Content-Type', 'text/html');

  // Different queries should have different cache keys
  // but cache key is path-only, allowing poisoning
  res.send(html);
});
```

## Secure Code

```javascript
// Secure Example 1: Proper cache key including request headers
import express, { Request, Response } from 'express';
import crypto from 'crypto';

interface CacheEntry {
  content: string;
  headers: Record<string, string>;
  timestamp: number;
}

const cache: Record<string, CacheEntry> = {};

function secureCacheMiddleware(req: Request, res: Response, next: Function) {
  // Cache key includes headers that affect the response
  const cacheKeyComponents = [
    req.path,
    req.method,
    req.query ? JSON.stringify(req.query) : '',
    req.get('Accept-Encoding') || '', // Compression affects response
    req.get('Accept-Language') || '', // i18n affects response
    // NOTE: Do NOT include Host, X-Forwarded-* if they affect the response!
    // Instead, normalize them on the server side.
  ];

  const cacheKey = crypto
    .createHash('sha256')
    .update(cacheKeyComponents.join('|'))
    .digest('hex');

  const cached = cache[cacheKey];
  const now = Date.now();

  if (
    cached &&
    now - cached.timestamp < 3600000 // 1 hour TTL
  ) {
    res.set('X-Cache', 'HIT');
    Object.entries(cached.headers).forEach(([k, v]) => res.set(k, v));
    res.send(cached.content);
    return;
  }

  // Intercept res.send to cache the response
  const originalSend = res.send;
  res.send = function (data: string) {
    const cacheControl = res.get('Cache-Control');

    // Only cache responses explicitly marked as cacheable
    if (cacheControl && cacheControl.includes('public')) {
      cache[cacheKey] = {
        content: data,
        headers: {
          'Cache-Control': cacheControl,
          'Content-Type': res.get('Content-Type') || 'text/html',
        },
        timestamp: now,
      };
    }

    res.set('X-Cache', 'MISS');
    return originalSend.call(this, data);
  };

  next();
}

app.use(secureCacheMiddleware);

// Secure endpoint: Normalize headers before using in response
app.get('/share', (req: Request, res: Response) => {
  // Always use a canonical hostname, not the request header
  const canonicalHost = 'example.com';
  const userAgent = req.get('User-Agent') || 'Unknown';

  // If you must use request headers, include them in the cache key
  // OR use strict CSP to prevent injected og:url from being used
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta property="og:url" content="https://${canonicalHost}/share" />
      <meta property="og:title" content="Check this out!" />
    </head>
    <body>
      <h1>Shared Page</h1>
    </body>
    </html>
  `;

  // Only cache for authenticated users OR mark as private
  const isAuthenticated = !!req.headers.authorization;

  if (!isAuthenticated) {
    res.set('Cache-Control', 'private, no-cache, no-store');
  } else {
    res.set('Cache-Control', 'private, max-age=3600');
  }

  res.send(html);
});

// Secure endpoint: Never cache private data
app.get('/api/profile', (req: Request, res: Response) => {
  // Check authentication
  const token = req.get('Authorization');
  if (!token) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const userData = {
    username: 'john_doe',
    email: 'john@example.com',
    sessionToken: 'secret-session-abc123',
  };

  // Explicitly mark as NOT cacheable
  res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');

  res.json(userData);
});

// Secure Varnish VCL configuration
vcl 4.1;

backend default {
  .host = "origin.example.com";
  .port = "443";
}

sub vcl_recv {
  // Only cache safe methods
  if (req.method != "GET" && req.method != "HEAD") {
    return (pass); // Don't cache
  }

  // Respect Pragma and Cache-Control headers
  if (req.http.Pragma ~ "no-cache" || req.http.Cache-Control ~ "no-cache") {
    return (pass);
  }

  // Separate cache for authenticated requests
  if (req.http.Authorization) {
    // Never cache authenticated requests
    return (pass);
  }

  return (hash);
}

sub vcl_hash {
  // Cache key includes full URL and query parameters
  hash_data(req.url); // Include query string!

  // Cache key includes Vary headers
  if (req.http.Accept-Encoding) {
    hash_data(req.http.Accept-Encoding);
  }

  if (req.http.Accept-Language) {
    hash_data(req.http.Accept-Language);
  }

  // Do NOT include Host, X-Forwarded-Host, etc. in cache key
  // Instead, normalize them server-side.
}

sub vcl_backend_response {
  // Respect Cache-Control from origin
  if (beresp.http.Cache-Control ~ "private") {
    set beresp.uncacheable = true;
    return (deliver);
  }

  // Set reasonable TTL
  if (beresp.ttl <= 0s || beresp.http.Cache-Control ~ "no-cache") {
    set beresp.ttl = 0s;
    set beresp.uncacheable = true;
  }
}

// Secure endpoint: Include full query string in cache key
app.get('/search', (req: Request, res: Response) => {
  const query = (req.query.q as string) || '';
  const sortBy = (req.query.sort as string) || 'relevance';

  // Different queries should have different cache keys
  // Ensure your CDN includes full query string in cache key
  const html = `
    <html>
    <head>
      <title>Search Results for: ${encodeHTMLAttribute(query)}</title>
    </head>
    <body>
      <h1>Results for: ${encodeHTMLAttribute(query)}</h1>
      <p>Sort by: ${encodeHTMLAttribute(sortBy)}</p>
    </body>
    </html>
  `;

  // Safe to cache since query string is part of URL
  res.set('Cache-Control', 'public, max-age=3600');
  res.send(html);
});

// Helper: Escape HTML attributes
function encodeHTMLAttribute(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
```

## Mitigations

- **Explicitly define cache keys that include all headers and query parameters that affect the response**: On your CDN and reverse proxy, configure cache keys to include the full URL (path + query string) and relevant Vary headers (Accept-Encoding, Accept-Language, Accept). Exclude headers like Host, X-Forwarded-Host, User-Agent unless they truly affect the response. Test cache key behavior by requesting the same resource with different header values and verifying they are cached separately.

- **Set Cache-Control headers correctly: use `private` for authenticated/personalized responses, `public` for cacheable content**: Never cache responses that contain authentication tokens, session data, or user-specific information. Use `Cache-Control: private, no-cache, no-store, must-revalidate` for private data and `Cache-Control: public, max-age=3600` for cacheable public content. Browsers and CDNs respect these headers; misconfiguration is the root cause of many deception attacks.

- **Normalize user-controlled headers (Host, X-Forwarded-*) before including them in responses**: Never echo request headers like Host, X-Forwarded-Host, or X-Forwarded-Scheme directly into HTML responses. Instead, use a canonical hostname configured server-side. If the header must be used (e.g., for redirect URLs), whitelist allowed values and include the header in the cache key.

- **Use CSP and X-Content-Type-Options headers to prevent cache poisoning impact**: Set `Content-Security-Policy: default-src 'self'` to limit what scripts and resources can be loaded. Use `X-Content-Type-Options: nosniff` to prevent MIME type sniffing. If your og:url meta tag is poisoned, CSP limits the attacker's ability to load external scripts, reducing blast radius.

- **Monitor CDN cache hit ratios and request patterns for anomalies**: Sudden cache poisoning may show up as unusual cache hit ratios or repeated requests for the same URL with different headers. Use CDN logs and analytics to detect when the cache is serving different content for the same URL. Set up alerts for high-frequency requests to specific URLs from unusual origins.

- **Test cache key behavior and document it explicitly**: Use tools like Burp Suite repeater, `curl`, or CDN-specific tools (e.g., Cloudflare's cache purge API) to verify what requests result in cache hits/misses. Document cache key configuration in your infrastructure-as-code and code comments. Include cache key configuration in security reviews and change control.

- **Purge cache entries immediately after deploying security patches or detecting poisoning**: If poisoning is detected, purge the affected URLs from the CDN immediately using APIs like Cloudflare's Purge Cache or AWS CloudFront's Invalidation. Implement automated cache purging for sensitive endpoints (e.g., authentication, user profiles) to limit the window an attacker can exploit a poisoned response.

## References

- [OWASP: Web Cache Poisoning](https://owasp.org/www-community/attacks/Web_Cache_Poisoning)
- [PortSwigger: Web Cache Poisoning](https://portswigger.net/research/web-cache-poisoning)
- [Cache Key Specification - Cloudflare Cache Rules](https://developers.cloudflare.com/cache/about/cache-control/)
- [HTTP Caching: Cache-Control and Related Headers - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching)
- [Varnish Cache: Hashing and Cache Keys - Varnish Docs](https://varnish-cache.org/docs/6.0/reference/vcl.html#obj_req)
