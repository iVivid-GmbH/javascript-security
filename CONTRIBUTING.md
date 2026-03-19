# Contributing

Thanks for your interest in improving this security reference. Contributions that fix inaccuracies, add missing concepts, or improve code examples are especially welcome.

## What this repo is

A developer-focused reference covering JavaScript and frontend security concepts, presented as:

- **47 deep-dive markdown files** (`01-xss-cross-site-scripting.md` … `49-web-cache-poisoning.md`) — one concept per file
- **`slides.html`** — canonical 2D Reveal.js presentation, deployed to GitHub Pages
- **`slides.md`** — companion Slidev deck (same content, linear format)
- **`README.md`** — index and quick-reference table

See [Architecture](#architecture) below for more detail on the two-deck setup.

## Quick start

```bash
git clone https://github.com/<your-org>/javascript-security
cd javascript-security
npm install          # installs Slidev + Playwright

# View the Reveal.js deck (canonical)
npm run present      # serves at http://localhost:8080

# View the Slidev deck (live-reload dev mode)
npm run dev
```

## How to contribute

### Fix a factual error or outdated recommendation

Open an issue or PR against the relevant numbered `.md` file. Please include a source (MDN, OWASP, a CVE, or a reputable blog post) so the correction can be verified.

### Add a new concept

1. Pick the next available number (currently `50`) and create `50-your-topic.md` following the structure below.
2. Add a row to the appropriate category table in `README.md`.
3. Add a slide to `slides.html` within the relevant `<section>` block.
4. Add a corresponding slide to `slides.md`.
5. Add a link to the reference library section of `slides.html`.
6. Run the CI checks locally before opening a PR (see below).

### Fix a slide

`slides.html` is the canonical presentation. `slides.md` is the companion Slidev deck. If your fix touches concepts, update both.

## Concept file structure

Each numbered file should follow this template:

```markdown
# NN · Topic Name

## What It Is
1-2 paragraph explanation.

## Why It Matters
1 paragraph on real-world impact.

## Attack Scenarios
3 concrete scenarios with brief descriptions.

## Vulnerable Code
```language
// comment
[code]
```

## Secure Code
```language
// comment
[code]
```

## Mitigations
- 5-7 bullet points, each 1-2 sentences, actionable.

## References
- [Title](URL) — 3-5 links (OWASP, MDN, RFCs, advisories)
```

## Running checks locally

```bash
# Verify all README and slide links resolve to existing files
python3 -c "
import re, sys, os
readme = open('README.md').read()
links = re.findall(r'\]\(\./([0-9a-z\-]+\.md)\)', readme)
missing = [l for l in links if not os.path.exists(l)]
print('Missing:', missing or 'none')
"

# Check CDN SRI hashes (requires network access)
npm run sri:check
# To regenerate hashes after updating CDN versions:
npm run sri
```

The CI pipeline (`check.yml`) runs these checks automatically on every push and PR.

## SRI hashes for CDN resources

`slides.html` loads Reveal.js and highlight.js from jsDelivr. After any CDN version update, regenerate the `integrity=` attributes by running:

```bash
npm run sri
```

This fetches each file, computes a SHA-384 hash, and patches `slides.html` in place. Commit the result. The CI `sri-check` job will fail if any CDN tag is missing an `integrity` attribute.

## Architecture

This repo intentionally ships two presentation formats:

| | `slides.html` (Reveal.js) | `slides.md` (Slidev) |
|-|---|---|
| **Purpose** | Canonical presentation, deployed to GitHub Pages | Companion deck for local dev with hot-reload |
| **Navigation** | 2D — Right = next category, Down = concept slides | Linear |
| **Deploy** | Automatically via `deploy.yml` | Manual build or `npm run dev` |
| **PDF export** | `npm run export:reveal-pdf` (Playwright) | `npm run export:slidev-pdf` |

If you update content, update both. If there is ever a conflict, `slides.html` is the source of truth.

## Intentional numbering gaps

Concepts 12 (LDAP Injection) and 26 (Certificate Pinning) were removed as out-of-scope for modern JS stacks. Their file numbers were not reused to avoid breaking any external links to the original files. This is intentional, not an error.

## Code of conduct

Be constructive, specific, and source your claims. Security recommendations without citations are hard to verify and may be rejected. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
