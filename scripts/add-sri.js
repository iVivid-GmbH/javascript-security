#!/usr/bin/env node
/**
 * add-sri.js
 *
 * Computes SHA-384 SRI hashes for every CDN resource in slides.html
 * and writes the integrity + crossorigin attributes in place.
 *
 * Usage:
 *   node scripts/add-sri.js           # patch slides.html
 *   node scripts/add-sri.js --check   # exit 1 if any CDN link lacks integrity
 */

import { createHash } from 'crypto';
import { readFileSync, writeFileSync } from 'fs';
import { get } from 'https';

const CHECK_ONLY = process.argv.includes('--check');
const SLIDES = new URL('../slides.html', import.meta.url).pathname;

function fetchBuffer(url) {
  return new Promise((resolve, reject) => {
    get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
}

function sri(buf) {
  const hash = createHash('sha384').update(buf).digest('base64');
  return `sha384-${hash}`;
}

// Match every CDN <link> and <script> that doesn't already have integrity=
const LINK_RE  = /(<link\b[^>]*href="(https:\/\/cdn\.[^"]+)"[^>]*?)(?:\s+integrity="[^"]*"[^>]*)?(>)/g;
const SCRIPT_RE = /(<script\b[^>]*src="(https:\/\/cdn\.[^"]+)"[^>]*?)(?:\s+integrity="[^"]*"[^>]*)?(><\/script>)/g;

async function run() {
  let html = readFileSync(SLIDES, 'utf8');

  // Collect all unique CDN URLs
  const urls = new Set();
  for (const m of html.matchAll(/<(?:link|script)\b[^>]*(https:\/\/cdn\.[^"]+)"/g)) {
    urls.add(m[1]);
  }

  if (CHECK_ONLY) {
    // In check mode just verify every CDN resource has an integrity attribute
    const missing = [];
    for (const url of urls) {
      if (!html.includes(`src="${url}" integrity`) && !html.includes(`href="${url}" integrity`) &&
          !html.includes(`integrity=`) ) {
        // More precise: look for the tag containing this url
        const hasIntegrity = new RegExp(`["']${url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["'][^>]*integrity=`).test(html) ||
                             new RegExp(`integrity=[^>]*["']${url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`).test(html);
        if (!hasIntegrity) missing.push(url);
      }
    }

    if (missing.length > 0) {
      console.error('❌ CDN resources missing SRI integrity attribute:');
      missing.forEach(u => console.error('  -', u));
      console.error('\nRun: node scripts/add-sri.js   to fix automatically.');
      process.exit(1);
    }
    console.log(`✅ All ${urls.size} CDN resources have SRI integrity attributes.`);
    return;
  }

  // Fetch and hash each URL
  console.log(`Fetching ${urls.size} CDN resources...`);
  const hashes = new Map();
  await Promise.all([...urls].map(async (url) => {
    try {
      process.stdout.write(`  ${url.split('/').slice(-1)[0]}... `);
      const buf = await fetchBuffer(url);
      hashes.set(url, sri(buf));
      console.log('✓');
    } catch (err) {
      console.log(`✗ (${err.message})`);
    }
  }));

  // Patch <link href="URL"> tags
  html = html.replace(
    /(<link\b)(([^>]*) href="(https:\/\/cdn\.[^"]+)"([^>]*?))(\/?>)/g,
    (match, open, middle, before, url, after, close) => {
      const hash = hashes.get(url);
      if (!hash || middle.includes('integrity=')) return match;
      return `${open}${before} href="${url}"${after} integrity="${hash}" crossorigin="anonymous"${close}`;
    }
  );

  // Patch <script src="URL"> tags
  html = html.replace(
    /(<script\b)(([^>]*) src="(https:\/\/cdn\.[^"]+)"([^>]*?))(><\/script>)/g,
    (match, open, middle, before, url, after, close) => {
      const hash = hashes.get(url);
      if (!hash || middle.includes('integrity=')) return match;
      return `${open}${before} src="${url}"${after} integrity="${hash}" crossorigin="anonymous"${close}`;
    }
  );

  writeFileSync(SLIDES, html);
  console.log(`\n✅ slides.html patched with ${hashes.size} SRI hashes.`);
  console.log('   Commit the result and re-run with --check to verify.');
}

run().catch((err) => { console.error(err); process.exit(1); });
