/**
 * Export slides.html (Reveal.js) to PDF using Playwright.
 * Reveal.js supports ?print-pdf query param for print-ready layout.
 *
 * Usage: node scripts/export-reveal-pdf.js [output-path]
 */
import { chromium } from 'playwright';
import { resolve, dirname } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const slideFile = resolve(__dirname, '..', 'slides.html');
const outputPath = process.argv[2]
  || resolve(__dirname, '..', 'dist', 'js-security-reveal-presentation.pdf');

if (!existsSync(slideFile)) {
  console.error('slides.html not found at', slideFile);
  process.exit(1);
}

mkdirSync(dirname(outputPath), { recursive: true });

console.log('Launching Chromium...');
const browser = await chromium.launch();
const page = await browser.newPage();

// Reveal.js ?print-pdf mode renders all slides as scrollable content
const fileUrl = `file://${slideFile}?print-pdf`;
console.log('Loading:', fileUrl);
await page.goto(fileUrl, { waitUntil: 'networkidle' });

// Give Reveal.js time to finish rendering all slides
await page.waitForTimeout(4000);

console.log('Exporting PDF to:', outputPath);
await page.pdf({
  path: outputPath,
  format: 'A4',
  landscape: true,
  printBackground: true,
  margin: { top: '0', right: '0', bottom: '0', left: '0' },
});

await browser.close();
console.log('✅ PDF exported successfully');
