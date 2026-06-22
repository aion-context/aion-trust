// Records the aion-trust demo: drives the live surfaces (8080) and the interop page (8091),
// holding each scene for its narration's measured duration (demo/durations.json) so the video
// tracks the per-scene ElevenLabs audio. Output: demo/playwright-video/*.webm.
const { chromium } = require('playwright');
const fs = require('fs');

const D = JSON.parse(fs.readFileSync('demo/durations.json', 'utf8'));
const BASE = 'http://127.0.0.1:8080';
const STATIC = 'http://127.0.0.1:8091';
const ms = (s) => Math.round(s * 1000);

(async () => {
  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 1,
    recordVideo: { dir: 'demo/playwright-video', size: { width: 1440, height: 900 } },
  });
  const page = await context.newPage();

  const scene = async (n, fn) => {
    const t0 = Date.now();
    try { await fn(); } catch (e) { console.log(`scene ${n} action error: ${e.message}`); }
    const remaining = ms(D[String(n)]) - (Date.now() - t0);
    if (remaining > 0) await page.waitForTimeout(remaining);
    console.log(`scene ${n}: ${((Date.now() - t0) / 1000).toFixed(1)}s (target ${D[String(n)].toFixed(1)})`);
  };

  // 1 — home hero
  await scene(1, async () => { await page.goto(BASE + '/', { waitUntil: 'networkidle' }); });

  // 2 — the three rooms
  await scene(2, async () => {
    await page.hover('a.room').catch(() => {});
    await page.waitForTimeout(700);
    await page.hover('a.room.feature').catch(() => {});
  });

  // 3 — issuer: fill the employment form and issue
  await scene(3, async () => {
    await page.goto(BASE + '/issuer', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1800);
    const f = page.locator('form[action="/issuer/issue"]').first();
    const emp = f.locator('input[name="employer"]');
    await emp.fill(''); await emp.type('Acme Corp', { delay: 45 });
    const title = f.locator('input[name="title"]');
    await title.fill(''); await title.type('Staff Engineer', { delay: 45 });
    await page.waitForTimeout(900);
    await f.locator('button[type="submit"]').click();
    await page.waitForTimeout(1500);
  });

  // 4 — wallet: build a presentation
  await scene(4, async () => {
    await page.goto(BASE + '/wallet', { waitUntil: 'networkidle' });
    await page.waitForTimeout(3000);
    await page.locator('form[action="/wallet/present"] button[type="submit"]').first().click();
    await page.waitForTimeout(1500);
  });

  // 5 — verify: run the four checks → ACCEPTED
  await scene(5, async () => {
    await page.goto(BASE + '/verify', { waitUntil: 'networkidle' });
    await page.waitForTimeout(2200);
    await page.locator('form[action="/verify/run"] button[type="submit"]').first().click();
    await page.waitForTimeout(1500);
  });

  // 6 — walkthrough: auto-runs the lifecycle over SSE
  await scene(6, async () => { await page.goto(BASE + '/walkthrough', { waitUntil: 'domcontentloaded' }); });

  // 7 — interop: the VC travels, guards hold
  await scene(7, async () => { await page.goto(STATIC + '/interop.html', { waitUntil: 'networkidle' }); });

  // 8 — close on the home hero + motto
  await scene(8, async () => {
    await page.goto(BASE + '/', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1200);
    await page.evaluate(() => window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }));
  });

  await context.close(); // finalizes the webm
  await browser.close();
  const file = fs.readdirSync('demo/playwright-video').find((f) => f.endsWith('.webm'));
  console.log('VIDEO:' + (file || 'none'));
})();
