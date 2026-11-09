// more-scam-sites: PhishDestroy added with a shared-host guard; real sites never flagged; short feeds keep the old copy.
// node test/more-scam-sites.test.mjs [path/to/primary.txt]   (an optional real PhishDestroy download; nothing is fetched here)
import fs from 'node:fs';
import { SOURCES, parseList, packMore, fetchMorePacked, neverShip, SHARED_HOSTS } from '../feed/more-scam-sites.mjs';
import { h64 } from './../feed/crypto-scams.mjs';
let pass = 0, fail = 0; const ok = (c, m) => { c ? pass++ : (fail++, console.log('  FAIL', m)); };
// Same lookup as the app (src/services/blocklist.ts isBlocklisted): the host, then each parent domain.
const table = (b64) => { const b = Buffer.from(b64, 'base64'); const t = new Uint32Array(b.length / 4); for (let i = 0; i < t.length; i++) t[i] = b.readUInt32LE(i * 4); return t; };
const inT = (t, [a, b]) => { let lo = 0, hi = t.length / 2 - 1; while (lo <= hi) { const m = (lo + hi) >> 1, x = t[m * 2], y = t[m * 2 + 1]; if (x === a && y === b) return true; if (x < a || (x === a && y < b)) lo = m + 1; else hi = m - 1; } return false; };
const listed = (t, host) => { let h = host.toLowerCase().replace(/^www\./, ''); while (h.includes('.')) { if (inT(t, h64(h))) return true; h = h.slice(h.indexOf('.') + 1); } return false; };

const pd = SOURCES.find((s) => s.id === 'phishdestroy');
ok(pd && /api\.destroy\.tools\/v1\/feed\/primary\.txt$/.test(pd.url) && pd.credit === 'Phishing data: PhishDestroy, CC BY 4.0' && pd.min === 100 && pd.keepPrevious, 'PhishDestroy source with credit, min 100, keep previous');
ok(!SOURCES.some((s) => /openphish|phishtank|urlhaus|abuse\.ch|phishing\.army/i.test(s.url)), 'no OpenPhish, PhishTank, URLhaus or Phishing Army');

// A hostile or mistaken feed: shared hosts and real companies listed whole-domain, plus real fake pages on shared hosts.
const bad = ['github.io', 'pages.dev', 'vercel.app', 'blogspot.com', 'google.com', 'docs.google.com', 'drive.google.com', 'sites.google.com', 'apple.com', 'coinbase.com', 'login.coinbase.com', 'amazon.com', 'chase.com', 'secure.chase.com', 'fake-chase-login.github.io', 'coinbase-wallet-verify.pages.dev', 'paypa1-secure.vercel.app', 'parcel-redelivery-help.top'];
const txt = bad.join('\n') + '\n' + Array.from({ length: 150 }, (_, i) => `scam-${i}.example-bad.top`).join('\n');
const packed = packMore([{ id: 'phishdestroy', hosts: parseList(txt, 'lines') }], new Set());
const t = table(packed.hashesB64);
for (const real of ['google.com', 'docs.google.com', 'drive.google.com', 'sites.google.com', 'accounts.google.com', 'apple.com', 'www.apple.com', 'coinbase.com', 'login.coinbase.com', 'amazon.com', 'chase.com', 'secure.chase.com', 'natarta.github.io', 'my-portfolio.github.io', 'docs.pages.dev', 'nextjs.vercel.app', 'blog.blogspot.com'])
  ok(!listed(t, real), `real site not flagged: ${real}`);
for (const fake of ['fake-chase-login.github.io', 'coinbase-wallet-verify.pages.dev', 'paypa1-secure.vercel.app', 'parcel-redelivery-help.top', 'pay.parcel-redelivery-help.top'])
  ok(listed(t, fake), `fake site still flagged: ${fake}`);
ok(neverShip('github.io') && neverShip('docs.google.com') && !neverShip('evil.github.io'), 'guard: shared host never shipped whole, pages on it are');

// Short or failed PhishDestroy download: reported as missing so the builder keeps the previous copy.
const fakeFetch = (n) => async (url) => new Response(/destroy\.tools/.test(url) ? Array.from({ length: n }, (_, i) => `x${i}.bad.top`).join('\n') : Array.from({ length: 2000 }, (_, i) => `y${i}.bad.top`).join('\n'));
const quiet = console.error; console.error = () => {};
const short = await fetchMorePacked({ fetchImpl: fakeFetch(40), top: new Set() });
const full = await fetchMorePacked({ fetchImpl: fakeFetch(500), top: new Set() });
console.error = quiet;
ok(short.missing.includes('phishdestroy') && !short.sources.some((s) => s.id === 'phishdestroy'), 'under 100 entries: PhishDestroy marked missing (keep previous copy)');
ok(!full.missing.length && full.sources.find((s) => s.id === 'phishdestroy').credit === 'Phishing data: PhishDestroy, CC BY 4.0', '500 entries: PhishDestroy used and credited');
const src = fs.readFileSync(new URL('../feed/build-feed.mjs', import.meta.url), 'utf8');
ok(/m\.missing\.length/.test(src) && /48 \* 3600e3/.test(src) && /Not listed never means safe/.test(src), 'builder keeps the previous copy and says "not listed never means safe"');

// Optional: the real PhishDestroy list, as downloaded.
const real = process.argv[2];
if (real && fs.existsSync(real)) {
  const hosts = parseList(fs.readFileSync(real, 'utf8'), 'lines');
  const p = packMore([{ id: 'phishdestroy', hosts }], new Set()); const rt = table(p.hashesB64);
  const top = ['google.com', 'docs.google.com', 'drive.google.com', 'sites.google.com', 'mail.google.com', 'apple.com', 'icloud.com', 'coinbase.com', 'amazon.com', 'chase.com', 'paypal.com', 'microsoft.com', 'github.com', 'natarta.github.io', 'pages.github.io', 'example.pages.dev', 'example.vercel.app', 'example.blogspot.com', 'wellsfargo.com', 'bankofamerica.com', 'netflix.com', 'usps.com', 'irs.gov', 'ssa.gov', 'wikipedia.org', 'youtube.com', 'x.com', 'reddit.com'];
  const hits = top.filter((h) => listed(rt, h));
  ok(hits.length === 0, `real PhishDestroy list (${hosts.length} hosts, ${p.count} shipped, ${p.dropped} guarded): no real site flagged ${hits.join(' ')}`);
  ok(hosts.length >= 100, 'real list has 100+ entries');
}
console.log(`${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
