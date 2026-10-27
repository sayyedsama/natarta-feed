#!/usr/bin/env node
/**
 * Natarta Local Scam Alerts aggregator. Free: runs on a scheduled GitHub Action, publishes static JSON (GitHub Pages).
 * - Fetches only enabled official feeds in sources.json (polite: 1 request per source per run, identifies itself).
 * - Keeps headline, date, short summary, link back. Filters general news feeds to scam/fraud items.
 * - Writes feed-out/<region>.json (national, state-XX, metro-YY) + index.json, each signed with Ed25519
 *   (secret NATARTA_FEED_SECRET_KEY, base64 64-byte tweetnacl secret key). App verifies with the bundled public key.
 * - Also writes src/data/alertsSnapshot.ts (bundled offline fallback) when run with --snapshot.
 * No personal data, no user locations: phones download their region file; the server never learns who asked.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const nacl = require('tweetnacl');
import { fetchFtcPacked } from './ftc-phones.mjs';
import { fetchCryptoPacked } from './crypto-scams.mjs';
const here = path.dirname(new URL(import.meta.url).pathname);
const { sources } = JSON.parse(fs.readFileSync(path.join(here, 'sources.json'), 'utf8'));
const OUT = path.join(here, '..', 'feed-out');
const UA = 'NatartaScamAlerts/1.0 (+https://github.com/; public-safety feed reader)';
const SCAM_RE = /\b(scam|scams|scammer|fraud|phish|smish|impersonat|imposter|identity theft|gift card|swindl|con artist|deceptive|counterfeit|ransomware|extort|sextortion|elder abuse|elder financial|robocall|spoof)/i;
const STRICT_RE = /\b(scam|scams|scammer|impersonat|imposter|elder|seniors?|older (adults|americans)|phish|smish|robocall|warn|alert|romance|sextortion|grandparent|tech support|gift card)/i;
const NOT_CONSUMER_RE = /\b(programmable logic|wastewater|industrial control|critical infrastructure|sector|vulnerabilit|CVE-|election crimes)/i;
const MAX_AGE_DAYS = 120;
const STATES = { Alabama:'AL',Alaska:'AK',Arizona:'AZ',Arkansas:'AR',California:'CA',Colorado:'CO',Connecticut:'CT',Delaware:'DE',Florida:'FL',Georgia:'GA',Hawaii:'HI',Idaho:'ID',Illinois:'IL',Indiana:'IN',Iowa:'IA',Kansas:'KS',Kentucky:'KY',Louisiana:'LA',Maine:'ME',Maryland:'MD',Massachusetts:'MA',Michigan:'MI',Minnesota:'MN',Mississippi:'MS',Missouri:'MO',Montana:'MT',Nebraska:'NE',Nevada:'NV','New Hampshire':'NH','New Jersey':'NJ','New Mexico':'NM','New York':'NY','North Carolina':'NC','North Dakota':'ND',Ohio:'OH',Oklahoma:'OK',Oregon:'OR',Pennsylvania:'PA','Rhode Island':'RI','South Carolina':'SC','South Dakota':'SD',Tennessee:'TN',Texas:'TX',Utah:'UT',Vermont:'VT',Virginia:'VA',Washington:'WA','West Virginia':'WV',Wisconsin:'WI',Wyoming:'WY','District of Columbia':'DC' };
const METROS = { 'dc-nova': /\b(Fairfax|McLean|Arlington|Alexandria|Northern Virginia|Loudoun|Tysons|Falls Church)\b/i, memphis: /\b(Memphis|Shelby County|Germantown|Bartlett|Collierville)\b/i };
/** Place hints for national feeds (e.g. DOJ 'Eastern District of Virginia'). */
function placeRegions(text) {
  const out = [];
  for (const [name, code] of Object.entries(STATES)) if (new RegExp(`\\b${name}\\b`).test(text) && !(name === 'Virginia' && /West Virginia/.test(text) && !/(^|[^t] )Virginia/.test(text.replace(/West Virginia/g, '')))) out.push(`state-${code}`);
  for (const [m, re] of Object.entries(METROS)) if (re.test(text)) out.push(`metro-${m}`);
  return out;
}

const decode = (s) => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0?39;|&apos;|&#8217;|&rsquo;/g, "'").replace(/&#8220;|&#8221;|&ldquo;|&rdquo;/g, '"').replace(/&#8211;|&#8212;|&ndash;|&mdash;/g, '—').replace(/&nbsp;|&#160;/g, ' ').replace(/&#\d+;/g, '').replace(/\s+/g, ' ').trim();
const tag = (x, t) => { const m = x.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`, 'i')); return m ? decode(m[1]) : ''; };

export function parseRss(xml) {
  return (xml.match(/<item[\s>][\s\S]*?<\/item>|<entry[\s>][\s\S]*?<\/entry>/gi) ?? []).map((it) => {
    let link = tag(it, 'link');
    if (!link) { const m = it.match(/<link[^>]*href="([^"]+)"/i); link = m ? m[1] : ''; }
    const date = tag(it, 'pubDate') || tag(it, 'updated') || tag(it, 'published') || tag(it, 'dc:date');
    return { title: tag(it, 'title'), link, date, summary: (tag(it, 'description') || tag(it, 'summary')).slice(0, 280) };
  });
}

async function fetchSource(src) {
  try {
    const res = await fetch(src.url, { headers: { 'User-Agent': UA, Accept: 'application/rss+xml, application/xml, text/xml' }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) return { src, items: [], error: `HTTP ${res.status}` };
    const items = parseRss(await res.text());
    return { src, items, error: items.length ? null : 'no items' };
  } catch (e) {
    return { src, items: [], error: String(e.message ?? e) };
  }
}

const now = Date.now();
const results = await Promise.all(sources.filter((s) => s.enabled).map(fetchSource));
const byRegion = {};
const report = [];
for (const { src, items, error } of results) {
  let kept = 0;
  for (const it of items) {
    const t = Date.parse(it.date);
    if (!it.title || !it.link || !/^https:\/\//.test(it.link)) continue;
    if (Number.isFinite(t) && now - t > MAX_AGE_DAYS * 864e5) continue;
    const text = it.title + ' ' + it.summary;
    if (src.scamFilter && !SCAM_RE.test(text)) continue;
    if (src.strictFilter && !STRICT_RE.test(text)) continue;
    if (NOT_CONSUMER_RE.test(text)) continue;
    kept++;
    const alert = { id: `${src.id}:${it.link}`, title: it.title, summary: it.summary, link: it.link, date: Number.isFinite(t) ? new Date(t).toISOString() : null, source: src.name, sourceId: src.id, license: src.license, kind: src.kind ?? 'alert' };
    const regs = new Set(src.regions.map((r) => r.replace(':', '-')));
    if (src.placeHints) for (const r of placeRegions(it.title + ' ' + it.summary)) regs.add(r);
    for (const r of regs) (byRegion[r] ??= []).push(alert);
  }
  report.push({ id: src.id, fetched: items.length, kept, error });
}
const generatedAt = new Date().toISOString();
const secret = process.env.NATARTA_FEED_SECRET_KEY ? Buffer.from(process.env.NATARTA_FEED_SECRET_KEY, 'base64') : null;
const sign = (body) => (secret ? Buffer.from(nacl.sign.detached(Buffer.from(body), new Uint8Array(secret))).toString('base64') : null);
fs.mkdirSync(OUT, { recursive: true });
const regions = {};
for (const [region, list] of Object.entries(byRegion)) {
  const seen = new Set();
  let alerts = list.filter((a) => !seen.has(a.link) && seen.add(a.link)).sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''));
  // Truth feed: a balanced mix (up to 6 per outlet) instead of whoever posts most.
  if (region === 'truth') { const per = {}; alerts = alerts.filter((a) => (per[a.sourceId] = (per[a.sourceId] ?? 0) + 1) <= 6); }
  alerts = alerts.slice(0, 25);
  const body = JSON.stringify({ region, generatedAt, alerts });
  fs.writeFileSync(path.join(OUT, `${region}.json`), JSON.stringify({ body, sig: sign(body) }));
  regions[region] = alerts.length;
}

// FCC unwanted-call complaints (public open data, no key): caller-ID numbers reported 3+ times in ~120 days.
// Caller ID is often spoofed, so the app only ever says "reported N times", never "this is a scammer".
try {
  const since = new Date(Date.now() - 120 * 864e5).toISOString().slice(0, 10);
  const q = `$select=caller_id_number,count(*) as n&$where=caller_id_number!='' and issue_date>'${since}'&$group=caller_id_number&$having=count(*)>=3&$order=n DESC&$limit=20000`;
  const res = await fetch(`https://opendata.fcc.gov/resource/vakf-fz8e.json?${encodeURI(q)}`, { signal: AbortSignal.timeout(60000) });
  const rows = res.ok ? await res.json() : [];
  const numbers = {};
  for (const r of rows) { const d = String(r.caller_id_number).replace(/\D/g, '').replace(/^1(?=\d{10}$)/, ''); if (d.length === 10) numbers[d] = (numbers[d] ?? 0) + Number(r.n); }
  const body = JSON.stringify({ kind: 'fcc-phones', generatedAt, since, source: 'FCC Consumer Complaints Data - Unwanted Calls (opendata.fcc.gov, public domain)', numbers });
  fs.writeFileSync(path.join(OUT, 'phones.json'), JSON.stringify({ body, sig: sign(body) }));
  report.push({ id: 'fcc-phones', ok: true, items: Object.keys(numbers).length });
} catch (e) { report.push({ id: 'fcc-phones', ok: false, error: e.message }); }
// FTC Do Not Call complaints by number, 2016 on (public-domain FTC + NANPA data, CC0 aggregation by
// usacallerlookup/ftc-robocall-dataset on GitHub, refreshed monthly). Packed into a compact lookup the phone
// downloads whole and searches on the device; a number is never sent anywhere. No caller names exist in it.
// If GitHub is unreachable this run, the last published signed file is carried over so the site never loses it.
try {
  const f = await fetchFtcPacked({ ua: UA });
  const body = JSON.stringify({ kind: 'ftc-phones', v: 1, generatedAt, coverage: f.coverage, datasetGenerated: f.datasetGenerated, numbers: f.numbers, complaints: f.complaints,
    source: 'FTC Do Not Call complaint data with NANPA carrier and rate center, aggregated by number (github.com/usacallerlookup/ftc-robocall-dataset)', license: 'CC0 1.0 aggregation of US public-domain data',
    note: 'A complaint is not proof. Caller ID is often spoofed. Carrier and rate center show where the number block was issued.',
    subjects: f.subjects, carriers: f.carriers, places: f.places, p: f.p });
  if (!/^[\x00-\x7f]*$/.test(body)) throw new Error('ftc-phones body must be ASCII');
  fs.writeFileSync(path.join(OUT, 'ftc-phones.json'), JSON.stringify({ body, sig: sign(body) }));
  report.push({ id: 'ftc-phones', ok: true, items: f.numbers, bytes: body.length, coverage: f.coverage });
} catch (e) {
  let carried = false;
  try { const r = await fetch('https://sayyedsama.github.io/natarta-feed/ftc-phones.json', { signal: AbortSignal.timeout(60000) }); if (r.ok) { const t = await r.text(); if (JSON.parse(t).sig) { fs.writeFileSync(path.join(OUT, 'ftc-phones.json'), t); carried = true; } } } catch { /* nothing to carry */ }
  report.push({ id: 'ftc-phones', ok: false, error: e.message, carriedOver: carried });
}
// Crypto phishing sites: MetaMask's open eth-phishing-detect blacklist (DBAD public license, credit given in the app's
// Credits and in the file), packed as sorted 64-bit hashes. The phone checks sites on the device; nothing is sent.
// If GitHub is unreachable this run, the last published signed file is carried over.
try {
  const c = await fetchCryptoPacked({ ua: UA });
  const body = JSON.stringify({ kind: 'crypto-phishing', v: 1, generatedAt, count: c.count, listVersion: c.version, whitelist: c.whitelist,
    source: 'MetaMask eth-phishing-detect blacklist (github.com/MetaMask/eth-phishing-detect)', license: "DBAD (Don't Be A Dick) public license, (C) 2018 kumavis",
    note: 'A site not on this list is not proof it is safe. New fake sites appear every day.', hashesB64: c.hashesB64 });
  if (!/^[\x00-\x7f]*$/.test(body)) throw new Error('crypto-scams body must be ASCII');
  fs.writeFileSync(path.join(OUT, 'crypto-scams.json'), JSON.stringify({ body, sig: sign(body) }));
  report.push({ id: 'crypto-scams', ok: true, items: c.count, bytes: body.length });
} catch (e) {
  let carried = false;
  try { const r = await fetch('https://sayyedsama.github.io/natarta-feed/crypto-scams.json', { signal: AbortSignal.timeout(60000) }); if (r.ok) { const t = await r.text(); if (JSON.parse(t).sig) { fs.writeFileSync(path.join(OUT, 'crypto-scams.json'), t); carried = true; } } } catch { /* nothing to carry */ }
  report.push({ id: 'crypto-scams', ok: false, error: e.message, carriedOver: carried });
}
// Happening now: curated items (own words, official source + date), schema-checked, then signed like every other file.
try {
  const KEYS = ['texts', 'emails', 'mail', 'links', 'phone', 'qr', 'news', 'media'];
  const { items } = JSON.parse(fs.readFileSync(path.join(here, 'happening.json'), 'utf8'));
  const valid = items.filter((it) =>
    typeof it.id === 'string' && typeof it.title === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(it.date) &&
    /^https:\/\/[a-z0-9.-]+\.gov\//.test(it.sourceUrl) && typeof it.source === 'string' && KEYS.includes(it.type) &&
    Array.isArray(it.what) && it.what.length >= 1 && it.what.length <= 3 &&
    Array.isArray(it.signs) && it.signs.length >= 2 && it.signs.length <= 4 &&
    Array.isArray(it.actions) && it.actions.length >= 2 && it.actions.length <= 3);
  if (valid.length !== items.length) throw new Error(`${items.length - valid.length} happening item(s) failed the schema check`);
  valid.sort((a, b) => b.date.localeCompare(a.date));
  const body = JSON.stringify({ kind: 'happening', generatedAt, items: valid.slice(0, 20) });
  fs.writeFileSync(path.join(OUT, 'happening.json'), JSON.stringify({ body, sig: sign(body) }));
  report.push({ id: 'happening', ok: true, items: valid.length });
} catch (e) { report.push({ id: 'happening', ok: false, error: e.message }); }
fs.writeFileSync(path.join(OUT, 'index.json'), JSON.stringify({ generatedAt, regions, report }, null, 1));
console.log(JSON.stringify({ generatedAt, regions, report }, null, 1));

if (process.argv.includes('--snapshot')) {
  const snap = Object.fromEntries(Object.entries(byRegion).map(([r]) => [r, JSON.parse(JSON.parse(fs.readFileSync(path.join(OUT, `${r}.json`), 'utf8')).body).alerts.slice(0, 12)]));
  fs.mkdirSync(path.join(here, '..', 'src', 'data'), { recursive: true }); fs.writeFileSync(path.join(here, '..', 'src', 'data', 'alertsSnapshot.ts'),
    `/* Bundled offline fallback for Local Scam Alerts. Generated by feed/build-feed.mjs --snapshot on ${generatedAt}. */\nexport const ALERTS_SNAPSHOT_AT = '${generatedAt}';\nexport const ALERTS_SNAPSHOT: Record<string, { id: string; title: string; summary: string; link: string; date: string | null; source: string; sourceId: string; license: string }[]> = ${JSON.stringify(snap, null, 1)};\n`);
  console.log('snapshot written');
}
