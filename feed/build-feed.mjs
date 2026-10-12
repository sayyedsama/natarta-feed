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
    const alert = { id: `${src.id}:${it.link}`, title: it.title, summary: it.summary, link: it.link, date: Number.isFinite(t) ? new Date(t).toISOString() : null, source: src.name, sourceId: src.id, license: src.license };
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
  const alerts = list.filter((a) => !seen.has(a.link) && seen.add(a.link)).sort((a, b) => (b.date ?? '').localeCompare(a.date ?? '')).slice(0, 25);
  const body = JSON.stringify({ region, generatedAt, alerts });
  fs.writeFileSync(path.join(OUT, `${region}.json`), JSON.stringify({ body, sig: sign(body) }));
  regions[region] = alerts.length;
}
fs.writeFileSync(path.join(OUT, 'index.json'), JSON.stringify({ generatedAt, regions, report }, null, 1));
console.log(JSON.stringify({ generatedAt, regions, report }, null, 1));

if (process.argv.includes('--snapshot')) {
  const snap = Object.fromEntries(Object.entries(byRegion).map(([r]) => [r, JSON.parse(JSON.parse(fs.readFileSync(path.join(OUT, `${r}.json`), 'utf8')).body).alerts.slice(0, 12)]));
  fs.mkdirSync(path.join(here, '..', 'src', 'data'), { recursive: true }); fs.writeFileSync(path.join(here, '..', 'src', 'data', 'alertsSnapshot.ts'),
    `/* Bundled offline fallback for Local Scam Alerts. Generated by feed/build-feed.mjs --snapshot on ${generatedAt}. */\nexport const ALERTS_SNAPSHOT_AT = '${generatedAt}';\nexport const ALERTS_SNAPSHOT: Record<string, { id: string; title: string; summary: string; link: string; date: string | null; source: string; sourceId: string; license: string }[]> = ${JSON.stringify(snap, null, 1)};\n`);
  console.log('snapshot written');
}
