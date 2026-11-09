/**
 * More known scam and phishing websites -> one signed, hashed on-device lookup (more-scam-sites.json) for Natarta's link checks.
 * Sources (licenses re-checked Oct 30, 2026):
 *  - CERT Polska Warning List (hole.cert.pl/domains/v2/domains.txt). "May be used by any user for any purpose, including
 *    commercial purposes." Attribution not required; if named, it must not imply any partnership or endorsement.
 *    Their rule: a domain removed from their list must stop being blocked. We rebuild from the current list every run,
 *    so removed domains drop out on the next build.
 *  - The Block List Project (github.com/blocklistproject/Lists), phishing.txt and scam.txt. Repository: Unlicense (public
 *    domain); the list files say MIT. Credit given in the file and in the app's credits either way.
 *  - PhishDestroy live feed (api.destroy.tools/v1/feed/primary.txt, no key, no sign-up), curated phishing and crypto-scam
 *    domains. The live feed is CC BY 4.0 (phishdestroy.io/live); credit "Phishing data: PhishDestroy, CC BY 4.0" in the
 *    file and wherever data credits appear. Visitors' links are never sent to PhishDestroy: we download the whole list
 *    and match on the device. If a fresh download has fewer than 100 entries we keep the previous copy (see build-feed).
 * NOT used: ThreatFox / URLhaus (abuse.ch). Downloads now need a signed-in Auth-Key, and abuse.ch says for-profit use may
 * need its paid commercial API. Phishing Army, OpenPhish and Google Safe Browsing: non-commercial terms.
 * Safety filter: never ship a host that is itself one of the ~20,000 most-linked sites (Majestic Million, CC BY 3.0),
 * or one of the big shared platforms below. Hosts on those platforms (like a fake page on a free site builder) stay.
 */
import { h64, cleanHost } from './crypto-scams.mjs';

export const SOURCES = [
  { id: 'cert-pl', name: 'CERT Polska Warning List', url: 'https://hole.cert.pl/domains/v2/domains.txt', license: 'Free for any use, including commercial (cert.pl/en/warning-list)', format: 'lines' },
  { id: 'blp-phishing', name: 'The Block List Project: phishing', url: 'https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt', license: 'Unlicense / MIT, The Block List Project', format: 'hosts' },
  { id: 'blp-scam', name: 'The Block List Project: scam', url: 'https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt', license: 'Unlicense / MIT, The Block List Project', format: 'hosts' },
  { id: 'phishdestroy', name: 'PhishDestroy', url: 'https://api.destroy.tools/v1/feed/primary.txt', license: 'CC BY 4.0, PhishDestroy (phishdestroy.io)', credit: 'Phishing data: PhishDestroy, CC BY 4.0', format: 'lines', min: 100, keepPrevious: true },
];
/** Shared hosting and big platforms: a listed host here is never blocked whole-domain (that would flag every site on it).
 * Fake pages ON them (like fake-bank.github.io) stay listed; the phone matches the full host first. */
export const SHARED_HOSTS = new Set(['github.io', 'pages.dev', 'vercel.app', 'netlify.app', 'workers.dev', 'web.app', 'firebaseapp.com', 'blogspot.com', 'wixsite.com', 'weebly.com', 'webflow.io', 'framer.app', 'glitch.me', 'repl.co', 'onrender.com', 'herokuapp.com', 'azurewebsites.net', 'amazonaws.com', 'cloudfront.net', 'r2.dev', 'ipfs.io', 'gitbook.io', 'notion.site', 'square.site', 'mystrikingly.com', 'godaddysites.com', 'carrd.co', '000webhostapp.com', 'sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.gle', 'googleusercontent.com', 'storage.googleapis.com', 'firebasestorage.googleapis.com', 'sharepoint.com', 'onedrive.live.com', '1drv.ms', 'dropbox.com', 'secureserver.net', 'cloudns.biz']);
/** First-party domains: neither the domain nor any of its subdomains is ever shipped (only the company controls them). */
export const FIRST_PARTY = ['google.com', 'googleapis.com', 'apple.com', 'icloud.com', 'coinbase.com', 'amazon.com', 'chase.com', 'paypal.com', 'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'github.com', 'gitlab.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'usps.com', 'netflix.com', 'bankofamerica.com', 'wellsfargo.com', 'binance.com', 'kraken.com', 'metamask.io', 'natarta.com'];
const firstParty = (h) => FIRST_PARTY.some((d) => h === d || h.endsWith('.' + d));
/** True if this listed host must never be shipped: a shared host itself, a first-party domain, or a big site. */
export const neverShip = (h, top = new Set()) => NEVER.has(h) || SHARED_HOSTS.has(h) || firstParty(h) || top.has(h);
const MAJESTIC = 'https://downloads.majestic.com/majestic_million.csv';
export const NEVER = new Set(['google.com', 'apple.com', 'icloud.com', 'paypal.com', 'amazon.com', 'microsoft.com', 'live.com', 'office.com', 'outlook.com', 'github.io', 'github.com', 'gitlab.com', 'blogspot.com', 'wixsite.com', 'weebly.com', '000webhostapp.com', 'firebaseapp.com', 'web.app', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'sharepoint.com', 'dropbox.com', 'googleusercontent.com', 'amazonaws.com', 'azurewebsites.net', 'herokuapp.com', 'r2.dev', 'ipfs.io', 'bit.ly', 'tinyurl.com', 't.co', 'facebook.com', 'instagram.com', 'linkedin.com', 'chase.com', 'usps.com', 'netflix.com', 'cash.app', 'natarta.com', 'sayyedsama.github.io']);
const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,}$/;

export function parseList(text, format) {
  const out = [];
  for (let line of text.split('\n')) {
    line = line.replace(/#.*/, '').trim().toLowerCase();
    if (!line) continue;
    if (format === 'hosts') { const p = line.split(/\s+/); if (p.length < 2) continue; line = p[1]; }
    const h = cleanHost(line);
    if (!HOST_RE.test(h) || /^\d+(\.\d+){3}$/.test(h) || h === 'localhost' || h === '0.0.0.0') continue;
    out.push(h);
  }
  return out;
}

/** lists: [{ id, hosts[] }], top: Set of big sites never to ship. */
export function packMore(lists, top) {
  const seen = new Set(); const perSource = {}; let dropped = 0;
  for (const { id, hosts } of lists) {
    let n = 0;
    for (const h of hosts) {
      if (neverShip(h, top)) { dropped++; continue; }
      if (!seen.has(h)) { seen.add(h); n++; }
    }
    perSource[id] = n;
  }
  const pairs = [...seen].map(h64).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const buf = Buffer.alloc(pairs.length * 8);
  pairs.forEach(([a, b], i) => { buf.writeUInt32LE(a, i * 8); buf.writeUInt32LE(b, i * 8 + 4); });
  return { count: pairs.length, dropped, perSource, hashesB64: buf.toString('base64') };
}

async function topSites(limit = 20000) {
  const top = new Set();
  try {
    const res = await fetch(MAJESTIC, { signal: AbortSignal.timeout(60000) });
    const reader = res.body.getReader(); const dec = new TextDecoder(); let rest = '', lines = 0;
    while (lines < limit) {
      const { value, done } = await reader.read(); if (done) break;
      const parts = (rest + dec.decode(value, { stream: true })).split('\n'); rest = parts.pop();
      for (const l of parts) { const d = l.split(',')[2]; if (d && lines++ > 0) top.add(cleanHost(d)); if (lines >= limit) break; }
    }
    reader.cancel().catch(() => {});
  } catch { /* the NEVER list still applies */ }
  return top;
}

export async function fetchMorePacked({ ua, fetchImpl = fetch, top } = {}) {
  const lists = []; const used = []; const missing = [];
  for (const s of SOURCES) {
    try {
      const r = await fetchImpl(s.url, { headers: ua ? { 'User-Agent': ua } : {}, signal: AbortSignal.timeout(90000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const hosts = parseList(await r.text(), s.format);
      if (hosts.length < (s.min ?? 1000)) throw new Error(`list looks wrong (${hosts.length} entries)`);
      lists.push({ id: s.id, hosts }); used.push({ id: s.id, name: s.name, license: s.license, ...(s.credit ? { credit: s.credit } : {}) });
    } catch (e) { console.error(`${s.id}: ${e.message} (skipped this run)`); if (s.keepPrevious) missing.push(s.id); }
  }
  if (!lists.length) throw new Error('no extra list could be downloaded');
  const packed = packMore(lists, top ?? await topSites());
  return { ...packed, missing, sources: used.map((u) => ({ ...u, count: packed.perSource[u.id] })) };
}
