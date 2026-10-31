/**
 * More known scam and phishing websites -> one signed, hashed on-device lookup (more-scam-sites.json) for Natarta's link checks.
 * Sources (licenses re-checked Oct 30, 2026):
 *  - CERT Polska Warning List (hole.cert.pl/domains/v2/domains.txt). "May be used by any user for any purpose, including
 *    commercial purposes." Attribution not required; if named, it must not imply any partnership or endorsement.
 *    Their rule: a domain removed from their list must stop being blocked. We rebuild from the current list every run,
 *    so removed domains drop out on the next build.
 *  - The Block List Project (github.com/blocklistproject/Lists), phishing.txt and scam.txt. Repository: Unlicense (public
 *    domain); the list files say MIT. Credit given in the file and in the app's credits either way.
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
];
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
      if (NEVER.has(h) || top.has(h)) { dropped++; continue; }
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

export async function fetchMorePacked({ ua } = {}) {
  const lists = []; const used = [];
  for (const s of SOURCES) {
    try {
      const r = await fetch(s.url, { headers: ua ? { 'User-Agent': ua } : {}, signal: AbortSignal.timeout(90000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const hosts = parseList(await r.text(), s.format);
      if (hosts.length < 1000) throw new Error('list looks wrong');
      lists.push({ id: s.id, hosts }); used.push({ id: s.id, name: s.name, license: s.license });
    } catch (e) { console.error(`${s.id}: ${e.message} (skipped this run)`); }
  }
  if (!lists.length) throw new Error('no extra list could be downloaded');
  const packed = packMore(lists, await topSites());
  return { ...packed, sources: used.map((u) => ({ ...u, count: packed.perSource[u.id] })) };
}
