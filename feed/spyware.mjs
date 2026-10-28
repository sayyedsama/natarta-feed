/**
 * Device Guard: known spyware and stalkerware web addresses -> compact on-device lookup for Natarta's link checks.
 *
 * Sources (license-compatible only; each credited in the app's About & credits and in the signed file):
 *  - MVT project indicator files hosted in github.com/mvt-project/mvt-indicators (MIT).
 *  - Amnesty International Security Lab investigations, github.com/AmnestyTech/investigations (CC BY 2.0, credit given).
 *  - Echap stalkerware-indicators, github.com/AssoEchap/stalkerware-indicators (CC BY 4.0, credit given).
 *  - Zero Breach Toolkit indicator set by archivegenocide.com, github.com/interplains/Zero-Breach-Toolkit (CC0 1.0).
 * The list of MVT-tracked files is read from mvt-indicators' indicators.yaml, but ONLY files published by the three
 * allowed owners above are used. NOT used: The Citizen Lab's malware-indicators repo (CC BY-NC-SA, non-commercial).
 *
 * We keep only web addresses (no IPs, no file hashes), drop shared platforms that host everyone (appspot.com,
 * firebaseio.com ...) unless a specific sub-address is named, drop government/education sites (those appear as hacked
 * "watering holes", and a warning on a real government site would mislead), hash each address with the same 64-bit
 * hash as the phishing rule pack, and ship sorted hashes in two tables: spyware (mercenary / targeted attacks) and
 * stalkerware (apps someone installs to secretly watch a phone). The phone checks addresses on the device only.
 */
export const MVT_INDEX_URL = 'https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml';
export const ZERO_BREACH_URL = 'https://raw.githubusercontent.com/interplains/Zero-Breach-Toolkit/main/dist/adfection.domains.txt';
/** Owner -> credit + license. Anything not here is skipped (the Citizen Lab repo in particular). */
export const ALLOWED_OWNERS = {
  'mvt-project': { credit: 'MVT project (mvt-indicators)', license: 'MIT' },
  AmnestyTech: { credit: 'Amnesty International Security Lab', license: 'CC BY 2.0' },
  AssoEchap: { credit: 'Echap (stalkerware-indicators)', license: 'CC BY 4.0' },
};
/** Shared hosting / platform names: never listed whole (only a named sub-address can be listed). */
export const SHARED = ['appspot.com', 'firebaseio.com', 'firebaseapp.com', 'web.app', 'azurewebsites.net', 'herokuapp.com', 'duckdns.org', 'ngrok.io',
  'github.io', 'blogspot.com', 'wordpress.com', 'amazonaws.com', 'cloudfront.net', 'googleapis.com', 'google.com', 'apple.com', 'icloud.com',
  'microsoft.com', 'windows.net', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'imwork.net', 'no-ip.com', 'ddns.net', 'kesug.com'];

/** Same two 32-bit hashes as src/services/hash64.ts (a test keeps them identical). */
export function h64(s) {
  let a = 0x811c9dc5, b = 0x12345678;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193) >>> 0;
    b = (Math.imul(b, 31) + c + (b >>> 13)) >>> 0;
    b = Math.imul(b ^ (b >>> 16), 0x45d9f3b) >>> 0;
  }
  return [a >>> 0, b >>> 0];
}
const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,}$/;
export const cleanHost = (h) => String(h).trim().toLowerCase().replace(/^\*\./, '').replace(/^www\./, '').replace(/\.$/, '');

/** Reads the small mvt-indicators index (a flat YAML list) into {owner, repo, branch, path, name}. */
export function parseIndex(yaml) {
  const out = [];
  for (const block of String(yaml).split(/\n\s*-\s*\n/)) {
    const g = (k) => (new RegExp(`\\n\\s*${k}:\\s*(\\S.*)`).exec('\n' + block) || [])[1]?.trim();
    const owner = g('owner'), repo = g('repo'), branch = g('branch'), path = g('path');
    if (owner && repo && branch && path) out.push({ owner, repo, branch, path, name: g('name') ?? path });
  }
  return out;
}
/** Web addresses named in a STIX 2 bundle (domain-name and url patterns). */
export function stixHosts(bundle) {
  const out = new Set();
  for (const o of bundle?.objects ?? []) {
    if (o.type !== 'indicator' || typeof o.pattern !== 'string') continue;
    for (const m of o.pattern.matchAll(/domain-name:value\s*=\s*'([^']+)'/g)) out.add(m[1]);
    for (const m of o.pattern.matchAll(/url:value\s*=\s*'([^']+)'/g)) { try { out.add(new URL(m[1].includes('://') ? m[1] : 'http://' + m[1]).hostname); } catch { /* skip */ } }
  }
  return [...out];
}
export function keepHost(raw) {
  const h = cleanHost(raw);
  if (!HOST_RE.test(h) || /^\d+(\.\d+){3}$/.test(h)) return null;
  if (/\.(gov|edu|mil)(\.[a-z]{2})?$|\.gouv\.|\.gob\./.test(h)) return null;
  if (SHARED.includes(h)) return null;
  return h;
}
function packHashes(hosts) {
  const pairs = [...hosts].map(h64).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const buf = Buffer.alloc(pairs.length * 8);
  pairs.forEach(([a, b], i) => { buf.writeUInt32LE(a, i * 8); buf.writeUInt32LE(b, i * 8 + 4); });
  return buf.toString('base64');
}
/** groups: [{ kind: 'spyware'|'stalkerware', hosts: string[] }] -> packed tables (a host in both counts as spyware). */
export function packSpyware(groups) {
  const spy = new Set(), stalk = new Set(); let dropped = 0;
  for (const g of groups) for (const raw of g.hosts) {
    const h = keepHost(raw);
    if (!h) { dropped++; continue; }
    (g.kind === 'stalkerware' ? stalk : spy).add(h);
  }
  for (const h of spy) stalk.delete(h);
  return { spyware: spy.size, stalkerware: stalk.size, dropped, spywareB64: packHashes(spy), stalkerwareB64: packHashes(stalk) };
}

/** Downloads every allowed source and packs it. Returns the packed tables plus the list of sources actually used. */
export async function fetchSpywarePacked({ ua } = {}) {
  const headers = ua ? { 'User-Agent': ua } : {};
  const get = async (url) => { const r = await fetch(url, { headers, signal: AbortSignal.timeout(60000) }); if (!r.ok) throw new Error(`${url} HTTP ${r.status}`); return r.text(); };
  const index = parseIndex(await get(MVT_INDEX_URL));
  if (index.length < 5) throw new Error('mvt-indicators index looks wrong');
  const groups = [], used = [], skipped = [];
  for (const e of index) {
    const allow = ALLOWED_OWNERS[e.owner];
    if (!allow) { skipped.push(`${e.owner}/${e.repo}`); continue; }
    try {
      const hosts = stixHosts(JSON.parse(await get(`https://raw.githubusercontent.com/${e.owner}/${e.repo}/${e.branch}/${e.path}`)));
      if (!hosts.length) continue;
      groups.push({ kind: e.owner === 'AssoEchap' ? 'stalkerware' : 'spyware', hosts });
      used.push({ name: e.name, by: allow.credit, license: allow.license, count: hosts.length });
    } catch { /* one missing file never sinks the list */ }
  }
  try {
    const hosts = (await get(ZERO_BREACH_URL)).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
    if (hosts.length) { groups.push({ kind: 'spyware', hosts }); used.push({ name: 'AdFection / Candiru web addresses', by: 'Zero Breach Toolkit (archivegenocide.com)', license: 'CC0 1.0', count: hosts.length }); }
  } catch { /* optional */ }
  const packed = packSpyware(groups);
  if (packed.spyware < 500 || packed.stalkerware < 200) throw new Error(`spyware list looks too small (${packed.spyware}/${packed.stalkerware})`);
  return { ...packed, sources: used, skipped: [...new Set(skipped)] };
}

/**
 * Current iPhone software versions, from Apple's public software-update catalog (gdmf.apple.com, the same list
 * Apple's device-management tools use). Apple serves it with its own root certificate, so we download Apple Root CA
 * from apple.com (normal, verified HTTPS) and trust only that for this one request. Returns e.g. ['18.7.11','26.7.2','27.2'].
 */
export async function fetchIosLines() {
  const https = await import('node:https');
  const der = Buffer.from(await (await fetch('https://www.apple.com/appleca/AppleIncRootCertificate.cer', { signal: AbortSignal.timeout(30000) })).arrayBuffer());
  const pem = `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
  const text = await new Promise((resolve, reject) => {
    const req = https.get('https://gdmf.apple.com/v2/pmv', { ca: pem, timeout: 30000 }, (res) => {
      if (res.statusCode !== 200) { reject(new Error(`gdmf HTTP ${res.statusCode}`)); res.resume(); return; }
      let s = ''; res.setEncoding('utf8'); res.on('data', (c) => { s += c; }); res.on('end', () => resolve(s));
    });
    req.on('error', reject); req.on('timeout', () => req.destroy(new Error('gdmf timeout')));
  });
  const sets = JSON.parse(text)?.PublicAssetSets?.iOS ?? [];
  const best = {};
  for (const s of sets) {
    const v = String(s.ProductVersion ?? ''); if (!/^\d+(\.\d+){0,2}$/.test(v)) continue;
    const major = v.split('.')[0];
    if (!best[major] || cmpVer(v, best[major]) > 0) best[major] = v;
  }
  const lines = Object.values(best).sort(cmpVer);
  if (!lines.length) throw new Error('no iOS versions');
  return lines;
}
export function cmpVer(a, b) {
  const x = String(a).split('.').map(Number), y = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; }
  return 0;
}
