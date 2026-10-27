/**
 * Known crypto-phishing sites -> compact on-device lookup for Natarta's link and message checks.
 * Source: MetaMask/eth-phishing-detect (src/config.json, DBAD "Don't Be A Dick" public license: use it freely,
 * give credit, don't pass it off as your own). We keep only the blacklist host names, hash each one (same 64-bit
 * hash as the phishing rule pack) and ship the sorted hashes, so the app can check a site on the phone without
 * the phone ever sending the site anywhere. We also carry MetaMask's small "whitelist" of real hosts as a safety net:
 * a host on it can never be flagged by this list.
 * NOT used: ScamSniffer's scam-database (GPL-3.0, a copyleft licence we don't want to mix into the app).
 */
export const ETH_PHISHING_URL = 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json';

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
export const cleanHost = (h) => String(h).trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');

export function packCrypto(config) {
  const white = new Set((config.whitelist ?? []).map(cleanHost));
  const seen = new Set();
  let dropped = 0;
  for (const raw of config.blacklist ?? []) {
    const h = cleanHost(raw);
    if (!HOST_RE.test(h) || /^\d+(\.\d+){3}$/.test(h)) { dropped++; continue; }
    // never ship a host that MetaMask itself lists as real, or any parent of one
    if ([...white].some((w) => w === h || w.endsWith('.' + h))) { dropped++; continue; }
    seen.add(h);
  }
  const pairs = [...seen].map(h64).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const buf = Buffer.alloc(pairs.length * 8);
  pairs.forEach(([a, b], i) => { buf.writeUInt32LE(a, i * 8); buf.writeUInt32LE(b, i * 8 + 4); });
  return { count: pairs.length, dropped, whitelist: [...white].sort(), hashesB64: buf.toString('base64'), version: config.version ?? null };
}

export async function fetchCryptoPacked({ ua } = {}) {
  const res = await fetch(ETH_PHISHING_URL, { headers: ua ? { 'User-Agent': ua } : {}, signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`eth-phishing-detect HTTP ${res.status}`);
  const config = await res.json();
  if (!Array.isArray(config.blacklist) || config.blacklist.length < 1000) throw new Error('eth-phishing-detect list looks wrong');
  return packCrypto(config);
}
