/**
 * FTC Do Not Call complaints by phone number -> compact on-device lookup for Natarta's phone check.
 * Source: usacallerlookup/ftc-robocall-dataset (CC0 aggregation of public-domain FTC Do Not Call
 * complaint files joined to the NANPA prefix registry). Downloaded from GitHub once per feed run;
 * the app downloads the signed result and looks numbers up on the phone. Numbers are never sent anywhere.
 *
 * Packed format (all ASCII, no quotes, so it signs and escapes cheaply):
 *   carriers: "AT&T|Verizon|..."            places: "Phoenix, AZ|Ukiah, CA|..."
 *   p: ";"-joined entries, sorted by 6-digit prefix:  NPANXX,<place b36>,<carrier b36>,<records>
 *      (empty index = unknown in the public registry, normal for toll-free)
 *   record: 4-digit line number + 1 code letter (CODES[subject*2 + robocall?1:0]),
 *           then "(complaints.robocalls)" only when complaints > 1. One complaint = the letter says it all.
 * NANPA assigns carrier and rate center per 6-digit prefix (checked: no prefix has two), so they live on the entry.
 */
import zlib from 'node:zlib';

export const FTC_DATA_URL = 'https://raw.githubusercontent.com/usacallerlookup/ftc-robocall-dataset/main/data/ftc-complaints-by-number.csv.gz';
export const FTC_SUMMARY_URL = 'https://raw.githubusercontent.com/usacallerlookup/ftc-robocall-dataset/main/data/summary.json';
export const CODES = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; // 52 letters → up to 26 subjects
/** FTC subject category → short phrase used in "mostly robocalls about …". null = say nothing about the topic. */
export const SUBJECTS = [
  [/^other$|no subject/i, null],
  [/reducing your debt/i, 'about debt relief'],
  [/pretending to be government/i, 'from callers pretending to be the government, a business or family'],
  [/dropped call|no message/i, 'calls that hung up or left no message'],
  [/medical/i, 'about medical or prescription offers'],
  [/warrant/i, 'about warranties'],
  [/home improvement/i, 'about home improvement'],
  [/vacation|timeshare/i, 'about vacations or timeshares'],
  [/energy|solar|utilit/i, 'about energy or solar'],
  [/lotter|prize|sweepstake/i, 'about prizes or sweepstakes'],
  [/computer|technical support/i, 'about tech support'],
  [/home security|alarm/i, 'about home security'],
  [/work from home|make money/i, 'about work-from-home or money-making offers'],
  [/charit/i, 'asking for charity'],
  [/debt collection/i, 'about debt collection'],
];

export function parseCsv(text) {
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); f = ''; if (row.length > 1 || row[0]) rows.push(row); row = []; }
    else f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  return rows;
}

const ascii = (s) => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^\x20-\x7e]/g, '').replace(/[|;,]/g, ' ').replace(/\s+/g, ' ').trim();
const titleWord = (w) => (/^[^AEIOUY]+$/i.test(w) && w.length <= 4) || /^[A-Z]{2,}&[A-Z]+$/.test(w) || /^(ACS|AT&T|ITC|NTS|TDS)$/.test(w) ? w.toUpperCase() : /^\d/.test(w) ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
const BRANDS = [
  [/ONVOY|INTELIQUENT/, 'Onvoy'],
  [/CELLCO|VERIZON|MCIMETRO|\bMCI\b/, 'Verizon'],
  [/T-MOBILE|METROPCS|SPRINT|OMNIPOINT|POWERTEL|VOICESTREAM|AERIAL COMM/, 'T-Mobile'],
  [/CINGULAR|AT&T|TELEPORT COMMUNICATIONS AMERICA|BELLSOUTH|SOUTHWESTERN BELL|PACIFIC BELL|ILLINOIS BELL|MICHIGAN BELL|OHIO BELL|INDIANA BELL|WISCONSIN BELL|NEVADA BELL|SOUTHERN NEW ENGLAND TEL/, 'AT&T'],
  [/QWEST|CENTURYLINK|CENTURYTEL|EMBARQ|LEVEL 3/, 'CenturyLink'],
  [/COMCAST/, 'Comcast'],
  [/\bTWC\b|TIME WARNER|CHARTER|BRIGHT HOUSE|BRESNAN|SPECTRUM/, 'Spectrum'],
  [/CABLEVISION|SUDDENLINK|CEBRIDGE|ALTICE|CSC WIRELESS|CSC VOICE/, 'Optimum'],
  [/^COX |\bCOX COM/, 'Cox'],
  [/FRONTIER/, 'Frontier'],
  [/WINDSTREAM/, 'Windstream'],
  [/BANDWIDTH\.COM/, 'Bandwidth'],
  [/BOOST /, 'Boost Mobile'],
  [/UNITED STATES CELLULAR|US CELLULAR|USCOC/, 'UScellular'],
];
/** Carrier of record → short everyday name (Verizon, AT&T, …); otherwise a tidy version of the registry name. */
export function carrierName(raw) {
  const s = ascii(String(raw ?? '')).toUpperCase();
  if (!s) return '';
  for (const [re, name] of BRANDS) if (re.test(s)) return name;
  let n = s.includes(' DBA ') ? s.split(' DBA ').pop() : s;
  n = n.replace(/\[.*?\]/g, '').replace(/\s+-\s+[A-Z]{2}$|-[A-Z]{2}$/, '')
    .replace(/[,.]?\s*\b(L\.?L\.?C|INC|CORP(ORATION)?|CO|COMPANY|L\.?P|LTD|LLP)\b\.?/g, '').replace(/\s+OF\s+(NO\.?\s+)?[A-Z. ]+$/, '')
    .replace(/\s+(INTERNATIONAL|S\/I\/I.*)$/, '').replace(/[,.\s]+$/, '').trim();
  return n.split(' ').filter(Boolean).map(titleWord).join(' ');
}
export function placeName(city, state) {
  const c = ascii(String(city ?? '')), st = ascii(String(state ?? '')).toUpperCase();
  if (!c && !st) return '';
  const tc = c === c.toUpperCase() ? c.split(' ').map((w) => w.charAt(0) + w.slice(1).toLowerCase()).join(' ') : c;
  return st ? (tc ? `${tc}, ${st}` : st) : tc;
}
const subjectIndex = (s) => { const i = SUBJECTS.findIndex(([re]) => re.test(String(s ?? ''))); return i < 0 ? 0 : i; };

/** rows: array of objects with the dataset's column names. Returns the packed lookup (without signing). */
export function packFtc(rows) {
  const carriers = [], carrierIx = new Map(), places = [], placeIx = new Map();
  const ix = (v, list, map) => { if (!v) return ''; if (!map.has(v)) { map.set(v, list.length); list.push(v); } return map.get(v).toString(36); };
  const byPrefix = new Map();
  let numbers = 0, complaintsTotal = 0, lastSeen = '';
  for (const r of rows) {
    const d = String(r.phone ?? '').replace(/\D/g, '').replace(/^1(?=\d{10}$)/, '');
    const n = Math.max(0, parseInt(r.complaints, 10) || 0), robo = Math.min(n, Math.max(0, parseInt(r.robocalls, 10) || 0));
    if (d.length !== 10 || !/^[2-9]\d{2}[2-9]/.test(d) || n < 1) continue;
    const pre = d.slice(0, 6);
    let e = byPrefix.get(pre);
    if (!e) { e = { place: ix(placeName(r.rate_center_city, r.rate_center_state), places, placeIx), carrier: ix(carrierName(r.carrier), carriers, carrierIx), recs: new Map() }; byPrefix.set(pre, e); }
    const s = subjectIndex(r.top_subject);
    const code = CODES[s * 2 + (robo * 2 > n ? 1 : 0)];
    e.recs.set(d.slice(6), d.slice(6) + code + (n > 1 ? `(${n}.${robo})` : ''));
    numbers++; complaintsTotal += n; if ((r.last_complaint ?? '') > lastSeen) lastSeen = r.last_complaint;
  }
  const p = [...byPrefix.keys()].sort().map((k) => { const e = byPrefix.get(k); return `${k},${e.place},${e.carrier},${[...e.recs.keys()].sort().map((x) => e.recs.get(x)).join('')}`; }).join(';');
  return { subjects: SUBJECTS.map(([, t]) => t), carriers: carriers.join('|'), places: places.join('|'), p, numbers: byPrefix.size ? [...byPrefix.values()].reduce((a, e) => a + e.recs.size, 0) : 0, complaints: complaintsTotal, lastComplaint: lastSeen || null };
}

export function rowsFromCsv(text) {
  const [head, ...rest] = parseCsv(text);
  return rest.map((cells) => Object.fromEntries(head.map((h, i) => [h.trim(), cells[i] ?? ''])));
}

/** Downloads the dataset (one polite request each) and returns the packed lookup + coverage. Throws on a broken download. */
export async function fetchFtcPacked({ ua } = {}) {
  const headers = ua ? { 'User-Agent': ua } : {};
  const res = await fetch(FTC_DATA_URL, { headers, signal: AbortSignal.timeout(90000) });
  if (!res.ok) throw new Error(`FTC dataset HTTP ${res.status}`);
  const text = zlib.gunzipSync(Buffer.from(await res.arrayBuffer())).toString('utf8');
  let summary = null;
  try { const s = await fetch(FTC_SUMMARY_URL, { headers, signal: AbortSignal.timeout(30000) }); if (s.ok) summary = await s.json(); } catch { /* optional */ }
  const rows = rowsFromCsv(text);
  if (rows.length < 50000) throw new Error(`FTC dataset looks truncated (${rows.length} rows)`);
  const packed = packFtc(rows);
  return { ...packed, coverage: summary?.temporal_coverage ?? null, datasetGenerated: summary?.generated ?? null };
}
