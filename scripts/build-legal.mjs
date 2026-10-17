// Local helper: builds pages/privacy.html and pages/terms.html from the app's in-app legal text (src/constants/legal.ts in the app repo). Run on the box only.
import { loadTs } from '/workspace/capit/sanctuary/scripts/ts-load.mjs';
import { writeFileSync } from 'node:fs';
const L = loadTs('src/constants/legal.ts', '/workspace/capit/sanctuary');
const esc = (t) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const link = (t) => esc(t).replace(/([a-z0-9.]+@[a-z0-9.]+\.[a-z]{2,})/gi, '<a href="mailto:$1">$1</a>');
const page = (slug, title, other, sections) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · Natarta</title>
<meta name="description" content="Natarta ${title}. Plain English: what you check stays on your phone. No accounts, no ads, no tracking.">
<meta name="color-scheme" content="light dark">
<link rel="canonical" href="https://sayyedsama.github.io/natarta-feed/${slug}.html">
<style>
:root{--bg:#F5F7FC;--panel:#FFFFFF;--text:#0B0F2A;--muted:#3B4268;--line:rgba(11,15,42,.12);--cyan:#0A6F8C;--gold:#8A5A00}
@media (prefers-color-scheme:dark){:root{--bg:#0B0F2A;--panel:#121737;--text:#FFFFFF;--muted:#B6BEDA;--line:rgba(255,255,255,.10);--cyan:#3DD6F5;--gold:#F5B942}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:400 1.0625rem/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:44rem;margin:0 auto;padding:2rem 1.25rem 4rem}
header{display:flex;align-items:center;gap:.75rem;margin-bottom:1.5rem}
header .brand{font-weight:800;font-size:1.25rem;letter-spacing:.01em}
.bar{height:4px;border-radius:2px;background:linear-gradient(90deg,var(--cyan),var(--gold));margin:0 0 2rem}
h1{font-size:2rem;line-height:1.2;margin:0 0 .25rem}
.updated{color:var(--muted);margin:0 0 2rem}
section{background:var(--panel);border:1px solid var(--line);border-radius:1rem;padding:1.25rem 1.25rem .5rem;margin:0 0 1rem}
h2{font-size:1.2rem;margin:0 0 .5rem}
p{margin:0 0 .9rem}
a{color:var(--cyan);text-underline-offset:.15em}
a:focus-visible{outline:3px solid var(--gold);outline-offset:2px;border-radius:4px}
nav.foot{margin-top:2rem;display:flex;gap:1.5rem;flex-wrap:wrap;color:var(--muted)}
nav.foot a{display:inline-block;min-height:44px;line-height:44px}
.note{color:var(--muted);font-size:.95rem}
</style>
</head>
<body>
<main class="wrap">
<header aria-label="Natarta">
<svg width="40" height="40" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
  
  <g transform="translate(0 30.72) scale(10.24)">
  <defs>
    <linearGradient id="ms" x1="20" y1="0" x2="80" y2="0" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#3DD6F5"/><stop offset="0.35" stop-color="#3DD6F5"/><stop offset="0.85" stop-color="#F5B942"/><stop offset="1" stop-color="#F5B942"/>
    </linearGradient>
    <radialGradient id="mf" cx="50" cy="66.5" r="11" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#FFFFFF"/><stop offset="0.3" stop-color="#FFE7A3"/><stop offset="0.62" stop-color="#F5B942"/><stop offset="1" stop-color="#3DD6F5" stop-opacity="0.85"/>
    </radialGradient>
    <filter id="mg" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="3.2"/></filter>
    <filter id="mg2" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="4"/></filter>
  </defs>
  <path d="M69 14 L72 14 Q80 14 80 22 L80 58 Q80 66 73.5 71.5 L56 85.5 Q50 90 44 85.5 L26.5 71.5 Q20 66 20 58 L20 24 C20 13.5 30.5 12 36.5 18.5 L76.5 56.5" fill="none" stroke="url(#ms)" stroke-width="6" stroke-linecap="round" stroke-linejoin="round" opacity="0.65" filter="url(#mg)"/>
  <path d="M50 46 C53 52 58.5 57 58.5 64.5 A8.5 8.5 0 0 1 41.5 64.5 C41.5 57 47 52 50 46 Z" fill="#F5B942" opacity="0.7" filter="url(#mg2)"/>
  <path d="M69 14 L72 14 Q80 14 80 22 L80 58 Q80 66 73.5 71.5 L56 85.5 Q50 90 44 85.5 L26.5 71.5 Q20 66 20 58 L20 24 C20 13.5 30.5 12 36.5 18.5 L76.5 56.5" fill="none" stroke="url(#ms)" stroke-width="4.6" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M50 46 C53 52 58.5 57 58.5 64.5 A8.5 8.5 0 0 1 41.5 64.5 C41.5 57 47 52 50 46 Z" fill="url(#mf)"/>
  <ellipse cx="50" cy="66.5" rx="2.6" ry="3.8" fill="#FFFFFF" opacity="0.85"/></g>
</svg>
<span class="brand">Natarta</span>
</header>
<div class="bar" role="presentation"></div>
<h1>${title}</h1>
<p class="updated">Last updated ${L.LEGAL_UPDATED}</p>
${sections.map((s) => `<section aria-labelledby="${s.h.toLowerCase().replace(/[^a-z0-9]+/g, '-')}">
<h2 id="${s.h.toLowerCase().replace(/[^a-z0-9]+/g, '-')}">${esc(s.h)}</h2>
${s.p.map((p) => `<p>${link(p)}</p>`).join('\n')}
</section>`).join('\n')}
<nav class="foot" aria-label="More">
<a href="${other[0]}">${other[1]}</a>
<a href="mailto:${L.SUPPORT_EMAIL}">Contact</a>
</nav>
<p class="note">This is the same text you see in the app under About &amp; credits.</p>
</main>
</body>
</html>
`;
writeFileSync('pages/privacy.html', page('privacy', 'Privacy Policy', ['terms.html', 'Terms of Use'], L.PRIVACY));
writeFileSync('pages/terms.html', page('terms', 'Terms of Use', ['privacy.html', 'Privacy Policy'], L.TERMS));
console.log('ok');
