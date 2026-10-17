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
<svg width="36" height="36" viewBox="0 0 100 100" aria-hidden="true"><defs><linearGradient id="g" x1="20" x2="80"><stop offset="0" stop-color="#3DD6F5"/><stop offset="1" stop-color="#F5B942"/></linearGradient></defs><path d="M28 18v52l22 16 22-16V18" fill="none" stroke="url(#g)" stroke-width="8" stroke-linejoin="round" stroke-linecap="round"/><path d="M28 18l44 40" stroke="url(#g)" stroke-width="8" stroke-linecap="round"/></svg>
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
