"""Security hardening for every page on the site.

GitHub Pages cannot send HTTP security headers, so this puts the equivalent
<meta> tags right after <meta charset> in each .html file:

  * Content-Security-Policy, with a sha256 hash for each inline <script>, so
    only the scripts already on the page (and same-origin files) can run.
  * Referrer-Policy.
  * robots "noai, noimageai" (the 404 page also keeps noindex).

Safe to re-run: it strips the block it inserted last time and recomputes the
hashes, so after editing any inline script run

    python3 scripts/harden.py .

The "Keep security tags current" workflow also runs it on every push to main.
"""
import re, sys, hashlib, base64, pathlib

root = pathlib.Path(sys.argv[1])
MARK_RE = re.compile(r'\n?[ \t]*<!-- hardening -->.*?<!-- /hardening -->', re.S)

COMMON = ["object-src 'none'", "base-uri 'self'", "form-action 'self'", "frame-src 'none'",
          "manifest-src 'self'", "upgrade-insecure-requests"]

def csp(hashes, dcc):
    s = "'self' " + " ".join(f"'sha256-{h}'" for h in hashes)
    if dcc:  # PixiJS compiles uniform/shader sync code with new Function()
        d = ["default-src 'self'", f"script-src {s} 'unsafe-eval'", "style-src 'self' 'unsafe-inline'",
             "font-src 'self' data:", "img-src 'self' data: blob:", "connect-src 'self' data: blob:",
             "media-src 'self' data: blob:", "worker-src 'self' blob:"]
    else:
        d = ["default-src 'self'", f"script-src {s}", "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
             "font-src 'self' https://fonts.gstatic.com", "img-src 'self' data: blob:", "connect-src 'self'",
             "media-src 'self'", "worker-src 'self' blob:"]
    return "; ".join(d + COMMON)

def inline_hashes(html):
    out = []
    for m in re.finditer(r'<script(?![^>]*\bsrc=)([^>]*)>(.*?)</script>', html, re.S):
        if 'application/json' in m.group(1) or 'application/ld+json' in m.group(1):
            continue
        h = base64.b64encode(hashlib.sha256(m.group(2).encode('utf-8')).digest()).decode()
        if h not in out:
            out.append(h)
    return out

pages = [p for p in root.rglob('*.html') if '.git' not in p.parts]
for p in sorted(pages):
    html = MARK_RE.sub('', p.read_text(encoding='utf-8'))
    rel = p.relative_to(root).as_posix()
    dcc = rel.startswith('dcc-guide/')
    is404 = rel == '404.html'
    m = re.search(r'<meta charset="[^"]*"\s*/?>', html, re.I)
    assert m, rel
    indent = re.match(r'[ \t]*', html[html.rfind('\n', 0, m.start()) + 1:]).group(0)
    if is404:
        html = re.sub(r'<meta name="robots" content="noindex[^"]*" />',
                      '<meta name="robots" content="noindex, noai, noimageai" />', html)
    robots = '' if is404 else f'\n{indent}<meta name="robots" content="noai, noimageai">'
    block = (f'\n{indent}<!-- hardening -->'
             f'\n{indent}<meta http-equiv="Content-Security-Policy" content="{csp(inline_hashes(html), dcc)}">'
             f'\n{indent}<meta name="referrer" content="strict-origin-when-cross-origin">'
             f'{robots}\n{indent}<!-- /hardening -->')
    html = html[:m.end()] + block + html[m.end():]
    p.write_text(html, encoding='utf-8')
    print(rel, len(inline_hashes(html)), 'hash(es)')
