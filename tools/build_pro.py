"""Build the paid version (pro/app.enc + pro/index.html) from the admin site (no secrets stored here).

  GATE_PW=<admin password> python3 tools/build_pro.py [--key-version N] [--print-key]

Steps: decrypt index.html with the admin password, remove the admin-only parts
(admin dashboard), add the subscription bar and the periodic license check, then encrypt
the result into pro/app.enc. pro/index.html is only the sign-in page: the license server
decrypts app.enc for a valid serial, so the key never reaches the browser.

The pro content key is derived from the admin password, so nothing secret is kept in
the repository. The same key must be stored in the Cloudflare Worker as CONTENT_KEY:
--print-key prints it (base64). Raise --key-version to make a new key (old copies stop
opening; then update CONTENT_KEY in the Worker too).
"""
import os, sys, gzip, json, base64, re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import gate  # noqa: E402

b = lambda x: base64.b64encode(x).decode()


def pro_key(pw, version):
    return PBKDF2HMAC(hashes.SHA256(), 32, f'candles-pro-content-v{version}'.encode(), 210000).derive(pw.encode())


def cut_div(html, div_id):
    """Remove <div ... id="div_id"> ... </div> (nested divs counted)."""
    m = re.search(r'<div[^>]*\bid="%s"[^>]*>' % re.escape(div_id), html)
    if not m:
        return html, False
    i, depth = m.end(), 1
    tag = re.compile(r'<(/?)div\b[^>]*>', re.I)
    while depth:
        t = tag.search(html, i)
        if not t:
            raise SystemExit(f'unbalanced div #{div_id}')
        depth += -1 if t.group(1) else 1
        i = t.end()
    return html[:m.start()] + html[i:], True


def cut_script(html, marker):
    """Remove the <script> block whose body starts with marker."""
    i = html.find(marker)
    if i < 0:
        return html, False
    s = html.rfind('<script', 0, i)
    e = html.index('</script>', i) + len('</script>')
    return html[:s] + html[e:], True


def transform(src):
    out = src
    for div in ('gateWrap', 'proAdminWrap'):
        out, _ = cut_div(out, div)
    for marker in ('/* access gate:', '/* admin dashboard:'):
        out, _ = cut_script(out, marker)
    if 'gateWrap' in out or "gate_role" in out:
        raise SystemExit('admin parts still present – check the markers in build_pro.py')
    out = re.sub(r'<title>[^<]*</title>', '<title>קורא נרות פרו – ניתוח טכני ושווקים</title>', out, count=1)
    a11y = ('<style>:focus-visible{outline:3px solid #ffb000!important;outline-offset:2px}'
            '@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important;scroll-behavior:auto!important}}</style>')
    h = out.find('</head>')
    out = out[:h] + a11y + out[h:]
    client = open(os.path.join(HERE, 'pro_client.js'), encoding='utf-8').read()
    j = out.rfind('</body>')
    out = out[:j] + '<script>\n' + client + '\n</script>\n' + out[j:]
    return out


def main():
    pw = os.environ.get('GATE_PW') or sys.exit('set GATE_PW')
    ver = 1
    if '--key-version' in sys.argv:
        ver = int(sys.argv[sys.argv.index('--key-version') + 1])
    K = pro_key(pw, ver)
    if '--print-key' in sys.argv:
        print(b(K))
        return
    page = os.path.join(ROOT, 'index.html')
    k, D = gate.key_from(page, pw)
    src = gzip.decompress(AESGCM(k).decrypt(base64.b64decode(D['iv']), base64.b64decode(D['ct']), None)).decode('utf-8')
    html = transform(src)
    iv = os.urandom(12)
    ct = AESGCM(K).encrypt(iv, gzip.compress(html.encode('utf-8'), 9), None)
    # the encrypted app goes to pro/app.enc; only the license server holds its key and hands out the app
    # binary (12-byte IV + ciphertext): the server reads it without base64 work, well inside the free plan's CPU limit
    open(os.path.join(ROOT, 'pro', 'app.bin'), 'wb').write(iv + ct)
    old = os.path.join(ROOT, 'pro', 'app.enc')
    if os.path.exists(old):
        os.remove(old)
    cfg = json.load(open(os.path.join(ROOT, 'pro', 'config.json'), encoding='utf-8'))
    data = json.dumps({'v': 2, 'cfg': cfg}, separators=(',', ':'), ensure_ascii=False)
    tpl = open(os.path.join(HERE, 'pro_gate_template.html'), encoding='utf-8').read()
    open(os.path.join(ROOT, 'pro', 'index.html'), 'w', encoding='utf-8').write(tpl.replace('__GATE_DATA__', data))
    mv = re.search(r'<meta name="app-version" content="([^"]+)"(?: data-date="([^"]*)")?', src)
    if mv:
        vj = json.dumps({'v': mv.group(1), 'date': mv.group(2) or ''}, ensure_ascii=False)
        for d in (ROOT, os.path.join(ROOT, 'pro')):
            open(os.path.join(d, 'version.json'), 'w', encoding='utf-8').write(vj + '\n')
    print('built pro/index.html', 'version', mv.group(1) if mv else '?', f'(key v{ver}, {len(html)//1024} KB app)')


if __name__ == '__main__':
    main()
