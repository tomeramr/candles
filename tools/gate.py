"""Encrypted login gate for קורא נרות (no secrets stored here).

  GATE_PW=<admin password> python3 tools/gate.py extract index.html source.html
      decrypt the deployed page back to the plain app (needs the admin password)
  GATE_PW=<admin password> python3 tools/gate.py build source.html index.html [--rotate]
      encrypt the app into index.html. Reuses the content key of the current index.html
      (so remembered logins and share links keep working); --rotate makes a new key,
      which cancels every share link and remembered login.
"""
import os,sys,gzip,json,base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
IT=210000;ADMIN='tomer'
HERE=os.path.dirname(os.path.abspath(__file__))
b=lambda x:base64.b64encode(x).decode();d=base64.b64decode
def kek(u,pw,salt,it=IT):return PBKDF2HMAC(hashes.SHA256(),32,salt,it).derive((u.lower()+'\n'+pw).encode())
def read_data(page):
    s=open(page,encoding='utf-8').read();a=s.index('<script id="gd" type="application/json">')+len('<script id="gd" type="application/json">');return json.loads(s[a:s.index('</script>',a)])
def key_from(page,pw):
    D=read_data(page)
    for sl in D['slots']:
        try:return AESGCM(kek(sl['u'],pw,d(sl['s']),D['it'])).decrypt(d(sl['i']),d(sl['w']),(sl.get('a') or '').encode()),D
        except Exception:pass
    raise SystemExit('wrong admin password')
def extract(page,out):
    K,D=key_from(page,os.environ['GATE_PW']);open(out,'wb').write(gzip.decompress(AESGCM(K).decrypt(d(D['iv']),d(D['ct']),None)));print('extracted',out)
def build(src,out,rotate=False):
    pw=os.environ['GATE_PW']
    K=os.urandom(32) if rotate or not os.path.exists(out) or '"slots"' not in open(out,encoding='utf-8').read() else key_from(out,pw)[0]
    iv=os.urandom(12);ct=AESGCM(K).encrypt(iv,gzip.compress(open(src,'rb').read(),9),None)
    salt=os.urandom(16);i2=os.urandom(12)
    slots=[{'u':ADMIN,'role':'admin','a':'','s':b(salt),'i':b(i2),'w':b(AESGCM(kek(ADMIN,pw,salt)).encrypt(i2,K,b''))}]
    data=json.dumps({'v':1,'it':IT,'iv':b(iv),'ct':b(ct),'slots':slots},separators=(',',':'))
    tpl=open(os.path.join(HERE,'gate_template.html'),encoding='utf-8').read()
    open(out,'w',encoding='utf-8').write(tpl.replace('__GATE_DATA__',data));print('built',out,'(new key)' if rotate else '')
if __name__=='__main__':
    cmd=sys.argv[1]
    if cmd=='extract':extract(sys.argv[2],sys.argv[3])
    elif cmd=='build':build(sys.argv[2],sys.argv[3],'--rotate' in sys.argv)
