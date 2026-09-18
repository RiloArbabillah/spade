"""Fixture target lokal untuk test spade.

Semua test berjalan tanpa jaringan eksternal: `vuln_server` menyediakan
mini-aplikasi rentan di 127.0.0.1 dengan port acak, sehingga hasil modul bisa
dibandingkan secara deterministik sebelum/sesudah perubahan.
"""

import base64
import hashlib
import hmac
import html as htmlmod
import json
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import spade  # noqa: E402


def _b64(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")


JWT_ALG_NONE = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64({'sub': '1'})}."

ROOT_HTML = """<!DOCTYPE html>
<html><head><title>Fixture</title></head>
<body>
<a href="/admin/">Admin</a>
<a href="/uploads/">Uploads</a>
<a href="/search">Search</a>
<script src="/static/app.js"></script>
<script>const stripeSecret = "sk_test_RESPONSE_SECRET_0123456789";</script>
<form method="GET" action="/item">
  <input type="text" name="id">
  <button type="submit">Cari</button>
</form>
<form method="POST" action="/submit">
  <input type="text" name="comment">
  <input type="password" name="password">
  <input type="url" name="url">
  <input type="file" name="xml_file">
  <button type="submit">Kirim</button>
</form>
{echo}
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.18.0"
    sys_version = ""
    _body_cache = None

    # ── helpers ──
    def _record(self):
        self.server.app.record(self.command, self.path, dict(self.headers))

    def _send(self, status, body="", ctype="text/html; charset=utf-8", extra=None):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or []):
            # Nilai header HTTP wajib latin-1; payload uji unicode (mis. `%E5%98%8A`)
            # tidak boleh mematikan thread fixture sebelum respons terkirim.
            text = value if isinstance(value, str) else str(value)
            self.send_header(key, text.encode("latin-1", "replace").decode("latin-1"))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _query(self):
        return parse_qs(urlparse(self.path).query, keep_blank_values=True)

    def handle_one_request(self):
        # Satu instance handler melayani beberapa request pada koneksi keep-alive,
        # jadi cache body harus dimulai ulang tiap request.
        self._body_cache = None
        return BaseHTTPRequestHandler.handle_one_request(self)

    def _body(self):
        # Body dibaca sekali lalu di-cache. Sisa body yang tidak dibaca server asli
        # (mis. POST ke endpoint yang tidak memakai body) akan terbaca sebagai request
        # line berikutnya pada koneksi keep-alive dan menghasilkan 501 palsu.
        if self._body_cache is None:
            length = int(self.headers.get("Content-Length") or 0)
            self._body_cache = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        return self._body_cache

    # ── routing ──
    def _handle(self):
        self._record()
        self._body()
        app = self.server.app
        parsed = urlparse(self.path)
        path = parsed.path
        query = self._query()

        if app.rate_limit_after and path == "/":
            app.hits["/"] += 1
            if app.hits["/"] > app.rate_limit_after:
                return self._send(429, "Too Many Requests", "text/plain")

        if path == "/":
            return self._root(query)
        if path == "/search":
            return self._send(200, f"<html><body>Hasil: {query.get('q', [''])[0]}</body></html>")
        if path == "/item":
            return self._item(query)
        if path == "/sqli/postgres" and "'" in query.get("id", [""])[0]:
            return self._send(500, 'ERROR:  syntax error at or near "spade"')
        if path == "/sqli/mssql" and "'" in query.get("id", [""])[0]:
            return self._send(500, "Microsoft OLE DB Provider: Unclosed quotation mark after the character string")
        if path == "/sqli/sqlite" and "'" in query.get("id", [""])[0]:
            return self._send(500, 'SQLite3::query(): unrecognized token: 1: near "spade": syntax error')
        if path == "/sqli/oracle" and "'" in query.get("id", [""])[0]:
            return self._send(500, "ORA-01756: quoted string not properly terminated")
        if path == "/sqli/boolean":
            value = query.get("id", [""])[0]
            if value == "1":
                return self._send(200, "RESULT")
            if "AND 1=1" in value:
                return self._send(200, "RESULT " + ("DATA" * 80))
            if "AND 1=2" in value:
                return self._send(200, "RESULT")
        if path == "/sqli/time":
            value = query.get("id", [""])[0]
            if "SLEEP" in value.upper():
                time.sleep(0.05)
        if path == "/submit":
            submitted = parse_qs(self._body(), keep_blank_values=True)
            fetched = submitted.get("url", [""])[0]
            if fetched.startswith("http://spade-ssrf.invalid/"):
                return self._send(200, "SSRF fetched control " + ("B" * 600), "text/plain")
            return self._send(200, f"<html><body>Komentar: {self._body()}</body></html>")
        if path == "/.env":
            return self._send(200, "APP_NAME=spade\nDB_PASSWORD=fixture-secret\nDB_TOKEN=DB_RESPONSE_SECRET_9876543210\n", "text/plain")
        if path == "/admin/":
            return self._send(200, "<html><body><h1>Admin Login</h1><form><input name='username'><input type='password' name='password'></form></body></html>")
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", "text/plain")
        if path == "/uploads/":
            return self._send(200, "<html><body><h1>Index of /uploads</h1><a href='../'>Parent Directory</a></body></html>")
        if path == "/static/app.js":
            return self._send(200, 'const apiKey = "AKIA1234567890ABCDEF";\nfetch("/api/v1/users");\n',
                              "application/javascript")
        if path == "/xss/safe":
            return self._send(200, f"<p>{htmlmod.escape(query.get('comment', [''])[0])}</p>")
        if path == "/xss/attribute":
            return self._send(200, f"<input value='{query.get('input', [''])[0]}'>")
        if path == "/xss/html":
            return self._send(200, f"<div>{query.get('input', [''])[0]}</div>")
        if path == "/lfi/safe":
            return self._send(200, "normal page " + ("LFI " * 100), "text/plain")
        if path == "/lfi/windows":
            return self._send(200, "; for 16-bit app support\n[fonts]\n[extensions]\n", "text/plain")
        if path == "/lfi/environ":
            return self._send(200, "PATH=/usr/local/bin\x00LANG=C.UTF-8\x00PWD=/\x00", "text/plain")
        if path == "/lfi/php":
            passwd = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            return self._send(200, base64.b64encode(passwd).decode(), "text/plain")
        if path == "/proxy":
            fetched = query.get("url", [""])[0]
            if "169.254.169.254/latest/meta-data" in fetched:
                return self._send(200, "ami-id\ninstance-id\nreservation-id\n", "text/plain")
            return self._send(200, "generic proxy response " + ("A" * 1200), "text/plain")
        if path == "/graphql":
            return self._graphql(query)
        if path == "/flaky":
            return self._flaky()
        if path == "/cookies/set":
            return self._send(200, "set", "text/plain", extra=[("Set-Cookie", f"sid={JWT_ALG_NONE}; Path=/")])
        return self._send(404, "not found", "text/plain")

    def _flaky(self):
        """503 pada percobaan pertama, 200 setelahnya — untuk menguji retry status."""
        self.server.app.hits["/flaky"] += 1
        if self.server.app.hits["/flaky"] > 1:
            return self._send(200, "ok", "text/plain")
        return self._send(503, "busy", "text/plain", extra=[("Retry-After", "0")])

    def _root(self, query):
        nxt = query.get("next", [""])[0]
        if nxt.startswith("http") and "evil.com" in nxt:
            return self._send(302, "", "text/plain", extra=[("Location", nxt)])
        # Parameter 'q' sengaja TIDAK dipantulkan supaya probe echo-endpoint
        # (yang memakai q) tidak menonaktifkan modul injection.
        echoed = " ".join(v for k, vs in query.items() if k != "q" for v in vs)
        extra = [("Set-Cookie", f"sid={JWT_ALG_NONE}; Path=/")]
        if self.headers.get("Origin"):
            extra.append(("Access-Control-Allow-Origin", "*"))
            extra.append(("Access-Control-Allow-Credentials", "true"))
        return self._send(200, ROOT_HTML.format(echo=echoed), extra=extra)

    def _item(self, query):
        value = query.get("id", [""])[0]
        if "'" in value or '"' in value:
            return self._send(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", "text/plain")
        return self._send(200, "<html><body>item ok</body></html>")

    def _graphql(self, query):
        raw = query.get("query", [""])[0]
        if not raw:
            raw = self._body()
        if "__schema" in raw:
            return self._send(200, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}),
                              "application/json")
        return self._send(200, json.dumps({"data": None}), "application/json")

    # ── HTTP methods ──
    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_HEAD(self): self._handle()

    def do_OPTIONS(self):
        self._record()
        self._send(200, "", "text/plain", extra=[("Allow", "GET, POST, PUT, DELETE, OPTIONS")])

    def do_TRACE(self):
        self._record()
        if urlparse(self.path).path == "/flaky":
            return self._flaky()
        self._send(200, "TRACE / HTTP/1.1", "message/http")

    def do_PUT(self):
        self._record()
        if urlparse(self.path).path == "/flaky":
            return self._flaky()
        self._send(405, "method not allowed", "text/plain")

    def do_DELETE(self):
        self._record()
        self._send(405, "method not allowed", "text/plain")

    def log_message(self, *args):
        pass


class FixtureApp:
    """State aplikasi fixture: catat request masuk & atur kebijakan rate limit."""

    def __init__(self, rate_limit_after=None):
        self.requests = []
        self.hits = defaultdict(int)
        self.rate_limit_after = rate_limit_after
        self._lock = threading.Lock()

    def record(self, method, path, headers):
        with self._lock:
            # `t` (monotonic) dipakai test penjadwal request untuk mengukur jarak antar request.
            self.requests.append({"method": method, "path": path, "headers": headers,
                                  "t": time.monotonic()})

    def paths(self):
        return [r["path"] for r in self.requests]

    def headers_for(self, path):
        """Header request pertama ke `path`, dengan nama header dinormalisasi lowercase.

        curl_cffi mengirim nama header dengan huruf besar-kecil yang berbeda antar
        profil (Chrome: `Sec-Fetch-Mode`, Safari: `sec-fetch-mode`), jadi lookup
        di test harus case-insensitive.
        """
        for req in self.requests:
            if urlparse(req["path"]).path == path:
                return {k.lower(): v for k, v in req["headers"].items()}
        return {}

    def last_headers_for(self, path):
        for req in reversed(self.requests):
            if urlparse(req["path"]).path == path:
                return {k.lower(): v for k, v in req["headers"].items()}
        return {}

    def times(self, path=None):
        """Waktu (monotonic) tiap request, opsional difilter per path."""
        return [r["t"] for r in self.requests
                if path is None or urlparse(r["path"]).path == path]


class FixtureServer:
    def __init__(self, rate_limit_after=None, handler=None):
        self.app = FixtureApp(rate_limit_after=rate_limit_after)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler or _Handler)
        self.httpd.app = self.app
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def base_url(self):
        host, port = self.httpd.server_address[0], self.httpd.server_address[1]
        return f"http://{host}:{port}/"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class _CmdEchoHandler(_Handler):
    def _handle(self):
        if urlparse(self.path).path == "/ping":
            payload = parse_qs(urlparse(self.path).query).get("cmd", [""])[0]
            if "echo spade-cmd-" in payload:
                token = payload.split("spade-cmd-", 1)[1].split(" ", 1)[0]
                return self._send(200, "output SPADE-CMD-" + token)
        return super()._handle()


class _CmdTimingHandler(_Handler):
    def _handle(self):
        if urlparse(self.path).path == "/ping":
            payload = parse_qs(urlparse(self.path).query).get("cmd", [""])[0]
            if "SLEEP" in payload.upper():
                time.sleep(0.05)
        return super()._handle()


class _XXEHandler(_Handler):
    def _handle(self):
        if urlparse(self.path).path == "/api/xml" and "file:///etc/passwd" in self._body():
            passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            return self._send(200, passwd)
        return super()._handle()

class _RetryAfterHandler(_Handler):
    """429 + `Retry-After: 1` pada request pertama ke `/`, 200 setelahnya.

    Dipakai test cooldown global: target yang membalas 429 harus menahan SEMUA
    worker, bukan hanya thread yang menerima respons itu.
    """

    def _handle(self):
        if urlparse(self.path).path == "/":
            self.server.app.hits["/retry-after"] += 1
            if self.server.app.hits["/retry-after"] == 1:
                self._record()
                self._body()
                return self._send(429, "too many requests", "text/plain",
                                  extra=[("Retry-After", "1")])
        return super()._handle()


@pytest.fixture
def vuln_server():
    server = FixtureServer().start()
    yield server
    server.stop()


@pytest.fixture
def rate_limited_server():
    server = FixtureServer(rate_limit_after=5).start()
    yield server
    server.stop()


@pytest.fixture
def cmd_echo_server():
    server = FixtureServer(handler=_CmdEchoHandler).start()
    yield server
    server.stop()


@pytest.fixture
def cmd_timing_server():
    server = FixtureServer(handler=_CmdTimingHandler).start()
    yield server
    server.stop()


@pytest.fixture
def xxe_server():
    server = FixtureServer(handler=_XXEHandler).start()
    yield server
    server.stop()

@pytest.fixture
def retry_after_server():
    server = FixtureServer(handler=_RetryAfterHandler).start()
    yield server
    server.stop()


@pytest.fixture
def sess(vuln_server):
    """Session scanner standar menuju fixture (paralel 1 worker agar deterministik)."""
    spade.set_request_executor(1)
    session = spade.ThreadLocalSession(timeout=10, verify_ssl=True)
    yield session
    spade.set_request_executor(1)


# ══════════════════════════════════════════════════════════════════
# Fixture lanjutan: sesi autentikasi, IDOR, CSRF, JWT, auth bypass,
# cache, CRLF, OOB, dan server desync (raw socket).
#
# Rute-rute di bawah sengaja TIDAK ditautkan dari ROOT_HTML supaya test
# regresi lama (crawl, form, XSS/SQLi) tidak berubah.
# ══════════════════════════════════════════════════════════════════

JWT_SECRET = "secret"
PUBLIC_KEY_PEM = ("-----BEGIN PUBLIC KEY-----\n"
                  "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AspadeFixtureKeyNotReal==\n"
                  "-----END PUBLIC KEY-----\n")
PRIVATE_BODY = "<html><body>SECRET-PRIVATE-BODY spade</body></html>"


def jwt_hs256(payload, secret=JWT_SECRET, header=None):
    head = {"alg": "HS256", "typ": "JWT"} if header is None else header
    return spade.jwt_sign(head, payload, secret)


OPENAPI_DOC = {
    "openapi": "3.0.0",
    "paths": {
        "/search": {"get": {"parameters": [{"name": "debug", "in": "query"}]}},
        "/admin/area": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {"role": {"type": "string"}}}}}}}},
    },
}

CSRF_FORM_HTML = """<html><body>
<form method="POST" action="/form/csrf-submit">
  <input type="hidden" name="csrf_token" value="fixture-token">
  <input type="text" name="comment">
  <button type="submit">Kirim</button>
</form>
</body></html>"""

NO_CSRF_FORM_HTML = """<html><body>
<form method="POST" action="/form/no-csrf-submit">
  <input type="text" name="comment">
  <button type="submit">Kirim</button>
</form>
</body></html>"""

# Halaman utama fixture JWT: hanya menautkan endpoint token supaya crawler mengisi
# `crawler.pages` dengan orakel JWT (urutan tautan = urutan BFS).
JWT_ROOT_HTML = """<!DOCTYPE html>
<html><head><title>Fixture JWT</title></head>
<body>
<a href="/jwt/expired">Sesi lama</a>
<a href="/jwt/rs256-protected">Panel admin</a>
<a href="/jwt/kid-protected">Kunci</a>
<a href="/jwt/protected">Profil</a>
{echo}
</body></html>"""

ADMIN_BODY = "<html><body>ADMIN AREA PANEL spade</body></html>"

# Halaman utama fixture lanjutan: tautan eksplisit supaya crawler menemukan objek
# ber-ID, form CSRF, halaman privat, dan area admin.
AUTH_ROOT_HTML = ROOT_HTML.replace(
    '<a href="/search">Search</a>',
    '<a href="/search">Search</a>\n'
    '<a href="/objects/1">Objek 1</a>\n'
    '<a href="/form/csrf">Form CSRF</a>\n'
    '<a href="/form/no-csrf">Form tanpa token</a>\n'
    '<a href="/private">Privat</a>\n'
    '<a href="/admin/area">Area admin</a>')


class _AuthHandler(_Handler):
    """Fixture dengan rute autentikasi/otorisasi untuk modul kelas lanjutan."""

    # Halaman utama versi handler ini: tautan tambahan + pantulan X-Forwarded-Host.
    root_html = AUTH_ROOT_HTML

    def _root(self, query):
        nxt = query.get("next", [""])[0]
        if nxt.startswith("http") and "evil.com" in nxt:
            return self._send(302, "", "text/plain", extra=[("Location", nxt)])
        parts = [value for key, values in query.items() if key != "q" for value in values]
        # Aplikasi membangun URL aset absolut dari host request. Canary dari scanner
        # ("spade-<hex>.invalid") sengaja dianggap host penyerang.
        candidates = [self.headers.get(name) for name in
                      ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "Host", "Forwarded")]
        host = next((value for value in candidates if value and "spade-" in value), None)
        extra = [("Set-Cookie", f"sid={JWT_ALG_NONE}; Path=/")]
        if host:
            # Aplikasi memakai host penyerang untuk URL aset absolutnya.
            parts.append(host)
            extra.append(("X-Cache", "HIT"))
        if self.headers.get("Origin"):
            extra.append(("Access-Control-Allow-Origin", "*"))
            extra.append(("Access-Control-Allow-Credentials", "true"))
        return self._send(200, self.root_html.format(echo=" ".join(parts)), extra=extra)

    # ── helpers ──
    def _is_authed(self):
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            # Token bearer eksplisit diperiksa lebih dulu dan cookie sesi diabaikan,
            # seperti aplikasi nyata yang memercayai header Authorization di atas cookie.
            # Inilah yang membuat uji token palsu di modul JWT tidak lolos karena cookie.
            return self._verify_hs256(auth[7:].strip())
        if self.headers.get("X-Spade-Auth") == "1":
            return True
        cookie = self.headers.get("Cookie") or ""
        for chunk in cookie.split(";"):
            name, _, value = chunk.strip().partition("=")
            if name.strip().lower() in ("sid", "session") and value.strip() in ("spade-auth", "ok"):
                return True
        return False

    def _bearer_token(self):
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        cookie = self.headers.get("Cookie") or ""
        for chunk in cookie.split(";"):
            name, _, value = chunk.strip().partition("=")
            if name.strip().lower() in ("jwt", "token"):
                return value.strip()
        return ""

    def _verify_hs256(self, token, key=JWT_SECRET, require_exp=False, alg="HS256", mac="HS256"):
        """Verifier naif ala aplikasi rentan: pilih algoritma dari klaim `alg`.

        `mac` memisahkan algoritma HMAC yang benar-benar dipakai dari klaim `alg`,
        supaya fixture bisa meniru alg confusion (klaim RS256, HMAC HS256).
        """
        parts = spade.jwt_parts(token)
        if parts is None:
            return False
        header, payload, signature, raw = parts
        alg_claim = str(header.get("alg") or "")
        if alg_claim != alg:
            return False
        digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[mac]
        expected = spade.b64url_decode(signature)
        if expected is None:
            return False
        signing_input = raw.rsplit(".", 1)[0].encode()
        raw_key = key if isinstance(key, bytes) else str(key).encode()
        if not hmac.compare_digest(hmac.new(raw_key, signing_input, digest).digest(), expected):
            return False
        if require_exp:
            exp = payload.get("exp")
            if isinstance(exp, (int, float)) and exp < time.time():
                return False
        return True

    def _fetch_callback(self, url):
        """Tirukan server yang menuruti URL penyerang (blind SSRF/XXE/CMDi)."""
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return False
        try:
            urllib.request.urlopen(url, timeout=3).read()
            return True
        except Exception:
            return False

    # ── rute baru ──
    def _handle(self):
        self._body()
        parsed = urlparse(self.path)
        path = parsed.path
        query = self._query()

        if path == "/search":
            self._record()
            if "debug" in query:
                return self._send(200, "<html><body>" + ("debug panel " * 60) + "</body></html>")
            return self._send(200, f"<html><body>Hasil: {query.get('q', [''])[0]}</body></html>")
        if path.startswith("/objects/"):
            self._record()
            ident = path.rsplit("/", 1)[-1]
            # Objek id=1 milik tester; id=2 bocor ke anonim (IDOR klasik).
            if not self._is_authed() and ident != "2":
                return self._send(401, "unauthorized", "text/plain")
            return self._send(200, json.dumps({"id": ident, "owner": "spade-tester",
                                               "note": f"object {ident}"}), "application/json")
        if path == "/private":
            self._record()
            if not self._is_authed():
                return self._send(401, "unauthorized", "text/plain")
            return self._send(200, PRIVATE_BODY)
        if path.startswith("/private/") and path.endswith(".css"):
            self._record()
            return self._send(200, PRIVATE_BODY, "text/css", extra=[("X-Cache", "HIT")])
        if path.startswith("/admin/area"):
            self._record()
            if self.headers.get("X-Original-URL") == "/" or self.headers.get("X-Rewrite-URL") == "/":
                return self._send(200, ADMIN_BODY)
            if self._is_authed():
                return self._send(200, ADMIN_BODY)
            return self._send(401, "forbidden area", "text/plain")
        if path == "/form/csrf":
            self._record()
            return self._send(200, CSRF_FORM_HTML)
        if path == "/form/no-csrf":
            self._record()
            return self._send(200, NO_CSRF_FORM_HTML)
        if path in ("/form/csrf-submit", "/form/no-csrf-submit"):
            self._record()
            # Token palsu diterima seperti token sah: proteksi CSRF kosong.
            return self._send(200, "submit ok", "text/plain")
        if path in ("/jwt/protected", "/jwt/expired", "/jwt/kid-protected"):
            self._record()
            token = self._bearer_token()
            if path == "/jwt/kid-protected":
                # Verifier rentan: file kunci dipilih dari klaim `kid`. Nilai ber-path
                # (mis. `../../etc/passwd`) ditiru sebagai file kosong -> kunci kosong.
                parts = spade.jwt_parts(token)
                kid = str(parts[0].get("kid") or "") if parts else ""
                key = b"" if (".." in kid or kid.startswith(("/", "\\"))) else JWT_SECRET
                ok = self._verify_hs256(token, key=key)
            else:
                ok = self._verify_hs256(token, require_exp=(path == "/jwt/protected"))
            if not ok:
                return self._send(401, "invalid token", "application/json")
            return self._send(200, json.dumps({"ok": True, "user": "spade-tester"}), "application/json")
        if path == "/jwt/rs256-protected":
            self._record()
            # Verifier rentan: kunci dipilih dari klaim `alg` token, bukan dari konfigurasi.
            token = self._bearer_token()
            parts = spade.jwt_parts(token)
            claimed = str(parts[0].get("alg") or "") if parts else ""
            key = PUBLIC_KEY_PEM if claimed == "RS256" else JWT_SECRET
            if not self._verify_hs256(token, key=key, alg=claimed, mac="HS256"):
                return self._send(401, "invalid token", "application/json")
            return self._send(200, json.dumps({"ok": True, "user": "spade-admin"}), "application/json")
        if path == "/jwks.pem":
            self._record()
            return self._send(200, PUBLIC_KEY_PEM, "application/x-pem-file")
        if path == "/openapi.json":
            self._record()
            return self._send(200, json.dumps(OPENAPI_DOC), "application/json")
        if path == "/cache":
            # Endpoint dengan respons kanonik: nilai Host/forwarded TIDAK boleh
            # berubah, jadi uji cache poisoning di sini harus negatif.
            self._record()
            return self._send(200, "<html><body>asset host: static spade</body></html>",
                              extra=[("X-Cache", "HIT")])
        if path == "/redirect":
            self._record()
            raw = urllib.parse.unquote(self.path)
            if "\r\n" in raw:
                return self._send(302, "", "text/plain",
                                  extra=[("Location", "/"), ("X-Spade-Injected", "1")])
            return self._send(302, "", "text/plain", extra=[("Location", query.get("next", ["/"])[0])])
        if path == "/ssrf-sink":
            self._record()
            self._fetch_callback(query.get("url", [""])[0])
            return self._send(200, "fetched", "text/plain")
        if path == "/xml-oob":
            self._record()
            body = self._body()
            for match in urllib.parse.unquote(body).split('"'):
                self._fetch_callback(match)
            return self._send(200, "parsed", "application/xml")
        if path == "/ping":
            self._record()
            # Parameter lain (host/target/exec) sengaja tidak dijalankan; hanya `cmd`.
            command = (query.get("cmd") or [""])[0].split()
            if command:
                self._fetch_callback(command[-1])
            return self._send(200, "pong", "text/plain")
        return super()._handle()


@pytest.fixture
def auth_server():
    server = FixtureServer(handler=_AuthHandler).start()
    yield server
    server.stop()

@pytest.fixture
def jwt_server():
    """Server dengan halaman utama khusus endpoint JWT (orakel token bersih)."""
    class _JwtHandler(_AuthHandler):
        root_html = JWT_ROOT_HTML

    server = FixtureServer(handler=_JwtHandler).start()
    yield server
    server.stop()


@pytest.fixture
def anon_sess(auth_server):
    spade.set_request_executor(1)
    session = spade.ThreadLocalSession(timeout=10, verify_ssl=True)
    yield session


def _auth_session():
    """Sesi tester: cookie jar berisi beberapa JWT + header penanda akun.

    Token dikirim lewat cookie jar, sedangkan jalur CLI `--cookie`/`-H` diuji
    terpisah (`test_auth_flags.py::test_cli_cookie_jwt_is_audited`). Nama cookie
    `sid` tidak dipakai: fixture menulis `sid` sendiri di halaman utama.
    """
    session = spade.ThreadLocalSession(timeout=10, verify_ssl=True,
                                       extra_headers={"X-Spade-Auth": "1"})
    session.cookies.set("token", jwt_hs256({"sub": "tester", "exp": int(time.time()) + 3600}))
    session.cookies.set("legacy", jwt_hs256({"sub": "tester", "exp": int(time.time()) - 60}))
    session.cookies.set("notoken", jwt_hs256({"sub": "tester"}))
    # `kid` berbentuk path: server rentan memuat file dari nilai ini (kunci kosong).
    session.cookies.set("kidtoken", jwt_hs256({"sub": "tester"},
                                              header={"alg": "HS256", "typ": "JWT",
                                                      "kid": "../../etc/passwd"}))
    return session

@pytest.fixture
def auth_sess(anon_sess):
    yield _auth_session()

@pytest.fixture
def jwt_anon_sess(jwt_server):
    spade.set_request_executor(1)
    yield spade.ThreadLocalSession(timeout=10, verify_ssl=True)

@pytest.fixture
def jwt_auth_sess(jwt_anon_sess):
    yield _auth_session()


class RawDesyncServer:
    """Server raw socket: memantulkan request mentah (tiruan desync CL.TE/TE.CL)."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}/"

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(1.0)
                chunks = []
                try:
                    while True:
                        data = conn.recv(4096)
                        if not data:
                            break
                        chunks.append(data)
                except (socket.timeout, TimeoutError, OSError):
                    pass
                body = b"".join(chunks)
                # Balas dengan body yang memuat request kedua (tanda desync terjadi).
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\n\r\n" + body)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=5)


@pytest.fixture
def desync_server():
    server = RawDesyncServer().start()
    yield server
    server.stop()


@pytest.fixture
def oob_collector():
    """Collector OOB asli (tools/oob_collector.py) jalan in-process."""
    tools_dir = Path(__file__).resolve().parents[1] / "tools"
    sys.path.insert(0, str(tools_dir))
    import oob_collector  # noqa: PLC0415

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), oob_collector._Handler)
    httpd.app = oob_collector._App(verbose=False)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)
