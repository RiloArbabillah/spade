"""Fixture target lokal untuk test spade.

Semua test berjalan tanpa jaringan eksternal: `vuln_server` menyediakan
mini-aplikasi rentan di 127.0.0.1 dengan port acak, sehingga hasil modul bisa
dibandingkan secara deterministik sebelum/sesudah perubahan.
"""

import base64
import json
import sys
import threading
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

    # ── helpers ──
    def _record(self):
        self.server.app.record(self.command, self.path, dict(self.headers))

    def _send(self, status, body="", ctype="text/html; charset=utf-8", extra=None):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _query(self):
        return parse_qs(urlparse(self.path).query, keep_blank_values=True)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    # ── routing ──
    def _handle(self):
        self._record()
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
        if path == "/submit":
            return self._send(200, f"<html><body>Komentar: {self._body()}</body></html>")
        if path == "/.env":
            return self._send(200, "APP_NAME=spade\nDB_PASSWORD=fixture-secret\n", "text/plain")
        if path == "/admin/":
            return self._send(200, "<html><body><h1>Admin Login</h1><form><input name='username'><input type='password' name='password'></form></body></html>")
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n", "text/plain")
        if path == "/uploads/":
            return self._send(200, "<html><body><h1>Index of /uploads</h1><a href='../'>Parent Directory</a></body></html>")
        if path == "/static/app.js":
            return self._send(200, 'const apiKey = "AKIA1234567890ABCDEF";\nfetch("/api/v1/users");\n',
                              "application/javascript")
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
            self.requests.append({"method": method, "path": path, "headers": headers})

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


class FixtureServer:
    def __init__(self, rate_limit_after=None):
        self.app = FixtureApp(rate_limit_after=rate_limit_after)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
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
def sess(vuln_server):
    """Session scanner standar menuju fixture (paralel 1 worker agar deterministik)."""
    spade.set_request_executor(1)
    session = spade.ThreadLocalSession(timeout=10, verify_ssl=True)
    yield session
    spade.set_request_executor(1)
