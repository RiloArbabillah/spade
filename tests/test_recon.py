"""Test recon (bagian 3): subdomain, URL historis, endpoint JS, dan port scan.

Semua test di sini offline-deterministik: sumber pihak ketiga (crt.sh, Cert
Spotter, Wayback, Common Crawl) diganti fungsi fake lewat `spade.recon_sources()`
dan resolver/port di-patch, jadi tidak ada satu pun request ke internet.
"""

import json
import socket
import threading
import time

import pytest

import spade

# ══════════════════════════════════════════════════════════════════
# Helper: session/response palsu dengan kontrak minimal curl_cffi
# ══════════════════════════════════════════════════════════════════

class FakeResponse:
    """Response minimal yang cukup untuk jalur recon + modul injection."""

    def __init__(self, status=200, text="", headers=None, payload=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.content = text.encode("utf-8")
        self.url = ""
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("respons ini tidak berisi JSON")
        return self._payload

class FakeSession:
    """Session pengganti `ThreadLocalSession` yang mencatat URL dan mengembalikan respons canned."""

    def __init__(self, routes=None, default_text="<html><body>ok</body></html>", default_status=200):
        self.routes = dict(routes or {})
        self.default_text = default_text
        self.default_status = default_status
        self.calls = []
        self._lock = threading.Lock()

    def _reply(self, method, url, params):
        with self._lock:
            self.calls.append((method, url, params))
        return self.routes.get(
            url, FakeResponse(status=self.default_status, text=self.default_text))

    def get(self, url, params=None, timeout=None, allow_redirects=True, **kwargs):
        return self._reply("GET", url, params)

    def post(self, url, data=None, timeout=None, **kwargs):
        return self._reply("POST", url, data)

    def request(self, method, url, **kwargs):
        return self._reply(method, url, kwargs.get("params"))

    def urls(self):
        return [u for _m, u, _p in self.calls]

def fake_response(text="<html><body>ok</body></html>", status=200, headers=None):
    return FakeResponse(status=status, text=text, headers=headers or {})

def fake_sources(monkeypatch, **sources):
    """Pasang registry sumber recon palsu: nama -> (names|urls, status, index_url)."""
    registry = {}
    for name, value in sources.items():
        result = value if isinstance(value, tuple) else (value, "ok", f"https://{name}.test/index")
        registry[name] = lambda _sess, _base, _host, _r=result: _r
    monkeypatch.setattr(spade, "recon_sources", lambda: registry)
    return registry

@pytest.fixture(autouse=True)
def _sequential_requests():
    """Batas request recon diuji berurutan supaya hasilnya deterministik."""
    spade.set_request_executor(1)
    yield
    spade.set_request_executor(1)

# ══════════════════════════════════════════════════════════════════
# Batas target: IP/localhost tidak boleh memicu enumerasi apa pun
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("url,expected", [
    ("http://127.0.0.1:8080/", ""),
    ("http://10.0.0.5/", ""),
    ("http://localhost:8080/", ""),
    ("http://[::1]:8080/", ""),
    ("https://example.com/", "example.com"),
    ("https://www.example.com/path", "example.com"),
    ("https://sub.example.co.id/x", "sub.example.co.id"),
])
def test_recon_target_host_scope(url, expected):
    assert spade._recon_target_host(url) == expected

def test_recon_sources_registry_contract():
    sources = spade.recon_sources()
    assert set(sources) == {"crtsh", "certspotter", "wayback", "commoncrawl"}
    assert all(callable(func) for func in sources.values())

class _ExplodingSession:
    """Session yang gagal kalau recon menyentuh jaringan untuk target IP."""

    def get(self, *args, **kwargs):
        raise AssertionError("recon tidak boleh mengirim request untuk target IP/localhost")

def test_recon_gather_inert_on_ip_target():
    ctx = {}
    data = spade.recon_gather(_ExplodingSession(), "http://127.0.0.1:8080/", ctx)
    assert data["subdomains"] == []
    assert data["historic_urls"] == []
    assert data["live_hosts"] == []
    assert data["open_ports"] == []
    assert set(data["sources"].values()) == {"skipped"}
    assert ctx["recon_urls"] == []

# ══════════════════════════════════════════════════════════════════
# Sumber pasif: gabung, dedupe, batas
# ══════════════════════════════════════════════════════════════════

def test_recon_gather_merges_sources_and_filters_out_of_scope(monkeypatch):
    fake_sources(
        monkeypatch,
        crtsh=(['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com',
                'b.example.com', 'unrelated.net'], "ok", "https://crt.sh/idx"),
        certspotter=(['d.example.com', 'e.example.com'], "ok", "https://certspotter/idx"),
        wayback=(['https://example.com/old?id=1', 'https://other.net/x',
                  'https://example.com/logo.png', 'https://static.example.com/a?b=2',
                  'https://example.com/old?id=1', 'ftp://example.com/skip'], "ok", "https://wayback/idx"),
        commoncrawl=([], "empty", "https://commoncrawl/idx"),
    )
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: None)

    data = spade.recon_gather(FakeSession(), "https://example.com/", {})

    assert data["subdomains"] == ["a.example.com", "b.example.com", "c.example.com",
                                  "d.example.com", "e.example.com"]
    assert data["historic_urls"] == ["https://example.com/old?id=1", "https://static.example.com/a?b=2"]
    assert data["param_targets"] == [("https://example.com/old", ["id"]),
                                     ("https://static.example.com/a", ["b"])]
    assert data["sources"]["crtsh"] == "ok"
    assert data["sources"]["commoncrawl"] == "empty"
    assert data["sources"]["dnsbrute"] == "empty"
    assert data["sources"]["hostprobe"] == "empty"
    assert data["sources"]["portscan"] == "skipped"
    assert data["sources"]["js"] == "skipped"
    assert data["index_urls"]["crtsh"] == "https://crt.sh/idx"

def test_recon_clean_names_normalizes_and_filters():
    cleaned = spade._recon_clean_names(
        ["A.example.com", "*.B.example.com", "example.com", "other.net",
         "bad name.example.com", "trailing.example.com."], "example.com")
    assert cleaned == ["a.example.com", "b.example.com", "trailing.example.com"]

def test_recon_clean_names_respects_limit():
    names = [f"h{i:03d}.example.com" for i in range(50)]
    assert len(spade._recon_clean_names(names, "example.com", limit=10)) == 10

def test_recon_gather_caps_subdomains(monkeypatch):
    names = [f"h{i:03d}.example.com" for i in range(spade.RECON_MAX_SUBDOMAINS + 40)]
    fake_sources(monkeypatch, crtsh=(names, "ok", "https://crt.sh/idx"))
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: None)

    data = spade.recon_gather(FakeSession(), "https://example.com/", {})
    assert len(data["subdomains"]) == spade.RECON_MAX_SUBDOMAINS == 200

def test_recon_gather_skips_missing_sources(monkeypatch):
    """Sumber yang tidak ada di registry tidak boleh membuat recon gagal."""
    fake_sources(monkeypatch, crtsh=(['a.example.com'], "ok", "https://crt.sh/idx"))
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: None)

    data = spade.recon_gather(FakeSession(), "https://example.com/", {})
    assert data["subdomains"] == ["a.example.com"]
    assert set(data["sources"]) == {"crtsh", "dnsbrute", "hostprobe", "portscan", "js"}

# ══════════════════════════════════════════════════════════════════
# DNS brute force + resolver
# ══════════════════════════════════════════════════════════════════

def test_recon_dns_brute_uses_resolver(monkeypatch):
    monkeypatch.setattr(spade, "recon_dns_resolve",
                        lambda fqdn, timeout=None: fqdn.startswith("api."))
    assert spade.recon_dns_brute("example.com") == ["api.example.com"]

def test_recon_dns_resolve_returns_true_when_resolved(monkeypatch):
    monkeypatch.setattr(spade.socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 443))])
    assert spade.recon_dns_resolve("ok.example.com", timeout=1.0) is True

def test_recon_dns_resolve_enforces_timeout(monkeypatch):
    """Resolver OS yang menggantung tidak boleh memblokir scan lebih dari timeout."""
    def _hang(*_args, **_kwargs):
        time.sleep(30)
        raise OSError("tidak pernah sampai sini")

    monkeypatch.setattr(spade.socket, "getaddrinfo", _hang)
    started = time.monotonic()
    assert spade.recon_dns_resolve("slow.example.com", timeout=0.2) is False
    assert time.monotonic() - started < 5

# ══════════════════════════════════════════════════════════════════
# Probe host hidup (fixture lokal, bukan jaringan publik)
# ══════════════════════════════════════════════════════════════════

def test_recon_probe_host_reports_status_title_and_server(vuln_server, sess):
    name = vuln_server.base_url.split("//", 1)[1].rstrip("/")
    info = spade.recon_probe_host(sess, name)
    assert info is not None
    assert info["url"] == f"http://{name}/"
    assert info["status"] == 200
    assert info["title"] == "Fixture"
    assert "nginx" in info["server"]

def test_recon_probe_host_returns_none_when_unreachable():
    # Port yang sengaja dibiarkan tertutup: tidak ada server di sana.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    session = spade.ThreadLocalSession(timeout=2)
    try:
        assert spade.recon_probe_host(session, f"127.0.0.1:{port}") is None
    finally:
        session.close()

# ══════════════════════════════════════════════════════════════════
# URL historis -> pool parameter modul injection
# ══════════════════════════════════════════════════════════════════

def test_recon_param_targets_uses_real_params_only():
    urls = [
        "https://example.com/item?id=1&sort=asc",
        "https://example.com/item?id=2",
        "https://example.com/noquery",
        "https://example.com/search?q=x&debug=1&extra=2&a=1&b=2&c=3",
        "https://example.com/a?x=1",
        "https://example.com/b?x=1",
        "https://example.com/c?x=1",
        "https://example.com/d?x=1",
    ]
    targets = spade.recon_param_targets(urls)
    assert targets[0] == ("https://example.com/item", ["id", "sort"])
    assert targets[1] == ("https://example.com/search", ["q", "debug", "extra", "a", "b"])
    assert len(targets) == spade.RECON_PARAM_URLS == 5

def test_recon_injection_targets_bounds_urls_and_params():
    ctx = {"recon_param_targets": [
        (f"https://example.com/p{i}", [f"p{j}" for j in range(9)]) for i in range(9)]}
    targets = spade.recon_injection_targets(ctx)
    assert len(targets) == spade.RECON_PARAM_URLS
    assert all(len(params) <= spade.RECON_PARAM_NAMES for _url, params in targets)

def test_injection_url_jobs_keeps_base_url_first_and_skips_duplicate():
    ctx = {"recon_param_targets": [
        ("https://example.com/", ["id"]),
        ("https://example.com/old", ["id", "page"]),
    ]}
    jobs = spade.injection_url_jobs(ctx, "https://example.com/")
    assert jobs == [("https://example.com/", None), ("https://example.com/old", ["id", "page"])]

@pytest.mark.parametrize("ctx", [None, {}, {"recon_param_targets": []}])
def test_injection_url_jobs_without_recon_keeps_legacy_behavior(ctx):
    assert spade.injection_url_jobs(ctx, "https://example.com/") == [("https://example.com/", None)]

def test_sqli_uses_recon_urls_and_params():
    ctx = {"recon_param_targets": [("https://recon.example.com/item", ["id", "page"])]}
    session = FakeSession()
    finds = spade.scan_sqli(session, "https://base.example.com/", ctx)

    recon_calls = [c for c in session.calls if c[1] == "https://recon.example.com/item"]
    assert recon_calls, "modul SQLi harus menembak URL hasil recon"
    assert {tuple((call[2] or {}).keys()) for call in recon_calls} <= {("id",), ("page",)}
    assert finds == []

def test_open_redirect_uses_recon_urls():
    ctx = {"recon_param_targets": [("https://recon.example.com/go", ["next"])]}
    session = FakeSession()
    spade.open_redirect(session, "https://base.example.com/", ctx)

    recon_calls = [c for c in session.calls if c[1] == "https://recon.example.com/go"]
    assert recon_calls
    assert {(call[2] or {}).get("next") for call in recon_calls} == {"https://evil.com"}

def test_lfi_uses_recon_urls():
    ctx = {"recon_param_targets": [("https://recon.example.com/dl", ["file"])]}
    session = FakeSession()
    spade.lfi_check(session, "https://base.example.com/", ctx)

    recon_calls = [c for c in session.calls if c[1] == "https://recon.example.com/dl"]
    assert recon_calls
    assert {(call[2] or {}).get("file") for call in recon_calls} == {
        "../../etc/passwd", "../../etc/hosts"}

def test_crawler_does_not_inject_recon_params_without_recon():
    """Tanpa recon, modul injection tetap memakai daftar parameter bawaan."""
    session = FakeSession()
    spade.scan_sqli(session, "https://base.example.com/", {})
    assert session.urls() and set(session.urls()) == {"https://base.example.com/"}

# ══════════════════════════════════════════════════════════════════
# Seed crawler dari URL historis
# ══════════════════════════════════════════════════════════════════

def test_recon_seed_urls_drops_static_and_caps():
    ctx = {"recon_urls": [f"https://example.com/p{i}" for i in range(10)]
           + ["https://example.com/x.pdf", "https://example.com/y.css"]}
    seeds = spade.recon_seed_urls(ctx)
    assert seeds == [f"https://example.com/p{i}" for i in range(spade.RECON_MAX_SEEDS)]

@pytest.mark.parametrize("ctx", [None, {}])
def test_recon_seed_urls_empty_without_recon(ctx):
    assert spade.recon_seed_urls(ctx) == []

def test_crawler_crawls_recon_seeds(vuln_server, sess):
    ctx = {"recon_urls": [vuln_server.base_url + "admin/", vuln_server.base_url + "robots.txt"]}
    crawler = spade.Crawler(sess, vuln_server.base_url, depth=1, max_p=10,
                            extra_seeds=spade.recon_seed_urls(ctx))
    crawler.crawl(seed_text="<html><body>tanpa link</body></html>")

    crawled = set(vuln_server.app.paths())
    assert "/admin/" in crawled
    assert "/robots.txt" in crawled

# ══════════════════════════════════════════════════════════════════
# Ekstraksi endpoint dari berkas JS
# ══════════════════════════════════════════════════════════════════

def test_extract_js_endpoints_filters_static_and_third_party():
    text = """
      const a = "/api/v1/users?page=1";
      const b = "/static/app.css";
      const c = "https://cdn.other.net/api/x";
      const d = "https://example.com/api/orders";
      const e = "/assets/logo.png";
      const f = "not-a-path";
      const g = "/admin/debug";
    """
    found = spade.extract_js_endpoints(text, "example.com")
    assert "/api/v1/users?page=1" in found
    assert "/api/orders" in found
    assert "/admin/debug" in found
    assert not [f for f in found if "app.css" in f or "logo.png" in f or "other.net" in f]
    assert "not-a-path" not in found

def test_extract_js_endpoints_caps_and_handles_empty():
    text = "".join(f'x("/api/v1/route{i}?id=1");' for i in range(120))
    assert len(spade.extract_js_endpoints(text, "example.com")) == spade.RECON_JS_MAX_ENDPOINTS
    assert spade.extract_js_endpoints("", "example.com") == []

# ══════════════════════════════════════════════════════════════════
# Panen JS (recon_js) + pemakaian ulang di modul `js`
# ══════════════════════════════════════════════════════════════════

def test_recon_js_harvests_endpoints_and_memoizes():
    root = ('<html><body><script src="/static/app.js"></script>'
            '<script src="/static/vendor.js"></script></body></html>')
    session = FakeSession(routes={
        "https://example.com/": fake_response(root),
        "https://example.com/static/app.js": fake_response('fetch("/api/v1/orders");'),
        "https://example.com/static/vendor.js": fake_response('url("/admin/users");'),
    })
    ctx = {}
    first = spade.recon_js(session, "https://example.com/", ctx)
    assert "/api/v1/orders" in first["endpoints"]
    assert "/admin/users" in first["endpoints"]
    assert set(first["texts"]) == {"https://example.com/static/app.js",
                                   "https://example.com/static/vendor.js"}
    assert session.urls().count("https://example.com/static/app.js") == 1

    calls_before = len(session.calls)
    second = spade.recon_js(session, "https://example.com/", ctx)
    assert second is first
    assert len(session.calls) == calls_before

def test_scan_js_reuses_recon_js_texts(vuln_server, sess):
    """Berkas JS hasil panen recon tidak boleh diunduh dua kali oleh modul `js`."""
    js_url = vuln_server.base_url + "static/app.js"
    ctx = {"js_texts": {js_url: 'fetch("/api/v1/secret-users");'}}
    finds = spade.scan_js(sess, vuln_server.base_url, ctx)

    assert "/static/app.js" not in vuln_server.app.paths()
    apis = [finding for finding in finds if finding.code == "JS_APIS"]
    assert apis and "/api/v1/secret-users" in apis[0].desc

# ══════════════════════════════════════════════════════════════════
# Port scan
# ══════════════════════════════════════════════════════════════════

def test_recon_port_open_detects_local_listener():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    open_port = listener.getsockname()[1]
    bound = socket.socket()
    bound.bind(("127.0.0.1", 0))
    closed_port = bound.getsockname()[1]
    try:
        assert spade.recon_port_open("127.0.0.1", open_port) is True
        assert spade.recon_port_open("127.0.0.1", closed_port) is False
    finally:
        listener.close()
        bound.close()

def test_recon_port_scan_reports_only_open_ports(monkeypatch):
    scanned = []

    def _fake_open(host, port, timeout=None):
        scanned.append((host, port))
        return port in {22, 3306}

    monkeypatch.setattr(spade, "recon_port_open", _fake_open)
    found = spade.recon_port_scan(["a.example.com", "b.example.com"])

    assert ("a.example.com", 22, "ssh") in found
    assert ("b.example.com", 3306, "mysql") in found
    assert len(found) == 4
    assert len(scanned) == 2 * len(spade.PORT_SCAN_PORTS)

# ══════════════════════════════════════════════════════════════════
# Modul recon: temuan + status sumber
# ══════════════════════════════════════════════════════════════════

def _recon_ctx(port_scan=False):
    return {"port_scan": port_scan}

def test_scan_recon_reports_live_hosts_urls_and_ports(monkeypatch):
    fake_sources(
        monkeypatch,
        crtsh=(['a.example.com'], "ok", "https://crt.sh/idx"),
        wayback=(['https://example.com/old?id=1'], "ok", "https://wayback/idx"),
    )
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: {
        "url": f"https://{name}/", "status": 200, "title": "Admin", "server": "nginx"})

    port_calls = []
    monkeypatch.setattr(spade, "recon_port_open",
                        lambda host, port, timeout=None: port_calls.append((host, port)) or port == 3306)

    ctx = _recon_ctx(port_scan=True)
    finds = spade.scan_recon(FakeSession(), "https://example.com/", ctx)

    codes = [finding.code for finding in finds]
    assert "SUBDOMAIN_LIVE" in codes
    assert "HISTORIC_URLS" in codes
    assert "PORT_OPEN" in codes

    live = [f for f in finds if f.code == "SUBDOMAIN_LIVE"][0]
    assert live.sev == "INFO"
    assert "a.example.com" in live.desc and "Admin" in live.desc and "nginx" in live.desc
    assert live.evidence is not None

    historic = [f for f in finds if f.code == "HISTORIC_URLS"][0]
    assert historic.confidence == "tentative"

    ports = [f for f in finds if f.code == "PORT_OPEN"]
    assert len(ports) == 2                     # target + 1 host hidup
    assert {f.sev for f in ports} == {"LOW"}   # 3306 termasuk port berisiko
    assert "3306" in ports[0].desc
    assert ports[0].evidence is None           # connect scan tidak punya bukti HTTP
    assert len(port_calls) == 2 * len(spade.PORT_SCAN_PORTS)

def test_scan_recon_reports_non_risky_port_as_info(monkeypatch):
    fake_sources(monkeypatch, crtsh=([], "empty", "https://crt.sh/idx"))
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: None)
    monkeypatch.setattr(spade, "recon_port_open",
                        lambda host, port, timeout=None: port == 8080)

    finds = spade.scan_recon(FakeSession(), "https://example.com/", _recon_ctx(port_scan=True))
    ports = [f for f in finds if f.code == "PORT_OPEN"]
    assert ports and {f.sev for f in ports} == {"INFO"}

def test_scan_recon_marks_failed_sources(monkeypatch):
    def _timeout(_sess, _base, _host):
        raise TimeoutError("connection timed out")

    def _broken(_sess, _base, _host):
        raise ConnectionError("name resolution failed")

    monkeypatch.setattr(spade, "recon_sources", lambda: {"crtsh": _timeout, "wayback": _broken})
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: None)

    ctx = _recon_ctx()
    data = spade.recon_gather(FakeSession(), "https://example.com/", ctx)
    finds = spade.scan_recon(FakeSession(), "https://example.com/", ctx)

    assert data["sources"]["crtsh"] == "timeout"
    assert data["sources"]["wayback"] == "error"
    skipped = [f for f in finds if f.code == "RECON_SOURCE_SKIPPED"]
    assert {f.confidence for f in skipped} == {"certain"}
    assert len(skipped) == 2
    assert all(f.evidence is None for f in skipped)
    assert any("tidak lengkap" in f.desc for f in skipped)

def test_scan_subdomains_reports_recon_result(monkeypatch):
    fake_sources(
        monkeypatch,
        crtsh=(['a.example.com', 'b.example.com'], "ok", "https://crt.sh/idx"),
    )
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: None)

    finds = spade.scan_subdomains(FakeSession(), "https://example.com/", {})
    subs = [f for f in finds if f.code == "SUBDOMAINS"]
    assert len(subs) == 1
    assert "a.example.com" in subs[0].desc and "CRT.sh" in subs[0].desc

def test_scan_subdomains_inert_on_ip_target(vuln_server, sess):
    ctx = {}
    assert spade.scan_subdomains(sess, vuln_server.base_url, ctx) == []
    assert vuln_server.app.paths() == []

# ══════════════════════════════════════════════════════════════════
# CLI: flag recon & gating
# ══════════════════════════════════════════════════════════════════

def test_port_scan_flag_requires_detailed_or_recon_only(vuln_server):
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--port-scan", "--quick", "--no-color"])
    assert exc.value.code == 2

@pytest.mark.parametrize("argv", [
    ["--recon-only", "--quick"],
    ["--recon-only", "--detailed"],
    ["--recon-only", "--no-recon"],
])
def test_recon_only_conflicts(vuln_server, argv):
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, *argv, "--no-color"])
    assert exc.value.code == 2

def test_recon_only_end_to_end_writes_reports(monkeypatch, tmp_path):
    fake_sources(
        monkeypatch,
        crtsh=(['a.example.com'], "ok", "https://crt.sh/idx"),
        wayback=(['https://example.com/old?id=1'], "ok", "https://wayback/idx"),
    )
    monkeypatch.setattr(spade, "recon_dns_resolve", lambda fqdn, timeout=None: False)
    monkeypatch.setattr(spade, "recon_probe_host", lambda sess, name: {
        "url": f"https://{name}/", "status": 200, "title": "Login", "server": "nginx"})
    monkeypatch.setattr(spade, "recon_port_open",
                        lambda host, port, timeout=None: port == 443)
    monkeypatch.setattr(spade, "ThreadLocalSession", lambda **kwargs: FakeSession())

    html_out = tmp_path / "recon.html"
    json_out = tmp_path / "recon.json"
    sarif_out = tmp_path / "recon.sarif"
    code = spade.main(["https://example.com/", "--recon-only", "--port-scan", "--no-color",
                       "-o", str(html_out), "--json", str(json_out), "--sarif", str(sarif_out)])

    assert code == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["mode"] == "recon"
    assert payload["scan"]["modules"] == ["recon"]
    assert html_out.exists() and sarif_out.exists()
    codes = {finding["code"] for finding in payload["findings"]}
    assert {"SUBDOMAIN_LIVE", "HISTORIC_URLS", "PORT_OPEN"} <= codes

def test_detailed_no_recon_skips_recon_stage(vuln_server, tmp_path):
    json_out = tmp_path / "detailed.json"
    code = spade.main([vuln_server.base_url, "--detailed", "--no-recon", "--no-color",
                       "--workers", "1", "-o", str(tmp_path / "detailed.html"),
                       "--json", str(json_out)])
    assert code == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["mode"] == "detailed"
    assert "recon" not in payload["scan"]["modules"]
    assert payload["scan"]["modules"] == [k for k in spade.ALL_MODULES if k != "recon"]
