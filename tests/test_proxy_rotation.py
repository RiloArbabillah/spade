"""Test rotasi proxy: validasi URL, round-robin, skip-on-block, dan integrasi CLI.

Dua level pengujian:

* **unit** — `parse_proxy_url()`, `load_proxy_file()`, dan `ProxyPool` diuji
  langsung supaya urutan rotasi dan cooldown bisa dipastikan tanpa jaringan;
* **CLI** — `spade.main()` dijalankan terhadap fixture lokal lewat **forward proxy
  asli** (`tests/conftest.py::ProxyServer`), jadi terbukti request scanner benar
  keluar lewat proxy, bukan langsung ke target.
"""

import json

import pytest

import spade

PROXY_SECRET = "spade-proxy-rahasia-77c1"


@pytest.fixture(autouse=True)
def _restore_proxy_state():
    """Pool proxy & executor global tidak boleh bocor antar test."""
    original = spade.REQUEST_PROXIES
    yield
    spade.set_request_proxies(original)
    spade.set_request_executor(1)


def _run_cli(argv):
    """Jalankan `spade.main()` dan pastikan berhenti dengan exit code 2."""
    with pytest.raises(SystemExit) as exc:
        spade.main(argv)
    assert exc.value.code == 2


# ══════════════════════════════════════════════════════════════════
# 1. Unit — parse_proxy_url
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080",
    "https://proxy.example.com:8443",
    "socks5://127.0.0.1:1080",
    "socks5h://user:pass@127.0.0.1:1080",
])
def test_parse_proxy_url_accepts_supported_schemes(url):
    assert spade.parse_proxy_url(url) == url


def test_parse_proxy_url_lowercases_scheme_and_strips_space():
    assert spade.parse_proxy_url("  HTTP://127.0.0.1:8080  ") == "http://127.0.0.1:8080"
    assert spade.parse_proxy_url("SOCKS5H://127.0.0.1:1080") == "socks5h://127.0.0.1:1080"


def test_parse_proxy_url_keeps_credentials():
    url = "http://tester:rahasia@127.0.0.1:8080"
    assert spade.parse_proxy_url(url) == url


@pytest.mark.parametrize("url", [
    "",
    "   ",
    "127.0.0.1:8080",          # tanpa skema -> libcurl menebak
    "proxy.example.com",       # tanpa skema & port
])
def test_parse_proxy_url_rejects_missing_scheme(url):
    with pytest.raises(ValueError):
        spade.parse_proxy_url(url)


@pytest.mark.parametrize("url", [
    "ftp://127.0.0.1:21",
    "socks4://127.0.0.1:1080",
    "socks://127.0.0.1:1080",
])
def test_parse_proxy_url_rejects_unsupported_scheme(url):
    with pytest.raises(ValueError, match="tidak didukung"):
        spade.parse_proxy_url(url)


def test_parse_proxy_url_rejects_missing_host():
    with pytest.raises(ValueError, match="tidak menyebut host"):
        spade.parse_proxy_url("http://:8080")


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:abc",
    "http://127.0.0.1:0",
    "http://127.0.0.1:70000",
])
def test_parse_proxy_url_rejects_bad_port(url):
    with pytest.raises(ValueError):
        spade.parse_proxy_url(url)


# ══════════════════════════════════════════════════════════════════
# 2. Unit — redaksi kredensial proxy
# ══════════════════════════════════════════════════════════════════

def test_redact_proxy_url_hides_password():
    redacted = spade._redact_proxy_url(f"http://tester:{PROXY_SECRET}@127.0.0.1:8080")
    assert PROXY_SECRET not in redacted
    assert redacted == "http://tester:***@127.0.0.1:8080"


def test_redact_proxy_url_leaves_plain_url_untouched():
    assert spade._redact_proxy_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_parse_proxy_url_error_message_is_redacted():
    """Pesan error validasi tidak boleh memuat password proxy."""
    with pytest.raises(ValueError) as exc:
        spade.parse_proxy_url(f"http://tester:{PROXY_SECRET}@127.0.0.1:70000")
    assert PROXY_SECRET not in str(exc.value)
    assert "***" in str(exc.value)


# ══════════════════════════════════════════════════════════════════
# 3. Unit — load_proxy_file
# ══════════════════════════════════════════════════════════════════

def test_load_proxy_file_reads_and_normalizes(tmp_path):
    path = tmp_path / "proxy.txt"
    path.write_text("# daftar proxy\n\nHTTP://127.0.0.1:8080\n  socks5h://127.0.0.1:1080  \n# komentar lagi\n",
                    encoding="utf-8")
    assert spade.load_proxy_file(str(path)) == ["http://127.0.0.1:8080", "socks5h://127.0.0.1:1080"]


def test_load_proxy_file_rejects_empty_file(tmp_path):
    path = tmp_path / "kosong.txt"
    path.write_text("\n# hanya komentar\n", encoding="utf-8")
    with pytest.raises(ValueError, match="tidak berisi satu URL proxy pun"):
        spade.load_proxy_file(str(path))


def test_load_proxy_file_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="tidak bisa membaca"):
        spade.load_proxy_file(str(tmp_path / "tidak-ada.txt"))


def test_load_proxy_file_reports_line_number(tmp_path):
    path = tmp_path / "proxy.txt"
    path.write_text("http://127.0.0.1:8080\nftp://127.0.0.1:21\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"proxy\.txt:2"):
        spade.load_proxy_file(str(path))


# ══════════════════════════════════════════════════════════════════
# 4. Unit — ProxyPool
# ══════════════════════════════════════════════════════════════════

def test_pool_disabled_when_empty():
    pool = spade.ProxyPool()
    assert pool.enabled is False
    assert pool.count == 0
    assert pool.next_proxy() is None
    assert pool.describe() == {"enabled": False, "count": 0, "source": "", "cooldown": 60.0}


def test_pool_round_robin_order():
    pool = spade.ProxyPool(["http://a:1", "http://b:2"])
    assert [pool.next_proxy() for _ in range(5)] == [
        "http://a:1", "http://b:2", "http://a:1", "http://b:2", "http://a:1"]


def test_pool_skips_blocked_proxy():
    pool = spade.ProxyPool(["http://a:1", "http://b:2"], cooldown=30)
    assert pool.next_proxy() == "http://a:1"
    assert pool.mark_blocked("http://a:1") is True
    assert [pool.next_proxy() for _ in range(3)] == ["http://b:2"] * 3


def test_pool_uses_blocked_proxy_again_after_cooldown():
    pool = spade.ProxyPool(["http://a:1", "http://b:2"], cooldown=0.05)
    pool.mark_blocked("http://a:1")
    assert pool.next_proxy() == "http://b:2"
    spade.time.sleep(0.08)
    assert pool.next_proxy() == "http://a:1"


def test_pool_falls_back_when_all_blocked():
    """Semua proxy istirahat: scan tetap dapat proxy (tidak berhenti total)."""
    pool = spade.ProxyPool(["http://a:1", "http://b:2"], cooldown=30)
    pool.mark_blocked("http://a:1")
    pool.mark_blocked("http://b:2")
    assert pool.next_proxy() in ("http://a:1", "http://b:2")


def test_pool_mark_blocked_ignores_unknown_url_and_zero_cooldown():
    pool = spade.ProxyPool(["http://a:1"], cooldown=30)
    assert pool.mark_blocked("http://lain:9") is False
    assert pool.blocked_count == 0
    pool.cooldown = 0
    assert pool.mark_blocked("http://a:1") is False
    assert pool.blocked_count == 0


def test_pool_mark_blocked_extends_cooldown_on_repeat():
    """Blokir berulang memperpanjang istirahat proxy dan tetap terhitung untuk audit."""
    pool = spade.ProxyPool(["http://a:1"], cooldown=30)
    assert pool.mark_blocked("http://a:1") is True
    first_until = pool._blocked_until["http://a:1"]
    assert pool.mark_blocked("http://a:1") is True
    assert pool._blocked_until["http://a:1"] > first_until
    assert pool.blocked_count == 2


def test_pool_describe_has_no_url_or_credentials():
    pool = spade.ProxyPool([f"http://tester:{PROXY_SECRET}@127.0.0.1:8080"],
                           cooldown=15, source="--proxy")
    described = json.dumps(pool.describe())
    assert described == json.dumps({"enabled": True, "count": 1,
                                    "source": "--proxy", "cooldown": 15.0})
    assert PROXY_SECRET not in described
    assert "127.0.0.1" not in described


# ══════════════════════════════════════════════════════════════════
# 5. CLI — validasi sebelum request apa pun
# ══════════════════════════════════════════════════════════════════

def test_cli_rejects_proxy_with_proxy_file(vuln_server, tmp_path, capsys):
    proxy_file = tmp_path / "proxy.txt"
    proxy_file.write_text("http://127.0.0.1:8080\n", encoding="utf-8")
    _run_cli([vuln_server.base_url, "--proxy", "http://127.0.0.1:8081",
              "--proxy-file", str(proxy_file)])
    assert "tidak bisa dipakai bersamaan" in capsys.readouterr().err
    assert vuln_server.app.requests == []


@pytest.mark.parametrize("url", ["ftp://127.0.0.1:21", "127.0.0.1:8080", "http://:8080"])
def test_cli_rejects_invalid_proxy_url(vuln_server, url, capsys):
    _run_cli([vuln_server.base_url, "--proxy", url])
    assert "--proxy" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_cli_rejects_missing_proxy_file(vuln_server, tmp_path, capsys):
    _run_cli([vuln_server.base_url, "--proxy-file", str(tmp_path / "tidak-ada.txt")])
    assert "tidak bisa membaca" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_cli_rejects_empty_proxy_file(vuln_server, tmp_path, capsys):
    proxy_file = tmp_path / "proxy.txt"
    proxy_file.write_text("# kosong\n", encoding="utf-8")
    _run_cli([vuln_server.base_url, "--proxy-file", str(proxy_file)])
    assert "tidak berisi satu URL proxy pun" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_cli_rejects_negative_proxy_cooldown(vuln_server, capsys):
    _run_cli([vuln_server.base_url, "--proxy", "http://127.0.0.1:8080", "--proxy-cooldown", "-1"])
    assert "--proxy-cooldown tidak boleh negatif" in capsys.readouterr().err
    assert vuln_server.app.requests == []


# ══════════════════════════════════════════════════════════════════
# 6. Integrasi — request benar-benar lewat proxy
# ══════════════════════════════════════════════════════════════════

def test_scan_routes_every_request_through_proxy(vuln_server, proxy_pair, tmp_path):
    first, second = proxy_pair
    json_out = tmp_path / "hasil.json"
    code = spade.main([vuln_server.base_url, "--quick",
                       "--proxy", first.url, "--proxy", second.url,
                       "-o", str(tmp_path / "laporan.html"), "--json", str(json_out)])
    assert code == 0
    origin_hits = len(vuln_server.app.requests)
    proxy_hits = len(first.app.requests) + len(second.app.requests)
    assert origin_hits > 0
    # Semua request yang sampai ke target melewati salah satu proxy (round-robin).
    assert proxy_hits == origin_hits
    assert first.app.requests and second.app.requests
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["proxy"] == {"enabled": True, "count": 2,
                                        "source": "--proxy", "cooldown": 60.0}


def test_scan_uses_proxy_file(vuln_server, proxy_pair, tmp_path):
    first, second = proxy_pair
    proxy_file = tmp_path / "proxy.txt"
    proxy_file.write_text(f"# rotasi\n{first.url}\n{second.url}\n", encoding="utf-8")
    json_out = tmp_path / "hasil.json"
    code = spade.main([vuln_server.base_url, "--quick", "--proxy-file", str(proxy_file),
                       "-o", str(tmp_path / "laporan.html"), "--json", str(json_out)])
    assert code == 0
    assert first.app.requests and second.app.requests
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["proxy"]["source"] == "--proxy-file"
    assert payload["scan"]["proxy"]["count"] == 2


def test_blocked_proxy_is_skipped_and_scan_continues(vuln_server, blocked_proxy, proxy_pair, tmp_path):
    """Proxy pertama membalas 403 → diistirahatkan, sisanya lanjut lewat proxy sehat."""
    healthy, _spare = proxy_pair
    json_out = tmp_path / "hasil.json"
    code = spade.main([vuln_server.base_url, "--quick",
                       "--proxy", blocked_proxy.url, "--proxy", healthy.url,
                       "-o", str(tmp_path / "laporan.html"), "--json", str(json_out)])
    assert code == 0
    # Proxy yang diblokir hanya dicoba sekali, sisanya pindah ke proxy sehat.
    assert len(blocked_proxy.app.requests) == 1
    assert len(healthy.app.requests) > 1
    assert len(healthy.app.requests) == len(vuln_server.app.requests)


def test_scan_without_proxy_reports_disabled_metadata(vuln_server, tmp_path):
    json_out = tmp_path / "hasil.json"
    code = spade.main([vuln_server.base_url, "--quick",
                       "-o", str(tmp_path / "laporan.html"), "--json", str(json_out)])
    assert code == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["proxy"] == {"enabled": False, "count": 0,
                                        "source": "", "cooldown": 60.0}


def test_proxy_credentials_never_leak_to_reports(vuln_server, proxy_pair, tmp_path, capsys):
    first, _spare = proxy_pair
    credential_url = first.url.replace("http://", f"http://tester:{PROXY_SECRET}@")
    html_out = tmp_path / "laporan.html"
    json_out = tmp_path / "hasil.json"
    code = spade.main([vuln_server.base_url, "--quick", "--proxy", credential_url,
                       "-o", str(html_out), "--json", str(json_out)])
    stdout = capsys.readouterr().out
    assert code == 0
    assert first.app.requests          # proxy tetap dipakai
    for blob in (stdout, html_out.read_text(encoding="utf-8"),
                 json_out.read_text(encoding="utf-8")):
        assert PROXY_SECRET not in blob


def test_smuggling_skipped_when_proxy_active(vuln_server, proxy_pair, capsys):
    first, _spare = proxy_pair
    spade.set_request_proxies(spade.ProxyPool([first.url]))
    sess = spade.ThreadLocalSession(timeout=10)
    finds = spade.scan_smuggling(sess, vuln_server.base_url, {"check_smuggling": True})
    assert list(finds) == []
    assert first.app.requests == []            # tidak ada payload desync yang keluar
    assert vuln_server.app.requests == []
    assert "dilewati" in capsys.readouterr().out
