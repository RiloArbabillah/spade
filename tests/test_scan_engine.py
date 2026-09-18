"""Test mesin scan / operasional: penjadwal request, safe-mode, dan impor sesi.

Dua level pengujian:

* **unit** — kelas `Throttle` diuji langsung supaya jarak request, jitter, dan
  backoff bisa dipastikan tanpa bergantung pada waktu jaringan;
* **CLI** — `spade.main()` dijalankan terhadap fixture lokal untuk membuktikan
  efeknya di request nyata (jarak request terukur, PUT/DELETE tidak terkirim,
  kredensial sesi benar-benar dipakai dan tidak bocor ke laporan).
"""

import json
import statistics
import time

import pytest

import spade

SESSION_SECRET = "spade-sesi-rahasia-9f3c"


@pytest.fixture(autouse=True)
def _restore_engine_state():
    """Penjadwal & executor global tidak boleh bocor antar test."""
    original = spade.REQUEST_THROTTLE
    yield
    spade.set_request_throttle(original)
    spade.set_request_executor(1)


@pytest.fixture
def non_tty(monkeypatch):
    """Paksa jalur non-interaktif (pytest biasanya sudah bukan TTY, tapi `-s` bisa TTY)."""
    monkeypatch.setattr(spade, "_stdin_is_tty", lambda: False)


def _scan_elapsed(argv):
    """Jalankan scan, kembalikan (durasi detik, jumlah request yang dicatat server)."""
    started = time.monotonic()
    code = spade.main(argv)
    return code, time.monotonic() - started


def _codes(json_out):
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    return {f["code"] for f in payload["findings"]}, payload


# ══════════════════════════════════════════════════════════════════
# 1. Unit — kelas Throttle
# ══════════════════════════════════════════════════════════════════


def test_throttle_disabled_by_default():
    throttle = spade.Throttle()
    assert throttle.enabled is False
    started = time.monotonic()
    throttle.acquire()
    assert time.monotonic() - started < 0.05
    assert throttle.describe() == {
        "enabled": False, "delay": 0.0, "max_rps": 0.0, "jitter": 0.0,
        "backoff_max": spade.DEFAULT_BACKOFF_MAX,
    }


def test_throttle_delay_spaces_acquires():
    throttle = spade.Throttle(delay=0.05)
    assert throttle.enabled is True
    throttle.acquire()
    started = time.monotonic()
    throttle.acquire()
    assert time.monotonic() - started >= 0.04


def test_throttle_max_rps_limits_total_rate():
    throttle = spade.Throttle(max_rps=20)
    assert throttle.interval == pytest.approx(0.05)
    throttle.acquire()
    started = time.monotonic()
    for _ in range(3):
        throttle.acquire()
    assert time.monotonic() - started >= 0.12


def test_throttle_jitter_stays_within_bounds():
    throttle = spade.Throttle(delay=0.1, jitter_pct=25)
    gaps = [throttle._jitter(0.1) for _ in range(300)]
    assert min(gaps) >= 0.075 - 1e-9
    assert max(gaps) <= 0.125 + 1e-9
    assert max(gaps) - min(gaps) > 0.01
    # jitter 0 = jeda tetap (tanpa pengacakan)
    assert spade.Throttle(delay=0.1)._jitter(0.1) == 0.1


def test_throttle_backoff_is_exponential_and_capped():
    throttle = spade.Throttle(delay=0.1, backoff_max=8.0)
    assert [throttle.backoff_for(n) for n in (1, 2, 3, 4, 5)] == [1.0, 2.0, 4.0, 8.0, 8.0]


def test_throttle_cooldown_blocks_every_worker():
    throttle = spade.Throttle(delay=0.01)
    assert throttle.cooldown(0.2) > 0.1
    started = time.monotonic()
    throttle.acquire()
    assert time.monotonic() - started >= 0.1


def test_throttle_cooldown_respects_backoff_max():
    throttle = spade.Throttle(delay=0.01, backoff_max=0.05)
    assert throttle.cooldown(30.0) <= 0.06


def test_throttle_helpers_are_noop_without_scheduler():
    spade.set_request_throttle(None)
    assert spade.throttle_cooldown(5.0) == 0.0
    started = time.monotonic()
    spade.throttle_acquire()
    assert time.monotonic() - started < 0.05


# ══════════════════════════════════════════════════════════════════
# 2. CLI — penjadwal request (--delay/--max-rps/--jitter/--backoff-max)
# ══════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("argv, fragment", [
    (["--delay", "-1"], "--delay"),
    (["--max-rps", "-1"], "--max-rps"),
    (["--jitter", "150"], "--jitter"),
    (["--jitter", "-1"], "--jitter"),
    (["--backoff-max", "-1"], "--backoff-max"),
])
def test_invalid_throttle_flags_exit_two(vuln_server, capsys, argv, fragment):
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color", *argv])
    assert exc.value.code == 2
    assert fragment in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_cli_delay_serializes_all_workers(vuln_server, tmp_path):
    """Dengan 4 worker, total durasi harus >= (N-1) * --delay."""
    json_out = tmp_path / "delay.json"
    code, elapsed = _scan_elapsed([
        vuln_server.base_url, "--quick", "--no-color", "--workers", "4",
        "--delay", "0.05", "--json", str(json_out), "-o", str(tmp_path / "delay.html"),
    ])
    assert code == 0
    requests = len(vuln_server.app.requests)
    assert requests >= 10, "fixture tidak menerima cukup request untuk diukur"
    assert elapsed >= 0.8 * (requests - 1) * 0.05, (
        f"{requests} request selesai dalam {elapsed:.2f}s — --delay tidak menahan semua worker")
    _, payload = _codes(json_out)
    assert payload["scan"]["throttle"]["delay"] == 0.05
    assert payload["scan"]["throttle"]["enabled"] is True


def test_cli_max_rps_limits_total_rate(vuln_server, tmp_path):
    json_out = tmp_path / "rps.json"
    code, elapsed = _scan_elapsed([
        vuln_server.base_url, "--quick", "--no-color", "--workers", "4",
        "--max-rps", "20", "--json", str(json_out), "-o", str(tmp_path / "rps.html"),
    ])
    assert code == 0
    requests = len(vuln_server.app.requests)
    assert requests >= 10
    assert elapsed >= 0.8 * (requests - 1) / 20, (
        f"{requests} request selesai dalam {elapsed:.2f}s — --max-rps tidak membatasi laju global")
    _, payload = _codes(json_out)
    assert payload["scan"]["throttle"]["max_rps"] == 20


def test_cli_jitter_keeps_gaps_within_bounds(vuln_server, tmp_path):
    """Jeda tetap di dalam ±50% dari --delay, tapi tidak seragam."""
    assert spade.main([
        vuln_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--delay", "0.08", "--jitter", "50",
        "-o", str(tmp_path / "jitter.html"),
    ]) == 0
    times = sorted(vuln_server.app.times())
    gaps = sorted(b - a for a, b in zip(times, times[1:]))
    assert len(gaps) >= 10
    # Waktu di sini dicatat oleh server fixture, jadi satu-dua jeda bisa terlihat
    # menyimpang kalau thread server kelaparan CPU (mesin uji sibuk) — bukan karena
    # penjadwal longgar. Karena itu rentang jitter diuji lewat median + p90, dan
    # satu nilai menyimpang masih ditoleransi.
    median = statistics.median(gaps)
    assert 0.035 <= median <= 0.135, f"median jeda {median:.3f}s di luar rentang jitter ±50%"
    p90 = gaps[min(len(gaps) - 1, int(len(gaps) * 0.9))]
    assert p90 <= 0.135, f"p90 jeda {p90:.3f}s lebih panjang dari batas jitter"
    outliers = [g for g in gaps if not 0.035 <= g <= 0.135]
    assert len(outliers) <= 1, f"jeda di luar rentang jitter: {outliers}"
    # Jitter benar-benar mengacak: sebaran jeda harus jauh lebih lebar dari derau
    # scheduler (tanpa jitter, simpangan baku hanya beberapa milidetik).
    spread = statistics.pstdev(gaps)
    assert spread > 0.005, f"jitter tidak mengacak jeda sama sekali (stdev {spread:.4f}s)"


def test_cli_banner_reports_throttle(vuln_server, tmp_path, capsys):
    assert spade.main([
        vuln_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--delay", "0.02", "--max-rps", "40", "--jitter", "10",
        "-o", str(tmp_path / "banner.html"),
    ]) == 0
    out = capsys.readouterr().out
    assert "Throttle: delay 0.02s, 40.0 req/s, jitter ±10%" in out


def test_retry_after_triggers_global_cooldown(retry_after_server, tmp_path):
    """429 + `Retry-After: 1` menahan request berikutnya selama ~1 detik."""
    assert spade.main([
        retry_after_server.base_url, "--quick", "--no-color", "--workers", "4",
        "--delay", "0.01", "-o", str(tmp_path / "retry.html"),
    ]) == 0
    times = sorted(retry_after_server.app.times("/"))
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert gaps, "fixture tidak menerima request ke /"
    assert max(gaps) >= 0.9, f"Retry-After tidak menahan worker lain (gap maks {max(gaps):.3f}s)"


def test_rate_limit_module_skipped_when_throttled(vuln_server, tmp_path, capsys):
    json_out = tmp_path / "ratelimit.json"
    assert spade.main([
        vuln_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--delay", "0.01", "--json", str(json_out),
        "-o", str(tmp_path / "ratelimit.html"),
    ]) == 0
    assert "dilewati: throttle aktif" in capsys.readouterr().out
    codes, _ = _codes(json_out)
    assert "RATE_LIMIT" not in codes
    assert "NO_RATE_LIMIT" not in codes


def test_rate_limit_module_still_runs_without_throttle(vuln_server, tmp_path, capsys):
    """Kontrol: tanpa penjadwal, modul rate limit tetap jalan seperti sebelumnya."""
    json_out = tmp_path / "ratelimit-off.json"
    assert spade.main([
        vuln_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--json", str(json_out), "-o", str(tmp_path / "ratelimit-off.html"),
    ]) == 0
    assert "dilewati: throttle aktif" not in capsys.readouterr().out
    codes, _ = _codes(json_out)
    assert "NO_RATE_LIMIT" in codes


# ══════════════════════════════════════════════════════════════════
# 3. CLI — safe-mode & gerbang otorisasi
# ══════════════════════════════════════════════════════════════════


def test_safe_mode_never_sends_put_or_delete(vuln_server, tmp_path, capsys):
    json_out = tmp_path / "safe.json"
    assert spade.main([
        vuln_server.base_url, "--no-color", "--workers", "1", "--safe-mode",
        "--json", str(json_out), "-o", str(tmp_path / "safe.html"),
    ]) == 0
    methods = {r["method"] for r in vuln_server.app.requests}
    assert "PUT" not in methods and "DELETE" not in methods
    assert {"TRACE", "OPTIONS"} <= methods, "modul HTTP methods tidak jalan sama sekali"
    assert "SAFE MODE" in capsys.readouterr().out
    _, payload = _codes(json_out)
    assert payload["scan"]["safe_mode"] is True


def test_without_safe_mode_put_and_delete_are_probed(vuln_server, tmp_path):
    """Kontrol: perilaku default (tanpa --safe-mode) tidak berubah."""
    assert spade.main([
        vuln_server.base_url, "--no-color", "--workers", "1",
        "-o", str(tmp_path / "unsafe.html"),
    ]) == 0
    methods = {r["method"] for r in vuln_server.app.requests}
    assert {"PUT", "DELETE"} <= methods


@pytest.mark.parametrize("flag", ["--active-writes", "--timing-probes", "--check-smuggling"])
def test_safe_mode_rejects_destructive_flags(vuln_server, capsys, flag):
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color", "--safe-mode", flag])
    assert exc.value.code == 2
    assert "--safe-mode" in capsys.readouterr().err
    assert vuln_server.base_url not in "".join(vuln_server.app.paths())


@pytest.mark.parametrize("flag", ["--active-writes", "--timing-probes", "--check-smuggling"])
def test_destructive_flags_need_authorization_without_tty(vuln_server, capsys, non_tty, flag):
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color", flag])
    assert exc.value.code == 2
    assert "konfirmasi otorisasi" in capsys.readouterr().err
    assert vuln_server.app.requests == []


@pytest.mark.parametrize("flag", ["--active-writes", "--timing-probes", "--check-smuggling"])
def test_destructive_flags_allowed_with_authorization(vuln_server, tmp_path, flag):
    json_out = tmp_path / "auth-ok.json"
    assert spade.main([
        vuln_server.base_url, "--quick", "--no-color", flag, "--i-have-authorization",
        "--json", str(json_out), "-o", str(tmp_path / "auth-ok.html"),
    ]) == 0
    _, payload = _codes(json_out)
    assert payload["scan"]["authorized"] is True


def test_authorization_prompt_denied_aborts_before_any_request(monkeypatch, vuln_server, tmp_path, capsys):
    monkeypatch.setattr(spade, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "tidak")
    assert spade.main([
        vuln_server.base_url, "--quick", "--no-color", "--active-writes",
        "-o", str(tmp_path / "denied.html"),
    ]) == 2
    assert vuln_server.app.requests == []
    assert "Konfirmasi otorisasi tidak diberikan" in capsys.readouterr().out


def test_authorization_prompt_accepted_runs_scan(monkeypatch, vuln_server, tmp_path):
    monkeypatch.setattr(spade, "_stdin_is_tty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "YES")
    json_out = tmp_path / "yes.json"
    assert spade.main([
        vuln_server.base_url, "--quick", "--no-color", "--active-writes",
        "--json", str(json_out), "-o", str(tmp_path / "yes.html"),
    ]) == 0
    assert vuln_server.app.requests
    _, payload = _codes(json_out)
    assert payload["scan"]["active_writes"] is True


# ══════════════════════════════════════════════════════════════════
# 4. CLI — impor sesi (--session)
# ══════════════════════════════════════════════════════════════════


SESSION_SHAPES = {
    "objek": {"sid": "spade-auth"},
    "daftar": [{"name": "sid", "value": "spade-auth"}],
    "cookies-headers": {"cookies": {"sid": "spade-auth"}, "headers": {"X-Spade-Auth": "1"}},
}


@pytest.mark.parametrize("shape", sorted(SESSION_SHAPES))
def test_session_file_shapes_are_sent(auth_server, tmp_path, shape):
    path = tmp_path / f"sesi-{shape}.json"
    path.write_text(json.dumps(SESSION_SHAPES[shape]), encoding="utf-8")
    json_out = tmp_path / f"sesi-{shape}.out.json"
    assert spade.main([
        auth_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--session", str(path), "--json", str(json_out),
        "-o", str(tmp_path / "sesi.html"),
    ]) == 0
    headers = auth_server.app.headers_for("/")
    assert "sid=spade-auth" in headers.get("cookie", "")
    if shape == "cookies-headers":
        assert headers.get("x-spade-auth") == "1"
    _, payload = _codes(json_out)
    assert payload["scan"]["auth"] is True
    assert payload["scan"]["auth_source"] == ["session"]


def test_session_file_reaches_authenticated_area(auth_server, tmp_path):
    """Cookie sesi harus masih terkirim setelah respons pertama (cookie jar).

    Nama cookie sengaja `session` (bukan `sid`) karena fixture selalu mengirim
    `Set-Cookie: sid=…` di halaman utama; lihat test berikutnya.
    """
    path = tmp_path / "sesi.json"
    path.write_text(json.dumps({"session": "spade-auth"}), encoding="utf-8")
    assert spade.main([
        auth_server.base_url, "--detailed", "--no-recon", "--no-color", "--workers", "1",
        "--crawl-max", "12", "--session", str(path),
        "-o", str(tmp_path / "sesi-detailed.html"),
    ]) == 0
    headers = auth_server.app.headers_for("/private")
    assert headers, "/private tidak pernah diuji"
    assert "session=spade-auth" in headers.get("cookie", ""), (
        "cookie sesi hilang setelah respons pertama menulis cookie sendiri")


def test_server_set_cookie_overrides_same_named_session_cookie(auth_server, tmp_path):
    """Perilaku seperti `curl -b`: cookie server dengan nama sama menggantikan cookie tester."""
    path = tmp_path / "sesi-bentrok.json"
    path.write_text(json.dumps({"sid": "spade-auth"}), encoding="utf-8")
    assert spade.main([
        auth_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--session", str(path), "-o", str(tmp_path / "sesi-bentrok.html"),
    ]) == 0
    assert "sid=spade-auth" in auth_server.app.headers_for("/").get("cookie", "")
    after = auth_server.app.last_headers_for("/").get("cookie", "")
    assert "spade-auth" not in after, "cookie server dengan nama sama harus menang"
    assert "sid=" in after


def test_cli_cookie_overrides_session_cookie(auth_server, tmp_path):
    path = tmp_path / "sesi-override.json"
    path.write_text(json.dumps({"sid": "nilai-sesi", "tema": "gelap"}), encoding="utf-8")
    assert spade.main([
        auth_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--session", str(path), "--cookie", "sid=nilai-cli",
        "-o", str(tmp_path / "override.html"),
    ]) == 0
    cookie = auth_server.app.headers_for("/").get("cookie", "")
    assert "sid=nilai-cli" in cookie
    assert "nilai-sesi" not in cookie
    assert "tema=gelap" in cookie, "cookie sesi yang tidak bentrok harus tetap dipakai"


@pytest.mark.parametrize("payload, fragment", [
    ("{ bukan json", "bukan JSON valid"),
    ("{}", "tidak ada cookie atau header"),
    ('"teks"', "objek JSON atau daftar cookie"),
    ('[{"name": "sid"}]', "kunci 'name' dan 'value'"),
    ('{"cookies": 5}', "kunci 'cookies' harus objek atau daftar"),
    ('{"headers": ["x"]}', "kunci 'headers' harus objek"),
])
def test_invalid_session_file_exits_two(vuln_server, tmp_path, capsys, payload, fragment):
    path = tmp_path / "sesi-rusak.json"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color", "--session", str(path)])
    assert exc.value.code == 2
    assert fragment in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_missing_session_file_exits_two(vuln_server, tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color",
                    "--session", str(tmp_path / "tidak-ada.json")])
    assert exc.value.code == 2
    assert "tidak bisa membaca --session" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_session_secret_never_in_reports(auth_server, tmp_path):
    path = tmp_path / "sesi-rahasia.json"
    path.write_text(json.dumps({"sid": SESSION_SECRET}), encoding="utf-8")
    json_out = tmp_path / "sesi-rahasia.out.json"
    html_out = tmp_path / "sesi-rahasia.html"
    assert spade.main([
        auth_server.base_url, "--quick", "--no-color", "--workers", "1",
        "--session", str(path), "--json", str(json_out), "-o", str(html_out),
    ]) == 0
    assert SESSION_SECRET not in json_out.read_text(encoding="utf-8")
    assert SESSION_SECRET not in html_out.read_text(encoding="utf-8")


# ══════════════════════════════════════════════════════════════════
# 5. Unit — cookie auth hanya untuk host target
# ══════════════════════════════════════════════════════════════════


def test_split_auth_cookies_moves_cookie_header_to_jar():
    headers, cookies = spade.split_auth_cookies(
        {"Cookie": "a=1; b=2", "Authorization": "Bearer token"})
    assert dict(headers) == {"Authorization": "Bearer token"}
    assert cookies == [("a", "1"), ("b", "2")]


def test_auth_cookies_are_scoped_to_the_target_host():
    """Cookie sesi tidak boleh ikut ke host pihak ketiga (crt.sh, Wayback, dll)."""
    sess = spade.ThreadLocalSession(extra_headers={"Cookie": "sid=rahasia"})
    assert dict(sess.extra_headers) == {}, "header Cookie harus dipindah ke cookie jar"
    assert sess.auth_cookies == [("sid", "rahasia")]
    sess._session("http://target.test/")                # host pertama → cookie di-seed
    assert sess._local.cookie_hosts == {"target.test"}
    assert sess._cookie_scope("crt.sh") is False        # host pihak ketiga ditolak
    assert sess._cookie_scope("") is False


def test_auth_cookie_scope_follows_explicit_auth_host():
    sess = spade.ThreadLocalSession(extra_headers={"Cookie": "sid=x"}, auth_host="target.test")
    assert sess._cookie_scope("target.test") is True
    assert sess._cookie_scope("api.target.test") is False
    assert sess._cookie_scope("crt.sh") is False
    # Tanpa cookie auth tidak ada yang perlu di-seed.
    assert spade.ThreadLocalSession()._cookie_scope("target.test") is False
