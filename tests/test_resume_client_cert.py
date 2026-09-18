"""Test checkpoint/resume (`--state`/`--resume`) dan client certificate (`--cert`/`--key`).

Dua level pengujian:

* **unit** — fingerprint konfigurasi, tulis atomik, baca+validasi state, dan
  rekonstruksi temuan diuji langsung supaya kontrak berkas state bisa dipastikan
  tanpa jaringan;
* **CLI** — `spade.main()` dijalankan terhadap fixture lokal untuk membuktikan
  checkpoint benar-benar ditulis, modul yang sudah selesai tidak diulang, temuan
  lama muncul lagi di laporan, dan konfigurasi berbeda ditolak sebelum satu
  request pun dikirim.
"""

import json

import pytest

import spade

CERT_SECRET = "spade-mtls-rahasia-4b7d"


@pytest.fixture(autouse=True)
def _restore_engine_state():
    """Penjadwal, pool proxy, dan executor global tidak boleh bocor antar test."""
    throttle = spade.REQUEST_THROTTLE
    proxies = spade.REQUEST_PROXIES
    yield
    spade.set_request_throttle(throttle)
    spade.set_request_proxies(proxies)
    spade.set_request_executor(1)


@pytest.fixture
def client_cert_files(tmp_path):
    """Sepasang berkas PEM tiruan; isinya tidak diverifikasi untuk target `http://`."""
    cert = tmp_path / "klien.pem"
    key = tmp_path / "klien.key"
    cert.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                    encoding="utf-8")
    key.write_text("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
                   encoding="utf-8")
    return cert, key


def _run_cli(argv):
    """Jalankan `spade.main()` dan pastikan berhenti dengan exit code 2."""
    with pytest.raises(SystemExit) as exc:
        spade.main(argv)
    assert exc.value.code == 2


def _sample_config(**overrides):
    config = {
        "target": "https://contoh.test",
        "mode": "standard",
        "impersonate": "",
        "modules": ["tech", "headers"],
        "auth": False,
        "safe_mode": False,
        "active_writes": False,
        "timing_probes": False,
        "check_smuggling": False,
        "port_scan": False,
        "oob": False,
    }
    config.update(overrides)
    return config


def _read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


# ══════════════════════════════════════════════════════════════════
# 1. Unit — fingerprint konfigurasi
# ══════════════════════════════════════════════════════════════════

def test_fingerprint_is_stable_for_equal_config():
    assert spade.scan_config_fingerprint(_sample_config()) == \
        spade.scan_config_fingerprint(_sample_config())


def test_fingerprint_ignores_key_order_and_unknown_keys():
    shuffled = dict(reversed(list(_sample_config().items())))
    shuffled["catatan"] = "kunci di luar cakupan tidak boleh mengubah hash"
    assert spade.scan_config_fingerprint(shuffled) == \
        spade.scan_config_fingerprint(_sample_config())


@pytest.mark.parametrize("overrides", [
    {"target": "https://lain.test"},
    {"mode": "detailed"},
    {"modules": ["tech"]},
    {"safe_mode": True},
    {"active_writes": True},
    {"port_scan": True},
    {"oob": True},
])
def test_fingerprint_changes_when_scope_changes(overrides):
    assert spade.scan_config_fingerprint(_sample_config(**overrides)) != \
        spade.scan_config_fingerprint(_sample_config())


def test_fingerprint_tolerates_empty_config():
    assert spade.scan_config_fingerprint(None) == spade.scan_config_fingerprint({})


def test_state_config_covers_every_fingerprint_key_and_no_secret():
    args = type("Args", (), {
        "impersonate": "", "safe_mode": False, "active_writes": False,
        "timing_probes": False, "check_smuggling": False, "port_scan": False,
    })()
    config = spade.scan_state_config("https://contoh.test", "quick", args,
                                     ["tech"], True, "")
    assert set(config) == set(spade.STATE_FINGERPRINT_KEYS)
    # Ringkasan konfigurasi hanya berisi cakupan uji: tanpa cookie, token,
    # kredensial, atau path berkas lokal.
    assert config["auth"] is True and config["mode"] == "quick"
    assert config["modules"] == ["tech"]
    blob = json.dumps(config).lower()
    for needle in ("cookie", "token", "authorization", "password", "session", ".pem"):
        assert needle not in blob


def test_state_fingerprint_mismatch_lists_differing_keys():
    saved = _sample_config(mode="detailed", safe_mode=True)
    beda = spade.state_fingerprint_mismatch(_sample_config(), saved)
    assert beda == ["mode", "safe_mode"]
    assert spade.state_fingerprint_mismatch(_sample_config(), _sample_config()) == []
    assert spade.state_fingerprint_mismatch(_sample_config(), None) == list(spade.STATE_FINGERPRINT_KEYS)


# ══════════════════════════════════════════════════════════════════
# 2. Unit — tulis & baca berkas state
# ══════════════════════════════════════════════════════════════════

def test_write_scan_state_writes_json_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "state.json"
    spade.write_scan_state(path, {"schema_version": spade.STATE_SCHEMA_VERSION, "a": 1})
    assert _read_json(path) == {"schema_version": spade.STATE_SCHEMA_VERSION, "a": 1}
    assert list(tmp_path.glob(".spade-state-*")) == []


def test_write_scan_state_replaces_previous_checkpoint(tmp_path):
    path = tmp_path / "state.json"
    spade.write_scan_state(path, {"schema_version": 1, "modules_done": ["tech"]})
    spade.write_scan_state(path, {"schema_version": 1, "modules_done": ["tech", "headers"]})
    assert _read_json(path)["modules_done"] == ["tech", "headers"]
    assert list(tmp_path.glob(".spade-state-*")) == []


def test_write_scan_state_reports_unwritable_path(tmp_path):
    target = tmp_path / "tidak-ada" / "state.json"
    with pytest.raises(ValueError) as exc:
        spade.write_scan_state(target, {"schema_version": 1})
    assert "tidak bisa menulis state" in str(exc.value)


def test_load_scan_state_round_trips_payload(tmp_path):
    path = tmp_path / "state.json"
    payload = {"schema_version": spade.STATE_SCHEMA_VERSION,
               "config": _sample_config(), "modules_done": ["tech"]}
    spade.write_scan_state(path, payload)
    assert spade.load_scan_state(path) == payload


def test_load_scan_state_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError) as exc:
        spade.load_scan_state(tmp_path / "tidak-ada.json")
    assert "tidak bisa membaca --resume" in str(exc.value)


def test_load_scan_state_rejects_invalid_json(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{bukan json", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        spade.load_scan_state(path)
    assert "bukan JSON yang valid" in str(exc.value)


def test_load_scan_state_rejects_non_object(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        spade.load_scan_state(path)
    assert "tidak berisi objek state" in str(exc.value)


def test_load_scan_state_rejects_unknown_schema_version(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"schema_version": 99, "config": {}}), encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        spade.load_scan_state(path)
    assert "schema_version" in str(exc.value)


def test_load_scan_state_rejects_missing_config(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(json.dumps({"schema_version": spade.STATE_SCHEMA_VERSION}),
                    encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        spade.load_scan_state(path)
    assert "tidak memuat konfigurasi scan" in str(exc.value)


# ══════════════════════════════════════════════════════════════════
# 3. Unit — payload & rekonstruksi temuan
# ══════════════════════════════════════════════════════════════════

def test_scan_state_payload_shape_and_pending_modules():
    config = _sample_config()
    payload = spade.scan_state_payload(config, "https://contoh.test",
                                       ["tech", "headers", "robots"], ["tech"],
                                       [], [], "2026-01-01T00:00:00")
    assert payload["schema_version"] == spade.STATE_SCHEMA_VERSION
    assert payload["tool"] == {"name": "spade", "version": spade.SPADE_VERSION}
    assert payload["fingerprint"] == spade.scan_config_fingerprint(config)
    assert payload["modules_done"] == ["tech"]
    assert payload["modules_pending"] == ["headers", "robots"]
    assert payload["finished_at"] is None
    assert payload["errors"] == []


def test_payload_keeps_evidence_but_never_stores_secrets():
    evidence = spade.Exchange(
        "GET", "https://contoh.test/admin", 200,
        request_headers={"Cookie": f"sid={CERT_SECRET}", "Authorization": f"Bearer {CERT_SECRET}"},
        request_body=f"password={CERT_SECRET}", response_snippet=f"token={CERT_SECRET}",
        response_headers={"Set-Cookie": f"sid={CERT_SECRET}"},
    )
    finding = spade.Finding("HIGH", "IDOR", "akses tanpa izin", "https://contoh.test/admin",
                            evidence=evidence)
    payload = spade.scan_state_payload(_sample_config(), "https://contoh.test",
                                       ["idor"], ["idor"], [finding], [], "2026-01-01T00:00:00")
    blob = json.dumps(payload, ensure_ascii=False)
    assert CERT_SECRET not in blob
    assert payload["findings"][0]["evidence"]["request_headers"]["Cookie"].endswith(
        spade.REDACT_PLACEHOLDER)


def test_findings_from_state_round_trips_finding_with_evidence():
    evidence = spade.Exchange("POST", "https://contoh.test/submit", 500,
                              request_body="a=1", response_snippet="galat server",
                              response_length=12, content_type="text/html",
                              elapsed_ms=42.0, timestamp="2026-01-01T00:00:01")
    original = spade.Finding("CRITICAL", "SQLI", "injeksi SQL", "https://contoh.test/submit",
                             evidence=evidence, confidence="firm")
    payload = spade.scan_state_payload(_sample_config(), "https://contoh.test",
                                       ["sqli"], ["sqli"], [original], [], "2026-01-01T00:00:00")
    restored = spade.findings_from_state(payload)
    assert len(restored) == 1
    assert restored[0].code == "SQLI"
    assert restored[0].sev == "CRITICAL"
    assert restored[0].confidence == "firm"
    assert restored[0].evidence.method == "POST"
    assert restored[0].evidence.status == 500
    assert restored[0].evidence.response_length == 12
    assert restored[0].evidence.elapsed_ms == 42.0


def test_findings_from_state_skips_malformed_entries():
    payload = {"findings": [
        {"code": "XSS", "severity": "HIGH", "description": "ok", "url": "https://contoh.test"},
        "bukan objek",
        {"severity": "HIGH"},              # tanpa kode
        None,
        {"code": "CORS", "severity": "LOW", "description": "ok", "evidence": "bukan objek"},
    ]}
    restored = spade.findings_from_state(payload)
    assert [f.code for f in restored] == ["XSS", "CORS"]
    assert restored[0].evidence is None
    assert restored[1].evidence is None


def test_findings_from_state_handles_empty_or_missing_list():
    assert spade.findings_from_state({}) == []
    assert spade.findings_from_state({"findings": []}) == []
    assert spade.findings_from_state(None) == []


def test_finding_from_state_requires_code():
    assert spade.finding_from_state(None) is None
    assert spade.finding_from_state({"severity": "HIGH"}) is None


# ══════════════════════════════════════════════════════════════════
# 4. CLI — validasi (exit 2 tanpa satu pun request)
# ══════════════════════════════════════════════════════════════════

def test_key_without_cert_exits_two(vuln_server, client_cert_files, capsys):
    _cert, key = client_cert_files
    _run_cli([vuln_server.base_url, "--quick", "--no-color", "--key", str(key)])
    assert "--key butuh --cert" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_missing_cert_file_exits_two(vuln_server, tmp_path, capsys):
    _run_cli([vuln_server.base_url, "--quick", "--no-color",
              "--cert", str(tmp_path / "tidak-ada.pem")])
    assert "--cert: berkas" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_missing_key_file_exits_two(vuln_server, client_cert_files, tmp_path, capsys):
    cert, _key = client_cert_files
    _run_cli([vuln_server.base_url, "--quick", "--no-color", "--cert", str(cert),
              "--key", str(tmp_path / "tidak-ada.key")])
    assert "--key: berkas" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_resume_missing_state_file_exits_two(vuln_server, tmp_path, capsys):
    _run_cli([vuln_server.base_url, "--quick", "--no-color",
              "--resume", str(tmp_path / "tidak-ada.json")])
    assert "tidak bisa membaca --resume" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_resume_invalid_state_file_exits_two(vuln_server, tmp_path, capsys):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"schema_version": 99}), encoding="utf-8")
    _run_cli([vuln_server.base_url, "--quick", "--no-color", "--resume", str(state)])
    assert "schema_version" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_resume_fingerprint_mismatch_on_mode_exits_two(vuln_server, tmp_path, capsys):
    state = tmp_path / "state.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "-o", str(tmp_path / "awal.html")]) == 0
    before = len(vuln_server.app.requests)
    _run_cli([vuln_server.base_url, "--detailed", "--no-color", "--resume", str(state),
              "-o", str(tmp_path / "lanjut.html")])
    err = capsys.readouterr().err
    assert "--resume: konfigurasi berbeda" in err
    assert "mode" in err
    # Tidak boleh ada request baru: penolakan terjadi sebelum sesi dibuat.
    assert len(vuln_server.app.requests) == before


def test_resume_fingerprint_mismatch_on_target_exits_two(vuln_server, rate_limited_server,
                                                        tmp_path, capsys):
    state = tmp_path / "state.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "-o", str(tmp_path / "awal.html")]) == 0
    _run_cli([rate_limited_server.base_url, "--quick", "--no-color", "--resume", str(state),
              "-o", str(tmp_path / "lanjut.html")])
    err = capsys.readouterr().err
    assert "--resume: konfigurasi berbeda" in err
    assert "target" in err
    assert rate_limited_server.app.requests == []


def test_resume_fingerprint_mismatch_on_safe_mode_exits_two(vuln_server, tmp_path, capsys):
    state = tmp_path / "state.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "-o", str(tmp_path / "awal.html")]) == 0
    before = len(vuln_server.app.requests)
    _run_cli([vuln_server.base_url, "--quick", "--no-color", "--safe-mode",
              "--resume", str(state), "-o", str(tmp_path / "lanjut.html")])
    assert "safe_mode" in capsys.readouterr().err
    assert len(vuln_server.app.requests) == before


# ══════════════════════════════════════════════════════════════════
# 5. CLI — checkpoint & resume pada scan nyata
# ══════════════════════════════════════════════════════════════════

def test_state_flag_writes_complete_checkpoint(vuln_server, tmp_path):
    state = tmp_path / "state.json"
    json_out = tmp_path / "hasil.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "--json", str(json_out), "-o", str(tmp_path / "laporan.html")]) == 0
    payload = _read_json(state)
    assert payload["schema_version"] == spade.STATE_SCHEMA_VERSION
    assert payload["target"] == vuln_server.base_url
    assert payload["config"]["mode"] == "quick"
    assert payload["modules_done"] == payload["modules_planned"] == spade.QUICK_MODULES
    assert payload["modules_pending"] == []
    assert payload["finished_at"]
    assert payload["fingerprint"] == spade.scan_config_fingerprint(payload["config"])
    meta = _read_json(json_out)["scan"]
    assert meta["state"] == {"enabled": True, "written": True}
    assert meta["resume"] == {"enabled": False, "modules_skipped": [],
                              "findings_restored": 0, "ctx_note": ""}


def test_scan_without_state_reports_disabled_metadata(vuln_server, tmp_path):
    json_out = tmp_path / "hasil.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--json", str(json_out),
                       "-o", str(tmp_path / "laporan.html")]) == 0
    meta = _read_json(json_out)["scan"]
    assert meta["state"] == {"enabled": False, "written": False}
    assert meta["resume"]["enabled"] is False


def test_resume_skips_completed_modules(vuln_server, tmp_path, capsys):
    state = tmp_path / "state.json"
    json_out = tmp_path / "lanjut.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "-o", str(tmp_path / "awal.html")]) == 0
    before = list(vuln_server.app.paths())
    assert any(p.startswith("/robots.txt") for p in before)
    assert any(p.startswith("/.env") for p in before)

    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--resume", str(state),
                       "--json", str(json_out), "-o", str(tmp_path / "lanjut.html")]) == 0
    baru = vuln_server.app.paths()[len(before):]
    # Semua modul sudah selesai → tidak ada request modul yang diulang.
    assert not any(p.startswith("/robots.txt") for p in baru)
    assert not any(p.startswith("/.env") for p in baru)
    assert "Resume:" in capsys.readouterr().out

    meta = _read_json(json_out)["scan"]
    assert meta["resume"]["enabled"] is True
    assert meta["resume"]["modules_skipped"] == spade.QUICK_MODULES
    assert meta["resume"]["ctx_note"]
    assert _read_json(state)["modules_pending"] == []


def test_resume_runs_only_pending_modules(vuln_server, tmp_path):
    """Checkpoint separuh jalan: modul yang belum selesai tetap dijalankan."""
    state = tmp_path / "state.json"
    json_out = tmp_path / "lanjut.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "-o", str(tmp_path / "awal.html")]) == 0
    # Pangkas progres seolah scan mati setelah dua modul pertama.
    payload = _read_json(state)
    payload["modules_done"] = ["tech", "headers"]
    state.write_text(json.dumps(payload), encoding="utf-8")

    before = list(vuln_server.app.paths())
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--resume", str(state),
                       "--json", str(json_out), "-o", str(tmp_path / "lanjut.html")]) == 0
    baru = vuln_server.app.paths()[len(before):]
    assert any(p.startswith("/robots.txt") for p in baru)
    assert any(p.startswith("/.env") for p in baru)

    meta = _read_json(json_out)["scan"]
    assert meta["resume"]["modules_skipped"] == ["tech", "headers"]
    akhir = _read_json(state)
    assert akhir["modules_done"] == spade.QUICK_MODULES
    assert akhir["modules_pending"] == []


def test_resume_restores_findings_into_report(vuln_server, tmp_path):
    state = tmp_path / "state.json"
    first = tmp_path / "awal.json"
    second = tmp_path / "lanjut.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "--json", str(first), "-o", str(tmp_path / "awal.html")]) == 0
    awal = _read_json(first)
    assert awal["findings"], "fixture tidak menghasilkan temuan; test tidak bermakna"

    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--resume", str(state),
                       "--json", str(second), "-o", str(tmp_path / "lanjut.html")]) == 0
    lanjut = _read_json(second)
    assert {f["code"] for f in lanjut["findings"]} == {f["code"] for f in awal["findings"]}
    meta = lanjut["scan"]["resume"]
    assert meta["findings_restored"] == len(awal["findings"])


def test_resume_without_state_flag_rewrites_same_file(vuln_server, tmp_path):
    state = tmp_path / "state.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "-o", str(tmp_path / "awal.html")]) == 0
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--resume", str(state),
                       "-o", str(tmp_path / "lanjut.html")]) == 0
    payload = _read_json(state)
    assert payload["modules_pending"] == []
    assert payload["modules_done"] == spade.QUICK_MODULES


def test_resume_state_is_written_atomically_without_temp_leftovers(vuln_server, tmp_path):
    state = tmp_path / "state.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--state", str(state),
                       "-o", str(tmp_path / "laporan.html")]) == 0
    assert list(tmp_path.glob(".spade-state-*")) == []


# ══════════════════════════════════════════════════════════════════
# 6. CLI — client certificate (--cert/--key)
# ══════════════════════════════════════════════════════════════════

def test_client_cert_scan_runs_and_reports_metadata(vuln_server, client_cert_files,
                                                    tmp_path, capsys):
    cert, key = client_cert_files
    json_out = tmp_path / "hasil.json"
    html_out = tmp_path / "laporan.html"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "--cert", str(cert), "--key", str(key),
                       "--json", str(json_out), "-o", str(html_out)]) == 0
    assert vuln_server.app.requests
    out = capsys.readouterr().out
    assert "mTLS" in out
    meta = _read_json(json_out)["scan"]
    assert meta["client_cert"] == {"enabled": True, "key": True}
    # Path berkas lokal tidak ikut ke laporan supaya laporan tetap portabel
    # (banner stdout memang menampilkan path supaya tester tahu berkas mana dipakai).
    for blob in (html_out.read_text(encoding="utf-8"),
                 json_out.read_text(encoding="utf-8")):
        assert str(cert) not in blob
        assert str(key) not in blob


def test_client_cert_without_key_is_allowed(vuln_server, client_cert_files, tmp_path):
    cert, _key = client_cert_files
    json_out = tmp_path / "hasil.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--cert", str(cert),
                       "--json", str(json_out), "-o", str(tmp_path / "laporan.html")]) == 0
    assert _read_json(json_out)["scan"]["client_cert"] == {"enabled": True, "key": False}


def test_client_cert_reaches_session_factory(client_cert_files, monkeypatch):
    """Kombinasi --cert/--key diteruskan apa adanya ke `make_session`."""
    cert, key = client_cert_files
    captured = []
    asli = spade.make_session

    def _spy(*args, **kwargs):
        captured.append(kwargs.get("cert"))
        return asli(*args, **kwargs)

    monkeypatch.setattr(spade, "make_session", _spy)
    sess = spade.ThreadLocalSession(timeout=5, client_cert=(str(cert), str(key)))
    sess._session()          # bangun Session tanpa mengirim request ke jaringan
    assert captured == [(str(cert), str(key))]
