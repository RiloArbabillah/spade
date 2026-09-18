"""Test flag CLI autentikasi & aktivasi: --cookie, -H, --bearer, --jwt-secrets,
--active-writes, --check-smuggling, --oob-host.

Fokusnya dua: parsing/validasi (gagal sebelum request pertama, exit code 2) dan
efek nyata di request (header benar-benar terkirim, rahasia tidak bocor ke
laporan).
"""

import json
import time
import urllib.parse

import pytest

import spade

SECRET_COOKIE_VALUE = "spade-dummy-session-value"
AUTH_CODES = ("idor", "csrf", "authbypass", "jwt", "hostheader")


@pytest.fixture(autouse=True)
def _restore_session_state():
    """Flag global (redaksi, workers) tidak boleh bocor ke test lain."""
    original = spade.REDACT_ENABLED
    yield
    spade.REDACT_ENABLED = original
    spade.set_request_executor(1)


# ══════════════════════════════════════════════════════════════════
# Parsing header autentikasi (unit, tanpa jaringan)
# ══════════════════════════════════════════════════════════════════

def test_build_auth_headers_combines_cookie_sources():
    headers = spade.build_auth_headers([f"sid={SECRET_COOKIE_VALUE}", "theme=dark"],
                                       ["Cookie: extra=1", "X-Api-Key: k"])
    assert headers["Cookie"] == f"sid={SECRET_COOKIE_VALUE}; theme=dark; extra=1"
    assert headers["X-Api-Key"] == "k"


def test_build_auth_headers_bearer_conflict_is_rejected():
    with pytest.raises(ValueError, match="bearer"):
        spade.build_auth_headers([], ["Authorization: Bearer abc"], bearer="xyz")


def test_parse_header_arg_rejects_missing_colon():
    with pytest.raises(ValueError, match="format header"):
        spade.parse_header_arg("X-Tanpa-Kolon")


def test_redact_auth_headers_hides_values():
    text = spade._redact_auth_headers({"Cookie": f"sid={SECRET_COOKIE_VALUE}",
                                       "Authorization": "Bearer abc", "X-Api-Key": "k"})
    assert SECRET_COOKIE_VALUE not in text
    assert "abc" not in text
    assert text.count("***") == 2
    assert "X-Api-Key=k" in text


# ══════════════════════════════════════════════════════════════════
# Validasi argumen gagal sebelum request pertama
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("argv, fragment", [
    (["--cookie", "tanpa-tanda-sama"], "cookie"),
    (["-H", "TanpaKolon"], "format header"),
    (["--bearer", "abc", "-H", "Authorization: Bearer def"], "bearer"),
    (["--oob-host", " "], "oob-host"),
    (["--oob-host", "spasi tidak boleh"], "oob-host"),
])
def test_invalid_auth_flags_exit_two_without_request(vuln_server, capsys, argv, fragment):
    """Argumen tidak valid harus ditolak argparse (SystemExit 2) sebelum request apa pun."""
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color", *argv])
    assert exc.value.code == 2
    assert fragment in capsys.readouterr().err
    assert vuln_server.app.requests == [], "validasi harus jalan sebelum request pertama"


def test_missing_jwt_secrets_file_exits_two(vuln_server, tmp_path, capsys):
    missing = tmp_path / "tidak-ada.txt"
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color", "--jwt-secrets", str(missing)])
    assert exc.value.code == 2
    assert "jwt-secrets" in capsys.readouterr().err
    assert vuln_server.app.requests == []


def test_empty_jwt_secrets_file_exits_two(vuln_server, tmp_path, capsys):
    empty = tmp_path / "kosong.txt"
    empty.write_text("# hanya komentar\n\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        spade.main([vuln_server.base_url, "--quick", "--no-color", "--jwt-secrets", str(empty)])
    assert exc.value.code == 2
    assert "satu secret per baris" in capsys.readouterr().err


# ══════════════════════════════════════════════════════════════════
# Header autentikasi benar-benar terkirim
# ══════════════════════════════════════════════════════════════════

def test_cli_sends_cookie_and_custom_header(vuln_server, tmp_path):
    out = tmp_path / "auth.html"
    assert spade.main([vuln_server.base_url, "--no-color",
                       "--cookie", f"sid={SECRET_COOKIE_VALUE}",
                       "-H", "X-Spade-Token: fixture",
                       "-o", str(out)]) == 0
    headers = vuln_server.app.headers_for("/")
    assert SECRET_COOKIE_VALUE in headers.get("cookie", "")
    assert headers.get("x-spade-token") == "fixture"


def test_cli_sends_bearer_token(vuln_server, tmp_path):
    out = tmp_path / "bearer.html"
    assert spade.main([vuln_server.base_url, "--no-color",
                       "--bearer", "spade.dummy.token", "-o", str(out)]) == 0
    assert vuln_server.app.headers_for("/").get("authorization") == "Bearer spade.dummy.token"


def test_cli_without_auth_flags_sends_no_credentials(vuln_server, tmp_path):
    """Tanpa flag auth, modul auth-only dimatikan supaya tidak ada klaim palsu."""
    assert spade.main([vuln_server.base_url, "--no-color",
                       "-o", str(tmp_path / "plain.html")]) == 0
    headers = vuln_server.app.headers_for("/")
    assert "authorization" not in headers


def test_auth_flag_enables_auth_only_modules(vuln_server, tmp_path, capsys):
    out = tmp_path / "detailed.html"
    assert spade.main([vuln_server.base_url, "--detailed", "--no-color",
                       "--cookie", f"sid={SECRET_COOKIE_VALUE}",
                       "--workers", "1", "--crawl-max", "5", "-o", str(out)]) == 0
    text = capsys.readouterr().out
    # Semua modul mode detailed dijalankan, termasuk yang butuh sesi autentikasi.
    for key in AUTH_CODES:
        assert spade.ALL_MODULES[key][0] in text, f"modul {key} tidak dijalankan"
    assert "Auth  : " in text


# ══════════════════════════════════════════════════════════════════
# Rahasia tidak boleh bocor ke laporan
# ══════════════════════════════════════════════════════════════════

def _scan_with_secret(target, tmp_path):
    json_out = tmp_path / "auth.json"
    html_out = tmp_path / "auth.html"
    assert spade.main([target, "--detailed", "--no-color", "--workers", "1",
                       "--crawl-max", "5",
                       "--cookie", f"sid={SECRET_COOKIE_VALUE}",
                       "-H", "Authorization: Bearer spade-dummy-bearer",
                       "-o", str(html_out), "--json", str(json_out)]) == 0
    return html_out.read_text(encoding="utf-8"), json_out.read_text(encoding="utf-8")


def _fixture_target(server):
    return urllib.parse.urlparse(server.base_url).netloc.split(":")[0]


def test_scan_output_never_contains_cookie_secret(auth_server, tmp_path):
    html, raw_json = _scan_with_secret(auth_server.base_url, tmp_path)
    assert SECRET_COOKIE_VALUE not in html, "cookie sesi bocor ke laporan HTML"
    assert SECRET_COOKIE_VALUE not in raw_json, "cookie sesi bocor ke laporan JSON"
    assert "spade-dummy-bearer" not in raw_json
    assert spade.REDACT_PLACEHOLDER in raw_json or "***" in raw_json


def test_json_scan_metadata_reports_auth_without_secrets(auth_server, tmp_path):
    _html, raw_json = _scan_with_secret(auth_server.base_url, tmp_path)
    payload = json.loads(raw_json)
    assert payload["scan"]["auth"] is True
    assert payload["scan"]["redacted"] is True
    assert SECRET_COOKIE_VALUE not in json.dumps(payload["scan"])


def test_console_banner_redacts_auth(capsys, auth_server, tmp_path):
    assert spade.main([auth_server.base_url, "--quick", "--no-color",
                       "--cookie", f"sid={SECRET_COOKIE_VALUE}",
                       "-o", str(tmp_path / "banner.html")]) == 0
    text = capsys.readouterr().out
    assert "Auth  : " in text
    assert SECRET_COOKIE_VALUE not in text


def test_cli_cookie_jwt_is_audited(jwt_server, tmp_path):
    """JWT yang dikirim lewat --cookie ikut diuji, bukan hanya cookie jar sesi.

    Regresi: `--cookie` disuntikkan sebagai header mentah, jadi tanpa parsing
    header `Cookie` token tester tidak pernah masuk kandidat uji JWT.
    """
    token = spade.jwt_sign({"alg": "HS256", "typ": "JWT"},
                           {"sub": "tester", "exp": int(time.time()) + 3600}, "secret")
    json_out = tmp_path / "jwt-cookie.json"
    assert spade.main([jwt_server.base_url, "--detailed", "--no-color", "--workers", "1",
                       "--crawl-max", "5", "--cookie", f"token={token}",
                       "-H", "X-Spade-Auth: 1",
                       "-o", str(tmp_path / "jwt-cookie.html"),
                       "--json", str(json_out)]) == 0
    raw = json_out.read_text(encoding="utf-8")
    payload = json.loads(raw)
    codes = {f["code"] for f in payload["findings"]}
    assert "JWT_WEAK_SECRET" in codes, "JWT dari --cookie tidak dianalisis"
    assert "SCAN_ERROR" not in codes
    assert token not in raw

# ══════════════════════════════════════════════════════════════════
# Flag aktivasi: --active-writes / --check-smuggling (+ gerbang otorisasi)
# ══════════════════════════════════════════════════════════════════

def test_active_writes_flag_warns_and_is_recorded(auth_server, tmp_path, capsys):
    json_out = tmp_path / "aw.json"
    assert spade.main([auth_server.base_url, "--detailed", "--no-color", "--workers", "1",
                       "--crawl-max", "5", "--active-writes",
                       "--i-have-authorization",
                       "--cookie", "sid=x", "-o", str(tmp_path / "aw.html"),
                       "--json", str(json_out)]) == 0
    assert "ACTIVE WRITES ON" in capsys.readouterr().out
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["active_writes"] is True
    assert payload["scan"]["authorized"] is True


def test_check_smuggling_flag_warns_and_is_recorded(vuln_server, tmp_path, capsys):
    json_out = tmp_path / "sm.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--check-smuggling",
                       "--i-have-authorization",
                       "-o", str(tmp_path / "sm.html"), "--json", str(json_out)]) == 0
    assert "REQUEST SMUGGLING ON" in capsys.readouterr().out
    assert json.loads(json_out.read_text(encoding="utf-8"))["scan"]["check_smuggling"] is True


def test_quick_mode_does_not_run_smuggling_or_oob(vuln_server, tmp_path):
    json_out = tmp_path / "quick.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "--check-smuggling", "-o", str(tmp_path / "quick.html"),
                       "--i-have-authorization",
                       "--json", str(json_out)]) == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert "smuggling" not in payload["scan"]["modules"]
    assert payload["scan"]["oob"] is False


def test_oob_flag_recorded_and_warns_on_self_reference(vuln_server, tmp_path, capsys):
    json_out = tmp_path / "oob.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "--oob-host", "127.0.0.1:9000", "-o", str(tmp_path / "oob.html"),
                       "--json", str(json_out)]) == 0
    text = capsys.readouterr().out
    assert "OOB   : collector" in text
    assert "host target yang sama" in text
    assert json.loads(json_out.read_text(encoding="utf-8"))["scan"]["oob"] is True


# ══════════════════════════════════════════════════════════════════
# Mode scan: anggota modul 7/19/32
# ══════════════════════════════════════════════════════════════════

def test_standard_mode_excludes_detailed_only_modules(vuln_server, tmp_path):
    json_out = tmp_path / "std.json"
    # Tanpa --quick/--detailed, mode default adalah standard (19 modul).
    assert spade.main([vuln_server.base_url, "--no-color",
                       "-o", str(tmp_path / "std.html"), "--json", str(json_out)]) == 0
    modules = json.loads(json_out.read_text(encoding="utf-8"))["scan"]["modules"]
    assert modules == spade.STANDARD_MODULES
    assert not set(modules) & spade.DETAILED_ONLY


def test_detailed_mode_runs_every_module(auth_server, tmp_path):
    json_out = tmp_path / "det.json"
    assert spade.main([auth_server.base_url, "--detailed", "--no-color", "--workers", "1",
                       "--crawl-max", "5", "--cookie", "sid=x",
                       "-o", str(tmp_path / "det.html"), "--json", str(json_out)]) == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["modules"] == list(spade.ALL_MODULES)
    assert payload["scan"]["errors"] == []


def test_detailed_mode_without_auth_skips_auth_modules_cleanly(vuln_server, tmp_path):
    """Tanpa sesi auth, modul auth-only harus mengembalikan kosong tanpa error."""
    json_out = tmp_path / "noauth.json"
    assert spade.main([vuln_server.base_url, "--detailed", "--no-color", "--workers", "1",
                       "--crawl-max", "5", "-o", str(tmp_path / "noauth.html"),
                       "--json", str(json_out)]) == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["errors"] == []
    assert "SCAN_ERROR" not in {f["code"] for f in payload["findings"]}
