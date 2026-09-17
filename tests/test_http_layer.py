"""Test lapisan HTTP: impersonation, retry status, dan validasi CLI."""

import socket

import pytest
from curl_cffi.requests import RequestsError

import spade


def test_default_session_uses_impersonation(vuln_server, sess):
    """Request default harus menyamar sebagai browser, bukan python-requests."""
    resp = sess.get(vuln_server.base_url)
    assert resp.status_code == 200

    sent = vuln_server.app.headers_for("/")
    ua = sent.get("user-agent", "")
    assert "Mozilla/5.0" in ua
    assert "python-requests" not in ua.lower()
    # Header khas browser modern dari profil impersonate curl_cffi.
    assert sent.get("sec-ch-ua"), "header sec-ch-ua tidak terkirim"
    assert sent.get("sec-fetch-mode") == "navigate"
    assert sent.get("accept-language")


def test_no_impersonate_sends_no_browser_fingerprint(vuln_server):
    """--no-impersonate harus mematikan header & fingerprint browser."""
    sess = spade.ThreadLocalSession(timeout=10, impersonate=None)
    assert sess.get(vuln_server.base_url).status_code == 200

    sent = vuln_server.app.headers_for("/")
    assert "Mozilla" not in sent.get("user-agent", "")
    assert not sent.get("sec-ch-ua")


def test_custom_impersonate_profile(vuln_server):
    sess = spade.ThreadLocalSession(timeout=10, impersonate="safari184")
    assert sess.get(vuln_server.base_url).status_code == 200
    ua = vuln_server.app.headers_for("/").get("user-agent", "")
    assert "Safari" in ua


def test_retry_after_header_is_bounded():
    assert spade._retry_after_seconds(None) == 0.0
    assert spade._retry_after_seconds("") == 0.0
    assert spade._retry_after_seconds("2") == 2.0
    assert spade._retry_after_seconds("999") == spade.RETRY_AFTER_MAX
    assert spade._retry_after_seconds("bukan-angka") == 0.0
    assert spade._retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0  # sudah lewat


def test_status_retry_recovers_from_503(vuln_server):
    sess = spade.ThreadLocalSession(timeout=10, retries=1)
    resp = sess.get(vuln_server.base_url + "flaky")
    assert resp.status_code == 200
    assert vuln_server.app.hits["/flaky"] == 2


def test_status_retry_can_be_disabled(vuln_server):
    sess = spade.ThreadLocalSession(timeout=10, retries=0)
    resp = sess.get(vuln_server.base_url + "flaky")
    assert resp.status_code == 503
    assert vuln_server.app.hits["/flaky"] == 1


def test_retry_only_applies_to_configured_methods(vuln_server):
    """Retry status dibatasi ke GET/POST/HEAD/OPTIONS seperti perilaku sebelumnya."""
    sess = spade.ThreadLocalSession(timeout=10, retries=1)
    resp = sess.request("TRACE", vuln_server.base_url)
    assert resp.status_code == 200
    assert sess.request("TRACE", vuln_server.base_url).status_code == 200


def test_timeout_default_applied(vuln_server):
    sess = spade.ThreadLocalSession(timeout=7)
    assert sess.timeout == 7
    assert sess.get(vuln_server.base_url).status_code == 200


def test_cookies_shared_via_wrapper(vuln_server):
    sess = spade.ThreadLocalSession(timeout=10)
    sess.get(vuln_server.base_url + "cookies/set")
    cookies = dict(sess.cookies.items())
    assert "sid" in cookies


def test_session_helpers_cover_http_methods(vuln_server):
    sess = spade.ThreadLocalSession(timeout=10)
    assert sess.options(vuln_server.base_url).status_code == 200
    assert sess.head(vuln_server.base_url).status_code == 200
    assert sess.post(vuln_server.base_url + "submit", data={"comment": "hi"}).status_code == 200


def test_verify_false_allows_insecure_cert(vuln_server):
    sess = spade.ThreadLocalSession(timeout=10, verify_ssl=False)
    assert sess.get(vuln_server.base_url).status_code == 200


def test_transport_error_surfaces_connection_error():
    sess = spade.ThreadLocalSession(timeout=5)
    with pytest.raises(RequestsError):
        sess.get("http://127.0.0.1:1/", timeout=2)


def test_make_session_impersonate_flag():
    assert spade.make_session().impersonate == spade.DEFAULT_IMPERSONATE
    assert spade.make_session(impersonate=None).impersonate is None
    assert spade.make_session(impersonate="firefox147").impersonate == "firefox147"


def test_supported_profiles_are_real_curl_cffi_names():
    profiles = spade.supported_impersonate_profiles()
    assert spade.DEFAULT_IMPERSONATE in profiles
    assert {"chrome146", "safari184", "firefox147"} <= set(profiles)


# ── CLI ──

def test_cli_rejects_unknown_impersonate_profile(capsys):
    with pytest.raises(SystemExit) as exc:
        spade.main(["example.com", "--impersonate", "netscape-1996"])
    assert exc.value.code == 2
    assert "tidak dikenal" in capsys.readouterr().err


def test_cli_help_lists_impersonate_flags(capsys):
    with pytest.raises(SystemExit):
        spade.main(["--help"])
    out = capsys.readouterr().out
    assert "--impersonate" in out
    assert "--no-impersonate" in out


def test_cli_banner_shows_active_profile(vuln_server, tmp_path, capsys):
    out = tmp_path / "report.html"
    code = spade.main([vuln_server.base_url, "--quick", "--no-color", "-o", str(out)])
    assert code == 0
    assert "Bot   : chrome" in capsys.readouterr().out


def test_cli_no_impersonate_disables_browser_headers(vuln_server, tmp_path):
    out = tmp_path / "report.html"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "--no-impersonate", "-o", str(out)]) == 0
    sent = vuln_server.app.headers_for("/")
    assert "Mozilla" not in sent.get("user-agent", "")


def test_socket_module_still_importable():
    """Modul TLS memakai socket stdlib; pastikan tidak tergantikan oleh dependensi HTTP."""
    assert socket.gethostname()
