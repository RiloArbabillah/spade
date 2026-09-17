"""Test model temuan: kompatibilitas tuple, metadata, redaksi, dan PoC reproduksi.

Model `Finding` sengaja tetap kompatibel dengan tuple lama `(sev, code, desc, url)`
karena seluruh modul scan dan generator laporan memakai bentuk itu. Test di sini
mengunci kompatibilitas tersebut sekaligus perilaku metadata/bukti yang baru.
"""

import json
import math

import pytest

import spade


@pytest.fixture(autouse=True)
def _isolate_evidence():
    """Indeks bukti bersifat global — bersihkan sebelum/sesudah tiap test."""
    spade.reset_evidence()
    original = spade.REDACT_ENABLED
    yield
    spade.REDACT_ENABLED = original
    spade.reset_evidence()

# ── kompatibilitas tuple lama ──

def test_finding_behaves_like_legacy_tuple():
    finding = spade.Finding("HIGH", "SQLI", "rentan", "http://t/item?id=1")
    assert len(finding) == 4
    assert tuple(finding) == ("HIGH", "SQLI", "rentan", "http://t/item?id=1")
    assert finding[0] == "HIGH" and finding[3] == "http://t/item?id=1"
    sev, code, desc, url = finding
    assert (sev, code, desc, url) == tuple(finding)
    # Kode lama membandingkan temuan dengan tuple; itu harus tetap benar.
    assert finding == ("HIGH", "SQLI", "rentan", "http://t/item?id=1")
    assert finding == spade.Finding("HIGH", "SQLI", "rentan", "http://t/item?id=1")
    assert hash(finding) == hash(("HIGH", "SQLI", "rentan", "http://t/item?id=1"))

def test_as_finding_normalizes_tuples():
    assert spade.as_finding(("LOW", "X", "y")).url is None
    same = spade.Finding("LOW", "X", "y")
    assert spade.as_finding(same) is same

def test_finding_list_extends_with_tuples_and_single_finding():
    flist = spade.FindingList()
    flist.append(("LOW", "A", "a", "http://t/a"))
    flist.extend([("LOW", "B", "b", "http://t/b")])
    flist.extend(("LOW", "C", "c", "http://t/c"))
    assert [f.code for f in flist] == ["A", "B", "C"]
    assert all(isinstance(f, spade.Finding) for f in flist)

# ── metadata CVSS/CWE/OWASP/confidence ──

def test_known_codes_have_verified_cvss_metadata():
    meta = spade.finding_meta("SQLI")
    assert meta.vector.startswith("CVSS:3.1/")
    assert meta.score == 9.8
    assert meta.cwe == "CWE-89"
    assert meta.owasp == "A03:2021"

def test_unknown_code_never_invents_cvss():
    assert spade.finding_meta("KODE_YANG_BELUM_ADA") is None
    finding = spade.Finding("LOW", "KODE_YANG_BELUM_ADA", "belum dipetakan")
    assert finding.meta is None
    assert spade.cvss_of(finding.meta) is None
    # Confidence tetap punya default yang aman.
    assert finding.confidence == "firm"

def test_prefix_families_get_metadata():
    for code, cwe in (("MISS_HSTS", "CWE-693"), ("HDR_X_POWERED_BY", "CWE-693"),
                      ("WEAK_TLS", "CWE-327")):
        meta = spade.finding_meta(code)
        assert meta is not None, code
        assert meta.cwe == cwe

def test_tentative_codes_are_forced_tentative():
    assert spade.finding_confidence("SSRF") == "tentative"
    assert spade.finding_confidence("CORS_REFLECT") == "tentative"
    assert spade.finding_confidence("SQLI") == "firm"
    # Deklarasi eksplisit tidak bisa menaikkan kode yang belum terverifikasi.
    assert spade.finding_confidence("SSRF", "certain") == "tentative"
    assert spade.finding_confidence("SQLI", "certain") == "certain"

def test_all_confidence_values_are_known_levels():
    for code in list(spade.FINDING_META):
        assert spade.finding_confidence(code) in spade.CONFIDENCE_LEVELS
    assert spade.finding_confidence("MISS_ANY") in spade.CONFIDENCE_LEVELS

def test_cvss_scores_match_their_vectors():
    """Setiap skor di tabel harus konsisten dengan vector CVSS 3.1-nya.

    Skor dihitung ulang dari vector memakai rumus CVSS 3.1 yang sama seperti
    CVSS v3.1 specification, tanpa memanggil library eksternal.
    """
    def base_score(vector):
        metrics = dict(part.split(":") for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        if scope_changed:
            pr = {"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[metrics["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        impact_sum = 1 - (1 - cia[metrics["C"]]) * (1 - cia[metrics["I"]]) * (1 - cia[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (impact_sum - 0.029) - 3.25 * (impact_sum - 0.02) ** 15
        else:
            impact = 6.42 * impact_sum
        expl = 8.22 * av * ac * pr * ui
        if impact <= 0:
            return 0.0
        raw = min((1.08 if scope_changed else 1.0) * (impact + expl), 10.0)
        # CVSS 3.1 Roundup: selalu dibulatkan ke atas pada 1 desimal.
        return math.ceil(raw * 10 - 1e-9) / 10

    for code, meta in spade.FINDING_META.items():
        if not meta.vector:
            continue
        assert base_score(meta.vector) == pytest.approx(meta.score, abs=0.001), code

# ── redaksi ──

def test_redact_headers_masks_secrets_but_keeps_shape():
    masked = spade.redact_headers({"Cookie": "sid=abc123; theme=dark",
                                   "Authorization": "Bearer token",
                                   "X-Custom": "boleh"})
    assert masked["Cookie"] == f"sid={spade.REDACT_PLACEHOLDER}; theme={spade.REDACT_PLACEHOLDER}"
    assert masked["Authorization"] == spade.REDACT_PLACEHOLDER
    assert masked["X-Custom"] == "boleh"

def test_redact_headers_can_be_disabled():
    masked = spade.redact_headers({"Authorization": "Bearer token"}, enabled=False)
    assert masked["Authorization"] == "Bearer token"

def test_redact_body_masks_form_and_json():
    assert spade.redact_body("user=admin&password=hunter2") == \
        f"user=admin&password={spade.REDACT_PLACEHOLDER}"
    assert json.loads(spade.redact_body('{"user":"admin","api_key":"abc"}')) == \
        {"user": "admin", "api_key": spade.REDACT_PLACEHOLDER}
    assert json.loads(spade.redact_body('{"nested":{"token":"x"}}')) == \
        {"nested": {"token": spade.REDACT_PLACEHOLDER}}

def test_redact_url_masks_sensitive_query_values():
    assert spade.redact_url("http://t/cb?token=abc&q=1") == \
        f"http://t/cb?token={spade.REDACT_PLACEHOLDER}&q=1"
    assert spade.redact_url("http://t/plain") == "http://t/plain"

def test_exchange_redacts_at_construction_time():
    """Exchange hasil konstruksi langsung tidak boleh menyimpan nilai sensitif."""
    exchange = spade.Exchange(
        method="POST",
        url="http://t/login?token=abc",
        status=200,
        request_headers={"Cookie": "sid=abc", "Authorization": "Bearer zzz"},
        request_body="user=admin&password=hunter2",
    )
    assert exchange.url == f"http://t/login?token={spade.REDACT_PLACEHOLDER}"
    assert exchange.request_headers["Cookie"] == f"sid={spade.REDACT_PLACEHOLDER}"
    assert exchange.request_headers["Authorization"] == spade.REDACT_PLACEHOLDER
    assert exchange.request_body == f"user=admin&password={spade.REDACT_PLACEHOLDER}"
    dumped = json.dumps(exchange.to_dict())
    assert "hunter2" not in dumped
    assert "Bearer zzz" not in dumped

# ── indeks bukti ──

def _exchange(method="GET", url="http://t/a", status=200, body=b"hello"):
    return spade.Exchange(method=method, url=url, status=status, response_snippet=body.decode())

def test_evidence_lookup_by_url_and_path():
    spade.record_exchange(_exchange(url="http://t/a?x=1"))
    assert spade.evidence_for("http://t/a?x=1").status == 200
    # Path saja tanpa query tetap menemukan bukti.
    assert spade.evidence_for("http://t/a").status == 200
    # URL yang tidak dikenal jatuh ke "request terakhir di thread ini" — ini
    # fallback yang disengaja untuk modul yang meng-append temuan tepat setelah
    # request pemicunya.
    assert spade.evidence_for("http://t/tidak-ada").url == "http://t/a?x=1"

def test_evidence_for_returns_none_when_index_is_empty():
    assert spade.evidence_for("http://t/a") is None
    assert spade.evidence_for() is None

def test_evidence_lookup_is_method_aware():
    spade.record_exchange(_exchange(method="OPTIONS", url="http://t/a", body=b"options"))
    spade.record_exchange(_exchange(method="GET", url="http://t/a", body=b"get"))
    assert spade.evidence_for("http://t/a", "OPTIONS").response_snippet == "options"
    assert spade.evidence_for("http://t/a", "GET").response_snippet == "get"
    # GET dan OPTIONS pada URL yang sama tidak boleh saling menimpa.
    assert spade.evidence_for("http://t/a", "TRACE") is not None

def test_evidence_falls_back_to_base_url():
    spade.set_evidence_base_url("http://t/")
    spade.record_exchange(_exchange(url="http://t/", body=b"root"))
    assert spade.evidence_for("http://t/nowhere").response_snippet == "root"

def test_reset_evidence_clears_index():
    spade.set_evidence_base_url("http://t/")
    spade.record_exchange(_exchange(url="http://t/a"))
    spade.reset_evidence()
    assert spade.evidence_for("http://t/a") is None
    assert spade.EVIDENCE_BASE_URL is None

def test_evidence_index_is_bounded():
    for index in range(spade.EVIDENCE_MAX_KEYS + 10):
        spade.record_exchange(_exchange(url=f"http://t/p{index}"))
    assert len(spade._EVIDENCE_BY_KEY) <= spade.EVIDENCE_MAX_KEYS
    # Entri terlama yang dibuang, yang terbaru tetap ada.
    assert spade.evidence_for(f"http://t/p{spade.EVIDENCE_MAX_KEYS + 9}") is not None

def test_finding_list_attaches_evidence_automatically():
    spade.record_exchange(_exchange(url="http://t/a", body=b"bukti"))
    flist = spade.FindingList()
    flist.append(("HIGH", "DIR_LISTING", "listing aktif", "http://t/a"))
    assert flist[0].evidence is not None
    assert flist[0].evidence.response_snippet == "bukti"

def test_finding_list_capture_false_skips_evidence():
    """Modul non-HTTP (mis. handshake TLS) tidak boleh dipaksa memakai bukti HTTP."""
    spade.record_exchange(_exchange(url="http://t/a"))
    flist = spade.FindingList(capture=False)
    flist.append(("LOW", "TLS_EXPIRING", "sertifikat hampir kedaluwarsa", None))
    assert flist[0].evidence is None

def test_exchange_from_response_reads_request_body_and_headers():
    class _Request:
        headers = {"X-A": "1"}
        body = b"a=1&password=rahasia"

    class _Response:
        request = _Request()
        url = "http://t/post"
        status_code = 200
        content = b"ok"
        headers = {"Content-Type": "text/plain"}

    exchange = spade.exchange_from_response(_Response(), "POST")
    assert exchange.request_body == f"a=1&password={spade.REDACT_PLACEHOLDER}"
    assert exchange.request_headers == {"X-A": "1"}
    assert exchange.response_snippet == "ok"
    assert exchange.content_type == "text/plain"
    assert exchange.path == "/post"

def test_exchange_from_response_survives_missing_request():
    class _Response:
        url = "http://t/x"
        status_code = 500
        content = b""
        headers = {}

    exchange = spade.exchange_from_response(_Response(), "GET")
    assert exchange.status == 500
    assert exchange.request_body is None

def test_exchange_from_response_falls_back_to_kwargs():
    class _Response:
        request = None
        url = "http://t/x"
        status_code = 200
        content = b""
        headers = {}

    exchange = spade.exchange_from_response(_Response(), "POST",
                                            kwargs={"data": {"password": "x"}})
    assert json.loads(exchange.request_body) == {"password": spade.REDACT_PLACEHOLDER}

def test_session_cookie_is_added_to_evidence_but_redacted():
    class _Response:
        request = None
        url = "http://t/x"
        status_code = 200
        content = b""
        headers = {}

    exchange = spade.exchange_from_response(_Response(), "GET",
                                            session_cookies=[("sid", "abc")])
    assert exchange.request_headers["Cookie"] == f"sid={spade.REDACT_PLACEHOLDER}"

# ── PoC reproduksi ──

def test_repro_curl_builds_portable_command_and_python_snippet():
    exchange = spade.Exchange(
        method="POST",
        url="http://t/item?id=1",
        status=200,
        request_headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Cookie": "sid=abc",
                         "Content-Length": "9"},
        request_body="id=1&s=q",
    )
    repro = spade.repro_curl(exchange)
    assert repro["curl"].startswith("curl -sS -i -X POST")
    # Cookie diganti placeholder, dan header yang diurus curl sendiri dibuang.
    assert "COOKIE_ANDA" in repro["curl"]
    assert "sid=abc" not in repro["curl"]
    assert "Content-Length" not in repro["curl"]
    assert "--data-raw 'id=1&s=q'" in repro["curl"]
    assert "from curl_cffi import requests" in repro["python_curl_cffi"]
    assert "impersonate=" in repro["python_curl_cffi"]

def test_repro_curl_shell_quotes_single_quotes():
    exchange = spade.Exchange(method="GET", url="http://t/?q=' OR '1'='1", status=200)
    assert "'\\''" in spade.repro_curl(exchange)["curl"]

def test_repro_curl_returns_empty_strings_without_evidence():
    assert spade.repro_curl(None) == {"curl": "", "python_curl_cffi": ""}

def test_repro_curl_reconstructs_json_body_python_side():
    exchange = spade.Exchange(method="POST", url="http://t/api", status=200,
                              request_headers={"Content-Type": "application/json"},
                              request_body='{"q": "x"}')
    repro = spade.repro_curl(exchange)
    assert "json=" in repro["python_curl_cffi"]
    assert "--data-raw" in repro["curl"]

# ── finding id ──

def test_finding_id_is_stable_and_content_addressed():
    first = spade.make_finding_id("SQLI", "http://t/a", "rentan")
    assert first == spade.make_finding_id("SQLI", "http://t/a", "rentan")
    assert first != spade.make_finding_id("SQLI", "http://t/b", "rentan")
    assert first.startswith("spade-") and len(first) == len("spade-") + 12
