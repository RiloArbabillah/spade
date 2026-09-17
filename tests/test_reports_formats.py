"""Test laporan JSON, SARIF, dan blok bukti di HTML.

Semua test di sini memakai temuan buatan (tanpa jaringan) supaya bentuk output
terkunci dan bisa dibandingkan antar perubahan.
"""

import json
from datetime import datetime

import pytest

import spade


@pytest.fixture(autouse=True)
def _isolate_evidence():
    spade.reset_evidence()
    original = spade.REDACT_ENABLED
    yield
    spade.REDACT_ENABLED = original
    spade.reset_evidence()

def _sample_exchange():
    return spade.Exchange(
        method="POST",
        url="http://target.test/submit?token=rahasia",
        status=200,
        request_headers={"Content-Type": "application/x-www-form-urlencoded",
                         "Cookie": "sid=abc", "Authorization": "Bearer zzz"},
        request_body="comment=%3Cscript%3E&password=rahasia",
        response_headers={"Content-Type": "text/html"},
        response_snippet="<html>Komentar tersimpan</html>",
        response_length=30,
        elapsed_ms=12.5,
    )

@pytest.fixture
def findings():
    return [
        spade.Finding("HIGH", "XSS_POST", "Field komentar rentan XSS",
                      "http://target.test/submit", evidence=_sample_exchange()),
        spade.Finding("LOW", "COOKIE_ISSUE", "Cookie tanpa flag Secure", None),
    ]

def _scan_meta():
    return {
        "mode": "detailed",
        "started_at": "2026-09-17T10:00:00",
        "finished_at": "2026-09-17T10:01:00",
        "duration_s": 60.0,
        "impersonate": "chrome",
        "workers": 4,
        "modules": ["tech", "headers"],
        "errors": [],
        "redacted": True,
    }

# ── JSON ──

def test_gen_json_schema_and_summary(tmp_path, findings):
    out = tmp_path / "report.json"
    assert spade.gen_json(findings, "http://target.test/", str(out), scan=_scan_meta()) == str(out)
    payload = json.loads(out.read_text(encoding="utf-8"))

    assert payload["tool"] == {"name": "spade", "version": spade.SPADE_VERSION}
    assert payload["target"] == "http://target.test/"
    assert payload["scan"]["mode"] == "detailed"
    assert payload["scan"]["impersonate"] == "chrome"
    assert payload["scan"]["duration_s"] == 60.0
    assert payload["scan"]["errors"] == []
    assert payload["summary"] == {"total": 2, "by_severity": {"HIGH": 1, "LOW": 1},
                                  "by_confidence": {"firm": 2}}
    assert len(payload["findings"]) == 2

def test_gen_json_finding_fields(tmp_path, findings):
    out = tmp_path / "report.json"
    spade.gen_json(findings, "http://target.test/", str(out), scan=_scan_meta())
    payload = json.loads(out.read_text(encoding="utf-8"))
    xss = payload["findings"][0]

    assert xss["id"].startswith("spade-")
    assert xss["severity"] == "HIGH"
    assert xss["code"] == "XSS_POST"
    assert xss["confidence"] == "firm"
    assert xss["cvss"]["score"] == 6.1
    assert xss["cvss"]["vector"].startswith("CVSS:3.1/")
    assert xss["cwe"] == "CWE-79"
    assert xss["owasp"] == "A03:2021"
    assert xss["evidence"]["status"] == 200
    assert xss["evidence"]["method"] == "POST"
    assert xss["evidence"]["response_length"] == 30
    assert xss["repro"]["curl"].startswith("curl -sS -i")

def test_gen_json_redacts_secrets_by_default(tmp_path, findings):
    out = tmp_path / "report.json"
    spade.gen_json(findings, "http://target.test/", str(out), scan=_scan_meta())
    raw = out.read_text(encoding="utf-8")
    assert "rahasia" not in raw
    assert "Bearer zzz" not in raw
    assert "sid=abc" not in raw
    assert spade.REDACT_PLACEHOLDER in raw

def test_gen_json_can_disable_redaction(tmp_path):
    """--no-redact harus benar-benar mematikan sensor (dan disadari risikonya).

    Sensor dipasang saat Exchange dibuat, jadi urutannya harus sama seperti CLI:
    matikan sensor dulu, baru lakukan request.
    """
    spade.REDACT_ENABLED = False
    findings = [spade.Finding("HIGH", "XSS_POST", "Field komentar rentan XSS",
                              "http://target.test/submit", evidence=_sample_exchange())]
    out = tmp_path / "plain.json"
    spade.gen_json(findings, "http://target.test/", str(out), scan=_scan_meta())
    raw = out.read_text(encoding="utf-8")
    assert "rahasia" in raw
    assert "Bearer zzz" in raw

def test_gen_json_info_finding_has_no_cvss(tmp_path):
    out = tmp_path / "info.json"
    spade.gen_json([spade.Finding("INFO", "TECH", "Teknologi: nginx")],
                   "http://t/", str(out), scan=_scan_meta())
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["findings"][0]["cvss"] is None
    assert payload["findings"][0]["cwe"] == "CWE-200"
    assert payload["findings"][0]["evidence"] is None
    assert payload["findings"][0]["repro"] == {"curl": "", "python_curl_cffi": ""}

def test_gen_json_truncates_long_response(tmp_path):
    exchange = spade.Exchange(method="GET", url="http://t/big", status=200,
                              response_snippet="A" * (spade.EVIDENCE_SNIPPET_CHARS_JSON + 500),
                              response_length=spade.EVIDENCE_SNIPPET_CHARS_JSON + 500)
    out = tmp_path / "big.json"
    spade.gen_json([spade.Finding("LOW", "X", "y", "http://t/big", evidence=exchange)],
                   "http://t/", str(out))
    payload = json.loads(out.read_text(encoding="utf-8"))
    evidence = payload["findings"][0]["evidence"]
    assert len(evidence["response_snippet"]) == spade.EVIDENCE_SNIPPET_CHARS_JSON
    assert evidence["response_truncated"] is True

# ── SARIF ──

def test_gen_sarif_document_shape(tmp_path, findings):
    out = tmp_path / "report.sarif"
    assert spade.gen_sarif(findings, "http://target.test/", str(out), scan=_scan_meta()) == str(out)
    document = json.loads(out.read_text(encoding="utf-8"))

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    assert len(document["runs"]) == 1
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "spade"
    assert run["tool"]["driver"]["version"] == spade.SPADE_VERSION
    assert run["invocations"][0]["startTimeUtc"] == "2026-09-17T10:00:00"

def test_gen_sarif_rules_and_results_are_linked(tmp_path, findings):
    out = tmp_path / "report.sarif"
    spade.gen_sarif(findings, "http://target.test/", str(out), scan=_scan_meta())
    run = json.loads(out.read_text(encoding="utf-8"))["runs"][0]

    rules = run["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["XSS_POST", "COOKIE_ISSUE"]
    for result in run["results"]:
        # ruleIndex harus menunjuk rule dengan id yang sama.
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["partialFingerprints"]["findingId"].startswith("spade-")
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    xss = run["results"][0]
    assert xss["level"] == "error"
    assert xss["properties"]["confidence"] == "firm"
    assert xss["properties"]["cwe"] == "CWE-79"
    assert run["results"][1]["level"] == "note"

def test_gen_sarif_severity_to_level_mapping():
    assert spade.SarifLevels == {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                                "LOW": "note", "INFO": "note"}

def test_gen_sarif_includes_help_uri(tmp_path):
    out = tmp_path / "report.sarif"
    spade.gen_sarif([spade.Finding("HIGH", "SQLI", "rentan")], "http://t/", str(out))
    rule = json.loads(out.read_text(encoding="utf-8"))["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"

def test_gen_sarif_deduplicates_rules(tmp_path):
    out = tmp_path / "report.sarif"
    spade.gen_sarif([spade.Finding("HIGH", "SQLI", "a", "http://t/1"),
                     spade.Finding("HIGH", "SQLI", "b", "http://t/2")], "http://t/", str(out))
    run = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2

def test_gen_sarif_handles_empty_findings(tmp_path):
    out = tmp_path / "empty.sarif"
    spade.gen_sarif([], "http://t/", str(out))
    run = json.loads(out.read_text(encoding="utf-8"))["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []

def test_gen_sarif_redacts_secrets(tmp_path, findings):
    out = tmp_path / "report.sarif"
    spade.gen_sarif(findings, "http://target.test/", str(out))
    raw = out.read_text(encoding="utf-8")
    assert "rahasia" not in raw
    assert spade.REDACT_PLACEHOLDER in raw

# ── HTML ──

def test_gen_html_includes_evidence_block(tmp_path, findings):
    out = tmp_path / "report.html"
    spade.gen_html(findings, "http://target.test/", datetime.now(), datetime.now(),
                   str(out), impersonate="chrome")
    body = out.read_text(encoding="utf-8")
    assert "Bukti &amp; repro" in body
    assert "Reproduksi (curl)" in body
    assert "Reproduksi (curl_cffi)" in body
    assert "Request headers (redaksi)" in body
    assert "Potongan respons" in body
    assert "confidence: firm" in body
    assert "CVSS 6.1" in body
    assert "CWE-79" in body

def test_gen_html_notes_missing_http_evidence(tmp_path):
    out = tmp_path / "report.html"
    spade.gen_html([spade.Finding("LOW", "TLS_EXP_SOON", "hampir kedaluwarsa")],
                   "http://target.test/", datetime.now(), datetime.now(), str(out))
    body = out.read_text(encoding="utf-8")
    assert "Tidak ada bukti HTTP" in body

def test_gen_html_does_not_leak_secrets(tmp_path, findings):
    out = tmp_path / "report.html"
    spade.gen_html(findings, "http://target.test/", datetime.now(), datetime.now(), str(out))
    body = out.read_text(encoding="utf-8")
    assert "rahasia" not in body
    assert "Bearer zzz" not in body

def test_gen_html_escapes_evidence_content(tmp_path):
    exchange = spade.Exchange(method="GET", url="http://t/x", status=200,
                              response_snippet="<script>alert(1)</script>")
    out = tmp_path / "esc.html"
    spade.gen_html([spade.Finding("LOW", "X", "y", "http://t/x", evidence=exchange)],
                   "http://t/", datetime.now(), datetime.now(), str(out))
    body = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body

# ── helper ──

def test_scan_summary_counts_by_severity_and_confidence(findings):
    summary = spade.scan_summary([spade.as_finding(f) for f in findings])
    assert summary["total"] == 2
    assert summary["by_severity"] == {"HIGH": 1, "LOW": 1}
    assert summary["by_confidence"] == {"firm": 2}

def test_scan_summary_on_empty_list():
    assert spade.scan_summary([]) == {"total": 0, "by_severity": {}, "by_confidence": {}}

def test_confidence_badge_formats_metadata(findings):
    badge = spade.confidence_badge(findings[0])
    assert badge.startswith("confidence: firm")
    assert "CVSS 6.1" in badge
    assert "CWE-79" in badge
    assert "A03:2021" in badge

def test_evidence_status_and_url(findings):
    assert spade.evidence_status(findings[0]) == "http"
    assert spade.evidence_status(findings[1]) == "none"
    assert spade.evidence_url(findings[0]) == "http://target.test/submit?token=" + spade.REDACT_PLACEHOLDER
    assert spade.evidence_url(findings[1]) == ""

def test_legacy_tuples_still_render(tmp_path):
    """Generator laporan harus tetap menerima tuple lama tanpa perubahan."""
    out = tmp_path / "legacy.json"
    spade.gen_json([("CRITICAL", "SENSITIVE_FILE", "File .env terbuka", "http://t/.env")],
                   "http://t/", str(out))
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["findings"][0]["code"] == "SENSITIVE_FILE"
    assert payload["findings"][0]["cvss"]["score"] == 7.5
