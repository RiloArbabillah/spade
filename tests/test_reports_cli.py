"""Test generator laporan (HTML/CSV) dan perilaku CLI."""

import csv
import json
from datetime import datetime

import pytest

import spade

CSV_HEADER = ["Severity", "Category", "Detail", "URL", "Target", "Confidence", "CVSS_Score",
              "CVSS_Vector", "CWE", "OWASP", "Repro_Curl", "Evidence_Status", "Evidence_URL"]


@pytest.fixture(autouse=True)
def _restore_redaction():
    """`--no-redact` mengubah flag global; pastikan tidak bocor ke test lain."""
    original = spade.REDACT_ENABLED
    yield
    spade.REDACT_ENABLED = original


@pytest.fixture
def findings():
    return [
        ("CRITICAL", "SENSITIVE_FILE", "File /.env dapat diakses publik", "http://target.test/.env"),
        ("HIGH", "SQLI", "Parameter 'id' rentan SQL injection", "http://target.test/item?id=1"),
        ("LOW", "COOKIE_ISSUE", "Cookie tidak memiliki flag Secure", None),
    ]


def test_gen_html_contains_findings(tmp_path, findings):
    out = tmp_path / "report.html"
    start = datetime(2026, 9, 17, 10, 0, 0)
    end = datetime(2026, 9, 17, 10, 1, 30)
    assert spade.gen_html(findings, "http://target.test/", start, end, str(out)) == str(out)

    body = out.read_text(encoding="utf-8")
    assert "Spade Scan Report" in body
    assert "http://target.test/" in body
    assert "SENSITIVE_FILE" in body
    assert "SQLI" in body
    # Durasi dihitung dari start/end
    assert "90.0s" in body


def test_gen_html_orders_by_severity(tmp_path, findings):
    out = tmp_path / "report.html"
    spade.gen_html(findings, "http://target.test/", datetime.now(), datetime.now(), str(out))
    body = out.read_text(encoding="utf-8")
    assert body.index("CRITICAL") < body.index("SQLI") < body.index("COOKIE_ISSUE")


def test_gen_html_escapes_target(tmp_path):
    out = tmp_path / "report.html"
    spade.gen_html([], "<script>alert(1)</script>", datetime.now(), datetime.now(), str(out))
    body = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body


def test_gen_html_handles_empty_findings(tmp_path):
    out = tmp_path / "report.html"
    spade.gen_html([], "http://target.test/", datetime.now(), datetime.now(), str(out))
    assert "Spade Scan Report" in out.read_text(encoding="utf-8")


def test_gen_csv_columns_and_rows(tmp_path, findings):
    out = tmp_path / "report.csv"
    spade.gen_csv(findings, "http://target.test/", str(out))

    with out.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == CSV_HEADER
    assert len(rows) == len(findings) + 1
    assert rows[1][0] == "CRITICAL"
    assert rows[1][4] == "http://target.test/"
    assert rows[3][3] == ""
    # Lima kolom lama tetap di posisi semula supaya konsumen CSV lama tidak rusak.
    assert rows[1][:5] == ["CRITICAL", "SENSITIVE_FILE", "File /.env dapat diakses publik",
                           "http://target.test/.env", "http://target.test/"]


def test_gen_csv_metadata_columns(tmp_path, findings):
    """Kolom metadata/bukti baru terisi dari tabel meta dan exchange temuan."""
    out = tmp_path / "report.csv"
    spade.gen_csv(findings, "http://target.test/", str(out))

    with out.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    index = {name: i for i, name in enumerate(rows[0])}
    sqli = rows[2]
    assert sqli[index["Confidence"]] == "firm"
    assert sqli[index["CVSS_Score"]] == "9.8"
    assert sqli[index["CVSS_Vector"]].startswith("CVSS:3.1/")
    assert sqli[index["CWE"]] == "CWE-89"
    assert sqli[index["OWASP"]] == "A03:2021"
    # Tanpa exchange, bukti tidak dikarang.
    assert sqli[index["Evidence_Status"]] == "none"
    assert sqli[index["Evidence_URL"]] == ""
    assert sqli[index["Repro_Curl"]] == ""

    cookie = rows[3]
    assert cookie[index["Confidence"]] == "firm"
    assert cookie[index["CVSS_Score"]] == "5.3"
    assert cookie[index["CWE"]] == "CWE-614"


def test_gen_csv_info_code_has_no_cvss(tmp_path):
    """Temuan informasional tetap punya CWE/OWASP, tapi skor/vector CVSS-nya kosong."""
    out = tmp_path / "info.csv"
    spade.gen_csv([("INFO", "TECH", "Teknologi: nginx", None)], "http://t/", str(out))
    with out.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    index = {name: i for i, name in enumerate(rows[0])}
    assert rows[1][index["CVSS_Score"]] == ""
    assert rows[1][index["CVSS_Vector"]] == ""
    assert rows[1][index["CWE"]] == "CWE-200"
    assert rows[1][index["OWASP"]] == "A05:2021"


def test_gen_csv_unknown_code_does_not_invent_cvss(tmp_path):
    out = tmp_path / "unknown.csv"
    spade.gen_csv([("LOW", "KODE_BARU", "belum dipetakan", None)], "http://t/", str(out))
    with out.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[1][1] == "KODE_BARU"
    assert rows[1][5:10] == ["firm", "", "", "", ""]


def test_gen_csv_quotes_commas(tmp_path):
    out = tmp_path / "report.csv"
    spade.gen_csv([("HIGH", "XSS", "payload, dengan koma", "http://t/")], "http://t/", str(out))
    with out.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[1][2] == "payload, dengan koma"


def test_cli_quick_mode_writes_default_report(vuln_server, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert spade.main([vuln_server.base_url, "--quick", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "mode: QUICK" in out
    assert "Total temuan:" in out
    reports = list(tmp_path.glob("spade_*.html"))
    assert len(reports) == 1, "laporan default spade_<host>.html harus dibuat"


def test_cli_custom_output_and_csv(vuln_server, tmp_path):
    html_out = tmp_path / "custom.html"
    csv_out = tmp_path / "custom.csv"
    code = spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "-o", str(html_out), "--csv", str(csv_out)])
    assert code == 0
    assert html_out.exists()
    assert csv_out.exists()
    assert csv_out.read_text(encoding="utf-8").startswith("Severity,Category,Detail,URL,Target")


def test_cli_workers_flag_is_honoured(vuln_server, tmp_path):
    html_out = tmp_path / "w1.html"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "--workers", "1", "-o", str(html_out)]) == 0
    assert html_out.exists()


def test_cli_skip_ssl_keeps_scanning(vuln_server, tmp_path):
    html_out = tmp_path / "ssl.html"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "--skip-ssl", "-o", str(html_out)]) == 0
    assert html_out.exists()


def test_cli_exits_cleanly_on_eof_at_target_prompt(monkeypatch, capsys):
    """Mode interaktif: EOF saat prompt target harus keluar dengan kode 2, tanpa traceback."""
    def _raise_eof(*_args, **_kwargs):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)
    assert spade.main([]) == 2
    captured = capsys.readouterr()
    assert "EOF" in captured.err
    assert "Traceback" not in captured.err


def test_cli_json_and_sarif_flags(vuln_server, tmp_path):
    json_out = tmp_path / "report.json"
    sarif_out = tmp_path / "report.sarif"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "-o", str(tmp_path / "r.html"),
                       "--json", str(json_out), "--sarif", str(sarif_out)]) == 0

    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["tool"]["name"] == "spade"
    assert payload["scan"]["mode"] == "quick"
    assert payload["scan"]["redacted"] is True
    assert payload["summary"]["total"] == len(payload["findings"])
    assert payload["findings"], "scan fixture harus menghasilkan temuan"
    for finding in payload["findings"]:
        assert finding["id"].startswith("spade-")
        assert finding["confidence"] in spade.CONFIDENCE_LEVELS
        assert set(finding) >= {"severity", "code", "confidence", "cvss", "evidence", "repro"}

    document = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "spade"
    assert run["results"], "SARIF harus memuat hasil"
    assert run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["partialFingerprints"]["findingId"].startswith("spade-")


def test_reports_never_leak_response_secrets(vuln_server, tmp_path):
    """Kredensial di body respons apa pun tidak boleh masuk format laporan mana pun."""
    html_out = tmp_path / "report.html"
    csv_out = tmp_path / "report.csv"
    json_out = tmp_path / "report.json"
    sarif_out = tmp_path / "report.sarif"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "-o", str(html_out), "--csv", str(csv_out),
                       "--json", str(json_out), "--sarif", str(sarif_out)]) == 0

    for report in (html_out, csv_out, json_out, sarif_out):
        raw = report.read_text(encoding="utf-8")
        assert "fixture-secret" not in raw, report
        assert "DB_RESPONSE_SECRET_9876543210" not in raw, report
        assert "sk_test_RESPONSE_SECRET_0123456789" not in raw, report
        assert "DB_RESPONSE_SECRET" not in raw, report
    assert "sk_test_RESPONSE_SECRET" not in raw, report


def test_cli_no_redact_flag_disables_redaction(vuln_server, tmp_path, capsys):
    json_out = tmp_path / "plain.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color",
                       "--no-redact", "-o", str(tmp_path / "r.html"),
                       "--json", str(json_out)]) == 0
    assert "REDACT OFF" in capsys.readouterr().out
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["redacted"] is False


def test_cli_timing_probes_metadata(vuln_server, tmp_path):
    json_out = tmp_path / "timing.json"
    assert spade.main([vuln_server.base_url, "--quick", "--no-color", "--timing-probes",
                       "-o", str(tmp_path / "timing.html"), "--json", str(json_out)]) == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert payload["scan"]["timing_probes"] is True
