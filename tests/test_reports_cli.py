"""Test generator laporan (HTML/CSV) dan perilaku CLI."""

import csv
from datetime import datetime

import pytest

import spade


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
    assert rows[0] == ["Severity", "Category", "Detail", "URL", "Target"]
    assert len(rows) == len(findings) + 1
    assert rows[1][0] == "CRITICAL"
    assert rows[1][4] == "http://target.test/"
    assert rows[3][3] == ""


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
