"""Regression test modul scan terhadap fixture lokal.

Test ini adalah jaring pengaman migrasi HTTP: setiap modul harus tetap
menghasilkan temuan yang sama setelah transport diganti ke curl_cffi.
"""

import json

import pytest

import spade


@pytest.fixture
def ctx(vuln_server, sess):
    """Context scan lengkap: crawler sudah jalan, form sudah ter-parse."""
    target = spade.normalize_url(vuln_server.base_url)
    context = {"crawler": None}
    spade.waf_detect(sess, target, context)
    base_resp = spade.get_base_response(sess, target, context)
    crawler = spade.Crawler(sess, target, depth=1, max_p=10)
    crawler.crawl(seed_text=base_resp.text if base_resp is not None else None)
    context["crawler"] = crawler
    context["target"] = target
    return context


def codes(findings):
    return [f[1] for f in findings]


def by_severity(findings, severity):
    return [f for f in findings if f[0] == severity]


def test_crawler_finds_pages_and_forms(ctx):
    assert len(ctx["crawler"].pages) >= 1
    forms = spade.get_forms(ctx)
    actions = {action for action, _method, _inputs, _page in forms}
    assert any(action.endswith("/submit") for action in actions)


def test_forms_are_parsed_once_per_crawler(ctx):
    assert spade.get_forms(ctx) is spade.get_forms(ctx)


def test_tech_fingerprint(sess, ctx):
    findings = spade.tech_finger(sess, ctx["target"], ctx)
    assert "TECH" in codes(findings)


def test_security_headers_and_cookie_flags(sess, ctx):
    findings = spade.sec_headers(sess, ctx["target"], ctx)
    found = codes(findings)
    assert "MISS_STRICT_TRANSPORT_SECURITY" in found
    assert "MISS_CONTENT_SECURITY_POLICY" in found
    assert "COOKIE_ISSUE" in found
    assert "SERVER_LEAK" in found


def test_robots_txt(sess, ctx):
    findings = spade.robots_txt(sess, ctx["target"], ctx)
    assert "ROBOTS" in codes(findings)


def test_sensitive_files_detects_env(sess, ctx):
    findings = spade.sensitive_files(sess, ctx["target"], ctx)
    assert "SENSITIVE_FILE" in codes(findings)
    assert by_severity(findings, "CRITICAL"), "file .env harus terdeteksi CRITICAL"
    assert any("/.env" in (f[3] or "") for f in findings)


def test_directory_listing(sess, ctx):
    findings = spade.dir_listing(sess, ctx["target"], ctx)
    assert "DIR_LISTING" in codes(findings)
    assert by_severity(findings, "HIGH")


def test_http_methods_detects_trace_and_allow_header(sess, ctx):
    findings = spade.http_methods(sess, ctx["target"], ctx)
    found = codes(findings)
    assert "TRACE_ENABLED" in found
    assert "HTTP_METHOD" in found


def test_cors_wildcard_with_credentials(sess, ctx):
    findings = spade.cors_check(sess, ctx["target"], ctx)
    assert "CORS_WILDCARD_CRED" in codes(findings)
    assert by_severity(findings, "HIGH")


def test_tls_module_skipped_on_plain_http(sess, ctx):
    assert spade.tls_ssl(sess, ctx["target"], ctx) == []


def test_forms_analysis_runs(sess, ctx):
    findings = spade.scan_forms_analyze(sess, ctx["target"], ctx)
    assert isinstance(findings, list)


def test_sqli_via_form_field(sess, ctx):
    findings = spade.scan_sqli(sess, ctx["target"], ctx)
    assert "SQLI" in codes(findings)
    assert by_severity(findings, "HIGH")


def test_reflected_xss(sess, ctx):
    findings = spade.scan_xss(sess, ctx["target"], ctx)
    assert any(c.startswith("XSS") for c in codes(findings))


def test_open_redirect(sess, ctx):
    findings = spade.open_redirect(sess, ctx["target"], ctx)
    assert "OPEN_REDIRECT" in codes(findings)


def test_lfi_no_false_positive(sess, ctx):
    findings = spade.lfi_check(sess, ctx["target"], ctx)
    assert "LFI" not in codes(findings)


def test_cmdi_no_false_positive(sess, ctx):
    findings = spade.cmd_injection(sess, ctx["target"], ctx)
    assert "CMD_INJECTION" not in codes(findings)
    assert "CMD_INJECTION_POST" not in codes(findings)


def test_ssrf_flagged_for_url_form_field(sess, ctx):
    findings = spade.ssrf_check(sess, ctx["target"], ctx)
    assert any(c.startswith("SSRF") for c in codes(findings))


def test_rate_limit_detects_429(rate_limited_server):
    spade.set_request_executor(1)
    sess = spade.ThreadLocalSession(timeout=10)
    target = spade.normalize_url(rate_limited_server.base_url)
    findings = spade.rate_limit(sess, target, {"crawler": None})
    assert "RATE_LIMIT" in codes(findings)
    assert by_severity(findings, "INFO")


def test_rate_limit_reports_missing_when_absent(sess, ctx):
    findings = spade.rate_limit(sess, ctx["target"], ctx)
    assert "NO_RATE_LIMIT" in codes(findings)


def test_graphql_introspection(sess, ctx):
    findings = spade.scan_graphql(sess, ctx["target"], ctx)
    assert "GRAPHQL_INTROSPECTION" in codes(findings)


def test_js_analysis_finds_api_endpoint(sess, ctx):
    findings = spade.scan_js(sess, ctx["target"], ctx)
    assert "JS_APIS" in codes(findings)


def test_jwt_alg_none_in_cookie(sess, ctx):
    findings = spade.scan_jwt(sess, ctx["target"], ctx)
    assert "JWT_ALG_NONE" in codes(findings)
    assert by_severity(findings, "CRITICAL")


def test_xxe_no_false_positive(sess, ctx):
    findings = spade.scan_xxe(sess, ctx["target"], ctx)
    assert "XXE_DIRECT" not in codes(findings)
    assert "XXE_FORM" not in codes(findings)


def test_ssti_no_false_positive(sess, ctx):
    findings = spade.scan_ssti(sess, ctx["target"], ctx)
    assert "SSTI" not in codes(findings)


def test_nosqli_no_false_positive(sess, ctx):
    findings = spade.scan_nosqli(sess, ctx["target"], ctx)
    assert "NOSQL" not in " ".join(codes(findings))


def test_subdomains_ignores_ip_target(sess, ctx):
    """Target IP tidak boleh memicu enumerasi subdomain."""
    assert spade.scan_subdomains(sess, ctx["target"], ctx) == []


def test_all_modules_return_lists(ctx):
    spade.set_request_executor(1)
    sess = spade.ThreadLocalSession(timeout=10)
    for key, (_label, func) in spade.ALL_MODULES.items():
        findings = func(sess, ctx["target"], ctx)
        assert findings is None or isinstance(findings, list), f"modul {key} tidak mengembalikan list"


def test_full_standard_scan_against_fixture(vuln_server, tmp_path):
    """Scan mode standard end-to-end: laporan HTML + CSV harus terbentuk."""
    html_out = tmp_path / "report.html"
    csv_out = tmp_path / "report.csv"
    code = spade.main([vuln_server.base_url, "--no-color", "--workers", "2",
                       "-o", str(html_out), "--csv", str(csv_out)])
    assert code == 0
    assert html_out.exists() and csv_out.exists()
    body = html_out.read_text(encoding="utf-8")
    assert "Spade Scan Report" in body
    csv_body = csv_out.read_text(encoding="utf-8")
    # Mode standard belum crawl, jadi SQLi (form-based) tidak termasuk; XSS header-based tetap ada.
    assert "XSS_REFLECTED" in csv_body
    assert "SENSITIVE_FILE" in csv_body


def test_full_detailed_scan_against_fixture(vuln_server, tmp_path):
    """Scan mode detailed end-to-end mencakup modul crawl-dependent (SQLi form)."""
    csv_out = tmp_path / "detailed.csv"
    code = spade.main([vuln_server.base_url, "--detailed", "--no-color", "--workers", "2",
                       "-o", str(tmp_path / "detailed.html"), "--csv", str(csv_out)])
    assert code == 0
    assert "SQLI" in csv_out.read_text(encoding="utf-8")


def test_all_modules_are_registered_once():
    keys = list(spade.ALL_MODULES)
    assert len(keys) == len(set(keys))
    assert set(spade.QUICK_MODULES) <= set(keys)
    assert set(spade.STANDARD_MODULES) | set(spade.DETAILED_ONLY) == set(keys)

def test_module_crash_is_reported_as_scan_error(vuln_server, tmp_path, monkeypatch):
    """Modul yang meledak harus muncul sebagai temuan INFO SCAN_ERROR, bukan hilang diam-diam."""

    def _boom(sess, target, ctx):
        raise RuntimeError("fixture meledak")

    monkeypatch.setitem(spade.ALL_MODULES, "headers", ("Security Headers", _boom))
    json_out = tmp_path / "err.json"
    code = spade.main([vuln_server.base_url, "--quick", "--no-color", "--workers", "1",
                       "-o", str(tmp_path / "err.html"), "--json", str(json_out)])
    assert code == 0
    payload = json.loads(json_out.read_text(encoding="utf-8"))
    errors = payload["scan"]["errors"]
    assert len(errors) == 1
    assert errors[0]["module"] == "headers"
    assert "RuntimeError" in errors[0]["error"]
    scan_error = [f for f in payload["findings"] if f["code"] == "SCAN_ERROR"]
    assert len(scan_error) == 1
    assert scan_error[0]["severity"] == "INFO"
    assert scan_error[0]["evidence"] is None
