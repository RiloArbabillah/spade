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


def test_ssrf_large_response_alone_is_not_finding(sess, ctx):
    findings = spade.ssrf_check(sess, ctx["target"], ctx)
    assert "SSRF" not in codes(findings)
    assert "SSRF_FORM" not in codes(findings)


def test_ssrf_metadata_signature_is_high_confidence(sess, ctx):
    findings = spade.ssrf_check(sess, ctx["target"], ctx)
    metadata = [f for f in findings if f[1] == "SSRF_METADATA"]
    assert metadata
    assert metadata[0][0] == "HIGH"
    assert metadata[0].confidence == "firm"


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


class _BaselineSession:
    def __init__(self, bodies):
        self.bodies = list(bodies)
        self.calls = []

    def get(self, url, **_kwargs):
        self.calls.append(url)

        class _Response:
            status_code = 200
            content = self.bodies.pop(0).encode()
            headers = {"Content-Type": "text/html"}

        return _Response()


def test_baseline_uses_four_similar_probes_for_dynamic_spa():
    body = "<!DOCTYPE html><html><body><main>app { }</main></body></html>"
    bodies = [body.replace("{ }", f"nonce-{i}") for i in range(4)]
    sess = _BaselineSession(bodies)
    baseline = spade.get_baseline_fingerprint(sess, "http://target.test")
    assert len(sess.calls) == 4
    assert baseline and baseline["detected"] == "spa_catchall"
    assert baseline["similarity"] >= 0.95


def test_baseline_rejects_distinct_responses():
    bodies = [f"completely different page number {i} {i * i}" for i in range(4)]
    baseline = spade.get_baseline_fingerprint(_BaselineSession(bodies), "http://target.test")
    assert baseline is None


def test_xss_context_parser_rejects_non_executable_reflection():
    payload = "<script>alert(1)</script>"
    assert spade.xss_reflection_context("<comment><!-- <script>alert(1)</script> --></comment>", payload) is None
    assert spade.xss_reflection_context("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>", payload) is None
    assert spade.xss_reflection_context("<input value='<script>alert(1)</script>'>", payload) is None


def test_xss_context_parser_detects_executable_contexts():
    payload = '"><svg onload=alert(1)>'
    assert spade.xss_reflection_context(f'<input value="{payload}">', payload) == "html"
    assert spade.xss_reflection_context(f"<div>{payload}</div>", payload) == "html"
    assert spade.xss_reflection_context("<a href='javascript:alert(1)'>x</a>", "javascript:alert(1)") == "url"


def test_xss_module_uses_context_oracle(sess, ctx):
    for path, expected in (("/xss/safe", False), ("/xss/attribute", False), ("/xss/html", True)):
        target = ctx["target"].rstrip("/") + path
        findings = spade.scan_xss(sess, target, ctx)
        found = any("/xss/" in str(f[3]) for f in findings if f[1] == "XSS_REFLECTED")
        assert found is expected, (path, found)


def test_lfi_expanded_oracles(sess, ctx):
    cases = {
        "/lfi/windows": "../../Windows/win.ini",
        "/lfi/environ": "../../proc/self/environ",
        "/lfi/php": "php://filter/convert.base64-encode/resource=/etc/passwd",
    }
    for path, payload in cases.items():
        findings = spade.lfi_check(sess, ctx["target"].rstrip("/") + path)
        assert "LFI" in codes(findings), (path, payload, findings)


def test_lfi_large_safe_page_is_not_finding(sess):
    assert spade.lfi_check(sess, "/lfi/safe") == []


def test_sqli_boolean_oracle(sess, vuln_server):
    findings = spade.scan_sqli(sess, vuln_server.base_url.rstrip("/") + "/sqli/boolean")
    assert "SQLI_BOOLEAN" in codes(findings)


def test_sqli_timing_requires_opt_in(sess, vuln_server, monkeypatch):
    monkeypatch.setattr(spade, "TIMING_MIN_ELAPSED", 0.01)
    target = vuln_server.base_url.rstrip("/") + "/sqli/time"
    assert "SQLI_TIME" not in codes(spade.scan_sqli(sess, target))
    assert "SQLI_TIME" in codes(spade.scan_sqli(sess, target, {"timing_probes": True}))


def test_cmdi_echo_oracle(sess, cmd_echo_server):
    findings = spade.cmd_injection(sess, cmd_echo_server.base_url.rstrip("/") + "/ping")
    assert "CMD_INJECTION" in codes(findings)


def test_cmdi_timing_requires_opt_in(sess, cmd_timing_server, monkeypatch):
    monkeypatch.setattr(spade, "TIMING_MIN_ELAPSED", 0.01)
    target = cmd_timing_server.base_url.rstrip("/") + "/ping"
    assert "CMDI_TIME" not in codes(spade.cmd_injection(sess, target))
    assert "CMDI_TIME" in codes(spade.cmd_injection(sess, target, {"timing_probes": True}))


def test_xxe_detects_passwd_without_bash(sess, xxe_server):
    findings = spade.scan_xxe(sess, xxe_server.base_url)
    assert "XXE_DIRECT" in codes(findings)


def test_internal_detection_templates_declare_context_and_safety():
    expected = {"xss", "lfi", "cmdi", "xxe"}
    assert set(spade.DETECTION_TEMPLATES) == expected
    for class_name, template in spade.DETECTION_TEMPLATES.items():
        assert template["payloads"] and template["context"]
        assert isinstance(template["safe"], bool)
        assert class_name != "cmdi" or not template["timing_default"]


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
