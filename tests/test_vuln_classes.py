"""Test kelas kerentanan baru: IDOR, CSRF, auth bypass, API spec, parameter
discovery, host header/cache, CRLF, request smuggling, OOB (SSRF/XXE/CMDi), JWT.

Setiap kelas diuji positif (temuan muncul di fixture rentan) dan negatif
(fixture bersih / tanpa flag tidak menghasilkan temuan palsu). Fixture-nya
lokal dan tanpa jaringan eksternal, jadi hasilnya deterministik.
"""

import pytest

import spade


def codes(findings):
    return [f[1] for f in findings]


def severities(findings):
    return [f[0] for f in findings]


def ctx_for(sess, target, depth=2, **flags):
    """Context scan seperti mode detailed: crawler + form + flag runtime."""
    base_resp = spade.get_base_response(sess, target, {})
    crawler = spade.Crawler(sess, target, depth=depth, max_p=30)
    crawler.crawl(seed_text=base_resp.text if base_resp is not None else None)
    ctx = {"crawler": crawler, "target": target}
    ctx["forms"] = spade.get_forms(ctx)
    ctx.update({"auth_enabled": False, "anon_sess": None, "active_writes": False,
                "check_smuggling": False, "oob_host": "", "jwt_secrets": []})
    ctx.update(flags)
    return ctx


def authed_ctx(auth_sess, anon_sess, target, depth=2, **flags):
    ctx = ctx_for(auth_sess, target, depth=depth, **flags)
    ctx["auth_enabled"] = True
    ctx["anon_sess"] = anon_sess
    return ctx


# ══════════════════════════════════════════════════════════════════
# IDOR / BOLA
# ══════════════════════════════════════════════════════════════════

def test_idor_reports_anonymous_read(auth_server, auth_sess, anon_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = authed_ctx(auth_sess, anon_sess, target)
    findings = spade.scan_idor(auth_sess, target, ctx)
    assert "IDOR_ANON" in codes(findings)
    assert "HIGH" in severities(findings)


def test_idor_skipped_without_auth_session(auth_server, auth_sess):
    """Tanpa sesi autentikasi modul dilewati, bukan diklaim bersih."""
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    assert codes(spade.scan_idor(auth_sess, target, ctx)) == []


def test_idor_evidence_points_to_object_url(auth_server, auth_sess, anon_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = authed_ctx(auth_sess, anon_sess, target)
    findings = spade.scan_idor(auth_sess, target, ctx)
    idor = next(f for f in findings if f[1] == "IDOR_ANON")
    assert idor.evidence is not None
    assert "/objects/" in idor.evidence.url
    assert idor.confidence == "firm"


# ══════════════════════════════════════════════════════════════════
# CSRF
# ══════════════════════════════════════════════════════════════════

def test_csrf_passive_detects_form_without_token(auth_server, auth_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    findings = spade.scan_csrf(auth_sess, target, ctx)
    assert "CSRF_NO_TOKEN" in codes(findings)
    report = next(f for f in findings if f[1] == "CSRF_NO_TOKEN")
    assert report.confidence == "tentative"


def test_csrf_active_test_is_skipped_by_default(auth_server, auth_sess):
    """Tanpa --active-writes tidak ada POST ke target: tidak ada CSRF_TOKEN_IGNORED."""
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    assert "CSRF_TOKEN_IGNORED" not in codes(spade.scan_csrf(auth_sess, target, ctx))


def test_csrf_active_test_detects_ignored_token(auth_server, auth_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target, active_writes=True)
    findings = spade.scan_csrf(auth_sess, target, ctx)
    ignored = [f for f in findings if f[1] == "CSRF_TOKEN_IGNORED"]
    assert ignored, f"harus ada CSRF_TOKEN_IGNORED, dapat: {codes(findings)}"
    assert ignored[0].confidence == "firm"
    assert ignored[0].evidence is not None


# ══════════════════════════════════════════════════════════════════
# Auth bypass
# ══════════════════════════════════════════════════════════════════

def test_auth_bypass_header(auth_server, auth_sess, anon_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = authed_ctx(auth_sess, anon_sess, target)
    findings = spade.scan_auth_bypass(auth_sess, target, ctx)
    assert "AUTH_BYPASS_HEADER" in codes(findings)
    assert "HIGH" in severities(findings)


def test_auth_bypass_no_false_positive_on_public_page(auth_server, auth_sess, anon_sess):
    """URL yang memang publik (200 anonim) tidak boleh dilaporkan sebagai bypass."""
    target = spade.normalize_url(auth_server.base_url)
    ctx = authed_ctx(auth_sess, anon_sess, target)
    findings = spade.scan_auth_bypass(auth_sess, target, ctx)
    assert all("admin/area" in str(f[3]) for f in findings)


# ══════════════════════════════════════════════════════════════════
# API spec (OpenAPI/Swagger) + panen parameter
# ══════════════════════════════════════════════════════════════════

def test_api_spec_exposed_and_params_harvested(auth_server, auth_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    findings = spade.scan_api_specs(auth_sess, target, ctx)
    assert "API_SPEC_EXPOSED" in codes(findings)
    assert ctx["api_params"] == ["debug", "role"]
    assert spade.spec_injection_targets(ctx) == ["debug", "role"]


def test_api_spec_params_feed_injection_modules(auth_server, auth_sess):
    """Parameter dari spesifikasi API ikut diuji modul SQLi/XSS (bukan hanya HTML)."""
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    # Sebelum panen: modul injection hanya pakai nama parameter bawaannya.
    assert spade.spec_injection_targets(ctx) == []
    spade.scan_api_specs(auth_sess, target, ctx)
    harvested = spade.spec_injection_targets(ctx)
    assert "debug" in harvested and "role" in harvested


def test_api_spec_absent_on_plain_fixture(vuln_server, sess):
    target = spade.normalize_url(vuln_server.base_url)
    ctx = ctx_for(sess, target)
    assert codes(spade.scan_api_specs(sess, target, ctx)) == []


# ══════════════════════════════════════════════════════════════════
# Parameter discovery
# ══════════════════════════════════════════════════════════════════

def test_param_discovery_finds_debug(auth_server, auth_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    findings = spade.scan_params(auth_sess, target, ctx)
    assert "PARAM_DISCOVERY" in codes(findings)
    assert "INFO" in severities(findings)
    assert any("debug" in f[2] for f in findings)


def test_param_discovery_no_false_positive_on_plain_fixture(vuln_server, sess):
    """Fixture dasar tidak punya parameter tersembunyi yang mengubah respons."""
    target = spade.normalize_url(vuln_server.base_url)
    ctx = ctx_for(sess, target)
    assert "PARAM_DISCOVERY" not in codes(spade.scan_params(sess, target, ctx))


# ══════════════════════════════════════════════════════════════════
# Host header & cache
# ══════════════════════════════════════════════════════════════════

def test_host_header_injection_detected(auth_server, auth_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    findings = spade.scan_host_header(auth_sess, target, ctx)
    assert "HOST_HEADER_INJECTION" in codes(findings)
    assert "CACHE_POISONING" in codes(findings)


def test_cache_poisoning_negative_on_canonical_endpoint(auth_server, auth_sess):
    """Endpoint /cache tidak memantulkan host: tidak boleh dilaporkan."""
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    findings = spade.scan_host_header(auth_sess, target, ctx)
    assert not [f for f in findings if str(f[3]).endswith("/cache")]


def test_cache_deception_detected(auth_server, auth_sess, anon_sess):
    """Halaman privat yang bisa dibaca anonim lewat akhiran .css dilaporkan."""
    target = spade.normalize_url(auth_server.base_url)
    ctx = authed_ctx(auth_sess, anon_sess, target)
    # Modul hanya melihat 3 halaman crawl pertama, jadi halaman privat disisipkan
    # di depan supaya ikut diuji sebagai kandidat cache deception.
    pages = {target + "/private": "<html><body>Privat</body></html>"}
    pages.update(ctx["crawler"].pages)
    ctx["crawler"].pages = pages
    findings = spade.scan_host_header(auth_sess, target, ctx)
    deception = [f for f in findings if f[1] == "CACHE_DECEPTION"]
    assert deception, f"harus ada CACHE_DECEPTION, dapat: {codes(findings)}"
    assert deception[0].confidence == "firm"
    assert deception[0].evidence.url.endswith(".css")


# ══════════════════════════════════════════════════════════════════
# CRLF injection (regresi bug unpack pmap_until)
# ══════════════════════════════════════════════════════════════════

def test_crlf_injection_firm_confidence(auth_server, auth_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target)
    findings = spade.scan_crlf(auth_sess, target, ctx)
    assert "CRLF_INJECTION" in codes(findings), "regresi: scan_crlf harus tetap melaporkan temuan"
    hit = next(f for f in findings if f[1] == "CRLF_INJECTION")
    assert hit.confidence == "firm"
    assert hit.evidence is not None


def test_crlf_no_false_positive_on_plain_fixture(vuln_server, sess):
    target = spade.normalize_url(vuln_server.base_url)
    ctx = ctx_for(sess, target)
    assert "CRLF_INJECTION" not in codes(spade.scan_crlf(sess, target, ctx))


# ══════════════════════════════════════════════════════════════════
# Request smuggling (raw socket)
# ══════════════════════════════════════════════════════════════════

def test_smuggling_requires_flag(desync_server, sess):
    target = spade.normalize_url(desync_server.base_url)
    ctx = {"crawler": None, "check_smuggling": False}
    assert codes(spade.scan_smuggling(sess, target, ctx)) == []


def test_smuggling_detects_desync(desync_server, sess):
    target = spade.normalize_url(desync_server.base_url)
    ctx = {"crawler": None, "check_smuggling": True}
    findings = spade.scan_smuggling(sess, target, ctx)
    assert "REQUEST_SMUGGLING" in codes(findings)
    assert "HIGH" in severities(findings)
    # Modul ini sengaja tidak menyimpan bukti HTTP (transport-nya socket mentah).
    assert all(f.evidence is None for f in findings)


# ══════════════════════════════════════════════════════════════════
# OOB: blind SSRF / XXE / command injection
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def fast_oob(monkeypatch):
    """Percepat tunggu callback supaya test OOB tidak lambat."""
    monkeypatch.setattr(spade, "OOB_CHECK_DELAY", 0.3)


@pytest.fixture
def oob_ctx(auth_server, auth_sess, anon_sess, oob_collector, fast_oob):
    target = spade.normalize_url(auth_server.base_url)
    ctx = authed_ctx(auth_sess, anon_sess, target, depth=1)
    ctx["oob_host"] = oob_collector
    return ctx, target


def test_oob_modules_disabled_without_host(auth_server, auth_sess):
    target = spade.normalize_url(auth_server.base_url)
    ctx = ctx_for(auth_sess, target, depth=1)
    assert codes(spade.scan_oob_ssrf(auth_sess, target, ctx)) == []
    assert codes(spade.scan_oob_xxe(auth_sess, target, ctx)) == []
    assert codes(spade.scan_oob_cmdi(auth_sess, target, ctx)) == []


def test_oob_ssrf_confirmed_by_callback(auth_sess, oob_ctx):
    ctx, target = oob_ctx
    findings = spade.scan_oob_ssrf(auth_sess, target, ctx)
    assert "SSRF_BLIND" in codes(findings)
    assert findings[0].confidence == "firm"


def test_oob_xxe_confirmed_by_callback(auth_sess, oob_ctx):
    ctx, target = oob_ctx
    findings = spade.scan_oob_xxe(auth_sess, target, ctx)
    assert "XXE_BLIND" in codes(findings)
    assert findings[0].confidence == "firm"


def test_oob_cmdi_confirmed_by_callback(auth_sess, oob_ctx):
    ctx, target = oob_ctx
    findings = spade.scan_oob_cmdi(auth_sess, target, ctx)
    assert "CMDI_BLIND" in codes(findings)
    assert "CRITICAL" in severities(findings)
    # Satu titik injeksi cukup satu temuan walau beberapa template berhasil.
    points = [str(f.evidence.url).split("?", 1)[0] for f in findings]
    assert len(points) == len(set(points))


def test_ssrf_embeds_oob_module(vuln_server, sess, oob_collector, fast_oob):
    """ssrf_check tetap jalan tanpa --oob-host (modul OOB hanya mengembalikan kosong)."""
    target = spade.normalize_url(vuln_server.base_url)
    ctx = ctx_for(sess, target, oob_host=oob_collector)
    findings = spade.ssrf_check(sess, target, ctx)
    assert "SSRF_BLIND" not in codes(findings)  # fixture dasar tidak mem-fetch URL form


# ══════════════════════════════════════════════════════════════════
# JWT lanjutan
# ══════════════════════════════════════════════════════════════════

@pytest.fixture
def jwt_ctx(jwt_server, jwt_auth_sess, jwt_anon_sess):
    target = spade.normalize_url(jwt_server.base_url)
    ctx = authed_ctx(jwt_auth_sess, jwt_anon_sess, target)
    return jwt_auth_sess, jwt_anon_sess, target, ctx


def test_jwt_static_findings(jwt_ctx):
    sess, _anon, target, ctx = jwt_ctx
    findings = spade.scan_jwt(sess, target, ctx)
    found = set(codes(findings))
    assert {"JWT_ALG_NONE", "JWT_WEAK_SECRET", "JWT_KID_SUSPECT",
            "JWT_ALG_CONFUSION_SURFACE"} <= found


def test_jwt_forgery_findings(jwt_ctx):
    """Token palsu buatan penyerang diterima server (kid traversal & alg confusion)."""
    sess, _anon, target, ctx = jwt_ctx
    findings = spade.scan_jwt(sess, target, ctx)
    found = set(codes(findings))
    assert "JWT_KID_TRAVERSAL" in found
    assert "JWT_ALG_CONFUSION" in found
    for code in ("JWT_KID_TRAVERSAL", "JWT_ALG_CONFUSION"):
        hit = next(f for f in findings if f[1] == code)
        assert hit.confidence == "firm"
        assert "HIGH" == hit[0]


def test_jwt_expiry_checks(jwt_ctx):
    sess, _anon, target, ctx = jwt_ctx
    findings = spade.scan_jwt(sess, target, ctx)
    found = set(codes(findings))
    assert "JWT_EXPIRED_ACCEPTED" in found
    assert "JWT_NO_EXPIRY" in found


def test_jwt_forgery_requires_auth_session(jwt_server, jwt_auth_sess):
    """Tanpa sesi autentikasi uji token palsu dilewati — bukan diklaim bersih."""
    target = spade.normalize_url(jwt_server.base_url)
    ctx = authed_ctx(jwt_auth_sess, None, target)
    ctx["auth_enabled"] = False
    found = set(codes(spade.scan_jwt(jwt_auth_sess, target, ctx)))
    assert "JWT_KID_TRAVERSAL" not in found
    assert "JWT_ALG_CONFUSION" not in found


# ══════════════════════════════════════════════════════════════════
# Registri modul & metadata temuan
# ══════════════════════════════════════════════════════════════════

def test_module_counts_match_cli_help():
    assert len(spade.ALL_MODULES) == 32
    assert len(spade.QUICK_MODULES) == 7
    assert len(spade.STANDARD_MODULES) == 19
    assert len(spade.DETAILED_ONLY) == 13


def test_new_codes_have_finding_meta():
    for code in ("IDOR_ANON", "IDOR_READ", "CSRF_NO_TOKEN", "CSRF_TOKEN_IGNORED",
                 "AUTH_BYPASS_HEADER", "AUTH_BYPASS_PATH", "HOST_HEADER_INJECTION",
                 "CACHE_POISONING", "CACHE_DECEPTION", "API_SPEC_EXPOSED", "PARAM_DISCOVERY",
                 "CRLF_INJECTION", "REQUEST_SMUGGLING", "SSRF_BLIND", "XXE_BLIND", "CMDI_BLIND",
                 "SUBDOMAIN_LIVE", "HISTORIC_URLS", "JS_ENDPOINT", "PORT_OPEN",
                 "RECON_SOURCE_SKIPPED", "SUBDOMAINS",
                 "JWT_WEAK_SECRET", "JWT_KID_TRAVERSAL", "JWT_ALG_CONFUSION",
                 "JWT_ALG_CONFUSION_SURFACE", "JWT_EXPIRED_ACCEPTED", "JWT_NO_EXPIRY",
                 "JWT_KID_SUSPECT", "JWT_COOKIE", "JWT_BEARER", "JWT_ALG_NONE",
                 "JS_SECRET", "JS_SECRET_MAYBE"):
        assert code in spade.FINDING_META, f"{code} belum terdaftar di FINDING_META"
        assert spade.finding_confidence(code) in ("certain", "firm", "tentative")
