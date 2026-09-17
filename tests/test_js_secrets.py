"""Test deteksi kredensial hardcode di JS (`JS_SECRET` / `JS_SECRET_MAYBE`).

Regresi utama: blok lama memakai `re.findall` dengan dua grup tangkap lalu
mengambil grup pertama (lookahead yang selalu kosong), jadi modul `js` praktis
tidak pernah melaporkan kredensial hardcode.

Semua nilai kredensial di file ini dibentuk dari potongan string (`"AKIA" +
"0" * 16`) supaya tidak ada satu pun literal di repo yang menyerupai kredensial
asli — dan tidak ada request ke luar jaringan lokal.
"""

import json

import pytest

import spade

# Nilai uji: hasil konkatenasi, bukan kredensial nyata.
AWS_KEY = "AKIA" + "0" * 16
STRIPE_KEY = "sk_live_" + "a" * 24
GITHUB_TOKEN = "ghp_" + "b" * 36

# Kunci AWS di fixture `tests/conftest.py` (`/static/app.js`) berbentuk
# "AKIA" + "1234567890ABCDEF". Test di bawah hanya memakai potongannya supaya
# tidak ada literal utuh yang menyerupai kredensial di file test ini.
FIXTURE_KEY_PREFIX = "AKIA"
FIXTURE_KEY_TAIL = "1234567890ABCDEF"
MASKED_FIXTURE_KEY = FIXTURE_KEY_PREFIX + "*" * 16

class FakeResponse:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.headers = {}
        self.content = text.encode("utf-8")
        self.url = ""

class FakeSession:
    """Session pengganti dengan respons canned per URL (tanpa jaringan)."""

    def __init__(self, routes=None, default_text="<html><body>ok</body></html>"):
        self.routes = dict(routes or {})
        self.default_text = default_text
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(url)
        return self.routes.get(url, FakeResponse(200, self.default_text))

    def urls(self):
        return list(self.calls)

@pytest.fixture(autouse=True)
def _clean_evidence():
    """Indeks bukti + flag redaksi bersifat global; kembalikan ke kondisi awal."""
    spade.reset_evidence()
    original = spade.REDACT_ENABLED
    yield
    spade.REDACT_ENABLED = original
    spade.reset_evidence()

def codes(findings):
    return [finding.code for finding in findings]

def by_code(findings, code):
    return [finding for finding in findings if finding.code == code]

# ══════════════════════════════════════════════════════════════════
# Fungsi murni: klasifikasi kandidat, masking, ekstraksi <script> inline
# ══════════════════════════════════════════════════════════════════

def test_candidates_flag_service_patterns_as_strong():
    text = (f'const apiKey = "{AWS_KEY}";\n'
            f'const stripe = "{STRIPE_KEY}";\n'
            f'const gh = "{GITHUB_TOKEN}";\n')
    candidates = {c["value"]: c for c in spade.js_secret_candidates(text)}

    assert set(candidates) == {AWS_KEY, STRIPE_KEY, GITHUB_TOKEN}
    assert all(c["strong"] for c in candidates.values())
    assert candidates[AWS_KEY]["label"] == "AWS access key"
    assert candidates[STRIPE_KEY]["label"] == "Stripe secret key"
    assert candidates[GITHUB_TOKEN]["label"] == "GitHub token"

def test_candidates_flag_generic_password_as_weak():
    text = 'const password = "correct-horse-battery-staple";\n'
    candidates = spade.js_secret_candidates(text)

    assert len(candidates) == 1
    assert candidates[0]["value"] == "correct-horse-battery-staple"
    assert candidates[0]["strong"] is False
    assert candidates[0]["offset"] > 0

def test_candidates_reject_placeholder_noise_and_plain_words():
    text = ('const apiKey = "your-api-key-here";\n'
            'const token = "Unexpected error message here";\n'
            'const secret = "abcdefghijklmnopqrst";\n'
            'const other = "changeme-placeholder-value";\n')

    assert spade.js_secret_candidates(text) == []

def test_candidates_dedupe_and_put_strong_first():
    text = ('const password = "correct-horse-battery-staple";\n'
            f'const apiKey = "{AWS_KEY}";\n')

    candidates = spade.js_secret_candidates(text)

    assert [c["strong"] for c in candidates] == [True, False]
    assert len({c["value"] for c in candidates}) == len(candidates)

def test_candidates_are_empty_for_blank_input():
    assert spade.js_secret_candidates("") == []
    assert spade.js_secret_candidates(None) == []

def test_mask_secret_value_keeps_prefix_and_min_eight_stars():
    assert spade.mask_secret_value(AWS_KEY) == "AKIA" + "*" * 16
    assert spade.mask_secret_value("short") == "shor" + "*" * 8
    assert spade.mask_secret_value(AWS_KEY, enabled=False) == AWS_KEY

def test_mask_secrets_in_text_replaces_values_only():
    text = f'const apiKey = "{AWS_KEY}";\nconst plain = "ok";\n'
    masked = spade.mask_secrets_in_text(text)

    assert AWS_KEY not in masked
    assert "AKIA" + "*" * 16 in masked
    assert '"ok"' in masked
    assert spade.mask_secrets_in_text(text, enabled=False) == text

def test_extract_inline_scripts_skips_src_and_non_js_types():
    html = ('<html><script src="/static/app.js"></script>'
            f'<script>var apiKey = "{AWS_KEY}";</script>'
            '<script type="application/json">{"a": 1}</script>'
            '<script type="text/template"><b>halo</b></script>'
            '</html>')

    blocks = spade.extract_inline_scripts(html)

    assert len(blocks) == 1
    assert AWS_KEY in blocks[0]
    assert spade.extract_inline_scripts("") == []

# ══════════════════════════════════════════════════════════════════
# Modul `js` — berkas .js, blok inline, batas temuan, redaksi
# ══════════════════════════════════════════════════════════════════

def test_scan_js_reports_strong_secret_from_external_file(sess, vuln_server):
    """Regresi: kredensial di /static/app.js harus terdeteksi (dulu selalu kosong)."""
    findings = spade.scan_js(sess, vuln_server.base_url)
    secrets = by_code(findings, "JS_SECRET")

    assert len(secrets) == 1
    finding = secrets[0]
    assert finding.sev == "CRITICAL"
    assert finding.confidence == "firm"
    assert finding.url == vuln_server.base_url + "static/app.js"
    assert "berkas JS app.js" in finding.desc
    assert FIXTURE_KEY_TAIL not in finding.desc
    assert MASKED_FIXTURE_KEY in finding.desc

def test_scan_js_generic_secret_is_tentative_maybe():
    base = "http://target.test/"
    html = ('<html><body><script>var password = "correct-horse-battery-staple";'
            "</script></body></html>")
    fake = FakeSession({base: FakeResponse(200, html)})

    findings = spade.scan_js(fake, base, {"crawler": None, "target": base})

    assert codes(findings) == ["JS_SECRET_MAYBE"]
    finding = findings[0]
    assert finding.sev == "HIGH"
    assert finding.confidence == "tentative"
    assert finding.url == base
    assert "inline <script> #1 di http://target.test/" in finding.desc
    assert "correct-horse-battery-staple" not in finding.desc

def test_scan_js_inline_secret_on_crawled_page_uses_page_url():
    base = "http://target.test/"
    page = "http://target.test/dashboard"
    page_html = f'<html><body><script>var apiKey = "{AWS_KEY}";</script></body></html>'
    fake = FakeSession({
        base: FakeResponse(200, '<html><body><a href="/dashboard">d</a></body></html>'),
        page: FakeResponse(200, page_html),
    })

    class Crawler:
        pages = {page: page_html}

    findings = spade.scan_js(fake, base, {"crawler": Crawler(), "target": base})
    secrets = by_code(findings, "JS_SECRET")

    assert len(secrets) == 1
    assert secrets[0].url == page
    assert f"inline <script> #1 di {page}" in secrets[0].desc

def test_scan_js_caps_findings_per_source():
    base = "http://target.test/"
    values = "".join(f'const key{i} = "AKIA{i:016d}";\n' for i in range(7))
    html = f"<html><body><script>{values}</script></body></html>"
    fake = FakeSession({base: FakeResponse(200, html)})

    findings = spade.scan_js(fake, base, {"crawler": None, "target": base})

    assert len(by_code(findings, "JS_SECRET")) == spade.JS_SECRET_MAX_FINDINGS

def test_scan_js_masks_secret_in_description_and_evidence():
    """Nilai kredensial tidak boleh muncul utuh di deskripsi maupun bukti."""
    base = "http://target.test/"
    js_url = base + "static/app.js"
    body = f'const apiKey = "{AWS_KEY}";\n'
    spade.record_exchange(spade.Exchange("GET", js_url, 200, response_snippet=body))
    fake = FakeSession({
        base: FakeResponse(200, f'<html><body><script src="{js_url}"></script></body></html>'),
        js_url: FakeResponse(200, body),
    })

    findings = spade.scan_js(fake, base, {"crawler": None, "target": base})
    secret = by_code(findings, "JS_SECRET")[0]

    assert AWS_KEY not in secret.desc
    assert AWS_KEY not in json.dumps(secret.to_dict())
    assert AWS_KEY not in secret.evidence.response_snippet

def test_scan_js_fixture_scan_hides_secret_everywhere(sess, vuln_server):
    """Seluruh laporan (semua temuan modul js) bebas nilai kredensial mentah."""
    findings = spade.scan_js(sess, vuln_server.base_url)
    dumped = json.dumps([finding.to_dict() for finding in findings])

    assert by_code(findings, "JS_SECRET"), "temuan kredensial harus ada"
    assert FIXTURE_KEY_TAIL not in dumped

    spade.REDACT_ENABLED = False
    plain_findings = spade.scan_js(sess, vuln_server.base_url)
    plain = json.dumps([finding.to_dict() for finding in plain_findings])

    assert FIXTURE_KEY_TAIL in plain, "--no-redact harus menampilkan nilai asli"
    assert FIXTURE_KEY_TAIL in by_code(plain_findings, "JS_SECRET")[0].desc

def test_scan_js_reuses_harvested_text_without_downloading():
    base = "http://target.test/"
    js_url = base + "static/app.js"
    html = f'<html><body><script src="{js_url}"></script></body></html>'
    fake = FakeSession({base: FakeResponse(200, html)})
    ctx = {"crawler": None, "target": base,
           "js_texts": {js_url: f'const apiKey = "{AWS_KEY}";\n'}}

    findings = spade.scan_js(fake, base, ctx)

    assert js_url not in fake.urls(), "berkas JS hasil panen recon tidak boleh diunduh lagi"
    assert len(by_code(findings, "JS_SECRET")) == 1

def test_scan_js_keeps_reporting_api_endpoints(sess, vuln_server):
    findings = spade.scan_js(sess, vuln_server.base_url)

    assert "JS_APIS" in codes(findings)
