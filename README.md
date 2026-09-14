# Spade

Automated web vulnerability scanner dengan 3 mode. Cek SQLi, XSS, LFI, CMDi, SSRF, open redirect, sensitive files, TLS, CORS, WAF, dan masih banyak lagi — cukup satu perintah.

**File:** `spade.py` (Python 3, dependensi minimal)

---

## Cara Pakai

```bash
python3 spade.py https://target.com          # STANDARD (16 modul)
python3 spade.py https://target.com --quick   # QUICK (7 modul, basic)
python3 spade.py https://target.com --detailed # DETAILED (23 modul, full)
```

URL boleh pakai `https://` atau langsung domain:

```bash
python3 spade.py example.com
python3 spade.py https://example.com
```

## Opsi

| Opsi | Fungsi |
|---|---|
| `--quick` | Mode cepat (7 modul, no crawl) |
| `--detailed` | Mode lengkap (23 modul, crawl depth 2) |
| `-o file.html` | Output HTML report |
| `--csv file.csv` | Export hasil ke CSV |
| `--no-color` | Output terminal tanpa warna |

### Contoh

```bash
python3 spade.py https://example.com -o laporan.html
python3 spade.py https://example.com --csv hasil.csv
python3 spade.py https://example.com --detailed -o full-report.html --csv full.csv
```

## Perbandingan Mode

| Fitur | QUICK | STANDARD | DETAILED |
|---|---|---|---|
| Durasi | ~15-30s | ~45-90s | ~2-5mnt |
| Modul | 7 | 16 | 23 |
| Crawl | ❌ | ❌ | ✅ depth 2 |
| Security headers | ✅ | ✅ | ✅ |
| TLS/SSL | ✅ | ✅ | ✅ |
| WAF detection | ✅ | ✅ | ✅ |
| Sensitive files | ✅ | ✅ | ✅ |
| SQL injection | ❌ | ✅ | ✅ |
| XSS | ❌ | ✅ | ✅ |
| LFI / LFI | ❌ | ✅ | ✅ |
| CMD injection | ❌ | ✅ | ✅ |
| Open redirect | ❌ | ✅ | ✅ |
| XXE | ❌ | ❌ | ✅ |
| SSTI | ❌ | ❌ | ✅ |
| NoSQL injection | ❌ | ❌ | ✅ |
| GraphQL | ❌ | ❌ | ✅ |
| JS analysis | ❌ | ❌ | ✅ |
| JWT analysis | ❌ | ❌ | ✅ |
| Subdomain enum | ❌ | ❌ | ✅ |

## Semua Modul

- Technology fingerprinting (server, framework, JS libs)
- Security headers (HSTS, CSP, XFO, dll) + WAF detection
- robots.txt, sensitive files (.env, .git, phpinfo), directory listing
- HTTP methods (PUT/DELETE/TRACE), CORS misconfig
- TLS/SSL cert + weak protocol check
- Form analysis, rate limiting, cookie security
- SQL injection, reflected XSS, open redirect
- LFI, command injection, SSRF
- XXE, SSTI (Jinja2/Freemarker/Velocity), NoSQLi
- GraphQL introspection, JS analysis, JWT analysis
- Subdomain enumeration (CRT.sh + wordlist)

## Instalasi

```bash
cd /Users/macbook/Experiment/web-vuln
pip3 install requests
python3 spade.py --help
```

Hanya butuh **`requests`**. Sisanya Python stdlib.

## Catatan

- Scan ini non-intrusive. Tapi hanya gunakan di situs sendiri/terotorisasi.
- False positive mungkin terjadi. Verifikasi manual temuan CRITICAL/HIGH.
- Mulai dengan `--quick`, lanjut `--detailed` kalau perlu.
