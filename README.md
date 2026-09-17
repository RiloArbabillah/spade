# Spade

Automated web vulnerability scanner dengan 3 mode + mode interaktif. Detect SQLi, XSS, LFI, CMDi, SSRF, XXE, GraphQL introspection, open redirect, sensitive files, TLS, CORS, WAF, dan masih banyak lagi.

**File:** `spade.py` (Python 3, dependensi minimal)

---

## Cara Pakai

```bash
python3 spade.py                          # INTERAKTIF — minta domain & mode
python3 spade.py https://target.com       # STANDARD (16 modul)
python3 spade.py https://target.com --quick   # QUICK (7 modul, basic)
python3 spade.py https://target.com --detailed # DETAILED (23 modul, full)
```

URL boleh pakai `https://` atau langsung domain:

```bash
python3 spade.py example.com
```

## Opsi

| Opsi | Fungsi |
|---|---|
| Tanpa argumen | Mode interaktif — minta target & pilih mode |
| `--quick` | Mode cepat (7 modul, no crawl) |
| `--detailed` | Mode lengkap (23 modul, crawl depth 2) |
| `-o file.html` | Output HTML report |
| `--csv file.csv` | Export hasil ke CSV |
| `--no-color` | Output terminal tanpa warna |
| `--impersonate PROFIL` | Profil browser untuk impersonation (default `chrome`). Contoh: `chrome136`, `safari184`, `firefox147` |
| `--no-impersonate` | Matikan browser impersonation (fingerprint default curl, untuk debugging) |
| `--workers N` | Jumlah request paralel (default 10, 1 = sekuensial) |
| `--crawl-depth N` | Kedalaman crawl mode detailed (default 2) |
| `--crawl-max N` | Maksimal halaman di-crawl mode detailed (default 30) |

### Contoh

```bash
python3 spade.py https://example.com -o laporan.html
python3 spade.py https://example.com --csv hasil.csv
python3 spade.py https://example.com --detailed -o full-report.html --csv full.csv
python3 spade.py https://example.com --impersonate safari184   # impersonate profil lain
```

## Perbandingan Mode

| Fitur | QUICK | STANDARD | DETAILED |
|---|---|---|---|
| Durasi | ~15-30s | ~45-90s | ~1-3mnt (paralel + early-exit) |
| Modul | 7 | 16 | 23 |
| Crawl | ❌ | ❌ | ✅ depth 2 |
| Security headers | ✅ | ✅ | ✅ |
| TLS/SSL | ✅ | ✅ | ✅ |
| WAF detection | ✅ | ✅ | ✅ |
| Sensitive files | ✅ | ✅ | ✅ |
| SQL injection | ❌ | ✅ | ✅ |
| XSS (GET + POST) | ❌ | ✅ | ✅ |
| LFI | ❌ | ✅ | ✅ |
| CMD injection (GET + POST) | ❌ | ✅ | ✅ |
| SSRF (GET + POST) | ❌ | ✅ | ✅ |
| Open redirect | ❌ | ✅ | ✅ |
| XXE (direct + form) | ❌ | ❌ | ✅ |
| SSTI | ❌ | ❌ | ✅ |
| NoSQL injection | ❌ | ❌ | ✅ |
| GraphQL introspection | ❌ | ❌ | ✅ |
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
- SQL injection (error-based + time-based)
- XSS reflected (GET params) + XSS via form POST + stored XSS
- Open redirect, LFI, command injection (GET + POST)
- SSRF (GET endpoint + via form field)
- XXE (direct XML endpoint + via form upload)
- SSTI (Jinja2/Twig/Freemarker/Velocity), NoSQLi
- GraphQL introspection (GET + POST), JS analysis, JWT analysis
- Subdomain enumeration (CRT.sh + DNS wordlist)

## Instalasi

```bash
git clone git@github.com:RiloArbabillah/spade.git
cd spade
pip3 install -r requirements.txt      # curl_cffi (HTTP client + browser impersonation)
python3 spade.py --help
```

Runtime hanya butuh **`curl_cffi`** (Python 3.9+). Sisanya Python stdlib.

### Anti-deteksi bot

Semua request dikirim lewat `curl_cffi` dengan **browser impersonation aktif
secara default** (profil `chrome`), sehingga TLS fingerprint (JA3/JA4), urutan
header, `sec-ch-ua*`, dan `User-Agent` menyerupai browser asli dan tidak langsung
diklasifikasikan sebagai bot. Profil bisa diganti dengan `--impersonate` atau
dimatikan dengan `--no-impersonate`.

Yang belum tersedia: rotasi IP/proxy, delay/jitter, dan pola request manusiawi.
Daftar lengkapnya ada di [docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md).
Detail HTTP layer ada di [docs/http-layer.md](docs/http-layer.md).

## Development

```bash
pip3 install -r requirements-dev.txt   # pytest + ruff
python3 -m pytest -q                   # test memakai fixture server lokal (tanpa internet)
python3 -m ruff check .                # lint (config di pyproject.toml)
```

## Catatan

- Scan ini non-intrusive. Tapi hanya gunakan di situs sendiri/terotorisasi.
- Roadmap celah fitur bug bounty (evidence, IDOR, OOB, proxy/rate limit, scope,
  dll) ada di [docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md).
- Request dijalankan paralel (default 10 worker). Naikkan `--workers` untuk target cepat, turunkan ke `--workers 1` jika target rate-limit/WAF sensitif.
- Modul deteksi (SQLi, XSS, LFI, CMDi, SSTI, XXE, GraphQL, SSRF, NoSQLi, Open Redirect) berhenti lebih awal begitu temuan pertama ketemu, jadi mode DETAILED tidak selalu mengirim semua payload.
- Halaman utama dan daftar form di-cache: satu request/parse dipakai ulang lintas modul, bukan diulang per modul.
- False positive mungkin terjadi. Verifikasi manual temuan CRITICAL/HIGH.
- Mulai dengan `--quick`, lanjut `--detailed` kalau perlu.
- Untuk hasil maksimal: `--detailed` karena mengaktifkan crawler untuk menemukan form POST.
