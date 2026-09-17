# Spade

Automated web vulnerability scanner dengan 4 mode + mode interaktif. Detect SQLi, XSS, LFI, CMDi, SSRF (termasuk blind/OOB), XXE, GraphQL introspection, IDOR/BOLA, CSRF, JWT, auth bypass, host header/cache poisoning, CRLF, request smuggling, open redirect, sensitive files, TLS, CORS, WAF, recon (subdomain/URL historis/JS/port), dan masih banyak lagi.

**File:** `spade.py` (Python 3, dependensi minimal)

---

## Cara Pakai

```bash
python3 spade.py                          # INTERAKTIF — minta domain & mode
python3 spade.py https://target.com       # STANDARD (19 modul)
python3 spade.py https://target.com --quick   # QUICK (7 modul, basic)
python3 spade.py https://target.com --detailed # DETAILED (32 modul, full)
python3 spade.py https://target.com --recon-only # RECON (enumerasi saja)
python3 spade.py https://target.com --detailed --port-scan # DETAILED + TCP connect scan
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
| `--detailed` | Mode lengkap (32 modul, crawl depth 2, recon, parameter discovery, JWT, OOB) |
| `-o file.html` | Output HTML report |
| `--csv file.csv` | Export hasil ke CSV |
| `--json file.json` | Export JSON (metadata scan + temuan + bukti request/response, cocok untuk pipeline) |
| `--sarif file.sarif` | Export SARIF 2.1.0 (untuk GitHub code scanning / CI) |
| `--no-redact` | Matikan sensor cookie/token/password. **Hati-hati: jangan dibagikan.** |
| `--no-color` | Output terminal tanpa warna |
| `--impersonate PROFIL` | Profil browser untuk impersonation (default `chrome`). Contoh: `chrome136`, `safari184`, `firefox147` |
| `--no-impersonate` | Matikan browser impersonation (fingerprint default curl, untuk debugging) |
| `--cookie "N=V;M=X"` | Cookie sesi untuk area terautentikasi (boleh diulang). Mengaktifkan modul IDOR, CSRF, JWT forgery, dan cache deception |
| `-H "Nama: nilai"` | Header tambahan untuk semua request, mis. token API (boleh diulang) |
| `--bearer TOKEN` | Isi header `Authorization: Bearer …` (bentrok dengan `-H 'Authorization: …'` → exit 2) |
| `--jwt-secrets FILE` | File daftar secret JWT (satu per baris) untuk crack HMAC offline |
| `--active-writes` | Izinkan uji yang mengirim data (submit form CSRF dengan token palsu). **Default: mati** |
| `--check-smuggling` | Aktifkan uji request smuggling CL.TE/TE.CL lewat socket mentah. **Default: mati** |
| `--oob-host HOST[:PORT]` | Host collector OOB milik tester untuk membuktikan blind SSRF/XXE/CMDi (jalankan `tools/oob_collector.py`) |
| `--workers N` | Jumlah request paralel (default 10, 1 = sekuensial) |
| `--crawl-depth N` | Kedalaman crawl mode detailed (default 2) |
| `--crawl-max N` | Maksimal halaman di-crawl mode detailed (default 30) |
| `--recon-only` | Hanya jalankan recon (subdomain, URL historis, endpoint JS, host hidup). Bentrok dengan `--quick`/`--detailed`/`--no-recon` → exit 2 |
| `--no-recon` | Lewati tahap recon di mode detailed (nama target tidak dikirim ke crt.sh/Wayback/Cert Spotter) |
| `--port-scan` | TCP connect scan ringan ke 41 port umum di target + host hasil enumerasi (butuh `--detailed` atau `--recon-only`) |

### Contoh

```bash
python3 spade.py https://example.com -o laporan.html
python3 spade.py https://example.com --csv hasil.csv
python3 spade.py https://example.com --detailed -o full-report.html --csv full.csv
python3 spade.py https://example.com --impersonate safari184   # impersonate profil lain
python3 spade.py https://example.com --json hasil.json --sarif hasil.sarif  # untuk pipeline/CI

# Area terautentikasi (wajib untuk IDOR/CSRF aktif/JWT forgery)
python3 spade.py https://example.com --detailed --cookie "session=..." -H "X-Api-Key: ..."

# Uji tulis + OOB (hanya di target yang mengizinkan)
python3 tools/oob_collector.py --host 0.0.0.0 --port 9000 &
python3 spade.py https://example.com --detailed --active-writes --oob-host 10.0.0.5:9000
```

## Struktur laporan

Setiap temuan disertai bukti request/response (method, URL, status, header,
body request, potongan respons, waktu) dan langkah reproduksi siap tempel.
Rahasia (Cookie, `Authorization`, field `password`/`token`, parameter URL
sensitif) disensor otomatis sebagai `***REDACTED***`; cookie di perintah
repro selalu jadi `COOKIE_ANDA`.

| Format | Flag | Isi |
|---|---|---|
| HTML | `-o file.html` (default `spade_<host>.html`) | Tabel temuan + blok `<details>` berisi bukti, metadata (confidence/CVSS/CWE/OWASP), dan dua langkah repro |
| CSV | `--csv file.csv` | 5 kolom lama + `Confidence`, `CVSS_Score`, `CVSS_Vector`, `CWE`, `OWASP`, `Repro_Curl`, `Evidence_Status`, `Evidence_URL` |
| JSON | `--json file.json` | `tool`, `target`, `scan` (mode, durasi, worker, `errors`, `redacted`, plus flag audit `auth`/`active_writes`/`check_smuggling`/`oob`), `summary`, dan `findings` lengkap dengan `evidence` + `repro` |
| SARIF | `--sarif file.sarif` | SARIF 2.1.0: satu rule per kode temuan + `partialFingerprints` supaya temuan tidak dobel di dashboard |

Metadata per temuan: skor + vector CVSS 3.1, CWE, kategori OWASP Top 10, dan
tingkat keyakinan (`certain` / `firm` / `tentative`). Kode yang belum
dipetakan tidak diberi skor CVSS karangan. Detail lengkap model temuan, aturan
redaksi, dan skema output ada di
[docs/findings-model.md](docs/findings-model.md).

## Perbandingan Mode

| Fitur | QUICK | STANDARD | DETAILED |
|---|---|---|---|
| Durasi | ~15-30s | ~45-90s | ~1-3mnt (paralel + early-exit) |
| Modul | 7 | 19 | 32 |
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
| JS analysis (endpoint + kredensial hardcode) | ❌ | ❌ | ✅ |
| JWT analysis | ❌ | ❌ | ✅ |
| IDOR / BOLA (butuh `--cookie`) | ❌ | ✅ | ✅ |
| CSRF | ❌ | ✅ | ✅ |
| Auth bypass (401/403) | ❌ | ✅ | ✅ |
| Parameter discovery | ❌ | ❌ | ✅ |
| API spec (OpenAPI/Swagger) | ❌ | ❌ | ✅ |
| Host header injection / cache poisoning | ❌ | ❌ | ✅ |
| CRLF injection | ❌ | ❌ | ✅ |
| Request smuggling (butuh `--check-smuggling`) | ❌ | ❌ | ✅ |
| Blind SSRF/CMDi (butuh `--oob-host`) | ❌ | ✅ | ✅ |
| Blind XXE (butuh `--oob-host`) | ❌ | ❌ | ✅ |
| Recon (subdomain + URL historis + JS) | ❌ | ❌ | ✅ |
| Subdomain enum (`crt.sh` + Cert Spotter + DNS wordlist) | ❌ | ❌ | ✅ |
| Port scan (butuh `--port-scan`, opt-in) | ❌ | ❌ | ✅ |

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
- IDOR/BOLA (dua sesi: anonim vs `--cookie`), CSRF (pasif + aktif)
- Auth bypass via header internal & normalisasi path
- Host header injection, cache poisoning, cache deception
- CRLF injection/response splitting, request smuggling CL.TE/TE.CL (opt-in)
- Blind SSRF/XXE/CMDi lewat collector OOB sendiri (opt-in)
- API spec OpenAPI/Swagger + parameter discovery
- Recon: subdomain (crt.sh + Cert Spotter + 134 kata DNS internal), host hidup (status/title/Server)
- URL historis (Wayback CDX + Common Crawl) → seed crawler + pool parameter modul injection
- Analisis JS: endpoint dari berkas JS (`<script src>` halaman utama + crawl) + kredensial hardcode (berkas JS & blok `<script>` inline)
- Port scan TCP connect 41 port umum (opt-in lewat `--port-scan`)

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

Request smuggling dan payload CRLF dikirim lewat socket mentah justru **karena**
`curl_cffi` menormalkan `Content-Length`/`Transfer-Encoding`/escape URL, sehingga
payload desync harus dikirim apa adanya.

Yang belum tersedia: rotasi IP/proxy, delay/jitter, dan pola request manusiawi.
Daftar lengkapnya ada di [docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md).

Detail HTTP layer ada di [docs/http-layer.md](docs/http-layer.md), model
temuan/bukti/laporan ada di [docs/findings-model.md](docs/findings-model.md),
tahap recon ada di [docs/recon.md](docs/recon.md), dan rincian kelas kerentanan
ada di [docs/vuln-classes.md](docs/vuln-classes.md).

**Catatan recon:** tahap recon di mode DETAILED mengirim **nama target** ke API
pihak ketiga (crt.sh, Cert Spotter, Wayback, Common Crawl) dari IP tester.
Request itu tidak bisa disamarkan dengan browser impersonation dan terlihat
sebagai passive reconnaissance. Pakai `--no-recon` kalau nama target tidak boleh
keluar ke pihak ketiga.

## Development

```bash
pip3 install -r requirements-dev.txt   # pytest + ruff
python3 -m pytest -q                   # test memakai fixture server lokal (tanpa internet)
python3 -m ruff check .                # lint (config di pyproject.toml)
python3 tools/oob_collector.py --help  # collector OOB (stdlib, tanpa dependency)
```

Test memakai fixture server lokal di `tests/conftest.py` (tanpa jaringan
eksternal): 242 test mencakup 32 modul, flag CLI, recon, dan generator laporan.

## Catatan

- Scan ini non-intrusive **kecuali** tiga uji opt-in: `--active-writes` (kirim
  POST), `--check-smuggling` (socket mentah), dan `--oob-host` (callback ke
  collector Anda). Semuanya mati secara default. Hanya gunakan di situs
  sendiri/terotorisasi.
- Roadmap celah fitur bug bounty (proxy/rate limit, scope file, multi-target)
  ada di [docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md).
  Bagian 1 (kualitas temuan: bukti, repro, CVSS/CWE/OWASP, confidence,
  JSON/SARIF), bagian 2 (cakupan kelas kerentanan: IDOR, CSRF, JWT, auth
  bypass, API spec, host header/cache, CRLF, smuggling, blind OOB), dan bagian 3
  (recon: subdomain, URL historis, endpoint JS, host hidup, port scan) sudah
  selesai.
- Detail tahap recon (sumber, batas request, alur data ke crawler dan modul
  injection, privasi) ada di [docs/recon.md](docs/recon.md).
- Model data temuan ada di [docs/findings-model.md](docs/findings-model.md);
  rincian tiap kelas kerentanan (apa yang diuji, flag yang dibutuhkan, batas
  request, penjaga false positive) ada di
  [docs/vuln-classes.md](docs/vuln-classes.md).
- Modul yang **butuh sesi autentikasi** (`idor`, `csrf` aktif, JWT forgery,
  cache deception) dilewati dengan catatan di log kalau `--cookie`/`-H`/
  `--bearer` tidak diberikan — bukan dilaporkan sebagai bersih.
- Setiap temuan membawa bukti request/response dan perintah `curl` siap pakai.
  Kredensial disensor otomatis (`***REDACTED***`) dan temuan `JS_SECRET`/
  `JS_SECRET_MAYBE` hanya menampilkan nilai yang sudah dimask (4 karakter awal +
  bintang); jangan pakai `--no-redact` kalau hasilnya akan dibagikan.
- Request dijalankan paralel (default 10 worker). Naikkan `--workers` untuk target cepat, turunkan ke `--workers 1` jika target rate-limit/WAF sensitif.
- Modul deteksi (SQLi, XSS, LFI, CMDi, SSTI, XXE, GraphQL, SSRF, NoSQLi, Open Redirect) berhenti lebih awal begitu temuan pertama ketemu, jadi mode DETAILED tidak selalu mengirim semua payload.
- Halaman utama dan daftar form di-cache: satu request/parse dipakai ulang lintas modul, bukan diulang per modul.
- False positive mungkin terjadi. Verifikasi manual temuan CRITICAL/HIGH.
- Mulai dengan `--quick`, lanjut `--detailed` kalau perlu.
- Untuk hasil maksimal: `--detailed` karena mengaktifkan crawler untuk menemukan form POST.
