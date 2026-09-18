# Spade

Automated web vulnerability scanner dengan 4 mode + mode interaktif. Detect SQLi, XSS, LFI, CMDi, SSRF (termasuk blind/OOB), XXE, GraphQL introspection, IDOR/BOLA, CSRF, JWT, auth bypass, host header/cache poisoning, CRLF, request smuggling, open redirect, sensitive files, TLS, CORS, WAF, recon (subdomain/URL historis/JS/port), dan masih banyak lagi.

**File:** `spade.py` (Python 3.9+, dependensi runtime hanya `curl_cffi`) · **32 modul** · **39 opsi CLI** · **424 test** · versi `3.1`

> ⚠️ **Hanya untuk pengujian yang sah.** Pakai Spade hanya pada aset milikmu
> sendiri atau aset yang kamu punya **izin tertulis** untuk diuji (program bug
> bounty, kontrak pentest, lab pribadi). **Pemilik repo dan kontributor tidak
> bertanggung jawab atas penyalahgunaan alat ini**, termasuk pemindaian tanpa
> izin, kerusakan layanan/data, maupun konsekuensi hukum apa pun — tanggung
> jawab sepenuhnya ada di pengguna. Selengkapnya: [Penafian](#penafian--batas-penggunaan).
>
> **Disclaimer (EN):** Use Spade only on assets you own or are explicitly
> authorized in writing to test. The repository owner and contributors accept
> **no responsibility or liability** for misuse of this repository or tool.

---

## Cara Pakai

```bash
python3 spade.py                          # INTERAKTIF — minta domain & mode, lalu semua opsi flag dengan nilai default
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

### Mode interaktif

Jalankan `python3 spade.py` tanpa argumen. Alurnya: **target → mode → menu
pengaturan lanjutan → ringkasan → scan**.

| Langkah | Yang terjadi |
|---|---|
| 1. Target | Minta domain/URL; input kosong ditanyakan ulang, EOF (bukan terminal) → keluar dengan exit 2 |
| 2. Mode | `[1] Quick` (7 modul), `[2] Standard` (19 modul, default), `[3] Detailed` (32 modul + crawl + recon), `[4] Recon` (`--recon-only`). Input selain 1–4 ditanyakan ulang (Enter = Standard) |
| 3. Menu pengaturan lanjutan | 33 opsi dalam 7 kelompok dicetak bersama **nilai default** yang akan dipakai scan, plus nama flag aslinya supaya bisa dipindah ke jalur CLI |
| 4. Ringkasan | Banner kedua menampilkan Workers, Crawl (mode detailed), dan status recon sebelum request pertama dikirim |

Menjawab menu: **Enter** = pakai semua default dan langsung scan; `1` atau
`1,3 5` = ubah satu/beberapa opsi; `l` (juga `list`/`?`) = cetak ulang daftar;
`-` di prompt nilai = kosongkan opsi teks/daftar (cookie, header, proxy, dst.).
Nilai rahasia (`--cookie`, `-H/--header`, `--bearer`) ditampilkan sebagai `***`
dan nilainya tetap lewat jalur validasi CLI yang sama. Konflik antar-flag
(mis. `--proxy` + `--proxy-file`, `--safe-mode` + `--active-writes`) dilaporkan
di menu, bukan menunggu `exit 2` di akhir. Detail ada di
[docs/scan-engine.md](docs/scan-engine.md).

Enam opsi CLI tidak muncul di menu karena sudah punya jalur sendiri:
`--quick`/`--detailed`/`--recon-only` (menjadi prompt mode), `--no-color`
(diproses sebelum menu dicetak), `--no-impersonate` (setara
`--impersonate -`), dan `--i-have-authorization` (digantikan prompt konfirmasi
otorisasi yang hanya muncul di terminal interaktif).

## Opsi

| Opsi | Fungsi |
|---|---|
| Tanpa argumen | Mode interaktif — minta target, pilih mode (`[4] Recon` termasuk), lalu tampilkan **33 opsi flag dalam 7 kelompok beserta nilai default** (`--workers`, `--delay`, `--proxy`, `--cookie`, `--safe-mode`, dst.). Enter = pakai default dan langsung scan; ketik nomor opsi untuk mengubahnya |
| `--quick` | Mode cepat (7 modul, no crawl) |
| `--detailed` | Mode lengkap (32 modul, crawl depth 2, recon, parameter discovery, JWT, OOB) |
| `-o` / `--output file.html` | Output HTML report (default `spade_<host>.html`) |
| `--csv file.csv` | Export hasil ke CSV |
| `--json file.json` | Export JSON (metadata scan + temuan + bukti request/response, cocok untuk pipeline) |
| `--sarif file.sarif` | Export SARIF 2.1.0 (untuk GitHub code scanning / CI) |
| `--no-redact` | Matikan sensor cookie/token/password. **Hati-hati: jangan dibagikan.** |
| `--no-color` | Output terminal tanpa warna |
| `--skip-ssl` | Lewati verifikasi sertifikat TLS server (self-signed/expired). Digabung `--cert` → peringatan di banner: hanya sisi klien yang diautentikasi |
| `--impersonate PROFIL` | Profil browser untuk impersonation (default `chrome`). Contoh: `chrome136`, `safari184`, `firefox147` |
| `--no-impersonate` | Matikan browser impersonation (fingerprint default curl, untuk debugging) |
| `--cookie "N=V;M=X"` | Cookie sesi untuk area terautentikasi (boleh diulang). Mengaktifkan modul IDOR, CSRF, JWT forgery, dan cache deception |
| `-H "Nama: nilai"` | Header tambahan untuk semua request, mis. token API (boleh diulang) |
| `--bearer TOKEN` | Isi header `Authorization: Bearer …` (bentrok dengan `-H 'Authorization: …'` → exit 2) |
| `--jwt-secrets FILE` | File daftar secret JWT (satu per baris) untuk crack HMAC offline |
| `--session FILE` | Impor sesi dari file JSON (objek nama→nilai, daftar `{name,value}`, atau `{cookies,headers}`). Nilainya tidak pernah ditulis ke laporan |
| `--active-writes` | Izinkan uji yang mengirim data (submit form CSRF dengan token palsu). **Default: mati**, butuh konfirmasi otorisasi |
| `--timing-probes` | Izinkan probe time-based SQLi/CMDi dengan delay 3 detik. **Default: mati**, butuh konfirmasi otorisasi |
| `--check-smuggling` | Aktifkan uji request smuggling CL.TE/TE.CL lewat socket mentah. **Default: mati**, butuh konfirmasi otorisasi |
| `--oob-host HOST[:PORT]` | Host collector OOB milik tester untuk membuktikan blind SSRF/XXE/CMDi (jalankan `tools/oob_collector.py`) |
| `--workers N` | Jumlah request paralel (default 10, 1 = sekuensial) |
| `--delay SEC` | Jeda minimum antar request untuk **semua** worker (default 0). Mis. `0.5` ≈ maksimal 2 request/detik |
| `--max-rps N` | Batas laju global request per detik (default 0 = tanpa batas). Boleh digabung `--delay`; batas terketat yang menang |
| `--jitter PCT` | Acak jeda ±`PCT`% (0–100) supaya pola request tidak seragam (default 0) |
| `--backoff-max SEC` | Batas atas cooldown global saat target membalas 429/503 (default 30s) |
| `--proxy URL` | Proxy keluar; boleh diulang untuk rotasi round-robin. Skema: `http`/`https`/`socks5`/`socks5h`. Kredensial di URL tidak pernah ditulis ke laporan |
| `--proxy-file FILE` | Daftar proxy untuk rotasi (satu URL per baris, `#` = komentar). Bentrok dengan `--proxy` → exit 2 |
| `--proxy-cooldown SEC` | Istirahatkan proxy selama SEC detik setelah respons 403/429/503 lalu pindah ke proxy lain (default 60s) |
| `--state FILE` | Tulis checkpoint JSON (atomik, per modul selesai) supaya scan panjang bisa dilanjutkan kalau terputus |
| `--resume FILE` | Lanjutkan scan dari checkpoint `--state`: modul yang sudah selesai dilewati, temuan lama dimuat ulang. Cakupan berbeda → exit 2 |
| `--cert FILE` | Client certificate PEM untuk target mTLS (satu berkas boleh memuat cert + key) |
| `--key FILE` | Private key PEM pasangan `--cert`. Diberikan tanpa `--cert` → exit 2 |
| `--safe-mode` | Mode aman: tidak mengirim PUT/DELETE, uji tulis, probe timing, atau smuggling. Bentrok dengan flag destruktif → exit 2 |
| `--i-have-authorization` | Konfirmasi non-interaktif bahwa kamu punya izin tertulis untuk uji destruktif (`--active-writes`/`--timing-probes`/`--check-smuggling`) |
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
python3 spade.py https://example.com --detailed --session sesi.json   # impor cookie/header dari file

# Sopan ke target: batas laju + jitter
python3 spade.py https://example.com --delay 0.5 --jitter 30    # maksimal ~2 req/s
python3 spade.py https://example.com --max-rps 5 --safe-mode    # batas laju + tanpa uji destruktif

# Rotasi IP keluar (skip otomatis kalau satu proxy diblokir)
python3 spade.py https://example.com --proxy socks5h://user:pass@proxy.example:1080
python3 spade.py https://example.com --proxy-file proxy.txt --proxy-cooldown 120

# Scan panjang yang bisa dilanjutkan kalau terputus
python3 spade.py https://example.com --detailed --state state.json
python3 spade.py https://example.com --detailed --resume state.json   # lanjut dari modul terakhir

# Target di balik mTLS
python3 spade.py https://example.com --cert klien.pem --key klien.key

# Uji tulis + OOB (hanya di target yang mengizinkan, butuh konfirmasi otorisasi)
python3 tools/oob_collector.py --host 0.0.0.0 --port 9000 &
python3 spade.py https://example.com --detailed --active-writes --oob-host 10.0.0.5:9000 --i-have-authorization
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
| JSON | `--json file.json` | `tool`, `target`, `scan` (mode, waktu mulai/selesai, durasi, worker, `impersonate`, `modules`, `errors`, `redacted`, plus flag audit `auth`/`auth_source`/`safe_mode`/`authorized`/`throttle`/`proxy`/`state`/`resume`/`client_cert`/`active_writes`/`timing_probes`/`check_smuggling`/`oob`), `summary`, dan `findings` lengkap dengan `evidence` + `repro` |
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

Mode keempat, **RECON** (`--recon-only`), hanya menjalankan modul `recon`
(subdomain, URL historis, endpoint JS, host hidup) — tanpa modul kerentanan.
Port scan tetap bisa digabung (`--recon-only --port-scan`).

## Semua Modul

- Technology fingerprinting (server, framework, JS libs)
- Security headers (HSTS, CSP, XFO, dll) + WAF detection
- robots.txt, sensitive files (.env, .git, phpinfo), directory listing
- HTTP methods (PUT/DELETE/TRACE), CORS misconfig
- TLS/SSL cert + weak protocol check
- Form analysis, rate limiting, cookie security
- SQL injection (error-based + time-based)
- XSS reflected (GET params) + XSS via form POST + stored XSS (hanya konteks yang benar-benar executable dilaporkan)
- Open redirect, LFI (katalog Linux/Windows/traversal ter-encode/`php://filter`), command injection (GET + POST)
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

Untuk pola request, gunakan `--delay`/`--max-rps`/`--jitter`: penjadwal global
membatasi laju seluruh worker dan mengacak jeda supaya pola tidak seragam.
Modul `rate_limit` otomatis dilewati saat penjadwal aktif (burst 15 request
tidak bisa diamati lagi) dan dicatat di log.

Untuk rotasi IP keluar, gunakan `--proxy`/`--proxy-file`: semua request (termasuk
recon) melewati pool proxy round-robin, dan proxy yang membalas 403/429/503
otomatis diistirahatkan lalu ditinggalkan. Modul request smuggling dilewati saat
rotasi aktif karena payload desync dikirim lewat socket mentah.

Untuk scan panjang (mode DETAILED bisa puluhan menit), tambahkan
`--state state.json`: checkpoint ditulis atomik setiap modul selesai, lalu
`--resume state.json` melanjutkan dari modul yang belum jalan. Temuan beserta
buktinya ikut disimpan, jadi laporan hasil resume tidak kehilangan temuan modul
sebelumnya. Resume menolak checkpoint dengan cakupan berbeda (mode, target,
daftar modul, atau flag destruktif berubah) dengan exit 2 sebelum mengirim
request. Target di balik mTLS diuji dengan `--cert`/`--key`.

Yang belum tersedia: pola request manusiawi (mis. `Referer` antar halaman atau
pemuatan aset statis). Daftar lengkapnya ada di
[docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md).

Detail HTTP layer ada di [docs/http-layer.md](docs/http-layer.md), model
temuan/bukti/laporan ada di [docs/findings-model.md](docs/findings-model.md),
tahap recon ada di [docs/recon.md](docs/recon.md), dan rincian kelas kerentanan
ada di [docs/vuln-classes.md](docs/vuln-classes.md). Kontrol operasional
(throttle, safe-mode, impor sesi, rotasi proxy, resume, mTLS, dan mode
interaktif dengan pengaturan lanjutan) ada di
[docs/scan-engine.md](docs/scan-engine.md).

**Catatan recon:** tahap recon di mode DETAILED mengirim **nama target** ke API
pihak ketiga (crt.sh, Cert Spotter, Wayback, Common Crawl) dari IP tester.
Request itu tidak bisa disamarkan dengan browser impersonation dan terlihat
sebagai passive reconnaissance. Pakai `--no-recon` kalau nama target tidak boleh
keluar ke pihak ketiga.

## Status Pengembangan

Roadmap celah fitur bug bounty ada di
[docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md). Kondisi saat ini:
**bagian 1–5 selesai, bagian 6 (kepatuhan & etika) masih terbuka.**

| Bagian | Cakupan | Status & PR | Dokumen |
|---|---|---|---|
| 1 | Kualitas temuan: bukti request/response, repro `curl`, CVSS/CWE/OWASP, confidence, output JSON/SARIF | ✅ `feat/finding-evidence-metadata` | [docs/findings-model.md](docs/findings-model.md) |
| 2 | Cakupan kelas kerentanan: IDOR/BOLA, CSRF, JWT, auth bypass, API spec, host header/cache, CRLF, smuggling, blind OOB | ✅ `feat/vuln-class-coverage` | [docs/vuln-classes.md](docs/vuln-classes.md) |
| 3 | Recon: subdomain (crt.sh + Cert Spotter + wordlist DNS), URL historis (Wayback + Common Crawl), endpoint JS, host hidup, port scan | ✅ `feat/recon-enum` | [docs/recon.md](docs/recon.md) |
| 4 | Kualitas deteksi modul lama: kredensial hardcode JS, orakel SSRF/XSS/LFI/SQLi/CMDi/XXE, baseline SPA, redaksi di objek `Exchange` | ✅ `fix/js-secret-detection` + `feat/module-detection-quality` | [docs/detection-quality.md](docs/detection-quality.md) |
| 5 | Mesin scan: throttle (`--delay`/`--max-rps`/`--jitter`/`--backoff-max`), safe-mode + gerbang otorisasi, impor sesi, rotasi proxy, checkpoint/resume, client certificate, mode interaktif | ✅ `feat/scan-throttle-safe-mode`, `feat/proxy-rotation`, `feat/resume-client-cert`, `feat/interactive-advanced-defaults` | [docs/scan-engine.md](docs/scan-engine.md) |
| 6 | Kepatuhan & etika: allowlist scope (`--scope-file`), `--respect-robots`, identitas tester di `User-Agent` | ⏳ belum dikerjakan (gerbang otorisasi sudah ada lewat `--i-have-authorization`/prompt interaktif) | [docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md) |

Sengaja **tidak** ditambahkan sebagai dependensi: `sqlmap`, `ffuf`, `nuclei`,
dan Playwright. Semua orakel memakai katalog internal supaya runtime tetap
`curl_cffi` + stdlib saja.

## Dokumentasi

| Dokumen | Isi |
|---|---|
| [docs/scan-engine.md](docs/scan-engine.md) | Penjadwal request, safe-mode & gerbang otorisasi, impor sesi, rotasi proxy, checkpoint/resume, mTLS, dan mode interaktif dengan pengaturan lanjutan |
| [docs/findings-model.md](docs/findings-model.md) | Model temuan: bukti request/response, CVSS/CWE/OWASP, confidence, aturan redaksi, skema HTML/CSV/JSON/SARIF |
| [docs/vuln-classes.md](docs/vuln-classes.md) | Rincian tiap kelas kerentanan: apa yang diuji, flag yang dibutuhkan, batas request, penjaga false positive |
| [docs/detection-quality.md](docs/detection-quality.md) | Orakel dan penjaga false positive modul lama (baseline SPA, SSRF, XSS, LFI, SQLi, CMDi/XXE) |
| [docs/recon.md](docs/recon.md) | Tahap recon: sumber data, batas request, alur ke crawler/modul injection, catatan privasi |
| [docs/http-layer.md](docs/http-layer.md) | HTTP layer `curl_cffi`, browser impersonation, dan alasan socket mentah untuk smuggling/CRLF |
| [docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md) | Roadmap dan status kesenjangan fitur bug bounty per bagian |

## Development

```bash
pip3 install -r requirements-dev.txt   # pytest + ruff
python3 -m pytest -q                   # test memakai fixture server lokal (tanpa internet)
python3 -m ruff check .                # lint (config di pyproject.toml)
python3 tools/oob_collector.py --help  # collector OOB (stdlib, tanpa dependency)
```

Test memakai fixture server lokal di `tests/conftest.py` (tanpa jaringan
eksternal): 424 test mencakup 32 modul, flag CLI, recon, mesin scan
(throttle/safe-mode/sesi/rotasi proxy/resume/mTLS), mode interaktif (menu
pengaturan lanjutan), dan generator laporan.

Kode keluar: `0` scan selesai (termasuk kalau ada modul yang gagal — kegagalan
modul dicatat sebagai `INFO SCAN_ERROR` dan masuk `scan.errors` di JSON), `1`
dependensi runtime `curl_cffi` belum terpasang, `2` argumen/konfigurasi tidak
valid (kombinasi flag bentrok, checkpoint `--resume` dengan cakupan berbeda,
prompt target atau menu pengaturan interaktif yang kehabisan input/EOF).

## Catatan

- Scan ini non-intrusive **kecuali** uji opt-in: `--active-writes` (kirim POST),
  `--timing-probes` (delay 3 detik), `--check-smuggling` (socket mentah), dan
  `--oob-host` (callback ke collector Anda). Semuanya mati secara default.
  Tiga flag destruktif pertama butuh konfirmasi otorisasi (prompt interaktif
  atau `--i-have-authorization` di CI); `--safe-mode` mematikannya total dan
  menolak kombinasi dengan flag destruktif (exit 2). Hanya gunakan di situs
  sendiri/terotorisasi.
- Batasi laju scan dengan `--delay`/`--max-rps`/`--jitter` kalau target sensitif
  atau WAF agresif; penjadwal ini global untuk semua worker dan ikut menghormati
  `Retry-After` (dibatasi `--backoff-max`).
- Roadmap celah fitur bug bounty ada di
  [docs/bug-bounty-gaps.md](docs/bug-bounty-gaps.md); yang masih terbuka:
  `--scope-file`/`-l targets.txt`, `--respect-robots`, identitas tester di
  `User-Agent`, dan screenshot recon. Ringkasan status per bagian (PR +
  dokumen pendamping) ada di [Status Pengembangan](#status-pengembangan).
- Detail tahap recon (sumber, batas request, alur data ke crawler dan modul
  injection, privasi) ada di [docs/recon.md](docs/recon.md).
- Model data temuan ada di [docs/findings-model.md](docs/findings-model.md);
  rincian tiap kelas kerentanan (apa yang diuji, flag yang dibutuhkan, batas
  request, penjaga false positive) ada di
  [docs/vuln-classes.md](docs/vuln-classes.md).
- Modul yang **butuh sesi autentikasi** (`idor`, `csrf` aktif, JWT forgery,
  cache deception) dilewati dengan catatan di log kalau `--cookie`/`-H`/
  `--bearer`/`--session` tidak diberikan — bukan dilaporkan sebagai bersih.
- Setiap temuan membawa bukti request/response dan perintah `curl` siap pakai.
  Kredensial disensor otomatis (`***REDACTED***`) dan temuan `JS_SECRET`/
  `JS_SECRET_MAYBE` hanya menampilkan nilai yang sudah dimask (4 karakter awal +
  bintang); jangan pakai `--no-redact` kalau hasilnya akan dibagikan.
- Orakel deteksi, batas payload, dan penjaga false positive per modul ada di
  [docs/detection-quality.md](docs/detection-quality.md).
- Request dijalankan paralel (default 10 worker). Naikkan `--workers` untuk target cepat, turunkan ke `--workers 1` jika target rate-limit/WAF sensitif.
- Modul deteksi (SQLi, XSS, LFI, CMDi, SSTI, XXE, GraphQL, SSRF, NoSQLi, Open Redirect) berhenti lebih awal begitu temuan pertama ketemu, jadi mode DETAILED tidak selalu mengirim semua payload.
- Halaman utama dan daftar form di-cache: satu request/parse dipakai ulang lintas modul, bukan diulang per modul.
- False positive mungkin terjadi. Verifikasi manual temuan CRITICAL/HIGH.
- Mulai dengan `--quick`, lanjut `--detailed` kalau perlu.
- Untuk hasil maksimal: `--detailed` karena mengaktifkan crawler untuk menemukan form POST.

## Penafian & Batas Penggunaan

Spade adalah alat uji keamanan untuk **aset milikmu sendiri atau aset yang kamu
punya izin tertulis untuk diuji** (program bug bounty, kontrak pentest, lab
pribadi). Baca bagian ini sebelum menjalankan scan.

**Pemilik repo tidak bertanggung jawab atas penyalahgunaan repo/alat ini.**
Secara eksplisit, pemilik repo dan para kontributor:

- **tidak bertanggung jawab** atas pemakaian Spade terhadap sistem yang tidak
  kamu miliki atau tidak kamu punya izin untuk menguji — termasuk pemindaian,
  pengujian berintrusi, atau eksploitasi tanpa izin;
- **tidak bertanggung jawab** atas kerusakan langsung maupun tidak langsung,
  kehilangan data, gangguan layanan, kerugian finansial, atau dampak lain yang
  timbul dari pemakaian alat ini;
- **tidak bertanggung jawab** atas tuntutan, sanksi, atau konsekuensi hukum apa
  pun yang timbul dari pemakaian alat ini, termasuk pelanggaran hukum yang
  berlaku di yurisdiksi pengguna dan pelanggaran aturan program bug bounty;
- **tidak memberikan jaminan** apa pun, tersurat maupun tersirat, termasuk
  kelayakan untuk tujuan tertentu dan akurasi temuan.

Tanggung jawab sepenuhnya ada di pengguna: pastikan izin tertulis sudah ada
sebelum request pertama dikirim, patuhi aturan program dan hukum yang berlaku,
hormati batas laju target, dan lindungi data hasil scan (termasuk sebelum
memakai `--no-redact`).

Catatan tambahan:

- Perangkat lunak ini disediakan **"sebagaimana adanya" (as is)**. Temuan bisa
  false positive maupun false negative; verifikasi manual temuan CRITICAL/HIGH
  sebelum dilaporkan ke program.
- Repo ini belum memuat berkas `LICENSE`. Tanpa lisensi eksplisit, hak pakai
  terbatas pada apa yang diizinkan pemilik repo — hubungi pemilik repo kalau
  butuh kejelasan lisensi sebelum memakai atau mendistribusikan ulang.
- Fitur penyamaran request (browser impersonation, rotasi proxy, `--safe-mode`)
  disediakan untuk pengujian berizin, **bukan** untuk menghindari tanggung
  jawab hukum.
- Kalau kamu menemukan Spade dipakai untuk aktivitas tanpa izin, laporkan ke
  pemilik repo lewat issue di
  [github.com/RiloArbabillah/spade](https://github.com/RiloArbabillah/spade).

### Disclaimer (English)

Spade is intended **for authorized security testing only** — assets you own or
assets you have **explicit written permission** to test (bug bounty programs,
pentest engagements, personal labs).

**The repository owner is not responsible for any misuse of this repository or
this tool.** The repository owner and contributors accept no liability for
unauthorized or illegal use, for any direct or indirect damage, data loss,
service disruption, or financial loss, or for any legal claim arising from the
use of this software. The tool is provided **"as is"**, without warranty of any
kind, express or implied. All responsibility rests with the user.
