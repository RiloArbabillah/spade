# Roadmap Kesenjangan Fitur Bug Bounty — Spade

Dokumen ini memetakan celah Spade sebagai alat *bug bounty* (bukan sekadar
scanner pasif), bukti konkret di kode saat ini, dampaknya, dan tool/target
perbaikan yang realistis.

Status: **bagian 1 dan 2 sudah dikerjakan** — bagian 1 di PR
`feat/finding-evidence-metadata` (detail di
[docs/findings-model.md](findings-model.md)), bagian 2 di PR
`feat/vuln-class-coverage` (detail per kelas di
[docs/vuln-classes.md](vuln-classes.md)). Bagian 3–6 masih terbuka. PR
`feat/curl-cffi-http-layer` sebelumnya hanya mengganti HTTP layer ke `curl_cffi`
+ menambah test + membuat dokumen ini.

Kondisi kode yang jadi basis analisis (per commit `main` saat dokumen ditulis):

- `spade.py` = 23 modul terdaftar di `ALL_MODULES`; `QUICK_MODULES` 7,
  `DETAILED_ONLY` 7, `STANDARD_MODULES` 16. (Setelah bagian 2: 31 modul,
  `DETAILED_ONLY` 12, `STANDARD_MODULES` 19.)
- 40 blok `except:` (bare) dan 42 titik `except ...: pass` — banyak modul gagal
  secara diam-diam. (Sejak `feat/finding-evidence-metadata`, kegagalan modul di
  `main()` tercatat sebagai `INFO SCAN_ERROR` + masuk `scan.errors`.)
- Temuan ditulis sebagai tuple `(severity, kode, deskripsi, url)`
  (mis. `f.append((sev, code, desc, url))`) — tanpa bukti request/response,
  tanpa CVSS, tanpa tingkat keyakinan, tanpa langkah reproduksi. (Sejak
  `feat/finding-evidence-metadata`, tuple itu tetap valid tapi sekarang
  otomatis jadi `Finding` lengkap dengan bukti + metadata; lihat bagian 1.)

Kolom **Prioritas**: P0 = wajib sebelum dipakai untuk bounty berbayar,
P1 = nilai tinggi/cepat, P2 = nilai menengah, P3 = nice-to-have.

---

## 1. Kualitas temuan (evidence & pelaporan)

Dikerjakan di `feat/finding-evidence-metadata` (semua baris di bawah **selesai**).

| Area | Bukti lama di kode | Dampak | Yang dikerjakan | Status |
|---|---|---|---|---|
| Tidak ada bukti request/response | Temuan hanya tuple `(sev, code, desc, url)`; `gen_html`/`gen_csv` menulis 4 kolom + target | Triager menolak laporan; tidak bisa dibuktikan tanpa reproduce manual | `class Exchange` + `exchange_from_response()` merekam request/response otomatis di funnel `ThreadLocalSession.request()`; `FindingList` menempelkan bukti dari indeks `evidence_for()`; bukti tampil di HTML/CSV/JSON | ✅ Selesai |
| Tidak ada perintah reproduce | Tidak ada generator `curl` | Reporter kehilangan waktu menulis PoC | `repro_curl()` menghasilkan `curl -sS -i -X … -H … --data-raw …` portabel + snippet `curl_cffi` (memakai profil `--impersonate` scan); cookie selalu `COOKIE_ANDA` | ✅ Selesai |
| Tidak ada CVSS / OWASP mapping | Hanya label `CRITICAL/HIGH/MEDIUM/LOW/INFO` | Severity subjektif, sulit diprioritaskan | `FINDING_META` (CVSS 3.1 + CWE + OWASP Top 10 per kode) + `META_PREFIX_RULES` untuk `MISS_*`/`HDR_*`/`WEAK_*`; `cvss_of()` mengosongkan skor temuan informasional | ✅ Selesai |
| Tidak ada confidence & deteksi FP | Modul langsung `f.append(...)` saat pola cocok | False positive menggerus kepercayaan | Field `confidence: certain/firm/tentative` via `finding_confidence()`; kode heuristik (`SSRF*`, `CORS_REFLECT`, `XSS_STORED`, `NO_RATE_LIMIT`, …) dipaksa `tentative`; hitungan per confidence ada di ringkasan laporan | ✅ Selesai |
| Output hanya HTML/CSV | `-o/--csv` saja | Tidak bisa dipakai di pipeline/CI | `--json` (metadata scan + temuan + bukti) dan `--sarif` (SARIF 2.1.0, siap GitHub code scanning) | ✅ Selesai |
| Tidak ada pembandingan antar scan | — | Sulit melihat temuan baru/hilang | `--diff <scan.json>` — **sengaja ditunda** ke PR terpisah | ⏳ Ditunda |

## 2. Cakupan kelas kerentanan yang hilang

Dikerjakan di `feat/vuln-class-coverage` (semua baris di bawah **selesai**;
rincian per kelas, flag, dan batas request ada di
[docs/vuln-classes.md](vuln-classes.md)).

| Area | Bukti di kode | Dampak | Yang dikerjakan | Status |
|---|---|---|---|---|
| IDOR / BOLA | Tidak ada modul otorisasi objek | Kelas bug paling umum di bounty modern tidak terdeteksi | Modul `idor`: kandidat ID/UUID dari query/path/form, dibandingkan **dua sesi** (anonim vs `--cookie`). `IDOR_ANON` (HIGH, firm) kalau objek tetangga terbaca anonim, `IDOR_READ` (MEDIUM, tentative) kalau hanya lewat sesi tester. Batas 25 kandidat | ✅ Selesai |
| CSRF | Hanya disebut di modul cookie (`SameSite (rentan CSRF)`); tidak ada uji token | Laporan CSRF tidak pernah muncul | Modul `csrf`: pasif — form POST tanpa field token → `CSRF_NO_TOKEN`. Aktif (`--active-writes`) — token palsu diterima dengan respons identik → `CSRF_TOKEN_IGNORED` (firm). Form login dilewati | ✅ Selesai |
| JWT exploitation | `scan_jwt` hanya decode `alg=none` + info cookie | JWT lemah lolos | `scan_jwt` diperluas: crack HMAC offline vs `--jwt-secrets` + 41 secret bawaan (`JWT_WEAK_SECRET`), uji forgery ke endpoint terlindungi (`JWT_ALG_CONFUSION`, `JWT_EXPIRED_ACCEPTED`), `kid` traversal, tanpa `exp`. Semua offline/berbuktikan orakel | ✅ Selesai |
| Auth bypass / 401-403 bypass | Tidak ada | Akses tidak sah tidak terdeteksi | Modul `authbypass`: 8 varian header (`X-Original-URL`, `X-Forwarded-For: 127.0.0.1`, …) + 9 varian normalisasi path (`..;/`, `//`, `%2e/`, trailing dot) ke path yang menolak anonim. `AUTH_BYPASS_HEADER`/`AUTH_BYPASS_PATH` (HIGH, firm) hanya kalau isi respons berbeda dari body penolakan | ✅ Selesai |
| API spec & endpoint discovery | Tidak ada (hanya link dari HTML + `static/app.js`) | Endpoint REST/GraphQL tersembunyi terlewat | Modul `apispec`: 6 path OpenAPI/Swagger JSON; `API_SPEC_EXPOSED` + panen path/parameter ke `ctx["api_params"]` yang ikut diuji modul injection. Modul `params`: 47 nama parameter umum × 8 URL → `PARAM_DISCOVERY` (INFO) | ✅ Selesai (parsial) |
| Host header injection / cache poisoning / request smuggling | Tidak ada | Bug bounty kelas tinggi terlewat | Modul `hostheader`: `Host`/`X-Forwarded-Host`/… → `HOST_HEADER_INJECTION`, `CACHE_POISONING`, dan cache deception (`/admin/spade-nonexistent.css`) → `CACHE_DECEPTION`. Modul `smuggling`: CL.TE/TE.CL lewat socket mentah, **hanya** dengan `--check-smuggling` | ✅ Selesai |
| CRLF / response splitting | Tidak ada | Terlewat | Modul `crlf`: 4 payload `%0d%0a` (+ unicode CRLF) dikirim mentah ke 4 path redirect + crawl; bukti = header `X-Spade-Injected`/cookie `spade=1` benar-benar muncul (`CRLF_INJECTION`, firm) | ✅ Selesai |
| Blind & OOB (XXE, SSRF, CMDi) | XXE/SSRF hanya deteksi in-band (`len(r.content) > 1000` untuk SSRF, string `/etc/passwd` untuk XXE) | Blind/OOB tidak terdeteksi sama sekali | `--oob-host` + `tools/oob_collector.py` (stdlib, kontrak `GET /<token>` + `GET /check?token=`): token unik per probe, `SSRF_BLIND`/`XXE_BLIND`/`CMDI_BLIND` hanya dibuat kalau collector mencatat callback | ✅ Selesai |

### Ditunda dari bagian 2

| Item | Alasan ditunda | Rencana |
|---|---|---|
| Parsing OpenAPI/Swagger **YAML**, SDL/inti GraphQL dari file spec | Butuh parser YAML → dependency baru (`PyYAML`) di proyek yang sengaja stdlib-only + `curl_cffi` | Ditambahkan bersama PR "recon" (bagian 3), atau dengan parser minimal YAML subset |
| Brute force parameter penuh (`arjun`/`x8`: wordlist besar + deteksi pola respons) | Menambah ribuan request per scan; butuh `--max-rps`/`--delay` (bagian 5) dulu supaya tidak membanjiri target | Setelah bagian 5 (`--delay`/`--max-rps`) selesai |
| Cache poisoning berantai (kunci cache berbeda per header) & `X-Forwarded-Host` di ekstensi aset | Butuh orkestrasi 2 pengguna + verifikasi cache nyata di CDN target | PR lanjutan setelah bagian 5; sementara temuan `CACHE_POISONING`/`CACHE_DECEPTION` tetap dilaporkan sebagai `tentative` |
| `--diff <scan.json>` (bagian 1) | Fitur pelaporan, bukan cakupan kelas | PR terpisah (sama seperti bagian 1) |
| `-l targets.txt` + `--scope-file` (bagian 3 & 6) | Menyentuh entry point CLI dan model target (saat ini satu target) | PR "operasional & scope" berikutnya |


## 3. Recon

| Area | Bukti di kode | Dampak | Tool / pendekatan konkret | Prioritas |
|---|---|---|---|---|
| Subdomain enum terbatas | `scan_subdomains` = CRT.sh (50 entry) + 20 kata statis via `socket.getaddrinfo` | Attack surface sebagian besar tidak terlihat | `subfinder` + `dnsx` + `httpx` (resolve + status + title), fallback ke wordlist besar | P1 |
| Tanpa crawling URL historis | Crawler hanya BFS dari HTML halaman seed (`Crawler`) | Endpoint lama/parameter tidak terlihat | `gau`/`waymore` untuk URL dari Wayback/Common Crawl, lalu umpan ke modul injection | P1 |
| Tanpa crawling JS/endpoint modern | Modul `js` hanya regex `apiKey` + path `/api/v1/...` di 1 file | Endpoint SPA terlewat | `katana` (headless crawl) atau `jsluice` untuk ekstraksi endpoint dari JS | P2 |
| Tanpa port/ service scan | Tidak ada | Service non-HTTP (8080, 8443, dsb) terlewat | `naabu`/`nmap` ringan untuk port umum lalu `httpx` untuk filter | P2 |
| Tanpa visual recon / screenshot | Tidak ada | Sulit memvalidasi temuan visual | `gowitness` / Playwright screenshot per host | P3 |
| Scope & multi-target | Argumen `target` tunggal; tidak ada file scope | Tidak bisa batch host dari program bounty | Tambah `-l targets.txt` + `--scope-file` (allowlist domain) | P0 |

## 4. Kualitas deteksi modul yang sudah ada

| Area | Bukti di kode | Dampak | Tool / pendekatan konkret | Prioritas |
|---|---|---|---|---|
| SSRF heuristik kasar | `if "169.254.169.254" in r.text or len(r.content) > 1000:` | FP besar pada respons normal >1 KB; blind SSRF lolos | Bandingkan respons dengan baseline (status + ukuran + waktu), tambah `interactsh` callback | P0 |
| XSS tanpa konteks/encoding | Cek payload muncul mentah di HTML | FP (dalam komentar/atribut) dan FN (encoding parsial) | Analisis konteks (HTML/attr/JS/URL), uji varian encoding, verifikasi eksekusi via headless browser (Playwright) | P1 |
| LFI hanya `/etc/passwd` & `/etc/hosts` | `["../../etc/passwd","../../etc/hosts"]` di param terbatas (`file,page,include,path,doc,load`) | FN besar (Windows, wrapper `php://filter`, log poisoning) | Tambah `php://filter/convert.base64-encode`, `C:\Windows\win.ini`, `/proc/self/environ`; integrasi `ffuf` wordlist LFI | P2 |
| SQLi tanpa eksploitasi lanjut | Error-based + `SLEEP(3)` saja | Banyak DBMS/Varian tidak terdeteksi | Validasi silang dengan `sqlmap` (`--batch --level 2 --risk 1`) hanya saat indikasi ditemukan | P2 |
| CMDi/XXE hanya in-band | Output dicek di respons | Blind tidak terdeteksi | Payload time-based (`; sleep 5`) + OOB (`interactsh`) | P1 |
| Baseline SPA scope | `get_baseline_fingerprint` memakai 2 path acak | FP/FN pada SPA dengan route dinamis | Perluas baseline (3-5 path + perbandingan similarity) | P2 |
| Template/pattern kaku | Semua deteksi berbasis daftar payload hardcoded | Mudah diblokir WAF dan cepat usang | Tambah dukungan template `nuclei` (jalankan `nuclei -t` opsional) | P2 |

## 5. Mesin scan / operasional

| Area | Bukti di kode | Dampak | Tool / pendekatan konkret | Prioritas |
|---|---|---|---|---|
| Tanpa rate limit / delay / jitter | Hanya `--workers`; request paralel penuh (default 10) | Target down / diblokir WAF → scan sia-sia | Tambah `--delay`, `--max-rps`, jitter acak, dan backoff saat 429/503 | P0 |
| Tanpa proxy / rotasi IP | Tidak ada opsi proxy | IP tester cepat diblokir | Tambah `--proxy`, `--proxy-file` (rotasi), dukung SOCKS5 | P1 |
| Tanpa auth/cookie/header injection | Tidak ada `--cookie`, `--header`, `--auth` | Tidak bisa scan area terautentikasi (mayoritas bounty) | Tambah `--cookie`, `-H`, `--bearer`, impor sesi (JSON cookie) | P0 |
| Tanpa resume / state | Hasil hanya akhir scan; tidak ada checkpoint | Scan panjang harus diulang | Tulis `state.json` per modul selesai + `--resume` | P2 |
| Tanpa client certificate | Tidak ada | Target mTLS tidak bisa diuji | `--cert/--key` (didukung `curl_cffi` lewat `cert=`) | P3 |
| Safe-mode / gating payload berbahaya | Semua payload destruktif (PUT/DELETE, `SLEEP`) jalan di mode apa pun | Risiko melanggar aturan program | Tambah `--safe-mode` (tanpa payload destruktif) + konfirmasi eksplisit untuk uji tulis/hapus | P0 |

## 6. Kepatuhan & etika

| Area | Bukti di kode | Dampak | Tool / pendekatan konkret | Prioritas |
|---|---|---|---|---|
| Tanpa allowlist scope | Argumen target apa pun langsung discan | Risiko scan di luar izin program | `--scope-file` (wildcard domain) + penolakan target di luar scope | P0 |
| Tidak menghormati robots.txt | Impor `urllib.robotparser` sudah dihapus; tidak ada pemakaian | Potensi pelanggaran aturan; catatan: sebagian program mengizinkan | `--respect-robots` opsional (default off untuk bounty, tapi dicatat di laporan) | P2 |
| Tanpa pakta otorisasi | Tidak ada konfirmasi izin sebelum scan | Salah pakai = masalah hukum | Prompt pertama kali + flag `--i-have-authorization` untuk mode non-interaktif | P1 |
| Identitas tester tidak jelas | Tidak ada `User-Agent` bounty/contact | Triager tidak tahu siapa memindai | Tambah `--user-agent-suffix` (mis. `spade/3 (+contact)`); catat saat impersonation dipakai | P2 |

---

## Catatan penting soal anti-deteksi bot

HTTP layer sudah memakai `curl_cffi` dengan *browser impersonation* aktif
secara default (profil `chrome`, dapat diubah lewat `--impersonate`, dimatikan
dengan `--no-impersonate`) sehingga TLS fingerprint (JA3) dan header klien
menyerupai browser asli.

Yang **belum** ada dan tetap jadi celah deteksi:

1. Rotasi IP/proxy (`--proxy-file`) — IP tetap sama selama scan.
2. Pola request: tanpa delay/jitter, urutan modul tetap sama tiap scan.
3. Fingerprint perilaku: tidak ada jeda berpikir, tidak memuat aset statis,
   tidak ada `Referer` realistis antar halaman.
4. Cookie/sesi palsu dan `Accept-Language` tetap seragam untuk semua target.

Item 1–2 ada di tabel bagian 5 (P0/P1) dan akan dikerjakan di PR terpisah.

## Urutan pengerjaan yang disarankan

1. ~~**P0 laporan**: evidence + `curl` repro + CVSS/OWASP (bagian 1).~~
   **Sudah selesai** di `feat/finding-evidence-metadata` — sisa yang tertunda
   hanya `--diff <scan.json>`.
2. ~~**P0/P1 cakupan kelas kerentanan** (bagian 2): IDOR/BOLA, CSRF, JWT,
   auth bypass, API spec, host header/cache, CRLF, smuggling, blind SSRF/XXE/CMDi
   lewat collector OOB.~~ **Sudah selesai** di `feat/vuln-class-coverage`
   (detail di [docs/vuln-classes.md](vuln-classes.md)). `--cookie/-H/--bearer`
   dari bagian 5 sudah dikerjakan sekaligus karena kelas di atas butuh sesi
   autentikasi.
3. **P0 operasional sisanya**: `--delay/--max-rps`, `--proxy/--proxy-file`,
   `--scope-file`, `-l targets.txt`, `--safe-mode`, `--i-have-authorization`
   (bagian 5 & 6).
4. **P0 akurasi**: perbaiki heuristik SSRF in-band dan perluas cakupan
   XSS/LFI (bagian 4).
5. **P1 recon**: `subfinder`/`dnsx`/`httpx`, `gau`/`waymore`, `katana`/`jsluice`
   (bagian 3).
6. Sisanya P2/P3 sesuai kebutuhan program bounty yang diikuti.
