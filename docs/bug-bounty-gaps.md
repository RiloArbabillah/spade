# Roadmap Kesenjangan Fitur Bug Bounty — Spade

Dokumen ini memetakan celah Spade sebagai alat *bug bounty* (bukan sekadar
scanner pasif), bukti konkret di kode saat ini, dampaknya, dan tool/target
perbaikan yang realistis. Semua baris di bawah **belum dikerjakan** pada PR
`feat/curl-cffi-http-layer` (PR tersebut hanya mengganti HTTP layer ke
`curl_cffi` + menambah test + dokumen ini).

Kondisi kode yang jadi basis analisis (per commit `main` saat dokumen ditulis):

- `spade.py` = 23 modul terdaftar di `ALL_MODULES`; `QUICK_MODULES` 7,
  `DETAILED_ONLY` 7, `STANDARD_MODULES` 16.
- 40 blok `except:` (bare) dan 42 titik `except ...: pass` — banyak modul gagal
  secara diam-diam.
- Semua temuan berbentuk tuple `(severity, kode, deskripsi, url)`
  (mis. `f.append((sev, code, desc, url))`) — tanpa bukti request/response,
  tanpa CVSS, tanpa tingkat keyakinan, tanpa langkah reproduksi.

Kolom **Prioritas**: P0 = wajib sebelum dipakai untuk bounty berbayar,
P1 = nilai tinggi/cepat, P2 = nilai menengah, P3 = nice-to-have.

---

## 1. Kualitas temuan (evidence & pelaporan)

| Area | Bukti di kode | Dampak | Tool / pendekatan konkret | Prioritas |
|---|---|---|---|---|
| Tidak ada bukti request/response | Temuan hanya tuple `(sev, code, desc, url)`; `gen_html`/`gen_csv` menulis 4 kolom + target | Triager menolak laporan; tidak bisa dibuktikan tanpa reproduce manual | Simpan `Evidence` dataclass: `method, url, request_headers, request_body, status, resp_snippet, timestamp`; tulis ke HTML/CSV/JSON | P0 |
| Tidak ada perintah reproduce | Tidak ada generator `curl` | Reporter kehilangan waktu menulis PoC | Emit `curl -sS '<url>' -H ... --data ...` per temuan (pakai profil impersonate yang dipakai scan) | P0 |
| Tidak ada CVSS / OWASP mapping | Hanya label `CRITICAL/HIGH/MEDIUM/LOW/INFO` | Severity subjektif, sulit diprioritaskan | Tambah `cvss_vector` (CVSS 3.1/4.0) + kategori OWASP Top 10/CWE per kode temuan | P1 |
| Tidak ada confidence & deteksi FP | Modul langsung `f.append(...)` saat pola cocok | False positive menggerus kepercayaan | Field `confidence: certain/firm/tentative`; heuristik skor (mis. SQLi error + status 500 + perbedaan respons) | P1 |
| Output hanya HTML/CSV | `-o/--csv` saja | Tidak bisa dipakai di pipeline/CI | Tambah `--json` dan `--sarif`; tambah `--diff <scan.json>` untuk membandingkan dua scan | P1 |

## 2. Cakupan kelas kerentanan yang hilang

| Area | Bukti di kode | Dampak | Tool / pendekatan konkret | Prioritas |
|---|---|---|---|---|
| IDOR / BOLA | Tidak ada modul otorisasi objek | Kelas bug paling umum di bounty modern tidak terdeteksi | Uji variasi ID pada endpoint yang sama (id±1, UUID tetangga), bandingkan status/ukuran respons dengan sesi berbeda | P0 |
| CSRF | Hanya disebut di modul cookie (`SameSite (rentan CSRF)`); tidak ada uji token | Laporan CSRF tidak pernah muncul | Periksa token anti-CSRF pada form, uji submit tanpa token/`Origin` palsu | P1 |
| JWT exploitation | `scan_jwt` hanya decode `alg=none` + info cookie | JWT lemah lolos | `jwt_tool` (crack HMAC secret, `alg=HS256↔RS256` confusion, kid path traversal, exp/claim bypass) | P1 |
| Auth bypass / 401-403 bypass | Tidak ada | Akses tidak sah tidak terdeteksi | Uji header `X-Original-URL`, `X-Rewrite-URL`, path normalisasi, `..;/`, trailing dot; bandingkan respons terautentikasi vs anonim | P1 |
| API spec & endpoint discovery | Tidak ada (hanya link dari HTML + `static/app.js`) | Endpoint REST/GraphQL tersembunyi terlewat | `arjun`/`x8` (parameter), parsing `openapi.json`/`swagger.json`, `kiterunner` | P2 |
| Host header injection / cache poisoning / request smuggling | Tidak ada | Bug bounty kelas tinggi terlewat | `Host`/`X-Forwarded-Host` injection, cache deception (`/admin.css`), deteksi CL.TE/TE.CL (hati-hati: hanya dengan izin) | P2 |
| CRLF / response splitting | Tidak ada | Terlewat | Payload `%0d%0a` pada param/redirect | P2 |
| Blind & OOB (XXE, SSRF, CMDi) | XXE/SSRF hanya deteksi in-band (`len(r.content) > 1000` untuk SSRF, string `/etc/passwd` untuk XXE) | Blind/OOB tidak terdeteksi sama sekali | `interactsh` (OOB HTTP/DNS callback) atau `--oob-host`; `burp collaborator` alternatif | P1 |

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

PR ini sudah memindahkan seluruh HTTP request ke `curl_cffi` dengan
*browser impersonation* aktif secara default (profil `chrome`, dapat diubah
lewat `--impersonate`, dimatikan dengan `--no-impersonate`) sehingga TLS
fingerprint (JA3) dan header klien menyerupai browser asli.

Yang **belum** ada dan tetap jadi celah deteksi:

1. Rotasi IP/proxy (`--proxy-file`) — IP tetap sama selama scan.
2. Pola request: tanpa delay/jitter, urutan modul tetap sama tiap scan.
3. Fingerprint perilaku: tidak ada jeda berpikir, tidak memuat aset statis,
   tidak ada `Referer` realistis antar halaman.
4. Cookie/sesi palsu dan `Accept-Language` tetap seragam untuk semua target.

Item 1–2 ada di tabel bagian 5 (P0/P1) dan akan dikerjakan di PR terpisah.

## Urutan pengerjaan yang disarankan

1. **P0 laporan**: evidence + `curl` repro + CVSS/OWASP (bagian 1).
2. **P0 operasional**: `--cookie/-H`, `--delay/--max-rps`, `--scope-file`,
   `--safe-mode` (bagian 5 & 6).
3. **P0 akurasi**: perbaiki heuristik SSRF dan tambah IDOR/BOLA (bagian 2 & 4).
4. **P1 recon & OOB**: `subfinder`/`dnsx`, `gau`, `interactsh` (bagian 2 & 3).
5. Sisanya P2/P3 sesuai kebutuhan program bounty yang diikuti.
