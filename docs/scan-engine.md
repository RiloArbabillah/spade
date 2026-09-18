# Mesin Scan / Operasional — Throttle, Safe-Mode, Impor Sesi, Rotasi Proxy

Dokumen ini menjelaskan empat kontrol operasional yang menempel di **satu funnel
request** (`ThreadLocalSession.request()` + `raw_http_probe()`): penjadwal laju
request, safe-mode beserta gerbang otorisasi, impor sesi dari file JSON, dan
rotasi proxy keluar.

Semua kontrol dijalankan **sebelum request pertama dikirim**. Pelanggaran
kombinasi flag berhenti dengan exit code `2` tanpa menyentuh target.

## 1. Penjadwal request (`--delay`, `--max-rps`, `--jitter`, `--backoff-max`)

| Flag | Default | Efek |
|---|---|---|
| `--delay SEC` | `0` | Jeda minimum antar request untuk **semua** worker. `0.5` ≈ maksimal 2 request/detik. |
| `--max-rps N` | `0` | Batas laju global request per detik. Boleh digabung dengan `--delay`; batas terketat yang menang. |
| `--jitter PCT` | `0` | Mengacak jeda ±`PCT`% (rentang 0–100) supaya pola request tidak seragam. |
| `--backoff-max SEC` | `30` | Batas atas cooldown global saat target membalas 429/503. |

### Cara kerja

`Throttle` adalah satu instance bersama seluruh worker (bukan per thread),
sehingga `--max-rps` benar-benar membatasi laju total scan. Algoritmanya:

1. Setiap request memanggil `throttle_acquire()` — satu titik masuk untuk semua
   modul, jadi tidak ada modul yang bisa lolos dari penjadwalan.
2. Waktu kirim berikutnya dihitung dari `max(delay, 1/max_rps)`, lalu digeser
   acak oleh jitter (`random.uniform(-spread, +spread)`), dan `_next_slot`
   digeser ke depan di bawah lock.
3. Kalau target membalas 429/503, `throttle_cooldown()` menahan **semua** worker
   (global), bukan hanya thread yang kena. Jeda diambil dari
   `max(Retry-After, backoff eksponensial)` dan dibatasi `--backoff-max`.

Tanpa `--delay`/`--max-rps`, `Throttle.enabled` bernilai `False` dan
`throttle_acquire()` langsung kembali — perilaku default scan tidak berubah.

Probe socket mentah (modul request smuggling) juga memanggil
`throttle_acquire()` sebelum `connect`, supaya jalur non-`curl_cffi` tetap
terhitung di batas laju.

### Dampak ke modul rate-limit

Modul `rate_limit()` mengamati apakah target mulai membalas 429 setelah burst
15 request paralel. Saat penjadwal aktif, burst itu memang diredam, jadi
hasilnya tidak bisa ditafsirkan. Modul **dilewati** dengan catatan di log:

```
(dilewati: throttle aktif — burst 15 request tidak bisa diamati)
```

Ini disengaja: lebih baik melewatkan satu modul daripada melaporkan "tidak ada
rate limit" dari burst yang tidak pernah terjadi.

### Metadata laporan

Blok `scan` di JSON/SARIF selalu memuat status penjadwal (tanpa nilai rahasia):

```json
"throttle": {"enabled": true, "delay": 0.5, "max_rps": 2.0, "jitter": 30.0, "backoff_max": 30.0}
```

### API publik

- `Throttle(delay=0.0, max_rps=0.0, jitter_pct=0.0, backoff_max=DEFAULT_BACKOFF_MAX)`
  dengan `enabled`, `describe()`, `acquire()`, `backoff_for(attempt)`,
  `cooldown(seconds)`.
- `set_request_throttle(throttle)` — pasang/lepas penjadwal global
  (`set_request_throttle(None)` di akhir `main()`).
- `throttle_acquire()` / `throttle_cooldown(seconds, attempt=1)` — no-op saat
  penjadwal tidak aktif.

## 2. Safe-mode & gerbang otorisasi

| Flag | Efek |
|---|---|
| `--safe-mode` | Tidak mengirim metode/payload yang mengubah state. Bentrok dengan flag destruktif → exit 2. |
| `--i-have-authorization` | Konfirmasi non-interaktif bahwa tester punya izin tertulis untuk uji destruktif. |

### Apa yang dimatikan safe-mode

1. **Metode PUT/DELETE** di modul `http_methods()` — hanya `TRACE`/`OPTIONS`
   yang dikirim (keduanya hanya membaca).
2. **Uji tulis CSRF aktif** — `scan_csrf()` memaksa `active = False` walaupun
   `--active-writes` diberikan.
3. **Probe time-based** SQLi/CMDi — `_timing_probes_on(ctx)` mengembalikan
   `False`.
4. **Request smuggling** — `scan_smuggling()` keluar lebih awal.

### Gerbang otorisasi untuk uji destruktif

Tiga flag destruktif (`--active-writes`, `--timing-probes`,
`--check-smuggling`) berhenti di gerbang otorisasi sebelum request pertama:

- `--safe-mode` digabung dengan salah satu flag destruktif → `parser.error`
  (exit 2), karena keduanya saling bertentangan.
- Flag destruktif tanpa `--i-have-authorization`:
  - **stdin bukan TTY** (CI/pipeline) → `parser.error` (exit 2) dengan pesan
    yang menyebut flag yang bermasalah.
  - **stdin TTY** → prompt konfirmasi; jawaban selain `yes` membatalkan scan
    dengan exit 2 **tanpa mengirim request apa pun**.

Status ini tercatat di laporan sebagai `scan.safe_mode` dan `scan.authorized`
supaya triager tahu cakupan uji.

## 3. Impor sesi (`--session FILE`)

`--session` membaca file JSON dan mengubahnya jadi cookie + header yang dipakai
seluruh modul autentikasi. Tiga bentuk diterima supaya ekspor alat lain bisa
langsung dipakai:

```json
{"session": "abc123", "csrftoken": "xyz"}              // objek nama → nilai
```

```json
[{"name": "session", "value": "abc123"}]               // daftar cookie
```

```json
{"cookies": {"session": "abc123"}, "headers": {"X-Api-Key": "..."}}
```

### Prioritas nilai

Nilai diproses berurutan: `--session` lebih dulu, lalu `--cookie`, lalu `-H`.
Karena itu nilai eksplisit dari CLI **menang** kalau nama cookie/header-nya
sama dengan isi file sesi.

Sumber yang terpakai dicatat (nama saja, bukan nilainya) di
`scan.auth_source`, mis. `["session", "cookie"]`.

### Kenapa cookie masuk ke cookie jar, bukan header mentah

Cookie auth (`--cookie`/`--session`) tidak dikirim sebagai header `Cookie`
mentah, melainkan di-seed ke cookie jar thread dengan `domain = host target`.
Alasannya dua:

1. `curl_cffi`/libcurl **mengabaikan** header `Cookie` mentah begitu cookie jar
   berisi entri. Banyak target mengirim `Set-Cookie` di respons pertama; tanpa
   seeding ke jar, kredensial tester hilang setelah respons pertama.
2. Cookie jadi ter-scope ke host target saja, sehingga tidak ikut terkirim ke
   API pihak ketiga yang dipakai recon (crt.sh, Cert Spotter, Wayback, Common
   Crawl).

Perilakunya setara `curl -b`: cookie dari server dengan nama sama menggantikan
cookie tester.

### Redaksi

Nilai sesi tidak pernah ditulis ke laporan (HTML/JSON/SARIF/CSV). Banner
terminal hanya menampilkan nama header yang dipakai lewat
`_redact_auth_headers()`. Test regresi memastikan nilai cookie sesi tidak
muncul di keluaran.

## 4. Rotasi proxy (`--proxy`, `--proxy-file`, `--proxy-cooldown`)

| Flag | Default | Efek |
|---|---|---|
| `--proxy URL` | – | Proxy keluar. Boleh diulang: setiap pengulangan menambah satu IP ke rotasi. |
| `--proxy-file FILE` | – | Daftar proxy dari file teks (satu URL per baris, `#` = komentar). Tidak bisa digabung dengan `--proxy` → exit 2. |
| `--proxy-cooldown SEC` | `60` | Lama proxy diistirahatkan setelah target membalas 403/429/503. `0` = langsung dipakai lagi. |

Skema yang didukung: `http`, `https`, `socks5`, `socks5h`. Skema wajib ditulis
eksplisit (tanpa skema, libcurl menebak dan hasilnya ambigu) dan semuanya
divalidasi **sebelum request pertama**; URL yang tidak layak berhenti dengan
exit code `2`. `socks5h` menyelesaikan DNS di sisi proxy, sehingga nama target
tidak terlihat dari jaringan tester.

```
http://127.0.0.1:8080
socks5h://user:pass@proxy.example.com:1080
# baris komentar diabaikan
```

### Cara kerja

`ProxyPool` adalah satu instance bersama seluruh worker:

1. Setiap request di `ThreadLocalSession.request()` meminta proxy berikutnya
   lewat `next_request_proxy()`, lalu mengirimnya sebagai parameter `proxy=`
   milik `curl_cffi`. Recon, crawl, dan semua modul vuln lewat funnel yang sama,
   jadi tidak ada jalur request yang tetap memakai IP tester.
2. Pemilihan proxy **round-robin**. Kalau responsnya 403/429/503, proxy itu
   diistirahatkan `--proxy-cooldown` detik (`mark_proxy_blocked()`) dan request
   berikutnya otomatis pindah ke proxy lain — inilah *skip-on-block*.
3. Kalau **semua** proxy sedang istirahat, proxy dengan waktu pulih tercepat
   dipakai lagi supaya scan tidak berhenti total (lebih baik lambat daripada
   mati di tengah jalan).
4. Saat rotasi aktif, pembacaan proxy dari variabel lingkungan
   (`http_proxy`/`https_proxy`) dimatikan (`trust_env=False`) supaya proxy
   eksplisit tidak tercampur proxy sistem tester.

### Yang tidak lewat proxy

- **Request smuggling** dikirim lewat socket mentah (bukan `curl_cffi`), jadi
  tidak bisa mengikuti rotasi. Modulnya **dilewati** dengan catatan di log
  supaya IP tester tidak bocor justru saat sedang disembunyikan.
- **Port scan** (`--port-scan`) memakai TCP connect langsung ke target. Ini
  memang perilaku aslinya dan tetap dicatat di banner saat proxy aktif.

### Redaksi

URL proxy bisa memuat kredensial (`user:pass@host`). Yang pernah muncul di
keluaran hanya `_redact_proxy_url()` (password → `***`) untuk pesan error, dan
`describe()` untuk metadata — yang isinya hanya jumlah, sumber, dan cooldown.
Banner menampilkan jumlah proxy, bukan URL-nya. Test regresi memastikan
password proxy tidak muncul di stdout, HTML, maupun JSON.

### Metadata laporan

```json
"proxy": {"enabled": true, "count": 2, "source": "--proxy-file", "cooldown": 60.0}
```

### API publik

- `parse_proxy_url(raw)` / `load_proxy_file(path)` — normalisasi + validasi
  (keduanya melempar `ValueError` yang siap diteruskan ke `parser.error`).
- `ProxyPool(proxies=(), cooldown=DEFAULT_PROXY_COOLDOWN, source="")` dengan
  `enabled`, `count`, `describe()`, `next_proxy()`, `mark_blocked(url)`.
- `set_request_proxies(pool)` — pasang/lepas pool global
  (`set_request_proxies(None)` di akhir `main()`).
- `proxy_rotation_enabled()` / `next_request_proxy()` / `mark_proxy_blocked(url)`
  — no-op saat rotasi tidak aktif.

## Verifikasi

```bash
.venv/bin/pytest -q tests/test_scan_engine.py    # unit + CLI end-to-end throttle/safe-mode/sesi
.venv/bin/pytest -q tests/test_proxy_rotation.py # unit + CLI end-to-end rotasi proxy (proxy lokal asli)
.venv/bin/pytest -q                             # seluruh suite (fixture lokal, tanpa internet)
.venv/bin/ruff check .                          # lint
```

Test rotasi proxy memakai forward proxy HTTP lokal di `tests/conftest.py`
(`ProxyServer`), bukan mock: request scanner benar-benar dikirim ke proxy lalu
diteruskan ke fixture target, sehingga round-robin dan *skip-on-block* terbukti
pada jalur HTTP nyata.

## Batasan / yang ditunda

- Resume/checkpoint (`--state`/`--resume`) dan client certificate
  (`--cert`/`--key`) belum ada.
- Rotasi proxy mengubah IP keluar, bukan fingerprint TLS/header: setiap proxy
  tetap memakai profil impersonation yang sama. Untuk target `https://`, proxy
  `http`/`socks5` hanya membuat tunnel (CONNECT) sehingga header origin utuh;
  untuk target `http://`, proxy HTTP mengakhiri koneksi dan sebagian header
  (mis. `Server`/`Via`) bisa berasal dari proxy, bukan target.
- `--delay`/`--max-rps` membatasi **laju**, bukan pola request manusiawi
  (tidak ada `Referer` realistis antar halaman atau pemuatan aset statis).
- Gunakan hanya pada aset yang Anda miliki atau yang secara eksplisit masuk
  scope program bounty.
