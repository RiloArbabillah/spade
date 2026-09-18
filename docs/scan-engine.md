# Mesin Scan / Operasional — Throttle, Safe-Mode, Impor Sesi

Dokumen ini menjelaskan tiga kontrol operasional yang menempel di **satu funnel
request** (`ThreadLocalSession.request()` + `raw_http_probe()`): penjadwal laju
request, safe-mode beserta gerbang otorisasi, dan impor sesi dari file JSON.

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

## Verifikasi

```bash
.venv/bin/pytest -q tests/test_scan_engine.py   # unit + CLI end-to-end throttle/safe-mode/sesi
.venv/bin/pytest -q                             # seluruh suite (fixture lokal, tanpa internet)
.venv/bin/ruff check .                          # lint
```

## Batasan / yang ditunda

- Rotasi IP/proxy (`--proxy`/`--proxy-file`) belum ada — lihat
  [bug-bounty-gaps.md](bug-bounty-gaps.md) bagian 5.
- Resume/checkpoint (`--state`/`--resume`) dan client certificate
  (`--cert`/`--key`) belum ada.
- `--delay`/`--max-rps` membatasi **laju**, bukan pola request manusiawi
  (tidak ada `Referer` realistis antar halaman atau pemuatan aset statis).
- Gunakan hanya pada aset yang Anda miliki atau yang secara eksplisit masuk
  scope program bounty.
