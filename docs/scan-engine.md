# Mesin Scan / Operasional — Throttle, Safe-Mode, Impor Sesi, Rotasi Proxy, Resume, mTLS, Mode Interaktif

Dokumen ini menjelaskan tujuh kontrol operasional: penjadwal laju request,
safe-mode beserta gerbang otorisasi, impor sesi dari file JSON, rotasi proxy
keluar, checkpoint/resume scan, client certificate untuk target mTLS, dan mode
interaktif yang menampilkan opsi flag-only beserta nilai default-nya.
Empat yang pertama menempel di **satu funnel request**
(`ThreadLocalSession.request()` + `raw_http_probe()`); resume dan mTLS bekerja
di lapisan orkestrasi `main()` dan pembuatan `Session`; mode interaktif bekerja
di depan validasi argumen, sebelum `main()` menyentuh jaringan.

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

## 5. Checkpoint & resume (`--state`, `--resume`)

| Flag | Default | Efek |
|---|---|---|
| `--state FILE` | – | Tulis checkpoint JSON secara atomik setiap satu modul selesai. |
| `--resume FILE` | – | Lanjutkan scan dari checkpoint: modul yang sudah selesai dilewati, temuan lama dimuat ulang. Konfigurasi berbeda → exit 2. |

Scan mode `detailed` bisa berjalan puluhan menit. Kalau jaringan putus, target
mendadak memblokir, atau terminal ditutup, scan tanpa checkpoint harus diulang
dari nol — dan mengulang berarti mengirim ulang ribuan request ke target yang
sama. `--state` menyimpan progres, `--resume` melanjutkannya.

### Isi berkas state

Satu berkas JSON kecil (bukan dump memori) yang memuat:

```json
{
  "tool": {"name": "spade", "version": "3.1"},
  "schema_version": 1,
  "target": "https://contoh.test",
  "started_at": "2026-01-01T10:00:00",
  "updated_at": "2026-01-01T10:04:11",
  "finished_at": null,
  "config": {"target": "...", "mode": "detailed", "modules": ["tech", "..."], "safe_mode": false, "...": "..."},
  "fingerprint": "9f2c…",
  "modules_planned": ["tech", "headers", "..."],
  "modules_done": ["tech", "headers"],
  "modules_pending": ["robots", "..."],
  "findings": [{"id": "...", "code": "XSS", "evidence": {"...": "..."}}],
  "errors": []
}
```

Temuan disimpan dengan bentuk yang sama seperti laporan JSON, **termasuk bukti
request/response yang sudah diredaksi** — jadi laporan hasil resume tidak
kehilangan temuan modul sebelumnya. Berkas state tidak memuat kredensial,
cookie sesi, atau path berkas lokal.

### Tulis atomik

`write_scan_state()` menulis ke berkas sementara di direktori yang sama,
`fsync`, lalu `os.replace()`. Proses yang mati di tengah penulisan tidak
meninggalkan state setengah jadi. Kalau checkpoint gagal ditulis (mis. direktori
tidak bisa ditulis), scan **tetap lanjut** dengan peringatan dan checkpoint
dimatikan untuk sisa run — kehilangan progres lebih ringan daripada kehilangan
hasil scan.

### Fingerprint: kenapa resume bisa ditolak

`--resume` hanya menerima checkpoint dengan cakupan uji yang sama. Sebelas kunci
konfigurasi (`STATE_FINGERPRINT_KEYS`) di-hash jadi `fingerprint`; kalau ada yang
berbeda, scan berhenti dengan exit code `2` **sebelum satu request pun dikirim**:

```
spade.py: error: --resume: konfigurasi berbeda dari checkpoint (mode, modules) — jalankan scan baru atau pakai checkpoint dengan konfigurasi yang sama
```

Yang ikut di-fingerprint: `target`, `mode`, `impersonate`, `modules`, `auth`,
`safe_mode`, `active_writes`, `timing_probes`, `check_smuggling`, `port_scan`,
dan `oob`. Alasannya: mengubah salah satunya mengubah arti temuan, jadi
menggabungkan hasil lama dengan hasil baru akan menyesatkan triager.

### Batas resume: ctx tidak dipulihkan

Modul yang dilewati tidak mengembalikan *ctx* yang dihitung di memori (URL hasil
recon, endpoint dari berkas JS, daftar parameter). Modul yang belum selesai
berjalan dengan seed yang dihitung ulang dari awal, sehingga bisa lebih sedikit
daripada scan penuh. Keterbatasan ini dicatat di log (`RESUME_CTX_NOTE`) dan di
laporan (`scan.resume.ctx_note`) supaya cakupan hasil resume tidak
ditafsirkan berlebihan.

### Metadata laporan

```json
"state":  {"enabled": true, "written": true},
"resume": {"enabled": true, "modules_skipped": ["tech", "headers"],
           "findings_restored": 3, "ctx_note": "Data ctx dari modul yang dilewati …"}
```

Path berkas state tidak ditulis ke laporan supaya laporan tetap portabel.

### API publik

- `scan_config_fingerprint(config)` / `state_fingerprint_mismatch(config, saved)`
  — hash cakupan uji dan daftar kunci yang berbeda.
- `scan_state_config(target, mode, args, modules, auth_enabled, oob_host)` —
  ringkasan konfigurasi tanpa rahasia.
- `scan_state_payload(...)` / `write_scan_state(path, payload)` /
  `load_scan_state(path)` — menyusun, menulis atomik, dan membaca+memvalidasi
  state (semuanya melempar `ValueError` yang siap diteruskan ke `parser.error`).
- `finding_from_state(data)` / `findings_from_state(data)` — membangun ulang
  `Finding` beserta bukti; entri rusak dilewati, bukan menggagalkan resume.

## 6. Client certificate (`--cert`, `--key`)

| Flag | Efek |
|---|---|
| `--cert FILE` | Client certificate PEM untuk target mTLS. Satu berkas boleh memuat cert + key sekaligus. |
| `--key FILE` | Private key PEM pasangan `--cert`. Diberikan tanpa `--cert` → exit 2. |

Target di balik mTLS menolak koneksi sebelum HTTP apa pun dikirim, sehingga
seluruh modul akan tampak "mati" tanpa cara memasang client certificate.

### Cara kerja

`--cert`/`--key` diteruskan apa adanya ke `curl_cffi` sebagai `cert=` — satu
path kalau tanpa `--key`, atau tuple `(cert, key)`. Nilainya dipasang sekali di
`make_session()` dan otomatis dipakai **semua** Session thread
(`ThreadLocalSession(client_cert=…)`), termasuk sesi anonim pembanding, jadi
tidak ada call site modul yang perlu diubah.

Isi berkas tidak pernah dibaca, disalin, atau dicatat spade: yang dikirim ke
libcurl hanya path-nya.

### Validasi sebelum request pertama

- `--key` tanpa `--cert` → `parser.error` (exit 2): private key sendirian tidak
  bisa dipakai libcurl dan hampir pasti salah ketik.
- `--cert`/`--key` menunjuk berkas yang tidak ada → `parser.error` (exit 2).
- `--cert` digabung `--skip-ssl` → peringatan di banner: koneksi tidak
  diverifikasi, hanya sisi klien yang diautentikasi.

### Metadata laporan

```json
"client_cert": {"enabled": true, "key": true}
```

Hanya status yang dicatat; path berkas lokal tidak ikut ke HTML/JSON supaya
laporan tetap portabel dan tidak membocorkan struktur direktori tester.

## 7. Mode interaktif & pengaturan lanjutan

| Cara pakai | Efek |
|---|---|
| Tanpa argumen | Tanya target → tanya mode → tampilkan menu pengaturan lanjutan |
| Enter di prompt menu | Pakai semua nilai default yang tampil, lalu mulai scan |
| `1`, `3` | Ubah satu opsi; prompt kedua minta nilai barunya |
| `1, 3 5` | Ubah beberapa opsi sekaligus (nomor dipisah koma/spasi) |
| `l` (atau `list`, `?`) | Cetak ulang daftar opsi |
| `-` di prompt nilai | Kosongkan opsi teks/daftar (cookie, header, proxy, dst.) |

Sebelumnya mode interaktif hanya menanyakan **target** dan **mode**. Fitur
lainnya — `--workers`, `--delay`, `--proxy`, `--cookie`, `--safe-mode`, dan
seterusnya — hanya bisa dipakai kalau pengguna sudah tahu nama flag-nya lebih
dulu. Sekarang semuanya dicetak bersama nilai default yang akan dipakai scan,
jadi fitur flag-only tetap bisa ditemukan tanpa membuka `--help`.

Prompt mode juga menambah opsi **[4] Recon** (`--recon-only`), yang tadinya
hanya bisa dijangkau lewat flag.

### Yang ditampilkan

Daftar dibangun dari registry `INTERACTIVE_OPTIONS` — 33 entri dalam 7
kelompok, dan setiap entri memuat nama flag aslinya supaya pengguna bisa
berpindah ke jalur non-interaktif kapan saja:

| Kelompok | Opsi |
|---|---|
| Kecepatan & stealth | `--workers`, `--impersonate`, `--delay`, `--max-rps`, `--jitter`, `--backoff-max`, `--proxy`, `--proxy-file`, `--proxy-cooldown` |
| Sesi & autentikasi | `--cookie`, `-H/--header`, `--bearer`, `--session`, `--jwt-secrets` |
| Cakupan uji | `--no-recon`, `--crawl-depth`, `--crawl-max`, `--port-scan`, `--safe-mode`, `--skip-ssl` |
| Uji destruktif (butuh otorisasi) | `--active-writes`, `--timing-probes`, `--check-smuggling` |
| Target khusus | `--oob-host`, `--cert`, `--key` |
| Checkpoint | `--state`, `--resume` |
| Laporan | `-o/--output`, `--json`, `--csv`, `--sarif`, `--no-redact` |

Opsi bernilai angka punya batas bawah/atas yang sama dengan validasi CLI
(`--jitter` 0–100, `--workers` ≥ 1, `--crawl-depth` ≥ 1, dst.), dan nama profil
`--impersonate` diperiksa terhadap daftar profil `curl_cffi` yang tersedia.

### Cara menjawab

- **Angka** untuk opsi `int`/`float`. Nilai di luar rentang ditolak dengan
  pesan batasnya lalu ditanyakan ulang — bukan `exit 2` yang membuang semua
  isian.
- **`aktif`/`mati`** (juga `ya`/`tidak`, `on`/`off`, `1`/`0`) untuk opsi
  boolean. Flag negatif ditampilkan sebagai **keadaan fiturnya**, bukan nama
  flag-nya: baris `Recon` menunjukkan `aktif`/`mati` walau yang ditulis ke
  `args` adalah `--no-recon`.
- **Enter** di prompt nilai membatalkan perubahan opsi itu saja; **Enter** di
  prompt menu berarti "pakai semua default dan mulai scan".

### Nilai rahasia tidak pernah ditampilkan

`--cookie`, `-H/--header`, dan `--bearer` ditampilkan sebagai `***`
(daftar: `*** (N item)`) — nilainya tidak pernah muncul di layar, termasuk di
ringkasan "Pengaturan diubah:" sebelum scan. Alasannya sama dengan redaksi
laporan: keluaran terminal bisa ikut tersimpan di log, `tmux` scrollback, atau
rekaman sesi.

### Konflik dicek di menu, validasi tetap di jalur CLI

Kombinasi yang pasti berakhir `exit 2` dicek lebih awal di dalam prompt supaya
pengguna tidak kehilangan isian:

- `--safe-mode` digabung flag destruktif (`--active-writes`,
  `--timing-probes`, `--check-smuggling`),
- `--proxy` digabung `--proxy-file`,
- `--port-scan` tanpa mode `detailed`/`recon`.

Menu **tidak** menggandakan aturan validasi: nilai yang diisi langsung ditulis
ke `args`, lalu `main()` menjalankan jalur validasi CLI yang sama. Kombinasi
yang tidak dicek di menu (mis. `--key` tanpa `--cert`, `--bearer` bentrok
`-H 'Authorization: …'`) tetap berhenti dengan `exit 2` lewat `parser.error`.

### Flag yang sengaja tidak masuk menu

| Flag | Alasan |
|---|---|
| `--quick` / `--detailed` / `--recon-only` | Sudah menjadi prompt mode (termasuk pilihan `[4] Recon`). |
| `--no-color` | Harus di-set sebelum menu ini dicetak; memprosesnya di tengah menu akan membuat tampilan separuh berwarna. Karena itu `--no-color` kini diproses paling awal di `main()`. |
| `--no-impersonate` | Sudah tercakup opsi `--impersonate` dengan nilai `-`/`tanpa`. |
| `--i-have-authorization` | Digantikan prompt konfirmasi otorisasi, yang memang hanya muncul di terminal interaktif. |

### Ringkasan sebelum scan

Banner kedua menambah baris yang tadinya hanya terlihat di `--help`:

```
Workers: 10 request paralel
Crawl : depth 2, maks 30 halaman      (hanya mode detailed)
Recon : dilewati (--no-recon) — ...   (hanya kalau recon dimatikan)
```

### Perilaku saat input berakhir (EOF)

Terminal non-TTY (pipeline/CI) tidak bisa menjawab prompt. EOF di prompt target
maupun di prompt menu keluar dengan `exit 2` dan pesan singkat di `stderr`,
tanpa traceback. Otomasi tetap harus memakai flag CLI.

### API publik

- `build_parser()` — parser `argparse` dipisah dari `main()` supaya daftar flag
  bisa diperiksa tanpa menjalankan scan. `INTERACTIVE_OPTIONS` diuji agar selalu
  sinkron dengannya: setiap dest CLI harus ada di menu atau terdaftar eksplisit
  sebagai pengecualian.
- `INTERACTIVE_OPTIONS` — tuple entri menu (`attr`, `flag`, `label`, `group`,
  `kind`, `hint`, `invert`, `minimum`, `maximum`, `show`, `secret`). Menambah
  flag baru cukup dengan menambah entri di sini.
- `_interactive_option_text(option, args, host="")` /
  `_apply_option_value(option, args, raw)` /
  `_interactive_conflicts(args)` / `_prompt_advanced_options(args, host="")` —
  bagian yang bisa diuji tanpa menjalankan scan penuh.

## Verifikasi

```bash
.venv/bin/pytest -q tests/test_scan_engine.py        # unit + CLI end-to-end throttle/safe-mode/sesi
.venv/bin/pytest -q tests/test_proxy_rotation.py     # unit + CLI end-to-end rotasi proxy (proxy lokal asli)
.venv/bin/pytest -q tests/test_resume_client_cert.py # unit + CLI end-to-end checkpoint/resume & mTLS
.venv/bin/pytest -q tests/test_interactive_defaults.py # menu pengaturan lanjutan: registry, nilai default, alur end-to-end
.venv/bin/pytest -q                                 # seluruh suite (fixture lokal, tanpa internet)
.venv/bin/ruff check .                              # lint
```

Test rotasi proxy memakai forward proxy HTTP lokal di `tests/conftest.py`
(`ProxyServer`), bukan mock: request scanner benar-benar dikirim ke proxy lalu
diteruskan ke fixture target, sehingga round-robin dan *skip-on-block* terbukti
pada jalur HTTP nyata.

Test mode interaktif menjalankan `spade.main([])` dengan `input()` yang
disuntik jawaban berurutan, jadi alur target → mode → menu → scan benar-benar
dieksekusi terhadap fixture target lokal. Salah satu test memastikan setiap
flag CLI muncul di menu (atau terdaftar sebagai pengecualian), sehingga flag
baru tidak bisa ditambahkan tanpa ikut tampil di mode interaktif.

## Batasan / yang ditunda

- Menu pengaturan lanjutan hanya muncul di mode interaktif. Pada pemanggilan
  dengan argumen (`spade.py contoh.test --quick`) perilakunya tidak berubah
  sama sekali; di terminal non-TTY menu ini langsung berakhir EOF → `exit 2`.
- Menu menampilkan **nilai** opsi, bukan konsekuensinya: mengubah
  `--crawl-depth` di mode `quick` tetap tidak berpengaruh karena crawl hanya
  jalan di mode `detailed` (baris `Crawl :` di banner menandai ini).
- Resume tidak memulihkan *ctx* modul yang dilewati (lihat §5) dan tidak
  melanjutkan modul yang terpotong di tengah: checkpoint ditulis per modul,
  jadi modul yang belum selesai diulang dari awal.
- `--cert`/`--key` hanya menerima berkas PEM (format yang dimengerti libcurl);
  PKCS#12/PFX dan passphrase belum didukung.
- Rotasi proxy mengubah IP keluar, bukan fingerprint TLS/header: setiap proxy
  tetap memakai profil impersonation yang sama. Untuk target `https://`, proxy
  `http`/`socks5` hanya membuat tunnel (CONNECT) sehingga header origin utuh;
  untuk target `http://`, proxy HTTP mengakhiri koneksi dan sebagian header
  (mis. `Server`/`Via`) bisa berasal dari proxy, bukan target.
- `--delay`/`--max-rps` membatasi **laju**, bukan pola request manusiawi
  (tidak ada `Referer` realistis antar halaman atau pemuatan aset statis).
- Gunakan hanya pada aset yang Anda miliki atau yang secara eksplisit masuk
  scope program bounty.
