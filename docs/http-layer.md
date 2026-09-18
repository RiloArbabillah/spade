# HTTP Layer Spade (`curl_cffi`)

Sejak PR `feat/curl-cffi-http-layer`, seluruh request Spade dikirim lewat
[`curl_cffi`](https://github.com/lexiforest/curl_cffi) dengan *browser
impersonation* aktif secara default. Tujuannya: TLS fingerprint (JA3/JA4),
urutan header, dan `User-Agent` menyerupai browser asli sehingga request tidak
langsung dikenali sebagai bot.

## API publik

### `make_session(timeout=15, verify_ssl=True, impersonate=_DEFAULT)`

Membuat satu `curl_cffi.requests.Session`.

- `impersonate` default (`_DEFAULT`) → memakai `DEFAULT_IMPERSONATE` (`"chrome"`,
  yaitu Chrome terbaru yang didukung `curl_cffi`).
- `impersonate=None` → impersonation dimatikan (mode paritas/debugging).
- `User-Agent`, `sec-ch-ua*`, `sec-fetch-*`, dan `Accept-Language` **tidak**
  diset manual: nilainya diambil dari profil impersonate. Menyetel `User-Agent`
  manual akan menimpa header profil dan merusak paritas fingerprint.
- `retry=TRANSPORT_RETRIES` hanya menangani error transport (koneksi/DNS/TLS).

### `ThreadLocalSession(timeout=15, verify_ssl=True, impersonate=_DEFAULT, retries=None)`

Proxy session yang membuat satu `curl_cffi` Session **per thread**, supaya
request paralel (`--workers`) tidak berbagi session/cookie state.

- Semua request lewat satu funnel `request(method, url, **kwargs)`; helper tipis
  `get/post/put/patch/delete/head/options` hanya meneruskan ke funnel itu.
- `timeout` di-`setdefault` sehingga call site tetap bisa menimpa per request.
- Retry status HTTP: 429/500/502/503/504 diulang maksimal `STATUS_RETRIES` kali
  untuk metode `GET/POST/HEAD/OPTIONS`, menghormati `Retry-After` (dibatasi
  `RETRY_AFTER_MAX = 5` detik). Ini menggantikan `urllib3.Retry` yang tidak
  tersedia di `curl_cffi`. Set `retries=0` untuk mematikannya.
- Atribut lain (`cookies`, `headers`, `close`) didelegasikan ke Session milik
  thread terkait lewat `__getattr__`.
- Funnel yang sama merekam setiap request/response menjadi objek `Exchange`
  (sudah tersensor) lewat `record_exchange()`, sehingga temuan bisa membawa
  bukti + langkah repro. Detailnya di
  [findings-model.md](findings-model.md).

### `supported_impersonate_profiles()`

Daftar profil yang valid untuk `--impersonate`, diambil dari
`curl_cffi.requests.BrowserTypeLiteral` (nama berversi seperti `chrome146`)
digabung nama enum `BrowserType` (alias generik seperti `chrome`, `safari`).
CLI memvalidasi nilai `--impersonate` terhadap daftar ini **sebelum** request
pertama dikirim, dan keluar dengan kode 2 bila profil tidak dikenal.

## Flag CLI terkait

| Flag | Efek |
|---|---|
| `--impersonate PROFIL` | Ganti profil impersonate (default `chrome`). Contoh: `chrome136`, `safari184`, `firefox147`. |
| `--no-impersonate` | Matikan impersonation (fingerprint default curl). Berguna untuk membandingkan perilaku atau men-debug target yang menolak TLS browser. |

Banner scan menampilkan profil yang dipakai, mis. `Bot   : chrome` atau
`Bot   : tanpa impersonation`.

## Catatan & batasan

- `curl_cffi` tidak menyediakan `Session.mount()` maupun `urllib3.Retry`, jadi
  kebijakan retry status dipindahkan ke `ThreadLocalSession.request`.
- `response.request.headers` tetap case-insensitive, sehingga kode yang membaca
  `Authorization` (mis. `scan_jwt`) tidak perlu diubah.

### Perubahan perilaku vs `requests` (disengaja)

1. **Error-based SQLi pada respons 500 kini terdeteksi.** Sebelumnya
   `HTTPAdapter(max_retries=Retry(..., status_forcelist=[500, ...]))` memakai
   `raise_on_status=True`, sehingga server yang membalas 500 (mis. pesan
   `SQL syntax error`) melempar `MaxRetryError`; di dalam modul, exception itu
   ditelan `except: pass` dan temuan hilang. Sekarang respons 500 dikembalikan
   setelah satu retry, jadi pola error SQL pada respons 500 ikut terdeteksi.
   Ini menambah cakupan deteksi, bukan menguranginya.
2. **Nilai header di-strip.** `curl_cffi` membuang spasi di ujung nilai header
   (`Server: nginx/1.18.0` bukan `'nginx/1.18.0 '`), sehingga beberapa detail
   temuan (mis. `SERVER_LEAK`) tampil sedikit berbeda/lebih rapi.
3. **`--no-impersonate` tersedia** sebagai jalur paritas: memakai fingerprint
   default curl tanpa impersonation untuk membandingkan hasil lama vs baru.

## Verifikasi

- 60 test (`tests/`) lulus saat PR itu dibuat, memakai fixture HTTP server lokal
  — tanpa koneksi internet. Mencakup header impersonation, retry status +
  `Retry-After`, timeout default, cookie, validasi `--impersonate`, serta regresi
  23 modul. (Suite saat ini 309 test / 32 modul; lihat
  [vuln-classes.md](vuln-classes.md).)
- Perbandingan hasil modul lama (`requests`) vs baru (`curl_cffi`) terhadap
  fixture yang sama: identik kecuali tiga perubahan perilaku di atas.
- Smoke scan ke target eksternal **belum** diverifikasi di PR ini.
- Impersonation hanya menyamarkan fingerprint klien. Delay/jitter sudah tersedia
  lewat `--delay`/`--max-rps`/`--jitter` (lihat [scan-engine.md](scan-engine.md)),
  tapi rotasi IP dan pola request manusiawi belum ada — lihat
  [bug-bounty-gaps.md](bug-bounty-gaps.md) bagian 5 dan "Catatan penting soal
  anti-deteksi bot".
- Gunakan hanya pada aset yang Anda miliki atau yang secara eksplisit masuk
  scope program bounty.
