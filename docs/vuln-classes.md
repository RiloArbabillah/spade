# Kelas Kerentanan yang Diuji Spade

Dokumen ini menjelaskan setiap kelas kerentanan yang ada di Spade: apa yang
diuji, flag/opsi CLI yang dibutuhkan, batas jumlah request, penjaga false
positive, dan status defaultnya. Latar belakang roadmap-nya ada di
[docs/bug-bounty-gaps.md](bug-bounty-gaps.md) bagian 2, model temuan/bukti ada di
[docs/findings-model.md](findings-model.md).

Prinsip umum:

- **Default aman.** Uji yang mengirim data (`--active-writes`), merusak stream
  koneksi (`--check-smuggling`), atau memanggil collector eksternal
  (`--oob-host`) **mati secara default**. Tanpa flag itu modulnya tetap
  terdaftar tapi mengembalikan daftar kosong tanpa mengirim request tambahan.
- **Tidak mengklaim bersih tanpa bukti.** Modul IDOR/CSRF aktif/JWT forgery
  butuh sesi autentikasi. Kalau `--cookie`/`-H`/`--bearer` tidak diberikan,
  modulnya dilewati dengan catatan di log — bukan dilaporkan sebagai aman.
- **Semua request lewat `curl_cffi`** dengan browser impersonation aktif
  (lihat [docs/http-layer.md](http-layer.md)).
- **Rahasia tidak pernah ditulis ke laporan.** Cookie/`Authorization` disensor
  otomatis di bukti request/response (`***REDACTED***`) kecuali `--no-redact`.

## Mode dan kelas yang jalan

| Kelas | Modul | QUICK (7) | STANDARD (19) | DETAILED (31) |
|---|---|---|---|---|
| IDOR / BOLA | `idor` | ❌ | ✅* | ✅* |
| CSRF | `csrf` | ❌ | ✅* | ✅* |
| Auth bypass | `authbypass` | ❌ | ✅ | ✅ |
| JWT | `jwt` | ❌ | ❌ | ✅* |
| API spec | `apispec` | ❌ | ❌ | ✅ |
| Parameter discovery | `params` | ❌ | ❌ | ✅ |
| Host header / cache | `hostheader` | ❌ | ❌ | ✅* |
| CRLF | `crlf` | ❌ | ❌ | ✅ |
| Request smuggling | `smuggling` | ❌ | ❌ | ✅ (butuh flag) |
| OOB (SSRF/XXE/CMDi) | di dalam `ssrf`/`xxe`/`cmdi` | ❌ | `ssrf`+`cmdi` | semua (`xxe` DETAILED) |

`*` = cakupan berkurang kalau tidak ada sesi autentikasi atau flag aktivasi
(lihat tabel flag di bawah).

## Flag yang mengubah cakupan

| Flag | Efek | Default |
|---|---|---|
| `--cookie "N=V;M=X"` | Cookie sesi untuk area terautentikasi; boleh diulang | tanpa sesi |
| `-H "Nama: nilai"` | Header tambahan di semua request; boleh diulang | — |
| `--bearer TOKEN` | Isi `Authorization: Bearer …` (bentrok dengan `-H 'Authorization: …'` → exit 2) | — |
| `--jwt-secrets FILE` | Daftar secret JWT (satu per baris, `#` komentar) untuk crack HMAC offline | 41 secret bawaan |
| `--active-writes` | Izinkan CSRF mengirim POST submit dengan token palsu | mati |
| `--check-smuggling` | Kirim payload CL.TE/TE.CL lewat socket mentah | mati |
| `--oob-host HOST[:PORT]` | Collector OOB milik tester untuk membuktikan blind SSRF/XXE/CMDi | mati |

Semua flag divalidasi **sebelum request pertama**. Nilai tidak valid (cookie
tanpa `=`, header tanpa `:`, `--bearer` + `-H 'Authorization: …'`,
`--oob-host` kosong, file `--jwt-secrets` tidak ada/kosong) membuat proses
berhenti dengan exit code 2 dan pesan dari `argparse`.

Status keempat flag aktivasi ini ikut dicatat di laporan JSON (`scan.auth`,
`scan.active_writes`, `scan.check_smuggling`, `scan.oob`) supaya hasil bisa
diaudit tanpa menebak konfigurasi saat scan.

---

## 1. IDOR / BOLA (`idor`)

**Apa yang diuji.** Otorisasi tingkat objek: apakah server memeriksa kepemilikan
objek sebelum mengembalikannya.

**Cara kerja.** Kandidat diambil dari query string, segmen path, dan form GET
(crawl + URL target). Untuk setiap nilai yang "ber-ID" (`id=5`, UUID, angka di
path), Spade menyusun tetangga (`6`, UUID+1). URL asli dan tetangganya diuji
dengan **dua sesi**:

1. anonim — dipakai sebagai pembanding dan untuk membuktikan objek tetangga
   terbuka tanpa login;
2. sesi tester (`--cookie`/`-H`/`--bearer`).

Prasyarat: objek asli mengembalikan 200 untuk sesi tester dan 401/403 untuk
anonim. Kalau tidak, kandidat dilewati.

**Kode temuan.**

| Kode | Severity | Confidence | Arti |
|---|---|---|---|
| `IDOR_ANON` | HIGH | `firm` | Objek tetangga terbaca **tanpa autentikasi** padahal objek asli menolak anonim — bukti terkuat, tidak butuh akun kedua |
| `IDOR_READ` | MEDIUM | `tentative` | Objek tetangga hanya terbaca sesi tester dan isinya berbeda — perlu diverifikasi dengan akun kedua |

**Penjaga false positive.** `IDOR_MAX_CANDIDATES = 25` kandidat; payload objek
harus benar-benar memuat ID tetangganya (bukan sekadar halaman 200); fingerprint
respons tetangga harus berbeda dari respons penolakan anonim dan dari objek
asli; SPA catch-all (`_is_spa_catchall`) membatalkan temuan.

**Batasan.** Tanpa sesi autentikasi modul kembali kosong dengan catatan
`(dilewati: butuh sesi autentikasi …)`. Tidak ada uji tulis (`PUT`/`DELETE`)
maupun manipulasi ID acak selain tetangga langsung.

---

## 2. CSRF (`csrf`)

**Apa yang diuji.** Proteksi anti-CSRF pada form POST.

**Cara kerja.** Dua tingkat:

1. **Pasif (selalu jalan).** Form POST tanpa field yang namanya cocok
   `CSRF_TOKEN_RE` (`csrf|xsrf|authenticity|antiforgery|_token|nonce`) →
   `CSRF_NO_TOKEN` (`MEDIUM`, `tentative`). Form login (punya field
   `type=password`) dilewati supaya tidak jadi false positive.
2. **Aktif (`--active-writes`).** Form yang punya field token dikirim dua kali
   dengan header `Origin`/`Referer` asing: sekali dengan token asli, sekali
   dengan nilai `spade-forged-token`. Kalau keduanya diterima (2xx/302) **dan**
   responsnya identik → `CSRF_TOKEN_IGNORED` (`MEDIUM`, `firm`): token ada tapi
   tidak divalidasi.

**Penjaga false positive.** Respons yang mirip halaman login diabaikan
(`_looks_like_login`); fingerprint token asli vs token palsu harus sama persis;
tanpa `--active-writes` tidak ada POST yang dikirim sama sekali.

**Batasan.** Tidak menguji CSRF per-parameter (JSON API) dan tidak menyimpan
token yang benar; uji aktif mengirim POST ke target sehingga hanya dipakai di
program yang mengizinkan.

---

## 3. Auth bypass / 401-403 bypass (`authbypass`)

**Apa yang diuji.** Apakah ACL di reverse proxy bisa dilewati header internal
atau normalisasi path.

**Cara kerja.** Kandidat = 9 path admin standar + 3 halaman hasil crawl yang
**menolak anonim** (401/403) dan bukan halaman login. Untuk setiap kandidat
(batas `AUTH_BYPASS_MAX_PATHS = 10`):

- **8 varian header** dikirim ke URL aslinya: `X-Original-URL: /`,
  `X-Rewrite-URL: /`, `X-Forwarded-For: 127.0.0.1`, `X-Client-IP: 127.0.0.1`,
  `X-Remote-Addr: 127.0.0.1`, `X-Originating-IP: 127.0.0.1`,
  `X-Custom-IP-Authorization: 127.0.0.1`, `X-HTTP-Method-Override: GET`.
- **9 varian path**: trailing slash, trailing dot (`/admin/.`), `..;/`,
  double slash (`//admin`), dot segment (`/./admin`), encoded dot
  (`/%2e/admin`), `.json`, `%20`, `/;/`.

Temuan `AUTH_BYPASS_HEADER` / `AUTH_BYPASS_PATH` (`HIGH`, `firm`) dibuat hanya
kalau respons 200/201/204 punya isi **berbeda** dari body penolakan, bukan
halaman login, dan bukan SPA catch-all.

**Batasan.** Header/path list bersifat statis dan sengaja konservatif; tidak ada
fuzzing path (mis. `kiterunner`) dan tidak ada uji `X-Forwarded-For` berantai.

---

## 4. JWT (`jwt`)

**Apa yang diuji.** Dua kelompok: temuan statis dari token yang dipakai scan,
dan uji forgery terhadap endpoint terlindungi.

**Statis (selalu jalan di DETAILED).** `alg=none` (`JWT_ALG_NONE`, CRITICAL),
info cookie/bearer (`JWT_COOKIE`, `JWT_BEARER`, INFO), `kid` berbentuk
path/URL/absolut (`JWT_KID_SUSPECT`, INFO), token tanpa `exp`
(`JWT_NO_EXPIRY`, LOW).

**Crack HMAC offline.** Token dikumpulkan dari tiga sumber: cookie jar sesi
(hasil `Set-Cookie`), header `Cookie` kiriman tester (`--cookie` /
`-H "Cookie: ..."`), dan header `Authorization` (`--bearer`). Semua diuji
terhadap `--jwt-secrets` (kalau ada) lalu 41 secret bawaan
(`DEFAULT_JWT_SECRETS`). Cocok → `JWT_WEAK_SECRET` (HIGH, `firm`). Uji ini
murni lokal: tidak ada request tambahan dan secret tidak pernah ditulis ke
laporan.

**Forgery (butuh sesi autentikasi).** Orakel = endpoint yang memberi 200 untuk
sesi tester dan 401/403 untuk anonim (`JWT_PROTECTED_PATHS` + sampai
`JWT_CRAWL_TARGETS = 8` halaman crawl). Token palsu dibuat dengan HMAC dari
secret yang ketemu, lalu dikirim sebagai `Authorization: Bearer …`; kalau
diterima (200 + isi identik) → `JWT_ALG_CONFUSION` (`HIGH`, `firm`). Public key
server (`/jwks.pem`, `/.well-known/jwks.json`, …) dipakai untuk uji HS256 vs
RS256; token `alg=none` dan token `exp` yang sudah lewat juga diuji ke orakel →
`JWT_EXPIRED_ACCEPTED` (`HIGH`, `firm`).

**Penjaga false positive.** Semua uji forgery butuh orakel yang benar-benar
membedakan sesi tester vs anonim; token yang sudah invalid tidak diuji;
`JWT_ALG_CONFUSION_SURFACE` (INFO) hanya menandai bahwa kunci publik terbuka,
bukan klaim bahwa confusion bisa dilakukan.

**Batasan.** Tidak menyimpan token hasil forgery, tidak memaksa
`kid` traversal ke file nyata, dan tidak menjalankan uji `jku`/`x5u` remote.

---

## 5. API spec & parameter discovery (`apispec`, `params`)

**`apispec` — spesifikasi API terekspos.** 6 path dicoba: `/openapi.json`,
`/swagger.json`, `/v3/api-docs`, `/api-docs`, `/.well-known/openapi.json`,
`/api/swagger.json`. Dokumen JSON yang memuat `openapi`/`swagger`/`paths`/
`swaggerVersion` → `API_SPEC_EXPOSED` (`MEDIUM`, `firm`). Path dan nama
parameter dipanen ke `ctx["api_endpoints"]`/`ctx["api_params"]` (maks 50) dan
ikut diuji modul injection (SQLi/XSS/LFI) sebagai parameter tambahan.

**`params` — parameter tersembunyi.** 47 nama umum (`debug`, `admin`, `id`,
`callback`, `cmd`, …) dikirim satu per satu ke tiap URL (maks
`PARAM_MAX_URLS = 8`); respons dibandingkan dengan baseline URL yang sama
(status + ukuran). Perbedaan → `PARAM_DISCOVERY` (`INFO`) — hanya penunjuk arah
untuk uji manual, bukan klaim kerentanan.

**Batasan (sengaja).** Brute force penuh ala `arjun`/`x8` (wordlist ribuan +
deteksi pola parameter) dan `kiterunner` **tidak** diimplementasikan di PR ini;
`apispec` hanya mem-parse OpenAPI/Swagger **JSON**, belum YAML, dan belum
meng-parse SDL GraphQL dari file.

---

## 6. Host header injection, cache poisoning, cache deception (`hostheader`)

**Host header injection.** Nilai canary (`spade-<hex>.invalid`) dikirim lewat 5
header (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`,
`Forwarded`) ke maksimal 5 URL (target + 4 halaman crawl):

- canary muncul di `Location`/`Set-Cookie` → `HOST_HEADER_INJECTION` (`MEDIUM`,
  `firm`);
- canary hanya muncul di body → `HOST_HEADER_INJECTION` (`MEDIUM`,
  `tentative`), perlu dicek manual;
- canary di body **dan** respons punya marker cache → `CACHE_POISONING`
  (`MEDIUM`, `tentative`).

**Cache deception.** Butuh sesi autentikasi. Untuk halaman yang 200 di sesi
tester tapi 401/403 anonim, Spade meminta versi berakhiran
`/spade-nonexistent.css` sebagai anonim. Kalau isinya sama dengan halaman
privat → `CACHE_DECEPTION` (`MEDIUM`). Confidence `firm` kalau ada marker cache,
`tentative` kalau tidak.

**Penjaga false positive.** Satu temuan per (kode, URL) — beberapa header
sering mengenai titik yang sama; hanya metode GET yang dipakai (tidak ada
`POST` dengan Host palsu); cache poisoning tidak diklaim tanpa marker cache.

---

## 7. CRLF injection / response splitting (`crlf`)

**Apa yang diuji.** Parameter yang nilainya diteruskan ke header respons
(mis. `next`/`url`/`redirect` pada endpoint redirect).

**Cara kerja.** 4 payload dikirim **mentah** (tanpa encode ulang, lihat
`_raw_query_url`) ke 4 path target (`/redirect`, `/login`, `/logout`,
`/api/redirect`) + 2 halaman crawl, dibatasi
`CRLF_MAX_PARAMS = 15` parameter × payload dan total `CRLF_MAX_JOBS = 120`
kombinasi:

| Payload | Label |
|---|---|
| `%0d%0aX-Spade-Injected:1` | CRLF ganda |
| `%0d%0aSet-Cookie:spade=1` | CRLF + Set-Cookie |
| `%0d%0a%0d%0a<spade>` | response splitting |
| `%E5%98%8A%E5%98%8DSpade-Injected:1` | unicode CRLF |

**Bukti.** Header `X-Spade-Injected` (atau cookie `spade=1`) yang benar-benar
muncul di respons → `CRLF_INJECTION` (`MEDIUM`, `firm`). Kalau hanya string
`spade-injected` yang muncul di body → confidence `tentative` (butuh konfirmasi
apakah CRLF-nya benar-benar memecah header di proxy di depan).

**Penjaga false positive.** Modul berhenti di temuan pertama yang pasti
(early-exit lewat `pmap_until`), dan `allow_redirects=False` supaya respons
redirect dilihat apa adanya.

---

## 8. Request smuggling (`smuggling`)

**Apa yang diuji.** Desync CL.TE / TE.CL antara front-end dan back-end.

**Cara kerja.** curl selalu menormalkan `Content-Length`/`Transfer-Encoding`,
jadi payload dikirim lewat **socket mentah** (`raw_http_probe`) dengan path
canary (`/spade-smuggle-<hex>`). Hanya jalan dengan `--check-smuggling`.

**Temuan.** `REQUEST_SMUGGLING` (`HIGH`, `firm`) hanya dibuat kalau string
canary memang muncul di respons mentah — artinya server memperlakukan bagian
body sebagai request terpisah.

**Batasan.** Modul ini sengaja tidak punya bukti HTTP terstruktur
(`capture=False`) karena requestnya bukan HTTP biasa; buktinya ada di log
terminal. Uji ini **merusak stream koneksi** dan bisa mengganggu pengguna lain
— hanya dipakai di target yang secara eksplisit mengizinkan.

---

## 9. Blind & OOB — SSRF, XXE, CMDi

Deteksi in-band (pantulan di respons) sudah ada di modul `ssrf`/`xxe`/`cmdi`.
Yang baru adalah pembuktian **blind** lewat collector milik tester:
`--oob-host HOST[:PORT]`.

**Cara kerja.** Setiap probe memakai token unik
(`spade-<hex>`, `OOB_TOKEN_BYTES = 4`). Payload menyematkan
`http://<collector>/<token>`:

| Kelas | Payload | Titik |
|---|---|---|
| SSRF | URL callback di parameter `url`/`uri`/`target` | 6 path (`/ssrf-sink`, `/fetch`, `/proxy`, `/api/fetch`, `/api/url`, `/url`) |
| XXE | `<!DOCTYPE … SYSTEM "callback">` + `%entity;` (Content-Type `application/xml`) | 5 path (`/xml-oob`, `/api/xml`, `/xml`, `/soap`, `/api/upload`) |
| CMDi | `; curl <callback>`, `\| curl <callback>`, `$(curl <callback>)`, `& curl <callback>` | 5 path (`/ping`, `/exec`, `/cmd`, `/run`, `/api/exec`) × parameter `cmd`/`host`/`target`/`exec` |

Setelah semua probe dikirim, Spade menunggu `OOB_CHECK_DELAY = 5.0` detik lalu
menanyakan `GET /check?token=<token>` ke collector (timeout
`OOB_TIMEOUT = 5.0`). Temuan hanya dibuat kalau collector mencatat ≥ 1 callback:

| Kode | Severity | Confidence |
|---|---|---|
| `SSRF_BLIND` | MEDIUM | `firm` |
| `XXE_BLIND` | HIGH | `firm` |
| `CMDI_BLIND` | CRITICAL | `firm` |

CMDi dideduplikasi per titik injeksi supaya 4 template yang mengenai parameter
yang sama hanya menghasilkan satu temuan.

**Menjalankan collector.** `tools/oob_collector.py` (Python stdlib, tanpa
dependency) harus berjalan di host yang **bisa dijangkau target**, bukan hanya
localhost:

```bash
python3 tools/oob_collector.py --host 0.0.0.0 --port 9000
python3 spade.py https://target.example --detailed --oob-host 10.0.0.5:9000
```

Kontrak HTTP-nya:

| Request | Respons |
|---|---|
| `GET /<token>` | mencatat callback, balas `200 ok` |
| `GET /check?token=<token>` | `{"token": "<token>", "hits": <n>}` |
| `GET /health` | `{"status": "ok", "hits": <total>}` |

Opsi collector: `--quiet` (jangan cetak tiap callback), `--export FILE` (tulis
ringkasan JSON saat Ctrl+C). Callback apa pun (termasuk yang tidak dikenal)
tetap tercatat berdasarkan token di segmen path pertama, lengkap dengan IP,
User-Agent, dan waktu pemanggilan.

**Batasan.** Hanya HTTP callback (belum DNS); collector merekam endpoint yang
memanggilnya, jadi jalankan hanya di lingkungan uji sendiri; kalau collector
tidak bisa dihubungi, `oob_check()` mengembalikan pesan gagal dan **tidak ada
temuan** yang dibuat (tidak ada klaim palsu).

---

## Melihat cakupan uji aktif

Laporan JSON merekam konfigurasi cakupan di blok `scan`:

```bash
python3 spade.py https://target.example --detailed   --cookie "session=..." --active-writes --json hasil.json
python3 -c "import json;print(json.load(open('hasil.json'))['scan'])"
```

Empat flag audit selalu ada dan `false` secara default: `auth`,
`active_writes`, `check_smuggling`, `oob`. Nilainya tidak pernah memuat
kredensial — cookie/token hidup di memori proses dan disensor di bukti
(`***REDACTED***`).
