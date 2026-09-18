# Recon — Enumerasi Subdomain, URL Historis, Endpoint JS, Port Scan

Dokumen ini menjelaskan tahap *recon* Spade: sumber data yang dipakai, batas
request, bagaimana hasilnya mengalir ke modul lain, dan apa yang dilaporkan.
Latar belakang roadmap-nya ada di [docs/bug-bounty-gaps.md](bug-bounty-gaps.md)
bagian 3, model temuan/bukti ada di [docs/findings-model.md](findings-model.md),
dan daftar kelas kerentanan ada di [docs/vuln-classes.md](vuln-classes.md).

Semua nama di bawah adalah API publik `spade.py` (bisa diimpor dan dipakai ulang
oleh tooling lain, mis. untuk menulis laporan kustom).

---

## 1. Prinsip

- **Hanya Python stdlib + `curl_cffi`.** Tidak ada binary eksternal
  (`subfinder`, `dnsx`, `httpx`, `gau`, `katana`, `naabu`, `gowitness`) dan tidak
  ada `subprocess`. Sumber pasif diakses lewat API HTTP publik memakai session
  yang sama dengan scan, jadi ikut `--impersonate`, `--workers`, `--skip-ssl`,
  `-H`/`--cookie`, dan otomatis punya bukti request/response.
- **Semua batas ada di konstanta** `RECON_*` / `PORT_SCAN_*`, bukan angka liar di
  tengah fungsi.
- **Tidak mengklaim target bersih.** Sumber yang gagal/timeout tercatat sebagai
  status dan jadi temuan `RECON_SOURCE_SKIPPED` — hasil enumerasi kosong bukan
  bukti tidak ada subdomain.
- **Inert pada target yang bukan domain publik.** `_recon_target_host()`
  mengembalikan `""` untuk IP, `localhost`, dan nama tanpa TLD; pada kasus itu
  tidak ada satu pun request recon (dipakai saat scan fixture lokal).
- **Recon tidak menjalankan modul kerentanan di host hasil enumerasi.** Host
  hanya dibuktikan hidup (status + `<title>` + header `Server`), sedangkan bahan
  yang dipanen (URL historis, endpoint JS, nama parameter) dipakai ulang oleh
  crawler dan modul injection di **target utama**.

## 2. Kapan recon jalan

| Mode | Recon | Catatan |
|---|---|---|
| QUICK (7 modul) | ❌ | — |
| STANDARD (19 modul) | ❌ | — |
| DETAILED (32 modul) | ✅ | jalan sebelum crawler; matikan dengan `--no-recon` |
| `--recon-only` | ✅ | hanya modul `recon`, tanpa modul kerentanan |

Di DETAILED, `recon_gather()` dipanggil **sekali** sebelum `Crawler` dibuat;
modul `recon` dan `subdomains` memakai hasil yang sama dari cache `ctx`
(`ctx_get(ctx, ("recon_result", base_url), …)`), jadi tidak ada enumerasi ganda.
`--recon-only` mengisi `scan.mode = "recon"` dan `scan.modules = ["recon"]`.

## 3. Sumber data & batas

| Sumber | Endpoint | Timeout | Batas | Status yang mungkin |
|---|---|---|---|---|
| `crtsh` | `crt.sh/?q=%.<host>&output=json` | `RECON_SOURCE_TIMEOUT` 20s | — | `ok` / `empty` / `timeout` / `error` |
| `certspotter` | `api.certspotter.com/v1/issuances` | 20s | — | idem |
| `wayback` | `web.archive.org/cdx/search/cdx` (limit 1000) | `RECON_CDX_TIMEOUT` 45s | 300 URL bersih | idem |
| `commoncrawl` | `index.commoncrawl.org/collinfo.json` + `cdx-api` (limit 500) | 20s / 45s | 300 URL bersih | idem |
| `dnsbrute` | `socket.getaddrinfo` (wordlist internal 134 kata) | `RECON_DNS_TIMEOUT` 1,5s per nama | — | `ok` / `empty` |
| `hostprobe` | `https://` lalu `http://` per host | `RECON_HOST_TIMEOUT` 8s | `RECON_MAX_HOSTS_PROBED` 25 host | `ok` / `empty` |
| `portscan` | TCP connect ke `PORT_SCAN_PORTS` (41 port) | `PORT_SCAN_TIMEOUT` 1s per port | `PORT_SCAN_MAX_HOSTS` 5 host | `ok` / `empty` / `skipped` |
| `js` | `<script src>` halaman utama + crawl, lalu berkas `.js` | 10s per berkas | 15 berkas, 50 endpoint | `ok` / `empty` / `skipped` |

Sumber pasif dijalankan paralel lewat `pmap` (menghormati `--workers`), DNS
brute force juga paralel, dan setiap sumber dibungkus `try/except` supaya satu
sumber bermasalah tidak membatalkan recon.

Batas lain: `RECON_MAX_SUBDOMAINS` 200, `RECON_MAX_HISTORIC_URLS` 300,
`RECON_MAX_SEEDS` 6, `RECON_PARAM_URLS` 5, `RECON_PARAM_NAMES` 5,
`RECON_JS_MAX_PAGES` 5 halaman crawl tambahan, `RECON_JS_MAX_FILES` 15,
`RECON_JS_MAX_ENDPOINTS` 50.

Nama dari sumber sertifikat selalu dinormalisasi `_recon_clean_names()`:
lowercase, wildcard `*.` dibuang, hanya nama yang benar-benar berada di dalam
`<host>` (atau subdomainnya), dan unik. Ini diulang di `recon_gather()` supaya
jaminan "subdomain selalu dalam scope target" tidak bergantung pada kepatuhan
tiap sumber yang didaftarkan di `recon_sources()`.

## 4. Alur data

```
recon_gather(sess, base_url, ctx)
   ├─ sumber pasif (crtsh, certspotter, wayback, commoncrawl)  -> subdomains, URL
   ├─ recon_dns_brute("host")                                  -> subdomains
   ├─ recon_probe_host(sess, nama) x<=25                       -> live_hosts
   ├─ _recon_clean_urls(...) + recon_param_targets(...)        -> historic_urls, param_targets
   └─ recon_port_scan(hosts)                                   -> open_ports (hanya --port-scan)
        -> _recon_apply_ctx(ctx, data):
             ctx["recon"]               = seluruh hasil
             ctx["recon_urls"]          = URL historis (seed crawler)
             ctx["recon_param_targets"] = [(url tanpa query, [nama parameter])]
```

Hasil itu dipakai di tiga tempat:

1. **Seed crawler** — `recon_seed_urls(ctx)` mengambil sampai 6 URL historis
   non-statis dan diberikan ke `Crawler(..., extra_seeds=…)`, jadi halaman lama
   yang tidak lagi ditautkan tetap di-crawl (dan form POST-nya ikut ditemukan).
2. **Pool parameter modul injection** — `injection_url_jobs(ctx, base_url)`
   mengembalikan `[(base_url, None)] + [(url_recon, [parameter])]`. `None` berarti
   "pakai daftar parameter bawaan modul", jadi perilaku tanpa recon tidak
   berubah. Hanya **nama parameter yang benar-benar ada di URL historis** yang
   dipakai (bukan wordlist), supaya modul tidak menembak parameter karangan.
   Dipakai modul `sqli`, `xss`, `lfi`, dan `openr`.
3. **Panen endpoint JS** — `recon_js(sess, base_url, ctx)` membaca `<script src>`
   dari halaman utama + halaman crawl, mengunduh berkas `.js`-nya, lalu
   `extract_js_endpoints()` mengambil literal rute yang menarik
   (`/api/…`, `/admin/…`, `/v1/…`, path ber-query). Endpoint yang punya query
   ikut ditambahkan ke `ctx["recon_param_targets"]`, dan teks JS disimpan di
   `ctx["js_texts"]` supaya modul `js` **tidak mengunduh berkas yang sama dua
   kali**. `result["endpoints"]` juga disalin ke `ctx["recon_js_endpoints"]`.
   Halaman yang sama juga jadi sumber blok `<script>` **inline** bagi modul
   `js` (kredensial hardcode, lihat [docs/vuln-classes.md](vuln-classes.md)
   § 10); blok inline sudah ada di HTML yang sudah diambil, jadi tidak ada
   request tambahan.

## 5. Anggaran request (kasus terburuk)

| Tahap | Request |
|---|---|
| Sumber pasif | 5 GET (crt.sh, Cert Spotter, Wayback, Common Crawl ×2) |
| DNS brute force | 134 lookup DNS (bukan HTTP) |
| Probe host hidup | ≤ 50 GET (25 host × 2 skema, berhenti di skema pertama yang menjawab) |
| Panen JS | ≤ 15 GET berkas JS (+1 halaman utama yang sudah di-cache) |
| Port scan (`--port-scan`) | ≤ 205 TCP connect (5 host × 41 port) |

Recon **tidak** mengirim request ke tiap URL historis — URL itu hanya jadi seed
crawler (dibatasi `--crawl-max`) dan daftar parameter modul injection (5 URL).
Pemindaian kredensial hardcode (modul `js`) memakai ulang teks JS yang sudah
diunduh dan blok `<script>` inline yang sudah ada di HTML, jadi anggaran ini
tidak bertambah.

## 6. Degradasi anggun

`recon_gather()` tidak pernah melempar exception ke pemanggil:

- sumber yang timeout/error → status `timeout`/`error`, masuk `data["errors"]`,
  dan dilaporkan sebagai `RECON_SOURCE_SKIPPED` oleh modul `recon`;
- sumber yang tidak memuat data → status `empty` (bukan kegagalan);
- `recon_port_open`/`recon_port_scan` menelan `socket` error per port;
- `recon_js` melewati berkas JS yang gagal diunduh.

Pembeda `timeout` vs `error` ada di `_recon_timeout_status()` supaya pesan di
laporan tidak salah menyebut penyebab.

## 7. Temuan yang dihasilkan

| Kode | Severity | Confidence | Bukti | Arti |
|---|---|---|---|---|
| `SUBDOMAIN_LIVE` | INFO | `firm` | URL host hasil probe | Host hasil enumerasi menjawab HTTP — lengkap dengan status, `<title>`, dan header `Server` |
| `HISTORIC_URLS` | INFO | `tentative` | URL indeks (Wayback/Common Crawl) | Ada URL historis untuk target; endpoint lama sering masih hidup tanpa autentikasi/rate limit |
| `JS_ENDPOINT` | INFO | `firm` | URL berkas JS | Berkas JS memuat endpoint yang tidak terdokumentasi |
| `JS_SECRET` | CRITICAL | `firm` | URL berkas JS / halaman (nilai dimask) | Kredensial layanan hardcode di berkas JS atau blok `<script>` inline (modul `js`, lihat [vuln-classes.md](vuln-classes.md) § 10). Pasangan `JS_SECRET_MAYBE` (`HIGH`, `tentative`) untuk string acak di belakang nama key lazim |
| `PORT_OPEN` | INFO / LOW | `firm` | — (connect scan tanpa respons HTTP, jadi `evidence` sengaja kosong) | Port TCP terbuka; naik ke LOW kalau port termasuk `PORT_SCAN_RISKY_PORTS` (2375, 3306, 5432, 6379, 9200, 11211, 27017, 5601, 2049, 3389) |
| `RECON_SOURCE_SKIPPED` | INFO | `certain` | — | Sumber recon timeout/gagal — laporan ini **bukan** bukti target bersih |
| `SUBDOMAINS` | INFO | — | URL indeks crt.sh | Ringkasan daftar subdomain (modul `subdomains`, tetap ada sebagai alias tipis di atas `recon_gather`) |

Tidak ada modul kerentanan yang dijalankan di host hasil enumerasi: Spade hanya
membuktikan host itu hidup. Uji lanjutan (mis. SQLi di `admin.example.com`)
dilakukan dengan menjalankan Spade pada host tersebut sebagai target.

## 8. Port scan (opt-in)

`--port-scan` hanya berlaku bersama `--detailed` atau `--recon-only` (kalau
tidak → exit code 2 dari `argparse`). Scan memakai TCP connect
(`socket.create_connection`) ke 41 port umum di target **dan** host hasil
enumerasi (maks 5 host). Tidak ada SYN scan, tidak ada OS fingerprint, dan tidak
ada banner grabbing — hasilnya murni "port terbuka/tertutup". Karena tidak ada
respons HTTP, temuan `PORT_OPEN` sengaja dibuat **tanpa bukti** request/response
supaya laporan tidak menampilkan bukti palsu.

## 9. Privasi & anti-deteksi

Recon menambah dua jenis jejak yang tidak ada di scan biasa:

1. **Nama target dikirim ke API pihak ketiga** (crt.sh, Cert Spotter, Wayback,
   Common Crawl) dari IP tester. Ini terlihat sebagai pemindaian
   *passive reconnaissance* dan, berbeda dari request ke target, **tidak** bisa
   disamarkan dengan browser impersonation.
2. **DNS brute force** memicu ratusan lookup ke resolver yang dipakai.

Karena itu ada `--no-recon`: di DETAILED, nama target tidak dikirim ke sumber
pihak ketiga sama sekali (modul `recon` dan `subdomains` juga tidak dijalankan).
Sejak `--proxy`/`--proxy-file` ada, request recon ikut rotasi proxy karena
memakai funnel `ThreadLocalSession` yang sama, jadi kalau rotasi proxy dipakai
nama target tidak lagi keluar dari IP tester. Catatan: **port scan**
(`--port-scan`) tetap TCP connect langsung, bukan lewat proxy. Detail rotasi ada di
[docs/scan-engine.md](scan-engine.md).

Catatan resume: checkpoint `--state`/`--resume` menyimpan progres **modul**, bukan
hasil recon. Saat `--resume` dipakai, recon dijalankan ulang dan seed modul
dihitung ulang dari awal, jadi modul yang belum selesai bisa menerima seed lebih
sedikit daripada scan penuh. Detailnya di [docs/scan-engine.md](scan-engine.md) §5.

## 10. API publik

```python
recon_sources() -> dict[str, Callable[[sess, base_url, host], tuple[list, str, str]]]
    # Registry sumber pasif: nama -> fungsi(sess, base_url, host) yang mengembalikan
    # (names|urls, status, index_url). Bisa di-monkeypatch untuk test offline.

recon_gather(sess, base_url, ctx=None) -> dict
    # Tahap recon lengkap. Kunci hasil: sources, errors, subdomains, live_hosts,
    # historic_urls, param_targets, open_ports, index_urls, counts.
    # Memoikan hasil di ctx dan menulis ctx["recon"], ["recon_urls"], ["recon_param_targets"].

recon_dns_resolve(fqdn, timeout=RECON_DNS_TIMEOUT) -> bool
recon_dns_brute(host, limit=RECON_MAX_SUBDOMAINS) -> list[str]
recon_probe_host(sess, name) -> dict | None      # {url, status, title, server}
recon_port_open(host, port, timeout=PORT_SCAN_TIMEOUT) -> bool
recon_port_scan(hosts) -> list[tuple[str, int, str]]
recon_param_targets(urls, max_urls=RECON_PARAM_URLS, max_names=RECON_PARAM_NAMES)
    -> list[tuple[str, list[str]]]
recon_injection_targets(ctx) -> list[tuple[str, list[str]]]
injection_url_jobs(ctx, base_url) -> list[tuple[str, list[str] | None]]
recon_seed_urls(ctx) -> list[str]
extract_js_endpoints(text, host="") -> list[str]
recon_js(sess, base_url, ctx=None) -> dict           # {endpoints, texts, by_file}
scan_recon(sess, base_url, ctx=None) -> FindingList  # modul "recon"
```

Helper internal (tidak dijamin stabil): `_recon_target_host`, `_recon_clean_names`,
`_recon_fetch_json`, `_recon_clean_urls`, `_recon_is_static`,
`_recon_timeout_status`, `_looks_like_endpoint`, `_recon_apply_ctx`.

## 11. Flag CLI

| Flag | Efek |
|---|---|
| `--recon-only` | Hanya jalankan recon (modul `recon`), tanpa modul kerentanan. Bentrok dengan `--quick`/`--detailed`/`--no-recon` → exit 2 |
| `--no-recon` | Di DETAILED: lewati tahap recon (tidak ada request ke sumber pihak ketiga) |
| `--port-scan` | TCP connect scan ke port umum; butuh `--detailed` atau `--recon-only` |

Status recon ikut tercatat di laporan JSON:

```json
"scan": {
  "mode": "detailed",
  "recon": {"enabled": true, "sources": {"crtsh": "ok", "...": "..."},
            "counts": {"subdomains": 12, "live_hosts": 3, "historic_urls": 40,
                       "js_endpoints": 8, "open_ports": 0},
            "errors": []},
  "port_scan": false,
  "recon_only": false
}
```

## 12. Batasan / yang ditunda

- Screenshot / visual recon (`gowitness`, Playwright) — P3.
- `-l targets.txt` + `--scope-file` (batch host + allowlist) — masuk PR
  "operasional & scope" bersama bagian 5/6.
- Brute force parameter penuh (`arjun`/`x8`) dan penguraian **YAML** OpenAPI —
  ditunda bersama bagian 5 (`--delay`/`--max-rps`).
- Recon hanya melihat host yang muncul di log sertifikat/indeks publik; tidak
  ada pengujian zone transfer, S3/GCS bucket, atau takeover subdomain.
