# Model Temuan, Bukti, dan Format Laporan

Dokumen ini menjelaskan model data temuan Spade setelah PR
`feat/finding-evidence-metadata`: bagaimana bukti request/response diambil,
bagaimana rahasia disensor, metadata apa yang menempel di tiap temuan, dan
bentuk keluaran HTML/CSV/JSON/SARIF.

Semua nama di bawah adalah API publik `spade.py` (bisa diimpor dan dipakai
ulang oleh tooling lain, mis. untuk menulis laporan kustom).

---

## 1. Alur bukti (evidence)

Setiap request yang lewat `ThreadLocalSession.request()` direkam otomatis
menjadi satu objek `Exchange` lalu disimpan di indeks bukti. Modul scan tidak
perlu diubah: saat temuan di-append, bukti yang cocok ditempelkan otomatis.

```
ThreadLocalSession.request()
   -> exchange_from_response(resp, method, elapsed_ms, kwargs, session_cookies)
        -> Exchange(method, url, status, ...)   # sudah disensor di __init__
             -> record_exchange(exchange)       # masuk indeks bukti

FindingList.append(...)
   -> evidence_for(url)     # cari exchange yang cocok
        -> finding.evidence = exchange
```

### `class Exchange`

Satu pasang request/response. Field: `method`, `url`, `status`,
`request_headers`, `request_body`, `response_headers`, `response_snippet`,
`response_length`, `content_type`, `elapsed_ms`, `timestamp`.

- **Sensor di konstruktor.** `Exchange.__init__` memanggil `redact_url`,
  `redact_headers`, dan `redact_body` (bisa dimatikan lewat argumen
  `redact=False`). Objek `Exchange` tidak pernah menyimpan header/body/URL
  mentah berisi kredensial, bahkan sebelum diserialisasi.
- `exchange.path` — path URL tanpa query/host (dipakai sebagai kunci fallback).
- `exchange.to_dict(snippet_chars, redact)` — bentuk JSON satu exchange,
  termasuk flag `response_truncated`.
- `exchange_from_response(resp, method, elapsed_ms, kwargs, session_cookies)`
  membangun `Exchange` dari `curl_cffi.Response`. Cookie jar milik session
  ditambahkan sebagai header `Cookie` karena `curl_cffi` tidak menaruh cookie
  di `resp.request.headers` (cookie dikirim di level engine), lalu nilainya
  tetap disensor.

### `FindingList` dan penempelan bukti

`FindingList(default_evidence_url=None, capture=True, iterable=())` adalah
`list` temuan yang otomatis:

1. mengubah tuple lama `(sev, code, desc, url)` menjadi `Finding` (`as_finding`),
2. menempelkan bukti hasil `evidence_for(...)`.

Aturannya:

- `default_evidence_url` dipakai kalau temuan tidak punya URL sendiri (modul
  pasif seperti security headers).
- `capture=False` untuk modul yang memang tidak menembak HTTP (mis. `tls_ssl`
  lewat socket).
- `append(item, evidence_url=None)` eksplisit berarti **temuan ini tidak punya
  request pemicu**, jadi tidak ada bukti yang ditempel (dipakai untuk
  `INFO SCAN_ERROR`).
- `append(item, evidence_url=<url>)` untuk modul yang butuh menunjuk request
  tertentu (mis. sub-request JS/param).

### Urutan pencarian `evidence_for(url=None, method=None)`

1. `(method, URL)` persis
2. URL apa pun dengan host/path/query sama
3. `(method, path)` tanpa query
4. path apa pun
5. request terakhir di thread yang sama
6. respons base URL scan (`set_evidence_base_url`)
7. `None`

Fallback nomor 5 disengaja: banyak modul meng-append temuan langsung setelah
request pemicunya di thread yang sama, dan thread sudah dipartisi oleh
`ThreadLocalSession`. Konsekuensinya, lookup untuk URL yang sama sekali asing
bisa mengembalikan exchange terakhir di thread itu — itu perilaku yang
dikunci oleh test, bukan bug.

Indeks dibatasi (`EVIDENCE_MAX_KEYS` per indeks, `EVIDENCE_MAX_THREADS` untuk
peta thread) supaya scan panjang tidak menumpuk memori. `reset_evidence()`
membersihkan semuanya; CLI memanggilnya di awal scan.

---

## 2. Redaksi rahasia

Redaksi **aktif secara default** (`REDACT_ENABLED = True`) dan berjalan di dua
lapis: saat `Exchange` dibuat, dan saat serialisasi. Nilai sensitif diganti
placeholder `***REDACTED***` (`REDACT_PLACEHOLDER`).

| Fungsi | Cakupan |
|---|---|
| `redact_headers(headers)` | Header di `REDACTED_HEADERS`: `cookie`, `set-cookie`, `authorization`, `proxy-authorization`, `x-api-key`, `x-csrf-token`, `x-xsrf-token`, `x-auth-token`. Cookie mempertahankan bentuk (`sid=***REDACTED***; theme=***REDACTED***`). |
| `redact_body(body)` | Body form-urlencoded dan JSON. Kunci yang cocok `pass`, `pwd`, `secret`, `token`, `api_key`, `auth`, `csrf`, `xsrf`, `session`, `otp`, `pin`, `credential` (case-insensitive) disensor rekursif, termasuk JSON bersarang. Dict/list disensor langsung sebagai struktur, bukan lewat `repr`. |
| `redact_url(url)` | Query parameter dengan nama sensitif (pola sama). Parameter lain dibiarkan byte-for-byte (tanpa encode ulang) supaya URL di laporan tetap identik dengan yang dikirim. |

`--no-redact` mematikan sensor dan CLI mencetak peringatan
`REDACT OFF — cookie/token/password ikut tersimpan di laporan`. Karena sensor
dipasang saat `Exchange` dibuat, urutannya penting: sensor harus dimatikan
**sebelum** request dilakukan. Laporan JSON mencatat status ini di
`scan.redacted`.

Perintah `curl` di bagian repro selalu memakai placeholder `COOKIE_ANDA`
untuk cookie — cookie hasil scan tidak valid untuk pembaca laporan, apa pun
status redaksi.

> Jangan pernah menjalankan `--no-redact` lalu membagikan hasilnya. Laporan
> HTML/CSV/JSON-nya berisi kredensial mentah.

---

## 3. Metadata temuan

`FindingMeta = namedtuple("FindingMeta", "vector score cwe owasp confidence")`.
Tabel `FINDING_META` memetakan sekitar 45 kode temuan ke metadata itu, dan
`META_PREFIX_RULES` menangani keluarga kode dinamis:

| Prefix | Arti | Metadata |
|---|---|---|
| `MISS_` | header keamanan tidak diset | CVSS 5.3, CWE-693, A05:2021, `certain` |
| `HDR_` | header terpasang | tanpa CVSS, CWE-693, A05:2021, `certain` |
| `WEAK_` | protokol/kriptografi lemah | CVSS 5.9, CWE-327, A02:2021, `certain` |

Skor CVSS 3.1 di tabel dihitung dari vector yang tertulis (bukan hasil
pengukuran runtime) dan diverifikasi aritmetikanya oleh test. Label severity
Spade tetap jadi prioritas operasional; severity dan skor CVSS boleh berbeda.

Fungsi terkait:

- `finding_meta(code)` -> `FindingMeta` atau `None`. Kode tak dikenal
  mengembalikan `None`; **vector CVSS tidak pernah dikarang**.
- `cvss_of(meta)` -> `{"vector": ..., "score": ...}`, atau `None` untuk temuan
  informasional (`vector` kosong) supaya laporan tidak menampilkan "skor 0.0".
- `finding_confidence(code, declared=None)` -> `certain` / `firm` / `tentative`.
  Kode di `TENTATIVE_CODES` (`SSRF`, `SSRF_FORM`, `SSRF_TIMEOUT`,
  `CORS_REFLECT`, `XSS_STORED`, `ROBOTS`, `SUBDOMAINS`, `NO_RATE_LIMIT`)
  selalu `tentative`, apa pun kata tabel meta.
- `make_finding_id(code, url, desc)` -> `spade-` + sha256(`code|url|desc`)
  12 karakter pertama. ID stabil antar scan, dipakai sebagai
  `partialFingerprints` SARIF.

Kode informasional (`TECH`, `ROBOTS`, `JS_APIS`, `JWT_COOKIE`, `JWT_BEARER`,
`RATE_LIMIT`, `NO_RATE_LIMIT`, `SUBDOMAINS`, `SCAN_ERROR`, dan `HDR_*`) punya
`vector = None`, jadi `cvss` bernilai `null` di JSON dan kolom CVSS-nya kosong
di CSV.

---

## 4. `class Finding`

`Finding` menyimpan `sev`, `code`, `desc`, `url`, plus `evidence`,
`confidence`, `meta`, dan `finding_id`.

Objektif penting: **tetap kompatibel dengan tuple lama**. Iterasi, `len()`,
indexing, `==` terhadap tuple, dan `hash()` tetap memakai bentuk
`(sev, code, desc, url)`:

```python
f = spade.Finding("HIGH", "SQLI", "SQL injection", "http://t/item?id=1")
sev, code, desc, url = f        # tuple unpacking lama tetap jalan
assert len(f) == 4 and f[0] == "HIGH"
assert f == ("HIGH", "SQLI", "SQL injection", "http://t/item?id=1")
```

Karena itu modul dan report lama tidak perlu diubah. `as_finding(item)`
menormalkan tuple/list apa pun menjadi `Finding`.

`finding.to_dict(snippet_chars, redact, impersonate)` adalah bentuk satu temuan
di laporan JSON.

---

## 5. Langkah reproduksi (`repro_curl`)

`repro_curl(exchange, impersonate=DEFAULT_IMPERSONATE, redact=None)` ->
`{"curl": "...", "python_curl_cffi": "..."}`.

- `curl` portabel jadi PoC utama: `curl -sS -i -X POST -H ... --data-raw ... '<url>'`.
  Header `Content-Length`, `Host`, dan `Accept-Encoding` dibuang karena diurus
  curl sendiri. Nilai di-`shell_quote` dengan kutip tunggal.
- `python_curl_cffi` jadi snippet sekunder supaya fingerprint impersonasi
  (`impersonate=`) scan bisa direplikasi. Body JSON dikirim sebagai `json=`,
  body lain sebagai `data=`.
- Cookie selalu `<nama>=COOKIE_ANDA`.
- Tanpa bukti, hasilnya `{"curl": "", "python_curl_cffi": ""}`.

Blok HTML menambahkan catatan bahwa scan memakai impersonasi browser, jadi
`curl` polos bisa memberi hasil berbeda dan snippet `curl_cffi` lebih akurat
untuk mereplikasi kondisi scan.

---

## 6. Format laporan

### HTML (`-o`, default `spade_<host>.html`)

Tabel temuan + kartu ringkasan berisi durasi, jumlah temuan, sebaran severity,
`with_evidence/total`, dan hitungan confidence. Setiap baris punya blok
`<details>` "Bukti & repro" berisi baris metadata
(`confidence: ... · CVSS ... · CWE-... · A0x:2021`), request headers
(tersensor), request body, potongan respons, dan dua langkah repro. Semua
isi bukti di-escape HTML. Temuan tanpa bukti menampilkan catatan bahwa bukti
HTTP tidak berlaku (mis. pemeriksaan TLS/socket).

### CSV (`--csv`)

Lima kolom lama tetap di posisi semula (`Severity`, `Category`, `Detail`,
`URL`, `Target`), diikuti kolom baru:

`Confidence`, `CVSS_Score`, `CVSS_Vector`, `CWE`, `OWASP`, `Repro_Curl`,
`Evidence_Status` (`http`/`none`), `Evidence_URL`.

Skor/vector CVSS dikosongkan untuk kode informasional dan kode tanpa mapping.

### JSON (`--json`)

```jsonc
{
  "tool": {"name": "spade", "version": "3.1"},
  "target": "https://example.com/",
  "scan": {
    "mode": "detailed", "started_at": "...", "finished_at": "...",
    "duration_s": 61.2, "impersonate": "chrome", "workers": 10,
    "modules": ["tech", "headers", "..."],
    "errors": [{"module": "xss", "error": "RuntimeError: ..."}],
    "redacted": true
  },
  "summary": {
    "total": 24,
    "by_severity": {"CRITICAL": 2, "HIGH": 7},
    "by_confidence": {"certain": 9, "firm": 12, "tentative": 3}
  },
  "findings": [
    {
      "id": "spade-1a2b3c4d5e6f",
      "severity": "HIGH", "code": "SQLI", "description": "...",
      "url": "https://example.com/item?id=1",
      "confidence": "firm",
      "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
      "cwe": "CWE-89", "owasp": "A03:2021",
      "evidence": {
        "url": "...", "method": "GET", "status": 500,
        "content_type": "text/html", "elapsed_ms": 42.1, "timestamp": "...",
        "request_headers": {}, "request_body": null,
        "response_status": 500, "response_length": 1234,
        "response_snippet": "...", "response_truncated": false
      },
      "repro": {"curl": "curl -sS -i -X GET ...", "python_curl_cffi": "from curl_cffi import requests\n..."}
    }
  ]
}
```

Potongan respons dipotong ke `EVIDENCE_SNIPPET_CHARS_JSON` karakter
(`response_truncated: true` bila terpotong). `evidence` bernilai `null` kalau
temuan tidak punya bukti HTTP.

### SARIF 2.1.0 (`--sarif`)

Satu `run` berisi `tool.driver.rules` (unik per kode temuan, dengan
`helpUri` ke CWE MITRE atau OWASP Top 10) dan `results` yang menunjuk balik
lewat `ruleId`/`ruleIndex`. Mapping level:

| Severity | SARIF level |
|---|---|
| CRITICAL, HIGH | `error` |
| MEDIUM | `warning` |
| LOW, INFO | `note` |

Tiap hasil membawa `partialFingerprints.findingId` (ID stabil antar scan,
supaya temuan tidak terduplikasi di dashboard) dan `properties` berisi
confidence, skor/vector CVSS, CWE, OWASP, serta `evidenceUrl`.

---

## 7. Kontrak `INFO SCAN_ERROR`

Kegagalan modul tidak lagi hilang diam-diam. Kalau sebuah modul melempar
exception, `main()` akan:

1. mencetak error ke stderr,
2. menambahkan `{"module": <key>, "error": "<Tipe>: <pesan>"}` ke
   `scan["errors"]`,
3. menambahkan temuan `("INFO", "SCAN_ERROR", "<detail>", <target>)` tanpa
   bukti HTTP,
4. mencetak peringatan `N modul gagal — lihat temuan SCAN_ERROR di laporan`.

Scan tetap selesai dengan exit code `0` — satu modul gagal bukan alasan
membatalkan seluruh hasil. Pipeline yang butuh gagal keras bisa memeriksa
`scan.errors` di JSON.

---

## 8. Ringkasan API publik

| Nama | Kegunaan |
|---|---|
| `Exchange`, `exchange_from_response` | model & pembuat bukti request/response |
| `record_exchange`, `evidence_for`, `reset_evidence`, `set_evidence_base_url` | indeks bukti |
| `redact_headers`, `redact_body`, `redact_url`, `REDACT_ENABLED`, `REDACT_PLACEHOLDER` | sensor rahasia |
| `FindingMeta`, `FINDING_META`, `finding_meta`, `cvss_of`, `finding_confidence` | metadata temuan |
| `Finding`, `FindingList`, `as_finding`, `make_finding_id` | model temuan |
| `repro_curl` | langkah reproduksi |
| `scan_summary`, `confidence_badge`, `evidence_html`, `evidence_status`, `evidence_url` | helper laporan |
| `gen_html`, `gen_csv`, `gen_json`, `gen_sarif` | penulis laporan |

**Belum termasuk di PR ini:** opsi `--diff <scan.json>` untuk membandingkan dua
scan (direncanakan di PR terpisah). Lihat
[docs/bug-bounty-gaps.md](bug-bounty-gaps.md) bagian 1.
