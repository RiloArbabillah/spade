# Deteksi modul yang sudah ada

Dokumen ini menjelaskan orakel dan penjaga false positive pada modul inti.
Semua uji jaringan di dokumentasi ini tetap membutuhkan otorisasi program.

## Prinsip umum

1. Temuan memakai orakel, bukan sekadar respons besar atau pantulan mentah.
2. Payload dibatasi per parameter, path, dan modul agar tidak membanjiri target.
3. Probe time-based tidak pernah jalan default. Aktifkan `--timing-probes`
   hanya pada target yang mengizinkannya.
4. `Exchange` menyensor nilai kredensial di body respons sejak objek bukti
   dibuat, sehingga HTML, CSV, JSON, dan SARIF tidak menyimpan nilai mentah.

## Baseline SPA

`get_baseline_fingerprint()` memakai empat path acak. Catch-all diterima hanya
jika minimal tiga respons valid, content type-nya HTML, dan similarity body
minimal `0.95`. Angka, hex panjang, dan whitespace dinamis dinormalisasi.
Helper `baseline_body_match()` dipakai modul lain sehingga respons SPA dinamis
tidak dilaporkan sebagai file sensitif atau directory listing.

## SSRF

Respons besar saja bukan temuan. `SSRF_METADATA` dilaporkan hanya jika body
memuat minimal dua signature cloud metadata seperti `ami-id`, `instance-id`,
`computeMetadata`, atau `service-accounts/`. Form POST dapat menghasilkan
`SSRF_DIFFERENTIAL` ketika respons berubah secara bermakna dibanding baseline.
Kode ini tentative. `SSRF_BLIND` tetap hanya dilaporkan setelah collector OOB
menerima callback.

## XSS

`xss_reflection_context()` mengklasifikasikan pantulan sebagai `html`,
`script`, `attribute`, atau `url`. Modul hanya melaporkan context executable.
Komentar, entity ter-encode, dan nilai attribute tanpa breakout diabaikan.
Varian percent-encoded dan double-encoded diperiksa untuk kasus decoder ganda.
Tidak ada browser headless yang dijalankan, sehingga scanner tidak mengklaim
eksekusi JavaScript yang tidak terbukti.

## LFI

Katalog internal memakai Linux, Windows, encoded traversal, `file://`,
`php://filter`, dan `/proc/self/environ`. Respons harus memuat signature file:
misalnya `root:x:0:0:` plus `daemon:`, `[fonts]` plus `[extensions]`, atau hasil
decode base64 yang valid. Halaman biasa yang besar tidak dilaporkan.

## SQLi

Error-based memakai signature MySQL, PostgreSQL, MSSQL, SQLite, Oracle, dan
driver database. Boolean oracle membandingkan `1 AND 1=1` dengan `1 AND 1=2`
terhadap baseline. Kode `SQLI_BOOLEAN` dan `SQLI_TIME` selalu tentative.

Probe `SLEEP`, `pg_sleep`, dan `WAITFOR DELAY` hanya berjalan dengan
`--timing-probes`. Scanner mengukur elapsed time dan menolak delay yang tidak
konsisten dengan payload.

## CMDi dan XXE

CMDi in-band memakai output command yang mengubah casing token scanner. Pantulan
token yang identik dengan input tidak dianggap eksekusi. `CMDI_TIME` hanya
opt-in dan tentative. XXE tidak lagi mensyaratkan `/bin/bash`; cukup signature
`/etc/passwd` yang konsisten. Blind callback tetap terpisah melalui
`--oob-host`.
