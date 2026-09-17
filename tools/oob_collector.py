#!/usr/bin/env python3
"""Collector OOB (out-of-band) untuk Spade — hanya stdlib, tanpa dependency.

Target scan memanggil HTTP callback ke collector ini saat payload blind
SSRF/XXE/CMDi dieksekusi server. Spade lalu bertanya ke collector apakah token
tersebut benar-benar pernah dipanggil, sehingga temuan blind bisa dibuktikan
(bukan sekadar dugaan dari perubahan respons).

Kontrak HTTP yang dipakai `spade.py`:

    GET /<token>            mencatat callback, balas 200 teks biasa
    GET /check?token=<tok>  balas JSON {"token": tok, "hits": n, ...}
    GET /health             status collector

Contoh pakai (collector harus bisa diakses target, bukan hanya localhost):

    python3 tools/oob_collector.py --host 0.0.0.0 --port 9000
    python3 spade.py https://target.example --oob-host 10.0.0.5:9000

Callback apa pun dicatat berdasarkan token di segmen path pertama, lengkap
dengan method, path utuh, IP pemanggil, User-Agent, dan waktu. Jalankan hanya
di lingkungan uji Anda sendiri: collector ini merekam endpoint yang memanggilnya.
"""

import argparse
import json
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class _Store:
    """Catatan callback di memori proses (token -> daftar hit)."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = {}
        self.total = 0

    def record(self, token, entry):
        with self._lock:
            self.total += 1
            self._hits.setdefault(token, []).append(entry)
            return len(self._hits[token])

    def count(self, token):
        with self._lock:
            return len(self._hits.get(token, ()))

    def export(self):
        with self._lock:
            return {
                "total": self.total,
                "tokens": {token: {"hits": len(hits), "events": hits}
                           for token, hits in sorted(self._hits.items())},
            }


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "spade-oob/1.0"
    sys_version = ""

    def _respond(self, status, body, ctype="text/plain; charset=utf-8"):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _entry(self, token):
        return {
            "token": token,
            "method": self.command,
            "path": self.path,
            "client": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def _handle(self):
        app = self.server.app
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/health", "/"):
            return self._respond(200, json.dumps({"status": "ok", "hits": app.store.total}),
                                 "application/json")
        if path == "/check":
            token = (parse_qs(parsed.query).get("token") or [""])[0]
            hits = app.store.count(token) if token else 0
            return self._respond(200, json.dumps({"token": token, "hits": hits}),
                                 "application/json")
        token = path.lstrip("/").split("/")[0]
        if not token:
            return self._respond(404, "no token in path")
        count = app.store.record(token, self._entry(token))
        if app.verbose:
            print(f"  [hit {count}] {token} <- {self.client_address[0]} {self.command} {self.path}",
                  file=sys.stderr, flush=True)
        return self._respond(200, "ok")

    def do_GET(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, *args):
        pass


class _App:
    def __init__(self, verbose=True):
        self.store = _Store()
        self.verbose = verbose


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Collector OOB untuk spade --oob-host (stdlib saja).",
        epilog="Jalankan di host yang bisa dijangkau target scan, mis. VPS kecil atau reverse tunnel.")
    parser.add_argument("--host", default="0.0.0.0", help="Alamat bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9000, help="Port bind (default: 9000)")
    parser.add_argument("--quiet", action="store_true", help="Jangan cetak tiap callback")
    parser.add_argument("--export", default="", metavar="FILE",
                        help="Tulis ringkasan callback ke file JSON saat collector berhenti (Ctrl+C)")
    args = parser.parse_args(argv)

    httpd = ThreadingHTTPServer((args.host, args.port), _Handler)
    httpd.app = _App(verbose=not args.quiet)
    host, port = httpd.server_address[0], httpd.server_address[1]
    print(f"[*] OOB collector aktif di http://{host}:{port}/")
    print(f"    Pakai dengan: python3 spade.py TARGET --oob-host {host}:{port}")
    print("    GET /<token> mencatat callback | GET /check?token=<token> membaca hasil")
    print("    Hentikan dengan Ctrl+C.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Berhenti.")
    finally:
        httpd.server_close()
        if args.export:
            try:
                with open(args.export, "w", encoding="utf-8") as handle:
                    json.dump(httpd.app.store.export(), handle, indent=2, sort_keys=True)
                print(f"[*] Ringkasan callback ditulis ke {args.export}")
            except OSError as exc:
                print(f"[!] Gagal menulis {args.export}: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
