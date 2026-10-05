#!/usr/bin/env python3
"""Small remote-capable web app for comparing certification transcripts."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
import argparse
import json
import re
import tempfile


BASE = Path(__file__).resolve().parent
CACHE = BASE / "certs"
CONFIG = BASE / "config.json"
CLASSIFICATIONS = BASE / "classifications.json"
DEFAULT_SOURCES = [
    {"url": "https://api.certmetrics.com/vmware/transcript/cb42c7284ecc42779a92605cc766e812", "name": "Marco Dalli"},
    {"url": "https://api.certmetrics.com/vmware/transcript/S7BN84BKKBE115GQ", "name": "Alessandro Zanotti"},
]


def read_config():
    if not CONFIG.exists():
        write_config(DEFAULT_SOURCES)
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def write_config(sources):
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=CONFIG.parent, delete=False) as tmp:
        json.dump({"sources": sources}, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
        temp_path = Path(tmp.name)
    temp_path.replace(CONFIG)


def validate_sources(payload):
    sources = payload.get("sources") if isinstance(payload, dict) else None
    if not isinstance(sources, list) or len(sources) > 100:
        raise ValueError("La configurazione deve contenere un array sources (massimo 100 righe).")
    cleaned = []
    for row in sources:
        if not isinstance(row, dict):
            raise ValueError("Ogni riga deve avere URL e Nome.")
        url = str(row.get("url", "")).strip()
        name = str(row.get("name", "")).strip()
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"URL non valido: {url or '(vuoto)'}")
        if not name:
            raise ValueError("Il campo Nome è obbligatorio per ogni URL.")
        cleaned.append({"url": url, "name": name})
    return cleaned


def safe_filename(name):
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_") or "candidato"
    return f"{stem}.json"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE), **kwargs)

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/config":
            try:
                self.send_json(read_config())
            except (OSError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 500)
            return
        if path == "/api/classifications":
            try:
                self.send_json(json.loads(CLASSIFICATIONS.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 500)
            return
        if path == "/api/refresh":
            self.refresh_sources()
            return
        if path == "/":
            self.path = "/index.html"
            return super().do_GET()
        if path in ("/index.html", "/table.html", "/settings.html", "/app.js", "/style.css"):
            return super().do_GET()
        self.send_json({"error": "Risorsa non trovata."}, 404)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/config":
            self.send_json({"error": "Endpoint non trovato."}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            sources = validate_sources(payload)
            write_config(sources)
            self.send_json({"sources": sources, "saved": True})
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except OSError as exc:
            self.send_json({"error": str(exc)}, 500)

    def refresh_sources(self):
        try:
            sources = read_config().get("sources", [])
        except (OSError, json.JSONDecodeError) as exc:
            self.send_json({"files": [], "error": f"Impossibile leggere config.json: {exc}"}, 500)
            return

        CACHE.mkdir(exist_ok=True)
        files = []
        saved = 0
        for source in sources:
            url, name = source["url"], source["name"]
            try:
                request = Request(url, headers={"Accept": "application/json", "User-Agent": "CertificazioniDashboard/1.0"})
                with urlopen(request, timeout=30) as response:
                    raw = response.read()
                data = json.loads(raw.decode("utf-8-sig"))
                cache_file = CACHE / safe_filename(name)
                cache_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
                cached_data = json.loads(cache_file.read_text(encoding="utf-8"))
                files.append({"url": url, "name": name, "file": cache_file.name, "data": cached_data})
                saved += 1
            except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                files.append({"url": url, "name": name, "message": str(exc), "error": True})
        self.send_json({"files": files, "saved": saved})


def main():
    parser = argparse.ArgumentParser(description="Avvia la webapp per il confronto delle certificazioni.")
    parser.add_argument("--host", default="0.0.0.0", help="Interfaccia di ascolto (default: tutte le interfacce)")
    parser.add_argument("--port", type=int, default=8765, help="Porta HTTP (default: 8765)")
    args = parser.parse_args()
    read_config()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Webapp: http://{args.host}:{args.port}/")
    print(f"Configurazione: {CONFIG}")
    print(f"Classificazioni: {CLASSIFICATIONS}")
    print(f"Cache JSON: {CACHE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer arrestato.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
