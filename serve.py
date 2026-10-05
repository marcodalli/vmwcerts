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
ALLOWED_TYPES = {"Sales", "Technical"}
ALLOWED_SPECS = {"Pre-Sales", "Implementation", "Support", "Architecture"}
ALLOWED_LEVELS = {"Proven Professional", "Certified Expert"}
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


def product_for(name):
    n = name.lower()
    if "vdefend" in n or "private cloud security" in n:
        return "VMware vDefend Security" if "vdefend" in n else "Private Cloud Security"
    if "vks" in n or "kubernetes service" in n: return "VKS"
    if "avi" in n or "load balancer" in n: return "Avi Load Balancer"
    if "automation" in n: return "VCF Automation"
    if "operation" in n: return "VCF Operations"
    if "storage" in n or "vsan" in n: return "VCF Storage"
    if "network" in n or "nsx" in n or "vcp-nv" in n: return "VCF Networking"
    if "vsphere foundation" in n or "vvf" in n: return "VMware vSphere Foundation"
    if "cloud foundation" in n or "vcf" in n: return "VMware Cloud Foundation"
    if "vsphere" in n or "vcp-dcv" in n or "vcp-cma" in n: return "VMware vSphere"
    return "VMware Core"


def normalize_classification(entry):
    item = dict(entry)
    old_product = item.get("focusProduct")
    if isinstance(old_product, str):
        item.setdefault("product", old_product)
        item["focusProduct"] = True
    item.setdefault("product", product_for(str(item.get("name", ""))))
    item["focusProduct"] = bool(item.get("focusProduct", False))
    kind = item.get("type", "")
    item["type"] = kind if kind in ALLOWED_TYPES else ""
    level = item.get("level", "")
    spec = item.get("specification", "")
    if not level and isinstance(spec, str):
        for allowed in ALLOWED_LEVELS:
            if spec == allowed or spec.startswith(allowed + " · "):
                level = allowed
                spec = spec[len(allowed):].strip(" ·")
                break
    if not level and spec in ALLOWED_LEVELS:
        level, spec = spec, ""
    item["level"] = level if level in ALLOWED_LEVELS else ""
    item["specification"] = spec if spec in ALLOWED_SPECS else ""
    item["vcap"] = bool(item.get("vcap", "vcap" in str(item.get("name", "")).lower() or "advanced professional" in str(item.get("name", "")).lower()))
    return item


def read_classifications():
    data = json.loads(CLASSIFICATIONS.read_text(encoding="utf-8"))
    items = data.get("certifications", [])
    return [normalize_classification(x) for x in items]


def write_classifications(items):
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=BASE, delete=False) as tmp:
        json.dump({"certifications": items}, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
        temp_path = Path(tmp.name)
    temp_path.replace(CLASSIFICATIONS)


def sync_classifications(downloaded):
    """Append unseen credential names, leaving every existing classification intact."""
    try:
        original = json.loads(CLASSIFICATIONS.read_text(encoding="utf-8")).get("certifications", [])
        items = [normalize_classification(x) for x in original]
    except (OSError, json.JSONDecodeError):
        original = []
        items = []
    by_name = {x.get("name", ""): x for x in items}
    added = []
    for transcript in downloaded:
        data = transcript.get("data") or {}
        for cert in data.get("certs", []):
            name = str(cert.get("name", "")).strip()
            if not name or name in by_name:
                continue
            item = {"ccatId": cert.get("ccatId", cert.get("id")), "name": name,
                    "product": product_for(name), "focusProduct": False,
                    "vcap": "vcap" in name.lower() or "advanced professional" in name.lower(),
                    "type": "", "specification": "", "level": "", "isNew": True}
            items.append(item)
            by_name[name] = item
            added.append(name)
    if added or original != items or not CLASSIFICATIONS.exists():
        write_classifications(items)
    return items, added


def refresh_and_sync():
    sources = read_config().get("sources", [])
    CACHE.mkdir(exist_ok=True)
    files, saved = [], 0
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
    _, added = sync_classifications(files)
    return {"files": files, "saved": saved, "newNames": added}


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
                self.send_json({"certifications": read_classifications()})
            except (OSError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 500)
            return
        if path == "/api/refresh":
            try:
                self.send_json(refresh_and_sync())
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                self.send_json({"files": [], "error": str(exc)}, 500)
            return
        if path == "/":
            self.path = "/index.html"
            return super().do_GET()
        if path in ("/index.html", "/table.html", "/settings.html", "/app.js", "/style.css"):
            return super().do_GET()
        self.send_json({"error": "Risorsa non trovata."}, 404)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/api/config", "/api/classifications"):
            self.send_json({"error": "Endpoint non trovato."}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if path == "/api/config":
                sources = validate_sources(payload)
                write_config(sources)
                self.send_json({"sources": sources, "saved": True})
            else:
                raw = payload.get("certifications") if isinstance(payload, dict) else None
                if not isinstance(raw, list):
                    raise ValueError("La configurazione deve contenere certifications.")
                items = []
                for row in raw:
                    item = normalize_classification(row)
                    if not item.get("name"):
                        raise ValueError("Ogni certificazione deve avere un nome.")
                    has_selected_value = bool(item["focusProduct"] or item["vcap"] or item["type"] or item["specification"] or item["level"])
                    if has_selected_value:
                        item.pop("isNew", None)
                    elif item.get("isNew"):
                        item["isNew"] = True
                    else:
                        item.pop("isNew", None)
                    items.append(item)
                write_classifications(items)
                self.send_json({"certifications": items, "saved": True})
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except OSError as exc:
            self.send_json({"error": str(exc)}, 500)

def main():
    parser = argparse.ArgumentParser(description="Avvia la webapp per il confronto delle certificazioni.")
    parser.add_argument("--host", default="0.0.0.0", help="Interfaccia di ascolto (default: tutte le interfacce)")
    parser.add_argument("--port", type=int, default=8765, help="Porta HTTP (default: 8765)")
    args = parser.parse_args()
    read_config()
    try:
        result = refresh_and_sync()
        print(f"Avvio: scaricati {result['saved']} JSON; aggiunte {len(result['newNames'])} nuove certificazioni.")
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"Aggiornamento classificazioni all'avvio non riuscito: {exc}")
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
