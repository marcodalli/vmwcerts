#!/usr/bin/env python3
"""Small remote-capable web app for comparing certification transcripts."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
from http.cookies import CookieError, SimpleCookie
import argparse
import hashlib
import hmac
import json
import re
import secrets
import tempfile
import time


BASE = Path(__file__).resolve().parent
CACHE = BASE / "certs"
TRANSCRIPTS_CACHE = CACHE / "transcripts"
CONFIG = CACHE / "candidates.json"
LEGACY_CONFIG = Path("/tmp/vmwcerts-legacy-candidates.json")
CLASSIFICATIONS = BASE / "classifications.json"
PASSWORD_FILE = BASE / "password.txt"
PASSWORD_ITERATIONS = 310_000
SESSIONS = {}
SESSION_TTL = 8 * 60 * 60
ALLOWED_TYPES = {"Sales", "Technical"}
ALLOWED_SPECS = {"Pre-Sales", "Implementation", "Support", "Architecture"}
ALLOWED_LEVELS = {"Proven Professional", "Certified Expert"}
DEFAULT_SOURCES = []


def read_config():
    if not CONFIG.exists():
        # Migrate the formerly bind-mounted file on first startup after upgrade.
        legacy = LEGACY_CONFIG if LEGACY_CONFIG.exists() else BASE / "candidates.json"
        if legacy.exists():
            old_data = json.loads(legacy.read_text(encoding="utf-8"))
            write_config(old_data.get("sources", DEFAULT_SOURCES))
        else:
            write_config(DEFAULT_SOURCES)
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def write_config(sources):
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=CONFIG.parent, delete=False) as tmp:
        json.dump({"sources": sources}, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
        temp_path = Path(tmp.name)
    temp_path.replace(CONFIG)


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PASSWORD_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest.hex()}"


def ensure_password_file():
    if not PASSWORD_FILE.exists():
        PASSWORD_FILE.write_text(hash_password("evoila") + "\n", encoding="utf-8")


def verify_password(password):
    ensure_password_file()
    try:
        algorithm, rounds, salt, expected = PASSWORD_FILE.read_text(encoding="utf-8").strip().split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (OSError, ValueError):
        return False


def extract_candidate_name(data):
    candidate = data.get("candidate")
    if isinstance(candidate, dict):
        name = str(candidate.get("name") or "").strip()
        if name:
            return name
        parts = [str(candidate.get(key) or "").strip() for key in ("firstName", "lastName")]
        if any(parts):
            return " ".join(part for part in parts if part)
    elif isinstance(candidate, str) and candidate.strip():
        return candidate.strip()
    for key in ("candidateName", "name", "ctranLabel"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise ValueError("Il JSON scaricato non contiene il nome del candidato.")


def download_source(url):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "CertificazioniDashboard/1.0"})
    with urlopen(request, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("Il file remoto non contiene un oggetto JSON valido.")
    name = extract_candidate_name(data)
    TRANSCRIPTS_CACHE.mkdir(parents=True, exist_ok=True)
    (TRANSCRIPTS_CACHE / safe_filename(name)).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"url": url, "name": name}


def normalize_source_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port:
        raise ValueError("Inserisci un URL HTTPS valido di CertMetrics.")
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.hostname == "api.certmetrics.com":
        if len(parts) != 3 or parts[:2] != ["vmware", "transcript"]:
            raise ValueError("L’URL API deve puntare a /vmware/transcript/{id}.")
        return value
    if parsed.hostname == "cp.certmetrics.com":
        if not parts:
            raise ValueError("L’URL CP non contiene l’identificativo del transcript.")
        return f"https://api.certmetrics.com/vmware/transcript/{parts[-1]}"
    raise ValueError("Sono accettati solo URL https://api.certmetrics.com o https://cp.certmetrics.com.")


def validate_sources(payload):
    sources = payload.get("sources") if isinstance(payload, dict) else None
    if not isinstance(sources, list) or len(sources) > 100:
        raise ValueError("La configurazione deve contenere un array sources (massimo 100 righe).")
    cleaned = []
    for row in sources:
        if not isinstance(row, dict):
            raise ValueError("Ogni riga deve contenere un URL.")
        url = str(row.get("url", "")).strip()
        if not url:
            continue
        api_url = normalize_source_url(url)
        try:
            cleaned.append(download_source(api_url))
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Download non riuscito per {api_url}: {exc}") from exc
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
    TRANSCRIPTS_CACHE.mkdir(parents=True, exist_ok=True)
    files, saved = [], 0
    for source in sources:
        url, name = source["url"], source["name"]
        try:
            request = Request(url, headers={"Accept": "application/json", "User-Agent": "CertificazioniDashboard/1.0"})
            with urlopen(request, timeout=30) as response:
                raw = response.read()
            data = json.loads(raw.decode("utf-8-sig"))
            cache_file = TRANSCRIPTS_CACHE / safe_filename(name)
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

    def send_json(self, data, status=200, headers=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie.get("cert_session").value if cookie.get("cert_session") else ""
        except (CookieError, ValueError, AttributeError):
            return ""

    def authenticated(self):
        now = time.time()
        token = self.session_token()
        for session, expires in list(SESSIONS.items()):
            if expires <= now:
                SESSIONS.pop(session, None)
        return bool(token and SESSIONS.get(token, 0) > now)

    def require_auth(self):
        if self.authenticated():
            return True
        self.send_json({"error": "Autenticazione richiesta."}, 401)
        return False

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/config":
            if not self.require_auth():
                return
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
        if path == "/api/partnership-requirements":
            try:
                self.send_json(json.loads((BASE / "partnership_requirements.json").read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 500)
            return
        if path == "/api/refresh":
            try:
                self.send_json(refresh_and_sync())
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                self.send_json({"files": [], "error": str(exc)}, 500)
            return
        if path == "/settings.html" and not self.authenticated():
            self.send_response(303)
            self.send_header("Location", "/login.html?next=/settings.html")
            self.end_headers()
            return
        if path in ("/", "/certificazioni.html"):
            self.path = "/index.html"
            return super().do_GET()
        if path == "/table.html":
            self.path = "/certifications.html"
            return super().do_GET()
        if path in ("/index.html", "/certifications.html", "/settings.html", "/login.html", "/app.js", "/style.css"):
            return super().do_GET()
        self.send_json({"error": "Risorsa non trovata."}, 404)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/api/login", "/api/password", "/api/config", "/api/classifications"):
            self.send_json({"error": "Endpoint non trovato."}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if path == "/api/login":
                password = str(payload.get("password", "")) if isinstance(payload, dict) else ""
                if not verify_password(password):
                    self.send_json({"error": "Password non corretta."}, 401)
                    return
                token = secrets.token_urlsafe(32)
                SESSIONS[token] = time.time() + SESSION_TTL
                secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
                self.send_json({"authenticated": True}, headers={"Set-Cookie": f"cert_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL}{secure}"})
                return
            if path == "/api/password":
                if not self.require_auth():
                    return
                if not isinstance(payload, dict):
                    raise ValueError("Dati password non validi.")
                current = str(payload.get("currentPassword", ""))
                new = str(payload.get("newPassword", ""))
                confirmation = str(payload.get("confirmation", ""))
                if not verify_password(current):
                    self.send_json({"error": "La password attuale non è corretta."}, 400)
                    return
                if len(new) < 8:
                    self.send_json({"error": "La nuova password deve contenere almeno 8 caratteri."}, 400)
                    return
                if new != confirmation:
                    self.send_json({"error": "La conferma della nuova password non corrisponde."}, 400)
                    return
                PASSWORD_FILE.write_text(hash_password(new) + "\n", encoding="utf-8")
                self.send_json({"changed": True})
                return
            if path == "/api/config":
                if not self.require_auth():
                    return
                sources = validate_sources(payload)
                write_config(sources)
                self.send_json({"sources": sources, "saved": True})
            else:
                if not self.require_auth():
                    return
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
    ensure_password_file()
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
