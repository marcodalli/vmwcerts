#!/usr/bin/env python3
"""Small remote-capable web app for comparing certification transcripts."""

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from http.cookies import CookieError, SimpleCookie
import argparse
import hashlib
import hmac
import json
import re
import secrets
import tempfile
import time
import unicodedata
from datetime import datetime, timezone


BASE = Path(__file__).resolve().parent
CACHE = BASE / "certs"
TRANSCRIPTS_CACHE = CACHE / "transcripts"
CONFIG = CACHE / "candidates.json"
REFRESH_STATE = CACHE / "last_refresh.json"
LEGACY_CONFIG = Path("/tmp/vmwcerts-legacy-candidates.json")
CLASSIFICATIONS = CACHE / "classifications.json"
LEGACY_CLASSIFICATIONS = BASE / "classifications.json"
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
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{CONFIG.name} contains invalid or empty JSON: {exc}") from exc


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


def fetch_json(url, accept="application/json, text/plain, */*"):
    headers = {
        "Accept": accept,
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    }
    if urlsplit(url).hostname in {"credly.com", "www.credly.com"}:
        headers["Origin"] = "https://www.credly.com"
        headers["Referer"] = "https://www.credly.com/"
    request = Request(url, headers=headers)
    with urlopen(request, timeout=30) as response:
        raw = response.read()
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        preview = raw[:120].decode("utf-8", errors="replace").replace("\n", " ").strip()
        raise ValueError(f"La risposta da {url} non è JSON valido: {exc}. Risposta iniziale: {preview!r}") from exc


def credly_cache_path(url):
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return TRANSCRIPTS_CACHE / f"credly_{digest}.json"


def fetch_credly_badges(url):
    """Fetch every Credly badge page by following its metadata pagination."""
    badges = []
    page_url = url
    seen = set()
    total_pages = None
    while page_url and page_url not in seen:
        seen.add(page_url)
        payload = fetch_json(page_url)
        if not isinstance(payload, dict):
            raise ValueError("Credly returned an invalid JSON response.")
        badges.extend(credly_badge_items(payload))
        metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        try:
            total_pages = int(metadata.get("total_pages", total_pages or 1))
        except (TypeError, ValueError):
            total_pages = total_pages or 1
        next_url = metadata.get("next_url") or metadata.get("next_page_url") or metadata.get("next_page") or metadata.get("next")
        if isinstance(next_url, dict):
            next_url = next_url.get("url") or next_url.get("href")
        if isinstance(next_url, str) and next_url:
            candidate_url = urljoin(page_url, next_url)
            parsed_next = urlsplit(candidate_url)
            if parsed_next.scheme != "https" or parsed_next.hostname not in {"credly.com", "www.credly.com"}:
                raise ValueError("Credly returned an invalid next-page URL.")
            page_url = candidate_url
        elif len(seen) < total_pages:
            parts = urlsplit(page_url)
            query = parse_qs(parts.query)
            try:
                page = int((query.get("page") or ["1"])[0])
            except ValueError:
                page = len(seen)
            query["page"] = [str(page + 1)]
            query.setdefault("page_size", ["48"])
            page_url = parts._replace(query=urlencode(query, doseq=True)).geturl()
        else:
            page_url = ""
    return {"data": badges, "metadata": {"total_pages": total_pages or 1}}


def normalize_credential_name(value):
    normalized = unicodedata.normalize("NFKD", str(value or "")).casefold()
    normalized = "".join(char for char in normalized if not unicodedata.combining(char))
    return " ".join(re.findall(r"[a-z0-9]+", normalized))


def credly_badge_items(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("data", "badges", "results", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            for nested_key in ("badges", "results", "items"):
                if isinstance(value.get(nested_key), list):
                    return value[nested_key]
            if any(key in value for key in ("badge_template", "badge", "credential")):
                return [value]
    return []


def credly_badge_names(item):
    names = []
    containers = [item]
    data = item.get("data")
    if isinstance(data, dict):
        containers.append(data)
    for container in containers:
        names.extend(container.get(key) for key in ("name", "badge_name", "badge_template_name", "credential_name"))
        for key in ("badge_template", "badge", "credential"):
            nested = container.get(key)
            if isinstance(nested, dict):
                names.extend(nested.get(name_key) for name_key in ("name", "badge_template_name", "credential_name"))
    return {normalize_credential_name(name) for name in names if isinstance(name, str) and name.strip()}


def merge_credly_expirations(transcript, credly_payload):
    badge_records = []
    for badge in credly_badge_items(credly_payload):
        if not isinstance(badge, dict):
            continue
        details = badge.get("data") if isinstance(badge.get("data"), dict) else badge
        expiration = badge.get("expires_at_date") or details.get("expires_at_date")
        if not isinstance(expiration, str):
            expiration = ""
        issued = badge.get("issued_at_date") or badge.get("issued_at") or details.get("issued_at_date") or details.get("issued_at") or ""
        created = str(badge.get("created_at") or details.get("created_at") or "")
        image_url = ""
        for container in (badge, details):
            template = container.get("badge_template") if isinstance(container, dict) else None
            candidate_image = template.get("image_url") if isinstance(template, dict) else ""
            if candidate_image:
                parsed_image = urlsplit(str(candidate_image))
                if parsed_image.scheme == "https" and parsed_image.hostname and (
                        parsed_image.hostname == "credly.com" or parsed_image.hostname.endswith(".credly.com")):
                    image_url = str(candidate_image)
                    break
        for name in credly_badge_names(badge):
            badge_records.append((name, created, str(issued)[:10], expiration[:10], image_url))
    matched_count = 0
    for cert in transcript.get("certs", []):
        if not isinstance(cert, dict):
            continue
        names = [normalize_credential_name(cert.get(key)) for key in ("name", "certificationName") if cert.get(key)]
        # Credly often omits the exam code appended to the CertMetrics name.
        # Match the Credly badge name as a substring of the CertMetrics name.
        matches = [
            (created, issued, expiration, image_url)
            for badge_name, created, issued, expiration, image_url in badge_records
            if badge_name and any(badge_name in cert_name for cert_name in names)
        ]
        matched_count += bool(matches)
        latest = max(matches, key=lambda record: record[0] or record[1]) if matches else None
        selected = latest[2] if latest else ""
        cert["expiresAtDate"] = selected
        cert["imageUrl"] = latest[3] if latest else ""
    return matched_count


def resolve_credly_profile(profile_url):
    payload = fetch_json(profile_url, accept="application/json")
    data = payload.get("data") if isinstance(payload, dict) else None
    synthetic_id = data.get("synthetic_id") if isinstance(data, dict) else None
    if not isinstance(synthetic_id, str) or not re.fullmatch(r"[A-Za-z0-9-]+", synthetic_id):
        raise ValueError("La risposta JSON del profilo Credly non contiene un data.synthetic_id valido.")
    return f"https://www.credly.com/users/{synthetic_id}/badges.json?api=api&page=1&page_size=48"


def normalize_credly_url(value):
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Inserisci un URL Credly valido.") from exc
    parts = [part for part in parsed.path.split("/") if part]
    profile_alias = len(parts) == 4 and parts[0] == "users" and parts[1] and parts[2:] == ["badges", "credly"]
    profile_path = len(parts) == 2 and parts[0] == "users" and parts[1]
    public_path = len(parts) == 3 and parts[0] == "users" and parts[1] and parts[2] in {"badges", "badges.json"}
    api_path = len(parts) == 5 and parts[:3] == ["api", "v1", "users"] and parts[3] and parts[4] == "badges"
    valid_path = profile_alias or profile_path or public_path or api_path
    if (parsed.scheme != "https" or parsed.hostname not in {"credly.com", "www.credly.com"}
            or parsed.username or parsed.password or port or parsed.fragment or not valid_path):
        raise ValueError("L’URL Credly deve puntare al profilo utente /badges o all’API /api/v1/users/{id}/badges.")
    if profile_alias or profile_path:
        if parsed.query:
            raise ValueError("L’URL profilo Credly non deve contenere parametri.")
        profile_slug = parts[1].rstrip(",")
        if not profile_slug:
            raise ValueError("Lo slug del profilo Credly non è valido.")
        profile_url = f"https://www.credly.com/users/{profile_slug}"
        return resolve_credly_profile(profile_url)
    query = parse_qs(parsed.query)
    if set(query) - {"api", "page", "page_size"}:
        raise ValueError("L’URL Credly può contenere solo i parametri api, page e page_size.")
    if "api" in query and query["api"] != ["api"]:
        raise ValueError("Il parametro Credly api deve avere valore api.")
    if public_path and parts[2] == "badges.json" and query.get("api") == ["api"] \
            and query.get("page") == ["1"] and query.get("page_size") == ["48"]:
        return value
    query.setdefault("api", ["api"])
    query.setdefault("page", ["1"])
    query.setdefault("page_size", ["48"])
    user_id = parts[3] if api_path else parts[1]
    query_string = urlencode(query, doseq=True)
    return f"https://www.credly.com/users/{user_id}/badges.json" + (f"?{query_string}" if query_string else "")


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
    existing = {row.get("url"): row for row in read_config().get("sources", [])}
    for row in sources:
        if not isinstance(row, dict):
            raise ValueError("Ogni riga deve contenere un URL.")
        url = str(row.get("url", "")).strip()
        if not url:
            continue
        api_url = normalize_source_url(url)
        credly_url = normalize_credly_url(str(row.get("credlyUrl", "")).strip())
        previous = existing.get(api_url, {})
        cleaned.append({"url": api_url, "credlyUrl": credly_url, "name": previous.get("name", "")})
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
    migrate_legacy_classifications()
    try:
        data = json.loads(CLASSIFICATIONS.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{CLASSIFICATIONS.name} contains invalid or empty JSON: {exc}") from exc
    items = data.get("certifications", [])
    items = [normalize_classification(x) for x in items]
    migrate_transcript_images(items)
    return items


def write_classifications(items):
    CLASSIFICATIONS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=CLASSIFICATIONS.parent, delete=False) as tmp:
        json.dump({"certifications": items}, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
        temp_path = Path(tmp.name)
    temp_path.replace(CLASSIFICATIONS)


def migrate_legacy_classifications():
    """Copy the old config into the certs volume, which may be a different filesystem."""
    if CLASSIFICATIONS.exists() or not LEGACY_CLASSIFICATIONS.exists():
        return
    CLASSIFICATIONS.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=CLASSIFICATIONS.parent, delete=False) as tmp:
        tmp.write(LEGACY_CLASSIFICATIONS.read_bytes())
        temp_path = Path(tmp.name)
    temp_path.replace(CLASSIFICATIONS)
    try:
        LEGACY_CLASSIFICATIONS.unlink()
    except FileNotFoundError:
        pass


def migrate_transcript_images(items):
    """Move any previously cached badge art from candidate JSON into shared classifications."""
    by_name = {item.get("name", ""): item for item in items}
    changed_classes = False
    for cache_file in TRANSCRIPTS_CACHE.glob("*.json"):
        try:
            payload = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        changed_candidate = False
        data = payload.get("data") if isinstance(payload, dict) else None
        for cert in data.get("certs", []) if isinstance(data, dict) else []:
            if not isinstance(cert, dict):
                continue
            name = str(cert.get("name") or cert.get("certificationName") or "").strip()
            image_url = cert.pop("imageUrl", "") or cert.pop("credlyImageUrl", "")
            if image_url:
                changed_candidate = True
                if name in by_name and by_name[name].get("imageUrl") != image_url:
                    by_name[name]["imageUrl"] = image_url
                    changed_classes = True
        if changed_candidate:
            cache_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    if changed_classes:
        write_classifications(items)


def sync_classifications(downloaded):
    """Append unseen credential names, leaving every existing classification intact."""
    migrate_legacy_classifications()
    try:
        original = json.loads(CLASSIFICATIONS.read_text(encoding="utf-8")).get("certifications", [])
        items = [normalize_classification(x) for x in original]
    except (OSError, json.JSONDecodeError):
        original = []
        items = []
    by_name = {x.get("name", ""): x for x in items}
    images_by_name = {}
    for transcript in downloaded:
        images_by_name.update(transcript.get("_certImages", {}))
        for cert in (transcript.get("data") or {}).get("certs", []):
            if not isinstance(cert, dict):
                continue
            name = str(cert.get("name") or cert.get("certificationName") or "").strip()
            image_url = cert.get("imageUrl")
            if name and image_url:
                images_by_name[name] = image_url
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
    for name, image_url in images_by_name.items():
        if name in by_name and by_name[name].get("imageUrl") != image_url:
            by_name[name]["imageUrl"] = image_url
    if added or original != items or not CLASSIFICATIONS.exists():
        write_classifications(items)
    return items, added


def refresh_and_sync():
    sources = read_config().get("sources", [])
    TRANSCRIPTS_CACHE.mkdir(parents=True, exist_ok=True)
    files, saved = [], 0
    updated_sources = []
    for source in sources:
        url, name = source["url"], source.get("name", "")
        try:
            data = fetch_json(url)
            if not isinstance(data, dict):
                raise ValueError("CertMetrics returned an invalid JSON object.")
            name = extract_candidate_name(data)
            credly_url = normalize_credly_url(str(source.get("credlyUrl", "")).strip())
            credly_error = ""
            if credly_url:
                try:
                    credly_data = fetch_credly_badges(credly_url)
                    matched_count = merge_credly_expirations(data, credly_data)
                    if data.get("certs") and not matched_count:
                        credly_error = "No certification names matched the Credly badges."
                    credly_cache_path(credly_url).write_text(
                        json.dumps(credly_data, ensure_ascii=False, indent=2), encoding="utf-8")
                except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                    credly_error = ("Credly ha risposto 401 Unauthorized. L’endpoint API richiede credenziali; "
                                    "l’URL è stato convertito al feed pubblico. Verifica che il profilo e i badge siano pubblici."
                                    if isinstance(exc, HTTPError) and exc.code == 401 else str(exc))
                    cached_credly = credly_cache_path(credly_url)
                    if cached_credly.exists():
                        try:
                            merge_credly_expirations(data, json.loads(cached_credly.read_text(encoding="utf-8")))
                        except (OSError, UnicodeError, json.JSONDecodeError):
                            pass
            # Badge art is shared certification metadata, not candidate transcript data.
            cert_images = {}
            for cert in data.get("certs", []):
                if isinstance(cert, dict) and cert.get("imageUrl"):
                    cert_images[str(cert.get("name") or cert.get("certificationName") or "").strip()] = cert["imageUrl"]
                if isinstance(cert, dict):
                    cert.pop("imageUrl", None)
            cache_file = TRANSCRIPTS_CACHE / safe_filename(name)
            cache_file.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            cached_data = json.loads(cache_file.read_text(encoding="utf-8"))
            item = {"url": url, "credlyUrl": credly_url, "name": name, "file": cache_file.name, "data": cached_data}
            item["_certImages"] = cert_images
            if credly_error:
                item["credlyError"] = credly_error
            files.append(item)
            updated_sources.append({"url": url, "credlyUrl": credly_url, "name": name})
            saved += 1
        except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            files.append({"url": url, "name": name, "message": str(exc), "error": True})
            updated_sources.append(source)
    write_config(updated_sources)
    _, added = sync_classifications(files)
    for item in files:
        item.pop("_certImages", None)
    refreshed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    REFRESH_STATE.write_text(json.dumps({"refreshedAt": refreshed_at}, ensure_ascii=False), encoding="utf-8")
    return {"files": files, "saved": saved, "newNames": added, "refreshedAt": refreshed_at}


def cached_transcripts():
    files, saved = [], 0
    for source in read_config().get("sources", []):
        name = source.get("name", "")
        path = TRANSCRIPTS_CACHE / safe_filename(name) if name else None
        if not path or not path.exists():
            files.append({"url": source["url"], "credlyUrl": source.get("credlyUrl", ""),
                          "name": name or source["url"], "message": "No downloaded data yet. Use Refresh data.", "error": True})
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            files.append({"url": source["url"], "credlyUrl": source.get("credlyUrl", ""),
                          "name": name, "file": path.name, "data": data})
            saved += 1
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            files.append({"url": source["url"], "name": name, "message": str(exc), "error": True})
    try:
        refreshed_at = json.loads(REFRESH_STATE.read_text(encoding="utf-8")).get("refreshedAt", "")
    except (OSError, UnicodeError, json.JSONDecodeError):
        refreshed_at = ""
    return {"files": files, "saved": saved, "refreshedAt": refreshed_at}


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
            except (OSError, ValueError) as exc:
                self.send_json({"error": str(exc)}, 500)
            return
        if path == "/api/classifications":
            try:
                self.send_json({"certifications": read_classifications()})
            except (OSError, ValueError) as exc:
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
                self.send_json(cached_transcripts())
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
        if path not in ("/api/login", "/api/password", "/api/config", "/api/classifications", "/api/refresh"):
            self.send_json({"error": "Endpoint non trovato."}, 404)
            return
        try:
            if path == "/api/refresh":
                payload = {}
            else:
                length = int(self.headers.get("Content-Length", "0"))
                raw_payload = self.rfile.read(length)
                if not raw_payload:
                    raise ValueError("La richiesta non contiene un payload JSON.")
                payload = json.loads(raw_payload.decode("utf-8"))
            if path == "/api/login":
                password = str(payload.get("password", "")) if isinstance(payload, dict) else ""
                if not verify_password(password):
                    self.send_json({"error": "Incorrect password."}, 401)
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
            if path == "/api/refresh":
                self.send_json(refresh_and_sync())
                return
            if path == "/api/config":
                if not self.require_auth():
                    return
                sources = validate_sources(payload)
                write_config(sources)
                refresh_result = refresh_and_sync()
                self.send_json({"sources": read_config().get("sources", []), "refresh": refresh_result, "saved": True})
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
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Webapp: http://{args.host}:{args.port}/")
    print(f"Configurazione: {CONFIG}")
    print(f"Classificazioni: {CLASSIFICATIONS}")
    print(f"Cache JSON: {CACHE}")
    print("I JSON vengono aggiornati solo su richiesta tramite Refresh data.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer arrestato.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
