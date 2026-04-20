import json
import ssl
import socket
import time
from datetime import datetime, timezone
from urllib.parse import urlparse
import re

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Vercel serverless handler ─────────────────────────────────────────────────

def handler(request):
    """Vercel Python serverless function entry point."""
    from http.server import BaseHTTPRequestHandler
    import urllib.parse

    if request.method == "OPTIONS":
        return Response("", 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        })

    if request.method != "POST":
        return Response(json.dumps({"error": "POST only"}), 405, cors_headers())

    try:
        body = request.body
        if isinstance(body, bytes):
            body = body.decode()
        data = json.loads(body)
        urls = data.get("urls", [])
        if not urls:
            return Response(json.dumps({"error": "No URLs provided"}), 400, cors_headers())

        # Limit to 10 per request
        urls = urls[:10]
        results = [scan_url(u) for u in urls]
        return Response(json.dumps({"results": results}), 200, cors_headers())

    except Exception as e:
        return Response(json.dumps({"error": str(e)}), 500, cors_headers())


def cors_headers():
    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
    }


class Response:
    def __init__(self, body, status=200, headers=None):
        self.body = body
        self.status_code = status
        self.headers = headers or {}


# ── URL validation ────────────────────────────────────────────────────────────

_URL_RE = re.compile(
    r"^https?://([\w\-]+\.)+[\w\-]{2,}(:\d{1,5})?(/.*)?$",
    re.IGNORECASE,
)

def validate_url(raw: str):
    raw = raw.strip()
    if not raw:
        return False, raw, "Empty URL"
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        return False, raw, f"Unsupported scheme '{parsed.scheme}'"
    if not parsed.netloc:
        return False, raw, "Missing host"
    if not _URL_RE.match(raw):
        return False, raw, "Malformed URL"
    return True, raw, None


# ── Security headers audit ────────────────────────────────────────────────────

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


# ── Core scanner ──────────────────────────────────────────────────────────────

def scan_url(raw_url: str) -> dict:
    result = {
        "url": raw_url,
        "valid": False,
        "status_code": None,
        "final_url": None,
        "redirect_chain": [],
        "response_time_ms": None,
        "ssl_valid": None,
        "ssl_days_left": None,
        "ssl_issuer": None,
        "missing_headers": [],
        "present_headers": [],
        "verdict": "ERROR",
        "error": None,
    }

    valid, normalised, err = validate_url(raw_url)
    if not valid:
        result["error"] = err
        return result

    result["valid"] = True
    result["url"] = normalised

    try:
        _http_probe(result)
        if result["final_url"] and result["final_url"].startswith("https://"):
            _ssl_check(result)
        _classify_verdict(result)
    except Exception as e:
        result["error"] = str(e)
        result["verdict"] = "ERROR"

    return result


def _http_probe(result: dict):
    if not HAS_REQUESTS:
        raise RuntimeError("requests library not available")

    session = req_lib.Session()
    session.headers["User-Agent"] = "URLRecon/1.0 (security-scanner)"

    start = time.monotonic()
    resp = session.get(result["url"], timeout=8, allow_redirects=True)
    elapsed = (time.monotonic() - start) * 1000

    result["status_code"] = resp.status_code
    result["final_url"] = resp.url
    result["response_time_ms"] = round(elapsed, 1)
    result["redirect_chain"] = [r.url for r in resp.history]

    headers_lower = {k.lower() for k in resp.headers}
    for h in SECURITY_HEADERS:
        if h.lower() in headers_lower:
            result["present_headers"].append(h)
        else:
            result["missing_headers"].append(h)


def _ssl_check(result: dict):
    host = urlparse(result["final_url"]).hostname
    port = urlparse(result["final_url"]).port or 443

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            expire_dt = expire_dt.replace(tzinfo=timezone.utc)
            days_left = (expire_dt - datetime.now(timezone.utc)).days
            result["ssl_days_left"] = days_left
            result["ssl_valid"] = days_left > 0

        issuer_pairs = dict(x[0] for x in cert.get("issuer", []))
        result["ssl_issuer"] = issuer_pairs.get("organizationName", "Unknown")

    except ssl.SSLCertVerificationError as e:
        result["ssl_valid"] = False
        result["error"] = f"SSL error: {e}"


def _classify_verdict(result: dict):
    score = 0
    if result["status_code"] is None:
        result["verdict"] = "ERROR"
        return
    if result["status_code"] >= 500:
        score += 2
    elif result["status_code"] >= 400:
        score += 1

    if result["ssl_valid"] is False:
        score += 3
    elif result["ssl_days_left"] is not None and result["ssl_days_left"] < 30:
        score += 2

    score += len(result["missing_headers"])

    if result["redirect_chain"]:
        orig = urlparse(result["url"]).netloc
        final = urlparse(result["final_url"]).netloc
        if orig and final and orig != final:
            score += 2

    if score == 0:
        result["verdict"] = "CLEAN"
    elif score <= 3:
        result["verdict"] = "WARNING"
    else:
        result["verdict"] = "CRITICAL"
