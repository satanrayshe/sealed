"""Local two-pane app: python -m sealed app

Standard library only (http.server). It listens on 127.0.0.1 and nowhere
else, answers only requests whose Host header names that address (so a
web page elsewhere cannot reach it by DNS rebinding), refuses cross-site
POSTs, caps request bodies at 5 MB, and serves three static files under a
strict Content-Security-Policy: no inline script or style, no third-party
origin, no eval. The page builds every element with textContent.

The one data endpoint returns the same report as `explain()`, plus a seal
check per alert: the model-input SHA-256 of a clean twin, which is the
same alert without its entity fields (username, user agent, URL, host) and
extra fields. Unrecognised signal strings stay in the twin: only their number
reaches the model.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .contract import MAX_INPUT_BYTES
from .explain import explain

WEB = Path(__file__).with_name("web")
SAMPLES = Path(__file__).with_name("samples")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
SAMPLE_FILES = {"track_example": "track_example.json", "attacked_username": "attacked_username.json",
                "edge_cases": "edge_cases.json"}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
TRUSTED_FIELDS = ("id", "severity", "signals", "action")


@dataclass
class Response:
    status: int
    content_type: str
    body: bytes
    headers: dict = field(default_factory=lambda: dict(SECURITY_HEADERS))


def _text(status: int, message: str) -> Response:
    return Response(status, "text/plain; charset=utf-8", message.encode("ascii"))


def _json(payload: object) -> Response:
    text = json.dumps(payload, ensure_ascii=True)
    # Never let "<", ">" or "&" appear raw, even inside JSON strings.
    text = text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return Response(200, "application/json; charset=utf-8", text.encode("ascii"))


def clean_twin(alert: dict) -> dict:
    """The alert without its entity and extra fields: only id, severity, signals and action stay. Unrecognised
    signal strings stay too; only their number reaches the model, so the hash is still comparable."""
    return {key: alert[key] for key in TRUSTED_FIELDS if key in alert}


def explain_with_seal_checks(body: bytes) -> dict:
    report = explain(body)
    checks = []
    if report["input"]["status"] == "ok":
        alerts = json.loads(body.decode("utf-8-sig"))["alerts"]  # already validated by explain()
        for result in report["results"]:
            if result["status"] != "explained":
                continue
            twin = explain(json.dumps({"alerts": [clean_twin(alerts[result["index"]])]}))["results"][0]
            twin_hash = twin["model_input"]["sha256"] if twin["status"] == "explained" else None
            checks.append({"index": result["index"], "clean_twin_sha256": twin_hash,
                           "identical": twin_hash == result["model_input"]["sha256"]})
    return {"report": report, "seal_checks": checks}


def handle(method: str, target: str, headers, body: bytes | None, port: int) -> Response:
    """Answer one request. Pure function of its inputs, so it can be tested without a socket."""
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    if headers.get("Host", "") not in allowed_hosts:
        return _text(403, "This app only answers requests addressed to 127.0.0.1.")
    path = urlsplit(target).path
    if method == "GET":
        if path in STATIC:
            name, content_type = STATIC[path]
            return Response(200, content_type, (WEB / name).read_bytes())
        if path == "/api/samples":
            return _json({key: (SAMPLES / name).read_text(encoding="utf-8") for key, name in SAMPLE_FILES.items()})
        return _text(404, "Not found.")
    if method == "POST" and path == "/api/explain":
        origin = headers.get("Origin")
        if origin is not None and origin not in {f"http://{host}" for host in allowed_hosts}:
            return _text(403, "Cross-site requests are refused.")
        if not headers.get("Content-Type", "").startswith("application/json"):
            return _text(415, "Send the alert document as application/json.")
        return _json(explain_with_seal_checks(body or b""))
    return _text(405, "Method not allowed.")


class Handler(BaseHTTPRequestHandler):
    server_version = "sealed-app"
    sys_version = ""

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        for name, value in response.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        self.wfile.write(response.body)

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        self._send(handle("GET", self.path, self.headers, None, self.server.server_port))

    def do_POST(self) -> None:  # noqa: N802
        length = self.headers.get("Content-Length", "")
        if not length.isdigit():
            self.close_connection = True
            return self._send(_text(411, "A Content-Length header is required."))
        if int(length) > MAX_INPUT_BYTES:
            self.close_connection = True  # the body is never read
            return self._send(_text(413, f"Request bodies are limited to {MAX_INPUT_BYTES} bytes."))
        body = self.rfile.read(int(length))
        self._send(handle("POST", self.path, self.headers, body, self.server.server_port))

    def log_message(self, format: str, *args) -> None:  # requests are not logged
        return


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve(port: int = 8765) -> None:
    server = make_server(port)
    print(f"Sealed app on http://127.0.0.1:{server.server_port}/ (local only; Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def start_in_thread(port: int = 0) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """For tests and screenshots: a server on a free local port, in a daemon thread."""
    server = make_server(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
