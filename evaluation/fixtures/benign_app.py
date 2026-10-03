#!/usr/bin/env python3
"""Small loopback-only benign control with security-looking endpoint names."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import json


HOST = "127.0.0.1"
PORT = 8000


class Handler(BaseHTTPRequestHandler):
    server_version = "BenignControl/1.0"

    def _send(self, status, body, content_type="application/json", headers=None):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/":
            body = """<!doctype html><title>Benign Control</title>
<a href="/admin">Admin</a><a href="/login">Login</a>
<script src="/app.js"></script>"""
            return self._send(200, body, "text/html; charset=utf-8")

        if parsed.path == "/app.js":
            body = """fetch('/rest/products/search?q=sample');
fetch('/redirect?to=/dashboard');
fetch('/api/profile?url=https://example.invalid/avatar.png');
fetch('/files/view?path=manual.txt');"""
            return self._send(200, body, "application/javascript")

        if parsed.path == "/rest/products/search":
            term = query.get("q", [""])[0]
            return self._send(200, json.dumps({"query_length": len(term), "items": []}))

        if parsed.path == "/redirect":
            destination = query.get("to", [""])[0]
            if destination.startswith("/") and not destination.startswith("//"):
                return self._send(302, "", headers=[("Location", destination)])
            return self._send(400, json.dumps({"error": "external redirects are blocked"}))

        if parsed.path == "/dashboard":
            return self._send(200, "<title>Dashboard</title>", "text/html")

        if parsed.path in ("/admin", "/login"):
            return self._send(403, json.dumps({"error": "access denied"}))

        if parsed.path == "/api/profile":
            return self._send(200, json.dumps({"avatar": "default.png"}))

        if parsed.path == "/files/view":
            return self._send(200, json.dumps({"file": "public manual unavailable"}))

        return self._send(404, json.dumps({"error": "not found"}))

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
