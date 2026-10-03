#!/usr/bin/env python3
"""Loopback-only positive controls for four bounded web detectors.

The SSRF route simulates backend network errors; it never performs an outbound
request. All behavior is deterministic and intended only for scanner testing.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


HOST = "127.0.0.1"
PORT = 8000


class Handler(BaseHTTPRequestHandler):
    server_version = "ReconPositiveControls/1.0"

    def _send(self, status, body, content_type="text/plain; charset=utf-8", headers=None):
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if parsed.path == "/":
            return self._send(
                200,
                '<!doctype html><title>Positive Controls</title><script src="/app.js"></script>',
                "text/html; charset=utf-8",
            )

        if parsed.path == "/app.js":
            body = """fetch('/xss?q=baseline');
fetch('/view?file=index');
fetch('/fetch?url=original');
fetch('/account');"""
            return self._send(200, body, "application/javascript")

        if parsed.path == "/xss":
            value = query.get("q", [""])[0]
            return self._send(200, value, "text/html; charset=utf-8")

        if parsed.path == "/view":
            value = query.get("file", [""])[0]
            if "etc/passwd" in value:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash")
            if value == "index":
                return self._send(200, "baseline")
            return self._send(404, "missing")

        if parsed.path == "/account":
            origin = self.headers.get("Origin")
            headers = []
            if origin:
                headers = [
                    ("Access-Control-Allow-Origin", origin),
                    ("Access-Control-Allow-Credentials", "true"),
                ]
            return self._send(200, '{"account":"control"}', "application/json", headers)

        if parsed.path == "/fetch":
            value = query.get("url", [""])[0]
            if "192.0.2.1" in value:
                return self._send(502, "connect timeout to reserved address")
            if "127.0.0.1" in value:
                return self._send(502, "connection refused for loopback")
            return self._send(200, "baseline")

        return self._send(404, "not found")

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
