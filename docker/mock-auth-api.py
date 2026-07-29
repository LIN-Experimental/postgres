#!/usr/bin/env python3
"""
Minimal stand-in for the LIN authentication API, for trying the "lin"
authentication method without a real identity service.

It answers POST requests with the contract described in README-LIN.md: HTTP 200
plus {"authenticated": true} when the credentials match, and 401 otherwise.
Users listed with a role get that role returned, so role mapping can be
exercised too.

    python3 mock-auth-api.py [port]

This is a testing aid.  It has no TLS, no rate limiting and hardcoded
passwords; do not put it anywhere near production.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

TENANT = "empresa-001"

# username -> (password, role to return or None to leave the role alone)
USERS = {
    "alex": ("secreto123", "app_writer"),
    "maria": ("otra456", "app_reader"),
    "sinrol": ("nada789", None),
}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)

        try:
            request = json.loads(raw)
        except ValueError:
            request = {}

        username = request.get("username")
        entry = USERS.get(username)
        ok = (request.get("tenant") == TENANT
              and entry is not None
              and request.get("password") == entry[0])

        body = {"authenticated": ok}
        if ok and entry[1] is not None:
            body["role"] = entry[1]

        print("tenant=%r username=%r -> %s"
              % (request.get("tenant"), username, "accepted" if ok else "rejected"),
              file=sys.stderr, flush=True)

        payload = json.dumps(body).encode()
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass        # the print() above is enough


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print("listening on port %d, tenant %r" % (port, TENANT), file=sys.stderr, flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
