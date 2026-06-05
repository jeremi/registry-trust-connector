#!/usr/bin/env python3
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def bind_addr():
    raw = os.environ.get("REGISTRY_RELAY_BIND", "0.0.0.0:8080")
    host, _, port = raw.rpartition(":")
    return host or "0.0.0.0", int(port or "8080")


class MockRelay(BaseHTTPRequestHandler):
    server_version = "registry-relay-mock/0.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self.respond(200, {"ok": True})
            return

        if parsed.path != "/v1/datasets/social_registry/entities/individual/records":
            self.respond(404, {"error": "not_found"})
            return

        limit = parse_qs(parsed.query).get("limit", ["10"])[0]
        self.respond(
            200,
            {
                "dataset": "social_registry",
                "entity": "individual",
                "limit": limit,
                "records": [
                    {
                        "id": "person-demo-001",
                        "household_id": "household-demo-001",
                        "municipality_code": "DEMO-001",
                    }
                ],
                "received": self.received_metadata(),
            },
        )

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/dci/social/registry/sync/search":
            self.respond(404, {"error": "not_found"})
            return

        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self.respond(400, {"error": "invalid_json"})
            return

        self.respond(
            200,
            {
                "matches": [
                    {
                        "person_id": "person-demo-001",
                        "matched": True,
                        "requested_national_id": request.get("national_id"),
                    }
                ],
                "received": self.received_metadata(),
            },
        )

    def log_message(self, fmt, *args):
        return

    def respond(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def received_metadata(self):
        authorization = self.headers.get("authorization", "")
        authorization_scheme = authorization.split(" ", 1)[0] if authorization else None
        connector_private_headers = [
            name.lower()
            for name in self.headers.keys()
            if name.lower().startswith("x-registry-connector-")
            and name.lower() != "x-registry-connector-client-identity"
        ]
        return {
            "authorization_received": bool(authorization),
            "authorization_scheme": authorization_scheme,
            "cookie_received": "cookie" in self.headers,
            "data_purpose": self.headers.get("data-purpose"),
            "request_id_received": bool(self.headers.get("x-request-id")),
            "connector_client_identity": self.headers.get(
                "x-registry-connector-client-identity"
            ),
            "connector_private_headers": sorted(connector_private_headers),
        }


if __name__ == "__main__":
    server = ThreadingHTTPServer(bind_addr(), MockRelay)
    print(f"mock relay listening on {server.server_address[0]}:{server.server_address[1]}")
    server.serve_forever()
