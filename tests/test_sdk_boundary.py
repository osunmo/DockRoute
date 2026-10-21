"""Exercise the real official SDK against a local controlled HTTP Engine API double."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import docker

from dockroute.compose import select_project
from dockroute.diagnostics import diagnose
from dockroute.discovery import discover
from dockroute.docker import Inspector


def test_official_sdk_inspection_and_inference_use_only_read_requests(tmp_path):
    labels = {
        "com.docker.compose.project": "shop",
        "com.docker.compose.service": "app",
        "com.docker.compose.project.working_dir": str(tmp_path),
    }
    seen = []

    class Engine(BaseHTTPRequestHandler):
        def do_GET(self):
            url = urlsplit(self.path)
            seen.append(url.path)
            if url.path.endswith("/containers/json"):
                filters = json.loads(parse_qs(url.query)["filters"][0])
                assert "com.docker.compose.service" in filters["label"]
                data = [
                    {"Id": "app-id", "Names": ["/shop-app-1"], "Labels": labels, "State": "running"}
                ]
            elif url.path.endswith("/containers/app-id/json"):
                data = {
                    "Id": "app-id",
                    "Name": "/shop-app-1",
                    "Config": {"Labels": labels, "Env": ["API_URL=http://api:8000"]},
                    "State": {"Status": "running"},
                    "HostConfig": {"NetworkMode": "shop_default"},
                    "NetworkSettings": {
                        "Networks": {
                            "shop_default": {
                                "NetworkID": "net",
                                "Aliases": ["app"],
                                "IPAddress": "172.20.0.2",
                            }
                        }
                    },
                }
            else:
                self.send_error(404)
                return
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Engine)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = docker.DockerClient(
        base_url=f"http://127.0.0.1:{server.server_port}", version="1.44", timeout=3
    )
    try:
        inspector = Inspector(client)
        assert select_project(inspector.identities(), cwd=Path(tmp_path)) == "shop"
        snapshot = inspector.snapshot("shop")
        edge = discover(snapshot)[0]
        assert edge.source == "app" and edge.host == "api" and edge.port == 8000
        assert diagnose(edge, snapshot).code == "UNKNOWN"
        assert all(path.startswith("/v1.44/containers/") for path in seen)
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
