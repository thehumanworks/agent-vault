"""A stand-in for Doppler's HTTP API, for the tests: only the calls agent-vault makes.

It enforces ``change_requests[].originalValue`` as Doppler documents it (the change is
applied only if the stored value matches) and logs every request line, so a test can
check that no secret value ever appears in a URL. Nothing here talks to Doppler.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

TOKEN = "dp.test.token"

Scope = Tuple[str, str]


class FakeDoppler:
    def __init__(self) -> None:
        self.configs: Dict[Scope, Dict[str, str]] = {}
        self.lock = threading.Lock()
        self.log: List[str] = []
        self.bodies: List[Dict[str, Any]] = []
        self.down = False
        """Every request fails with 503."""
        self.create_overwrites = True
        """A change without originalName replaces an existing secret (the pessimistic
        reading of Doppler's docs, which do not say)."""
        self.before_write: Optional[Callable[[FakeDoppler], None]] = None
        """Called once, just before the next write is applied: a concurrent writer."""
        self.writes = 0
        self.refused = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> FakeDoppler:
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    # -- test helpers -------------------------------------------------------------------

    def put(self, project: str, config: str, secrets: Dict[str, Any]) -> None:
        with self.lock:
            self.configs[(project, config)] = {
                k: v if isinstance(v, str) else json.dumps(v) for k, v in secrets.items()
            }

    def remove_config(self, project: str, config: str) -> Dict[str, str]:
        with self.lock:
            return self.configs.pop((project, config))

    def get(self, project: str, config: str, name: str) -> Optional[str]:
        with self.lock:
            return self.configs.get((project, config), {}).get(name)

    def doc(self, project: str, config: str, name: str) -> Any:
        value = self.get(project, config, name)
        return None if value is None else json.loads(value)

    def set(self, project: str, config: str, name: str, value: str) -> None:
        with self.lock:
            self.configs[(project, config)][name] = value

    # -- the server ---------------------------------------------------------------------

    def _handler(self) -> type:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _send(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _fail(self, status: int, message: str) -> None:
                self._send(status, {"messages": [message], "success": False})

            def _start(self) -> Optional[Tuple[str, Dict[str, str]]]:
                fake.log.append(f"{self.command} {self.path}")
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self._fail(401, "Invalid Auth token")
                    return None
                url = urllib.parse.urlparse(self.path)
                if url.path == "/_fake/down":  # test control, not part of Doppler's API
                    fake.down = urllib.parse.parse_qs(url.query).get("value") == ["1"]
                    self._send(200, {"down": fake.down})
                    return None
                if fake.down:
                    self._fail(503, "Service Unavailable")
                    return None
                query = {k: v[-1] for k, v in urllib.parse.parse_qs(url.query).items()}
                return url.path, query

            def _config(self, project: Optional[str], config: Optional[str]) -> Optional[Dict[str, str]]:
                secrets = fake.configs.get((project or "", config or ""))
                if secrets is None:
                    self._fail(404, "Could not find requested config")
                return secrets

            def do_GET(self) -> None:
                started = self._start()
                if started is None:
                    return
                path, query = started
                with fake.lock:
                    secrets = self._config(query.get("project"), query.get("config"))
                    if secrets is None:
                        return
                    if path == "/v3/configs/config/secret":
                        name = query.get("name", "")
                        if name not in secrets:
                            self._fail(404, "Could not find requested secret")
                            return
                        value = secrets[name]
                        self._send(
                            200, {"name": name, "value": {"raw": value, "computed": value, "note": ""}}
                        )
                    elif path == "/v3/configs/config/secrets/download":
                        only = [s for s in query.get("secrets", "").split(",") if s]
                        if only:
                            out = {k: v for k, v in secrets.items() if k in only}
                        else:
                            out = dict(secrets)
                            out.update(
                                DOPPLER_PROJECT=query["project"],
                                DOPPLER_CONFIG=query["config"],
                                DOPPLER_ENVIRONMENT=query["config"],
                            )
                        self._send(200, out)
                    else:
                        self._fail(404, "Not found")

            def do_POST(self) -> None:
                started = self._start()
                if started is None:
                    return
                path, _ = started
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                fake.bodies.append(body)
                if path != "/v3/configs/config/secrets":
                    self._fail(404, "Not found")
                    return
                hook, fake.before_write = fake.before_write, None
                if hook is not None:
                    hook(fake)
                with fake.lock:
                    secrets = self._config(body.get("project"), body.get("config"))
                    if secrets is None:
                        return
                    changes = body.get("change_requests")
                    if not isinstance(changes, list) or "secrets" in body:
                        self._fail(400, "Either secrets or change_requests must be specified")
                        return
                    for change in changes:
                        name = change["name"]
                        if "originalValue" in change and secrets.get(name) != change["originalValue"]:
                            fake.refused += 1
                            self._fail(400, "The secret's value does not match originalValue")
                            return
                        if (
                            change.get("originalName") is None
                            and name in secrets
                            and not fake.create_overwrites
                        ):
                            fake.refused += 1
                            self._fail(400, "A secret with this name already exists")
                            return
                    for change in changes:
                        secrets[change["name"]] = change["value"]
                    fake.writes += 1
                    self._send(200, {"secrets": {c["name"]: {"raw": c["value"]} for c in changes}})

        return Handler
