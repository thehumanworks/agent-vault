"""Doppler, through its HTTP API (https://docs.doppler.com/reference/api).

Endpoints used, all under ``DOPPLER_API_HOST`` (default ``https://api.doppler.com``):

* ``GET /v3/configs/config/secret``: one secret's raw value.
* ``GET /v3/configs/config/secrets/download``: the config's secrets for the command,
  as ``doppler run`` passes them.
* ``POST /v3/configs/config/secrets`` with ``change_requests``: a write guarded by
  ``originalValue``, which Doppler applies "only if the provided value matches what's
  found in Doppler". That is the compare-and-set the sync protocol needs.

Auth is ``Authorization: Bearer <token>``, with ``DOPPLER_TOKEN`` or, when it is not set,
the token of ``doppler login`` (``doppler configure get token --plain``). The token is
never put in a URL, an argument list or a message.

Doppler does not document the answer to a failed guard, so a refused write is told apart
from other errors by reading the secret again: if it no longer holds the expected value,
the write lost to another writer (a conflict); if it holds the value just written, the
write went through.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .. import __version__
from ..vault import Snapshot, Vault, VaultError

DEFAULT_API_HOST = "https://api.doppler.com"
TIMEOUT = 15.0
RETRIES = 3
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class _Failure(Exception):
    def __init__(self, status: Optional[int], message: str):
        super().__init__(message)
        self.status = status


def _api_host(value: Optional[str]) -> str:
    host = (value or DEFAULT_API_HOST).rstrip("/")
    parsed = urllib.parse.urlparse(host)
    if parsed.scheme == "https" and parsed.hostname:
        return host
    if parsed.scheme == "http" and parsed.hostname in LOCAL_HOSTS:
        return host  # a stand-in on this machine, for tests
    raise ValueError("DOPPLER_API_HOST must be an https:// URL")


class DopplerVault(Vault):
    kind = "Doppler"
    atomic_write = True

    def __init__(
        self,
        project: str,
        config: str,
        api_host: Optional[str] = None,
        token: Optional[str] = None,
        environ: Optional[Mapping[str, str]] = None,
    ):
        self.project = project
        self.config = config
        env = os.environ if environ is None else environ
        self.api_host = _api_host(api_host or env.get("DOPPLER_API_HOST"))
        self._token = token if token is not None else env.get("DOPPLER_TOKEN") or None
        self._token_looked_up = token is not None or self._token is not None

    @classmethod
    def from_options(cls, options: Mapping[str, str]) -> DopplerVault:
        unknown = sorted(set(options) - {"project", "config"})
        if unknown:
            raise ValueError(f"unknown Doppler option {unknown[0]} (project, config)")
        for option in ("project", "config"):
            if not options.get(option):
                raise ValueError(f"--{option} is required (or use --preset)")
        return cls(options["project"], options["config"])

    @property
    def label(self) -> str:
        return f"{self.project}/{self.config}"

    # -- auth -------------------------------------------------------------------------

    def token(self) -> Optional[str]:
        if not self._token_looked_up:
            self._token_looked_up = True
            self._token = _cli_token()
        return self._token

    def login_problem(self) -> Optional[str]:
        return None if self.token() else "no Doppler login"

    # -- requests ---------------------------------------------------------------------

    def _request(self, method: str, path: str, query: Dict[str, str], body: Any = None) -> Any:
        token = self.token()
        if not token:
            raise VaultError("no Doppler login")
        url = f"{self.api_host}{path}?{urllib.parse.urlencode(query)}"
        data = None if body is None else json.dumps(body).encode()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"agent-vault/{__version__}",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        delay = 0.5
        for attempt in range(RETRIES):
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                    payload = response.read()
                return json.loads(payload) if payload else {}
            except urllib.error.HTTPError as e:
                failure = _Failure(e.code, _messages(e))
                retry_after = e.headers.get("Retry-After") if e.headers else None
                e.close()
                if e.code != 429 and e.code < 500:
                    raise failure from None
                if retry_after and retry_after.isdigit():
                    delay = min(float(retry_after), 5.0)
            except (urllib.error.URLError, OSError, ValueError) as e:
                reason = getattr(e, "reason", None) or e.__class__.__name__
                failure = _Failure(None, f"cannot reach Doppler ({reason})")
            if attempt + 1 < RETRIES:
                time.sleep(delay)
                delay *= 3
        raise failure

    def _scope(self, **extra: str) -> Dict[str, str]:
        return dict(project=self.project, config=self.config, **extra)

    # -- Vault ------------------------------------------------------------------------

    def environment(self, only: Optional[Sequence[str]] = None) -> Dict[str, str]:
        query = self._scope(format="json")
        if only:
            query["secrets"] = ",".join(only)
        try:
            secrets = self._request("GET", "/v3/configs/config/secrets/download", query)
        except _Failure as e:
            raise VaultError(str(e)) from None
        if not isinstance(secrets, dict):
            raise VaultError("Doppler returned no secrets object")
        wanted = set(only) if only else None
        return {
            str(name): value if isinstance(value, str) else json.dumps(value)
            for name, value in secrets.items()
            if wanted is None or name in wanted
        }

    def read(self, name: str) -> Snapshot:
        try:
            data = self._request("GET", "/v3/configs/config/secret", self._scope(name=name))
        except _Failure as e:
            if e.status == 404:
                return Snapshot(None, None)
            raise VaultError(str(e)) from None
        try:
            raw = data["value"]["raw"]
        except (KeyError, TypeError):
            raise VaultError("Doppler returned a secret without a value") from None
        if raw is None:
            return Snapshot(None, None)
        return Snapshot(str(raw), str(raw))

    def write(self, name: str, value: str, expected: Snapshot) -> bool:
        change: Dict[str, Any] = {
            "originalName": name if expected.value is not None else None,
            "name": name,
            "value": value,
        }
        if expected.value is not None:
            change["originalValue"] = expected.value
        body = {"project": self.project, "config": self.config, "change_requests": [change]}
        try:
            self._request("POST", "/v3/configs/config/secrets", {}, body)
        except _Failure as e:
            # Refused or lost on the way: what the secret holds now tells which.
            return self._settle(name, value, expected, str(e))
        if expected.value is None:
            # A new secret has no value to guard on; a writer that created it at the same
            # moment would have replaced it. Check, and merge again if so.
            return self.read(name).value == value
        return True

    def _settle(self, name: str, value: str, expected: Snapshot, why: str) -> bool:
        try:
            now = self.read(name).value
        except VaultError:
            raise VaultError(why) from None
        if now == value:
            return True
        if now != expected.value:
            return False
        raise VaultError(why)


def _messages(error: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(error.read() or b"{}")
    except (ValueError, OSError):
        body = {}
    messages: List[str] = []
    if isinstance(body, dict) and isinstance(body.get("messages"), list):
        messages = [str(m) for m in body["messages"]]
    detail = "; ".join(messages) or error.reason or "error"
    return f"Doppler answered {error.code}: {detail}"


def _cli_token() -> Optional[str]:
    """The token of ``doppler login``, when the doppler CLI is installed."""
    doppler = shutil.which("doppler")
    if not doppler:
        return None
    try:
        result = subprocess.run(
            [doppler, "configure", "get", "token", "--plain"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    token = result.stdout.decode(errors="replace").strip()
    return token if result.returncode == 0 and token else None
