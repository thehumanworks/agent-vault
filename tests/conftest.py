from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

import pytest

from fake_doppler import TOKEN, FakeDoppler

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))


@pytest.fixture
def doppler() -> Iterator[FakeDoppler]:
    fake = FakeDoppler().start()
    fake.put("app", "dev", {"API_KEY": "key-1", "OTHER": "other-1"})
    fake.put("agents", "pi", {})
    fake.put("agents", "codex", {})
    yield fake
    fake.stop()


@pytest.fixture
def home(tmp_path: Path) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    return path


def base_env(home: Path, doppler: Optional[FakeDoppler]) -> Dict[str, str]:
    """A clean environment: a fresh HOME, the fake Doppler, and no real Doppler login."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("DOPPLER_", "AGENT_VAULT_", "PI_", "CODEX_", "XDG_"))
    }
    env.update(
        HOME=str(home),
        PYTHONPATH=str(SRC),
        NO_PROXY="127.0.0.1,localhost",
        no_proxy="127.0.0.1,localhost",
    )
    for proxy in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        env.pop(proxy, None)
    if doppler is not None:
        env.update(DOPPLER_TOKEN=TOKEN, DOPPLER_API_HOST=doppler.url)
    return env


class Avlt:
    """Runs ``python -m agent_vault`` as a separate process, as a user would."""

    def __init__(self, home: Path, doppler: Optional[FakeDoppler]):
        self.home = home
        self.env = base_env(home, doppler)

    def __call__(
        self,
        *args: str,
        env: Optional[Dict[str, str]] = None,
        timeout: float = 60,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        full_env = dict(self.env)
        full_env.update(env or {})
        result = subprocess.run(
            [sys.executable, "-m", "agent_vault", *args],
            env=full_env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and result.returncode != 0:
            raise AssertionError(f"avlt {args} failed: {result.stderr}")
        return result

    def popen(self, *args: str, env: Optional[Dict[str, str]] = None) -> subprocess.Popen:
        full_env = dict(self.env)
        full_env.update(env or {})
        return subprocess.Popen(
            [sys.executable, "-m", "agent_vault", *args],
            env=full_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )


@pytest.fixture
def avlt(home: Path, doppler: FakeDoppler) -> Avlt:
    return Avlt(home, doppler)


def py(code: str) -> List[str]:
    """A command that runs Python ``code``: the stand-in for the program avlt wraps."""
    return [sys.executable, "-c", code]


PRELUDE = """
import json, os, sys, time, pathlib, urllib.parse, urllib.request
H = pathlib.Path(os.environ["HOME"])
API, TOK = os.environ.get("DOPPLER_API_HOST"), os.environ.get("DOPPLER_TOKEN")
def call(method, path, query=None, body=None):
    url = API + path + "?" + urllib.parse.urlencode(query or {})
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"Authorization": "Bearer " + TOK, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())
def remote(project, config, name):
    raw = call("GET", "/v3/configs/config/secret", dict(project=project, config=config, name=name))["value"]["raw"]
    return json.loads(raw)
def remote_set(project, config, name, doc):
    change = dict(originalName=name, name=name, value=json.dumps(doc))
    call("POST", "/v3/configs/config/secrets", body=dict(project=project, config=config, change_requests=[change]))
def doppler_down(value):
    call("POST", "/_fake/down", {"value": "1" if value else "0"}, body={})
def load(p):
    return json.loads(pathlib.Path(p).read_text())
def save(p, v):
    p = pathlib.Path(p); t = p.with_name(p.name + ".new"); t.write_text(json.dumps(v)); os.replace(t, p)
def until(f, expected, timeout=15):
    end = time.time() + timeout
    got = None
    while time.time() < end:
        try:
            got = f()
        except Exception:
            got = None
        if got == expected:
            return got
        time.sleep(0.1)
    return got
"""


def program(body: str) -> List[str]:
    return py(PRELUDE + body)


def compact(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def wait_for(predicate: Callable[[], bool], timeout: float = 15) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.1)
    return False
