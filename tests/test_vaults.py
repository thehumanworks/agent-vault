"""The adapters on their own: the Doppler HTTP adapter against the fake, and the file vault."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from agent_vault.vault import Snapshot, Vault, VaultError, adapter, open_vault
from agent_vault.vaults.doppler import DopplerVault, _api_host
from agent_vault.vaults.file import FileVault
from fake_doppler import TOKEN, FakeDoppler


@pytest.fixture(autouse=True)
def no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    for proxy in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(proxy, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")


def vault(doppler: FakeDoppler, project: str = "app", config: str = "dev") -> DopplerVault:
    return DopplerVault(project, config, api_host=doppler.url, token=TOKEN)


def test_read_and_environment(doppler: FakeDoppler) -> None:
    v = vault(doppler)
    assert v.read("API_KEY") == Snapshot("key-1", "key-1")
    assert v.read("MISSING") == Snapshot(None, None)
    env = v.environment()
    assert env["API_KEY"] == "key-1" and env["DOPPLER_CONFIG"] == "dev"
    assert v.environment(["API_KEY"]) == {"API_KEY": "key-1"}
    assert "secrets=API_KEY" in doppler.log[-1]


def test_write_is_guarded(doppler: FakeDoppler) -> None:
    v = vault(doppler)
    seen = v.read("API_KEY")
    doppler.set("app", "dev", "API_KEY", "key-2")  # another writer
    assert v.write("API_KEY", "key-3", seen) is False
    assert doppler.get("app", "dev", "API_KEY") == "key-2"
    assert v.write("API_KEY", "key-3", v.read("API_KEY")) is True
    assert doppler.get("app", "dev", "API_KEY") == "key-3"
    assert doppler.bodies[-1] == {
        "project": "app",
        "config": "dev",
        "change_requests": [
            {"originalName": "API_KEY", "name": "API_KEY", "value": "key-3", "originalValue": "key-2"}
        ],
    }


def test_creating_a_secret_checks_that_it_won(doppler: FakeDoppler) -> None:
    v = vault(doppler)
    absent = v.read("NEW")
    assert v.write("NEW", "mine", absent) is True
    assert doppler.bodies[-1]["change_requests"][0]["originalName"] is None
    # A creator that raced another one: Doppler took the other value.
    doppler.before_write = lambda fake: None
    other_won = Snapshot(None, None)
    doppler.create_overwrites = False
    assert v.write("NEW", "late", other_won) is False
    assert doppler.get("app", "dev", "NEW") == "mine"


def test_errors_and_retries(doppler: FakeDoppler) -> None:
    v = vault(doppler)
    doppler.down = True
    with pytest.raises(VaultError, match="Doppler answered 503"):
        v.read("API_KEY")
    doppler.down = False
    timer = threading.Timer(0.3, lambda: setattr(doppler, "down", False))
    doppler.down = True
    timer.start()
    assert v.read("API_KEY").value == "key-1", "a short outage is retried"
    with pytest.raises(VaultError):
        DopplerVault("app", "dev", api_host=doppler.url, token="wrong").read("API_KEY")


def test_a_write_whose_answer_was_lost_is_settled_by_reading(doppler: FakeDoppler) -> None:
    v = vault(doppler)
    seen = v.read("API_KEY")
    doppler.down = True  # the write fails; the value is unchanged, so it is an error
    with pytest.raises(VaultError):
        v.write("API_KEY", "key-9", seen)
    doppler.down = False


def test_login(doppler: FakeDoppler, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOPPLER_TOKEN", raising=False)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert DopplerVault("a", "b", api_host=doppler.url).login_problem() == "no Doppler login"
    cli = tmp_path / "doppler"
    cli.write_text(f"#!/bin/sh\n[ \"$*\" = 'configure get token --plain' ] && echo {TOKEN}\n")
    cli.chmod(0o755)
    v = DopplerVault("app", "dev", api_host=doppler.url)
    assert v.login_problem() is None
    assert v.read("API_KEY").value == "key-1"


def test_api_host() -> None:
    assert _api_host(None) == "https://api.doppler.com"
    assert _api_host("https://doppler.example/") == "https://doppler.example"
    assert _api_host("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    with pytest.raises(ValueError):
        _api_host("http://doppler.example")


def test_options() -> None:
    with pytest.raises(ValueError, match="--project is required"):
        DopplerVault.from_options({"config": "x"})
    with pytest.raises(ValueError, match="unknown Doppler option path"):
        DopplerVault.from_options({"project": "a", "config": "b", "path": "x"})
    assert isinstance(open_vault("file", {"path": "/tmp/x.json"}), FileVault)
    with pytest.raises(ValueError, match="unknown vault"):
        adapter("nope")


def test_file_vault(tmp_path: Path) -> None:
    v = FileVault(tmp_path / "vault.json")
    assert v.read("A") == Snapshot(None, None)
    assert v.write("A", "1", v.read("A"))
    stale = v.read("A")
    assert v.write("A", "2", stale)
    assert not v.write("A", "3", stale)
    assert v.read("A").value == "2"
    assert v.environment() == {"A": "2"}
    assert json.loads((tmp_path / "vault.json").read_text()) == {"A": "2"}
    assert oct(os.stat(tmp_path / "vault.json").st_mode & 0o777) == "0o600"


def test_the_core_imports_no_adapter() -> None:
    """AC-3: the orchestration knows adapters only through the registry."""
    import ast

    src = Path(__file__).resolve().parent.parent / "src" / "agent_vault"
    for module in ("sync.py", "cli.py", "merge.py", "localfile.py", "vault.py", "presets.py"):
        tree = ast.parse((src / module).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert "vaults" not in node.module, f"{module} imports {node.module}"
            if isinstance(node, ast.Import):
                assert all("vaults" not in alias.name for alias in node.names)


def test_a_third_party_adapter_plugs_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An adapter from another package, found through its entry point."""
    package = tmp_path / "site"
    (package / "memvault").mkdir(parents=True)
    (package / "memvault" / "__init__.py").write_text(
        "from agent_vault.vaults.file import FileVault\nclass MemVault(FileVault):\n    kind = 'memory'\n"
    )
    dist = package / "memvault-1.0.dist-info"
    dist.mkdir()
    (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: memvault\nVersion: 1.0\n")
    (dist / "entry_points.txt").write_text("[agent_vault.vaults]\nmemory = memvault:MemVault\n")
    monkeypatch.syspath_prepend(str(package))
    cls = adapter("memory")
    assert issubclass(cls, Vault) and cls.kind == "memory"
