"""Built-in settings for known tools, as in doppler-nix's ``--preset``.

Options given on the command line win over a preset's.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Optional


@dataclass(frozen=True)
class Preset:
    name: str
    program: str
    vault: str
    vault_options: Dict[str, str]
    secret: str
    envelope: str
    time_key: str
    per_entry: bool
    remove_on_exit: bool
    home: Callable[[], Path]
    """The tool's directory, which holds the file (and, for codex, the lock)."""
    file_name: str = "auth.json"
    lock_file_name: Optional[str] = None
    description: str = field(default="", compare=False)

    def file(self) -> Path:
        return self.home() / self.file_name

    def lock_file(self) -> Optional[Path]:
        return self.home() / self.lock_file_name if self.lock_file_name else None


def _env_dir(variable: str, default: str) -> Callable[[], Path]:
    def home() -> Path:
        value = os.environ.get(variable)
        return Path(value) if value else Path.home() / default

    return home


PRESETS: Dict[str, Preset] = {
    "pi": Preset(
        name="pi",
        program="pi",
        vault="doppler",
        vault_options={"project": "agents", "config": "pi"},
        secret="PI_AUTH_JSON",
        envelope="piAuthJson",
        time_key="expires",
        per_entry=True,
        remove_on_exit=True,
        home=_env_dir("PI_CODING_AGENT_DIR", ".pi/agent"),
        description="agents/pi PI_AUTH_JSON, ${PI_CODING_AGENT_DIR:-~/.pi/agent}/auth.json, "
        "envelope piAuthJson, per provider by expires, removed on exit; log in with "
        "`pi auth login PROVIDER` (`pi login` is a prompt)",
    ),
    "codex": Preset(
        name="codex",
        program="codex",
        vault="doppler",
        vault_options={"project": "agents", "config": "codex"},
        secret="CODEX_AUTH_JSON",
        envelope="codexAuthJson",
        time_key="last_refresh",
        per_entry=False,
        remove_on_exit=False,
        home=_env_dir("CODEX_HOME", ".codex"),
        lock_file_name="auth.lock",
        description="agents/codex CODEX_AUTH_JSON, ${CODEX_HOME:-~/.codex}/auth.json, "
        "envelope codexAuthJson, whole file by last_refresh, flock auth.lock",
    ),
}
