"""A vault in a local JSON file: ``{"NAME": "value", ...}``.

For tests, for machines that share a filesystem, and as the smallest example of an
adapter. ``--vault file --vault-option path=PATH``. Every read and write holds an flock
on ``PATH.lock``, so :meth:`FileVault.write` is a true compare-and-set.
"""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Mapping, Optional, Sequence

from ..localfile import atomic_write
from ..vault import Snapshot, Vault, VaultError


class FileVault(Vault):
    kind = "file vault"
    atomic_write = True

    def __init__(self, path: Path):
        self.path = path

    @classmethod
    def from_options(cls, options: Mapping[str, str]) -> FileVault:
        unknown = sorted(set(options) - {"path"})
        if unknown:
            raise ValueError(f"unknown file vault option {unknown[0]} (path)")
        path = options.get("path")
        if not path:
            raise ValueError("the file vault needs --vault-option path=PATH")
        if path.startswith("~/"):
            path = str(Path.home() / path[2:])
        return cls(Path(path).absolute())

    @property
    def label(self) -> str:
        return str(self.path)

    def login_problem(self) -> Optional[str]:
        return None

    @contextmanager
    def _locked(self, exclusive: bool) -> Iterator[None]:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(str(self.path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as e:
            raise VaultError(f"cannot open {self.path}: {e.strerror}") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            os.close(fd)

    def _load(self) -> Dict[str, str]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as e:
            raise VaultError(f"cannot read {self.path}: {e.strerror}") from None
        try:
            data = json.loads(text) if text.strip() else {}
        except ValueError:
            data = None
        if not isinstance(data, dict):
            raise VaultError(f"{self.path} is not a JSON object")
        return {str(k): v if isinstance(v, str) else json.dumps(v) for k, v in data.items()}

    def environment(self, only: Optional[Sequence[str]] = None) -> Dict[str, str]:
        with self._locked(exclusive=False):
            data = self._load()
        return {k: v for k, v in data.items() if not only or k in only}

    def read(self, name: str) -> Snapshot:
        with self._locked(exclusive=False):
            value = self._load().get(name)
        return Snapshot(value, value)

    def write(self, name: str, value: str, expected: Snapshot) -> bool:
        with self._locked(exclusive=True):
            data = self._load()
            if data.get(name) != expected.value:
                return False
            data[name] = value
            try:
                atomic_write(self.path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
            except OSError as e:
                raise VaultError(f"cannot write {self.path}: {e.strerror}") from None
        return True
