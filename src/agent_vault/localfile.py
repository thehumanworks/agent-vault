"""The login file on disk: atomic writes and the locks around it.

Four locks are involved, all modelled in ``spec/``:

* The *tool lock* is the lock the program itself takes on its login file: a
  proper-lockfile directory (``auth.json.lock``, pi) or an flock on a file
  (``auth.lock``, codex). agent-vault takes it around every read-merge-write of the file,
  so a merge never interleaves with the program's own writes.
* The *steal mutex* is agent-vault's own flock, held while it removes a lock directory
  left behind by a process that died. Two agent-vault processes then never both remove
  it and both believe they hold the lock (``spec/LockSteal.tla``).
* The *session lock* is a shared flock on the file's directory, held by every run for
  its whole length. Only the last run to exit can take it exclusively, so only that one
  removes the file.
* The *sync mutex* (:class:`MachineState`) makes the runs on one machine sync one at a
  time.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Dict, Optional

STALE_SECONDS = 10.0
"""A lock directory untouched this long belongs to a process that died (proper-lockfile's
default ``stale``; a live holder touches it every 5 seconds)."""


def read_text(path: Path) -> str:
    """The file's text, or ``""`` when it cannot be read (absent)."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def atomic_write(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` so a reader sees the old or the new file, never a part.

    The temporary file is created mode 0600 in the same directory and renamed over the
    file; both are synced to disk, so a crash leaves one of the two whole.
    """
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(str(directory), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    _fsync_dir(path.parent)


def state_dir() -> Path:
    """agent-vault's own files: ``$XDG_STATE_HOME/agent-vault`` (``~/.local/state/...``)."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    directory = Path(base) / "agent-vault"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory


def _key(path: Path) -> str:
    return hashlib.sha256(str(path).encode()).hexdigest()[:32]


def _flock(fd: int, deadline: float) -> bool:
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as e:
            if e.errno not in (errno.EAGAIN, errno.EACCES) or time.monotonic() >= deadline:
                return False
            time.sleep(0.02)


class MachineState:
    """What the runs on one machine share about one file.

    * The *sync mutex*, an flock held for each whole sync operation (read the secret,
      merge under the tool lock, write the secret). Runs on one machine sync one at a
      time; machines race each other, and the compare-and-set settles that.
    * The *base*: for each credential, the digest of its value when the file and the vault
      last held the same value. Shared by all runs on the machine, since they share the
      file; doppler-nix kept one per run, so a run that had not synced for a while took a
      credential another run had synced for a change of its own (spec/README.md).
    """

    def __init__(self, file: Path, directory: Optional[Path] = None):
        directory = directory or state_dir()
        key = _key(file)
        self.mutex_path = directory / f"{key}.sync"
        self.base_path = directory / f"{key}.base"
        self._fd: Optional[int] = None

    def acquire(self, timeout: float) -> bool:
        try:
            fd = os.open(str(self.mutex_path), os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            return False
        if not _flock(fd, time.monotonic() + timeout):
            os.close(fd)
            return False
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def load_base(self) -> Optional[Dict[str, str]]:
        try:
            data = json.loads(self.base_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        base = data.get("base") if isinstance(data, dict) else None
        if not isinstance(base, dict) or not all(isinstance(v, str) for v in base.values()):
            return None
        return {str(k): v for k, v in base.items()}

    def save_base(self, base: Dict[str, str]) -> None:
        try:
            atomic_write(self.base_path, json.dumps({"version": 1, "base": base}, sort_keys=True) + "\n")
        except OSError:
            pass

    def forget_base(self) -> None:
        try:
            self.base_path.unlink()
        except OSError:
            pass


class ToolLock:
    """The program's own lock on the file: a lock directory or an flock on a lock file."""

    def __init__(self, lock_dir: Optional[Path] = None, lock_file: Optional[Path] = None):
        if (lock_dir is None) == (lock_file is None):
            raise ValueError("give exactly one of lock_dir and lock_file")
        self.lock_dir = lock_dir
        self.lock_file = lock_file
        self._fd: Optional[int] = None
        self._held = False

    @property
    def path(self) -> Path:
        return self.lock_dir if self.lock_dir is not None else self.lock_file  # type: ignore[return-value]

    def acquire(self, timeout: float, steal: bool) -> bool:
        """Take the lock within ``timeout`` seconds.

        With ``steal``, a lock directory untouched for 10 seconds is taken over. While the
        command runs, the sync never steals: the command may be holding the lock through
        a slow refresh.
        """
        if self._held:
            raise RuntimeError("lock already held")
        deadline = time.monotonic() + timeout
        if self.lock_file is not None:
            return self._acquire_flock(deadline)
        return self._acquire_dir(deadline, steal)

    def _acquire_flock(self, deadline: float) -> bool:
        assert self.lock_file is not None
        try:
            fd = os.open(str(self.lock_file), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        except OSError:
            return False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    os.close(fd)
                    return False
                if time.monotonic() >= deadline:
                    os.close(fd)
                    return False
                time.sleep(0.05)
                continue
            self._fd = fd
            self._held = True
            return True

    def _acquire_dir(self, deadline: float, steal: bool) -> bool:
        assert self.lock_dir is not None
        while True:
            try:
                os.mkdir(str(self.lock_dir))
            except FileExistsError:
                pass
            except OSError:
                return False
            else:
                self._held = True
                return True
            if steal and self._steal_if_stale():
                continue
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def _steal_if_stale(self) -> bool:
        """Remove the lock directory if its holder died. True if it was removed.

        The check and the removal happen under the steal mutex, so another agent-vault
        process cannot replace the stale directory with its own fresh one in between and
        lose it to this removal (doppler-nix's race, found by spec/LockSteal.tla).
        """
        assert self.lock_dir is not None
        digest = _key(self.lock_dir)
        try:
            fd = os.open(str(state_dir() / f"{digest}.steal"), os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                mtime = os.stat(str(self.lock_dir)).st_mtime
            except FileNotFoundError:
                return True  # gone already: try again
            except OSError:
                return False
            if time.time() - mtime <= STALE_SECONDS:
                return False
            try:
                os.rmdir(str(self.lock_dir))
            except FileNotFoundError:
                return True
            except OSError:
                return False
            return True
        finally:
            os.close(fd)  # releases the flock

    def release(self) -> None:
        if not self._held:
            return
        self._held = False
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        elif self.lock_dir is not None:
            try:
                os.rmdir(str(self.lock_dir))
            except OSError:
                pass

    @property
    def held(self) -> bool:
        return self._held


class SessionLock:
    """A shared flock on the file's directory, held by every run that uses the file."""

    def __init__(self, directory: Path):
        self.directory = directory
        self._fd: Optional[int] = None

    def acquire_shared(self, wait: bool = True) -> bool:
        """Count as a user of the file. Waits while the last user removes it."""
        try:
            fd = os.open(str(self.directory), os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | (0 if wait else fcntl.LOCK_NB))
        except OSError:
            os.close(fd)
            return False
        self._fd = fd
        return True

    def try_exclusive(self) -> bool:
        """Become the only user of the file, without waiting.

        Linux converts a shared flock to an exclusive one by dropping the shared lock
        first, so after a refusal this run no longer counts as a user. That is fine: it
        is exiting. The spec models exactly this.
        """
        if self._fd is None:
            return False
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
