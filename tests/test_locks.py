"""The locks: the tool's lock (a directory or an flock), the stale-lock steal, the session lock."""

from __future__ import annotations

import multiprocessing
import os
import time
from pathlib import Path

from agent_vault.localfile import STALE_SECONDS, SessionLock, ToolLock, atomic_write, read_text


def test_lock_dir_excludes_and_releases(tmp_path: Path) -> None:
    a, b = ToolLock(lock_dir=tmp_path / "f.lock"), ToolLock(lock_dir=tmp_path / "f.lock")
    assert a.acquire(1, steal=False)
    assert not b.acquire(0.3, steal=True), "a fresh lock is not stolen"
    a.release()
    assert b.acquire(1, steal=False)
    b.release()
    assert not (tmp_path / "f.lock").exists()


def test_a_stale_lock_dir_is_stolen_only_when_allowed(tmp_path: Path, monkeypatch: object) -> None:
    os.environ["XDG_RUNTIME_DIR"] = str(tmp_path)
    lock = tmp_path / "f.lock"
    lock.mkdir()
    old = time.time() - STALE_SECONDS - 5
    os.utime(lock, (old, old))
    assert not ToolLock(lock_dir=lock).acquire(0.3, steal=False), "never while the command runs"
    taker = ToolLock(lock_dir=lock)
    assert taker.acquire(1, steal=True)
    assert time.time() - lock.stat().st_mtime < 5, "the lock is a new directory"
    taker.release()


def test_flock_lock(tmp_path: Path) -> None:
    a, b = ToolLock(lock_file=tmp_path / "auth.lock"), ToolLock(lock_file=tmp_path / "auth.lock")
    assert a.acquire(1, steal=False)
    assert not b.acquire(0.3, steal=False)
    a.release()
    assert b.acquire(1, steal=False)
    b.release()


def _steal_and_count(lock: str, counter: str, runtime: str, rounds: int) -> int:
    """Take the lock (stealing a stale one) and check nobody else holds it meanwhile."""
    os.environ["XDG_RUNTIME_DIR"] = runtime
    overlaps = 0
    for _ in range(rounds):
        tool = ToolLock(lock_dir=Path(lock))
        if not tool.acquire(20, steal=True):
            continue
        fd = os.open(counter, os.O_CREAT | os.O_EXCL | os.O_WRONLY)  # fails if another holder
        os.close(fd)
        time.sleep(0.002)
        os.unlink(counter)
        # Leave a stale lock behind now and then, as a process that died would.
        if os.getpid() % 2 and _ % 7 == 0:
            old = time.time() - STALE_SECONDS - 5
            os.utime(lock, (old, old))
            tool._held = False  # abandoned
        else:
            tool.release()
    return overlaps


def test_concurrent_steals_keep_mutual_exclusion(tmp_path: Path) -> None:
    """Several processes race to steal abandoned lock directories; at no time do two of
    them hold the lock (a second holder would fail to create the marker file)."""
    lock = tmp_path / "f.lock"
    counter = tmp_path / "holder"
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(4) as pool:
        results = pool.starmap(_steal_and_count, [(str(lock), str(counter), str(tmp_path), 40)] * 4)
    assert results == [0, 0, 0, 0]


def test_session_lock_only_the_last_user_is_exclusive(tmp_path: Path) -> None:
    a, b = SessionLock(tmp_path), SessionLock(tmp_path)
    assert a.acquire_shared() and b.acquire_shared()
    assert not a.try_exclusive(), "b still uses the directory"
    assert b.try_exclusive(), "a's refused upgrade dropped its shared lock, as Linux does"
    a.release()
    b.release()


def test_atomic_write(tmp_path: Path) -> None:
    f = tmp_path / "auth.json"
    atomic_write(f, '{"a": 1}\n')
    assert read_text(f) == '{"a": 1}\n'
    assert oct(f.stat().st_mode & 0o777) == "0o600"
    assert [p.name for p in tmp_path.iterdir()] == ["auth.json"], "no temporary file is left"
    assert read_text(tmp_path / "missing") == ""
