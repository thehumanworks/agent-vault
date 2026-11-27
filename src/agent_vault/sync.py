"""Keeping a login file and one vault secret in step around a command.

The life of a run, as in doppler-nix's ``doppler-auth-sync`` (``spec/AgentVaultSync.tla``
models each step):

1. **Pull**: credentials newer in the vault are merged into the file.
2. **During the run**: a background thread writes a change to the file back within two
   seconds and reads the secret every ``sync_interval`` seconds for newer credentials.
   Its messages wait until the command exits, and what the command removes from the file
   stays out of it.
3. **Write-back**: after the command exits, credentials newer locally are written back.
4. **Removal** (``remove_on_exit``): the file is removed once the vault holds all of it
   and no other run on the machine still uses it.

Each of these *operations* holds the machine's sync mutex (:class:`MachineState`), so the
runs on one machine sync one at a time and share one base. Each write of the secret is a
compare-and-set (:meth:`Vault.write`); when it loses to another machine, the operation
reads the secret again and merges once more, up to :data:`MAX_ATTEMPTS` times. That is
what keeps a credential rotated on one machine from being overwritten by another
machine's older copy.

An operation is made of *phases* (:meth:`Syncer.begin_pull`, :meth:`Syncer.finish_pull`,
:meth:`Syncer.fetch`, :meth:`Syncer.reconcile`, :meth:`Syncer.publish`), which match the
actions of the spec. The tests drive the phases of several syncers in random
interleavings and check the spec's invariants on the result.
"""

from __future__ import annotations

import math
import sys
import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from . import merge
from .localfile import MachineState, SessionLock, ToolLock, atomic_write, read_text, remove
from .merge import Credentials, Digests, Format, MergeError, Pushed
from .vault import Snapshot, Vault, VaultError

MAX_ATTEMPTS = 5
"""Compare-and-set attempts per operation before it gives up until the next one."""

PULL_ATTEMPTS = 3
"""Reads of the secret at the start while the file keeps changing under them."""

LOCK_WAIT = 10.0
"""Seconds to wait for the tool lock before and after the command (doppler-nix: 100 tries
of 0.1 s)."""

LOCK_WAIT_DURING_RUN = 3.0
"""Seconds to wait for it while the command runs (doppler-nix: 30 tries)."""

MUTEX_WAIT = 120.0
"""Seconds to wait for another run on this machine to finish syncing, before and after the
command. While it runs, a step that cannot have the mutex at once waits for the next."""

ANOTHER_RUN = "{secret} was updated by another run during this one; the newer copy of each credential won"


@dataclass(frozen=True)
class Settings:
    name: str
    """Prefix for messages."""
    secret: str
    file: Path
    """Absolute, with symlinks resolved."""
    fmt: Format
    lock_dir: Optional[Path] = None
    lock_file: Optional[Path] = None
    remove_on_exit: bool = False
    sync_interval: int = 30

    def tool_lock(self) -> ToolLock:
        if self.lock_file is not None:
            return ToolLock(lock_file=self.lock_file)
        return ToolLock(lock_dir=self.lock_dir or self.file.with_name(self.file.name + ".lock"))


@dataclass
class Plan:
    """A merge made under the tool lock, waiting to be published."""

    snapshot: Snapshot
    pushed: Pushed
    file_now: Credentials
    """What the file holds now: the merge's ``kept`` if written (or equal), else as read."""


@dataclass
class Messages:
    """Messages for the user. While the command runs they wait, since it may own the
    terminal; each is printed once."""

    name: str
    quiet: bool = False
    waiting: List[str] = field(default_factory=list)
    said: List[str] = field(default_factory=list)
    stream: object = None

    def __call__(self, text: str) -> None:
        if text in self.said or text in self.waiting:
            return
        if self.quiet:
            self.waiting.append(text)
            return
        self.emit(text)

    def emit(self, text: str) -> None:
        self.said.append(text)
        stream = self.stream or sys.stderr
        try:
            print(f"{self.name}: {text}", file=stream, flush=True)  # type: ignore[arg-type]
        except (OSError, ValueError):
            pass

    def flush(self) -> List[str]:
        """Print the waiting messages; return them."""
        self.quiet = False
        waiting, self.waiting = self.waiting, []
        for text in waiting:
            self.emit(text)
        return waiting


class Syncer:
    """The sync state of one run."""

    def __init__(self, settings: Settings, vault: Vault, messages: Messages,
                 machine: Optional[MachineState] = None):
        self.s = settings
        self.vault = vault
        self.say = messages
        self.machine = machine or MachineState(settings.file)
        self.base: Optional[Digests] = None
        """The machine's base, as loaded at the start of the current operation."""
        self.assumed = False
        """The base was taken from the file as it is, without a sync; it is not saved."""
        self.refreshed: object = None
        """The secret's ``meta.lastRefreshed`` as last seen."""
        self.seen: str = ""
        """The file's text as last read during the run."""
        self.seen_remote: Optional[str] = None
        self.pulled: Optional[Snapshot] = None
        self.dirty = False
        """A merge is still to be published (the last write failed)."""
        self.current: Optional[str] = None
        """The file as read for the write-back, for the removal check."""
        self.synced = False
        """The vault holds every credential of ``current``."""

    @property
    def kind(self) -> str:
        return self.vault.kind

    # -- the sync mutex -----------------------------------------------------------------

    def begin(self, wait: float) -> bool:
        """Take the machine's sync mutex and load its base."""
        if not self.machine.acquire(wait):
            return False
        loaded = self.machine.load_base()
        if loaded is not None:
            self.base, self.assumed = loaded, False
        return True

    def end(self) -> None:
        """Save the base and release the mutex."""
        if self.base is not None and not self.assumed:
            self.machine.save_base(self.base)
        self.machine.release()

    def _assume_base(self) -> None:
        """No sync happened: the file as it is stands for the last sync, so a credential
        changed in the vault meanwhile is not undone at the write-back."""
        if self.base is None:
            try:
                self.base = merge.base_of(read_text(self.s.file), self.s.fmt)
            except MergeError:
                self.base = {}
            self.assumed = True

    # -- phases ---------------------------------------------------------------------

    def fetch(self) -> Snapshot:
        return self.vault.read(self.s.secret)

    def begin_pull(self) -> Tuple[str, Optional[Snapshot]]:
        """The file as it is now, then the secret (``None``: unreadable)."""
        before = read_text(self.s.file)
        try:
            return before, self.fetch()
        except VaultError:
            return before, None

    def finish_pull(self, before: str, snapshot: Optional[Snapshot], last: bool) -> bool:
        """Under the tool lock, merge ``snapshot`` into the file. ``False``: the file
        changed since ``before``, so fetch again.

        Without a base, a pull lets the vault's copy of a credential without a later time
        key win. That is right only if the snapshot is newer than what the file holds; a
        file changed after the snapshot was taken may hold a newer copy, and merging the
        snapshot over it would undo that copy.
        """
        lock = self.s.tool_lock()
        if snapshot is None or not lock.acquire(LOCK_WAIT, steal=True):
            if snapshot is not None:
                self.say(f"{lock.path} is held by another process; not syncing {self.s.secret}")
            self._assume_base()
            return True
        try:
            text = read_text(self.s.file)
            if text != before:
                if not last:
                    return False
                self._assume_base()  # it keeps changing: leave it to whoever changes it
                return True
            try:
                pulled = merge.pull(text, snapshot.value, self.s.fmt, self.kind, self.base)
            except MergeError as e:
                self.say(f"{e}; left {self.s.file} as it is")
                self._assume_base()
                return True
            self.refreshed = pulled.last_refreshed
            self.pulled = snapshot
            file_now = pulled.merged
            if pulled.changed:
                try:
                    atomic_write(self.s.file, merge.dump_file(pulled.file))
                except OSError:
                    self.say(f"could not write {self.s.file}")
                    file_now = merge.split(merge.parse_object(text, "the local file"), self.s.fmt, "")
            self.base, self.assumed = merge.rebase(self.base, file_now, pulled.remote), False
            return True
        finally:
            lock.release()

    def reconcile(self, snapshot: Snapshot, write_file: bool, wait: float, steal: bool) -> Optional[Plan]:
        """Under the tool lock: read the file and merge it with ``snapshot``.

        With ``write_file`` (during the run) the file gets what the merge keeps of it.
        Returns ``None`` when the lock is held or the data cannot be merged (said why).
        """
        lock = self.s.tool_lock()
        if not lock.acquire(wait, steal):
            self.say(f"{lock.path} is held by another process; not syncing {self.s.secret}")
            return None
        try:
            current = read_text(self.s.file)
            self.current = current
            try:
                pushed = merge.push(current, snapshot.value, self.base or {}, self.s.fmt, self.kind)
            except MergeError as e:
                if write_file:
                    self.say(f"{e}; did not sync {self.s.secret} during the run")
                    self.seen, self.seen_remote = current, snapshot.value
                else:
                    self.say(f"{e}; not writing back {self.s.secret}")
                return None
            file_now = pushed.kept if not pushed.changed else pushed.local
            if write_file:
                if pushed.changed:
                    try:
                        atomic_write(self.s.file, merge.dump_file(pushed.file))
                        file_now = pushed.kept
                    except OSError:
                        self.say(f"could not write {self.s.file} during the run")
                self.seen, self.seen_remote = read_text(self.s.file), snapshot.value
            return Plan(snapshot, pushed, file_now)
        finally:
            lock.release()

    def publish(self, plan: Plan, during_run: bool) -> str:
        """Store the merge if the vault still holds the snapshot it was made from.

        Returns ``"done"``, ``"conflict"`` (read again and retry) or ``"failed"``. The base
        moves to what the file and the vault now hold in common.
        """
        pushed = plan.pushed
        self._note_refreshed(pushed.last_refreshed)
        if pushed.value is None:
            self._rebase(plan, pushed.remote)
            self.dirty = False
            return "done"
        when = " during the run" if during_run else ""
        try:
            stored = self.vault.write(self.s.secret, pushed.value, plan.snapshot)
        except VaultError:
            self._rebase(plan, pushed.remote)
            self.dirty = True
            if during_run:
                self.say(f"could not write {self.s.secret} to {self.kind} during the run")
            return "failed"
        if not stored:
            self._rebase(plan, pushed.remote)
            self.dirty = True
            return "conflict"
        self._rebase(plan, pushed.merged)
        self.dirty = False
        self.seen_remote = pushed.value
        self.refreshed = merge.last_refreshed_of(pushed.value)
        self.say(f"wrote newer credentials back to {self.s.secret}{when}")
        return "done"

    def _rebase(self, plan: Plan, vault_now: Credentials) -> None:
        self.base, self.assumed = merge.rebase(self.base, plan.file_now, vault_now), False

    def _note_refreshed(self, latest: object) -> None:
        if self.refreshed is not None and latest is not None and latest != self.refreshed:
            self.say(ANOTHER_RUN.format(secret=self.s.secret))
        if latest is not None:
            self.refreshed = latest

    # -- operations: each holds the sync mutex ------------------------------------------

    def pull(self) -> str:
        """Step 1. Returns ``"pulled"``, ``"unreadable"`` or ``"busy"``."""
        if not self.begin(MUTEX_WAIT):
            self.say(f"another run on this machine is still syncing {self.s.file}; not syncing it now")
            self._assume_base()
            return "busy"
        try:
            for attempt in range(PULL_ATTEMPTS):
                before, snapshot = self.begin_pull()
                if snapshot is None:
                    self._assume_base()
                    return "unreadable"
                if self.finish_pull(before, snapshot, last=attempt + 1 == PULL_ATTEMPTS):
                    break
            return "pulled"
        finally:
            self.end()

    def step(self, now: str) -> None:
        """Step 2, once: sync while the command runs. ``now`` is the file as just read."""
        if not self.begin(0.5):
            return  # another run on this machine is syncing: the next tick tries again
        try:
            for attempt in range(MAX_ATTEMPTS):
                try:
                    snapshot = self.fetch()
                except VaultError:
                    self.say(f"could not read {self.s.secret} from {self.kind} during the run")
                    return
                if attempt == 0 and now == self.seen and snapshot.value == self.seen_remote and not self.dirty:
                    return
                plan = self.reconcile(snapshot, write_file=True, wait=LOCK_WAIT_DURING_RUN, steal=False)
                if plan is None or self.publish(plan, during_run=True) != "conflict":
                    return
            self.say(f"{self.s.secret} kept changing in {self.kind} during the run; trying again later")
        finally:
            self.end()

    def finish(self, session: SessionLock) -> None:
        """Steps 3 and 4: write back, then remove the file if this is its last user."""
        if not self.begin(MUTEX_WAIT):
            self.say(
                f"another run on this machine is still syncing {self.s.file}; "
                f"newer credentials stay in it until the next run"
            )
            return
        try:
            self.write_back()
            self.remove_if_last(session)
        finally:
            self.end()

    # -- the parts of finish ----------------------------------------------------------

    def write_back(self) -> None:
        """Step 3: write back what is newer locally. The caller holds the mutex."""
        for _ in range(MAX_ATTEMPTS):
            try:
                snapshot = self.fetch()
            except VaultError:
                self.say(
                    f"could not read {self.s.secret} from {self.kind}; "
                    f"newer credentials stay in {self.s.file} until the next run"
                )
                return
            plan = self.reconcile(snapshot, write_file=False, wait=LOCK_WAIT, steal=True)
            if plan is None:
                return
            outcome = self.publish(plan, during_run=False)
            if outcome == "done":
                self.synced = True
                return
            if outcome == "failed":
                self.say(
                    f"could not write {self.s.secret} to {self.kind}; "
                    f"newer credentials stay in {self.s.file} until the next run"
                )
                return
        self.say(
            f"{self.s.secret} kept changing in {self.kind}; "
            f"newer credentials stay in {self.s.file} until the next run"
        )

    def remove_if_last(self, session: SessionLock) -> None:
        """Step 4: remove the file once the vault holds all of it and no other run uses it.
        The caller holds the mutex."""
        if not (self.s.remove_on_exit and self.synced):
            return
        if not session.try_exclusive():
            return
        lock = self.s.tool_lock()
        if not lock.acquire(LOCK_WAIT, steal=True):
            self.say(f"{lock.path} is held by another process; keeping {self.s.file}")
            return
        try:
            if read_text(self.s.file) == self.current:
                remove(self.s.file)
                self.machine.forget_base()
                self.base = None
            else:
                self.say(f"{self.s.file} changed during the write-back; keeping it until the next run")
        finally:
            lock.release()


class Background(threading.Thread):
    """Step 2 for the length of the command: a change to the file is synced within
    ``tick`` seconds, and the secret is read every ``sync_interval`` seconds."""

    def __init__(self, syncer: Syncer, read: Callable[[Path], str] = read_text):
        super().__init__(name="agent-vault-sync", daemon=True)
        self.syncer = syncer
        self.read = read
        self.stopping = threading.Event()
        self.crashed: Optional[str] = None
        interval = syncer.s.sync_interval
        self.tick = min(interval, 2)
        self.every = math.ceil(interval / self.tick) if self.tick else 0

    def run(self) -> None:
        polls = 0
        try:
            while not self.stopping.wait(self.tick):
                now = self.read(self.syncer.s.file)
                polls += 1
                if now != self.syncer.seen or polls >= self.every:
                    polls = 0
                    self.syncer.step(now)
        except BaseException:  # noqa: BLE001 - reported at exit, and the exit sync still runs
            self.crashed = traceback.format_exc(limit=3)

    def stop(self) -> None:
        """Let the current step finish, then end."""
        self.stopping.set()
        self.join()
