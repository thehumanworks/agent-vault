"""Concurrency: the real sync code under random interleavings, and real processes.

``test_model_*`` drive the phases of :class:`agent_vault.sync.Syncer` (fetch, reconcile,
publish, write-back, removal) for several runs on two machines in a random order, with
programs refreshing credentials, edits made in the vault by hand and vault failures in
between. After every step they check the invariants of ``spec/AgentVaultSync.tla``:

* **NoLostRefresh**: the newest version of each credential with a time key is in the
  vault or in a machine's file.
* **NoResurrection**: a value the vault replaced never comes back to it.
* **SafeRemoval**: a file is removed only when the vault holds what it held.
* **NoLostLocalChange**: a sync replaces, in a file, only values the vault has had.
* **Converged**: once all runs end without giving up, the vault holds the newest refresh.

The mutation tests put back doppler-nix's behaviour (blind writes; the old base after a
failed write) and check that the same harness finds the violations TLC finds.

``test_processes_*`` run several ``avlt`` processes per machine against the fake Doppler.
"""

from __future__ import annotations

import json
import os
import random
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

import pytest

from agent_vault import merge
from agent_vault.localfile import MachineState, SessionLock, ToolLock, atomic_write, read_text
from agent_vault.merge import Format
from agent_vault.sync import MAX_ATTEMPTS, Messages, Plan, Settings, Syncer
from agent_vault.vault import Snapshot, Vault, VaultError
from conftest import Avlt, program

FMT = Format(envelope="authJson", time_key="expires", per_entry=True)
TIMED, UNTIMED = "openai", "apikey"


class MemoryVault(Vault):
    """An in-memory vault with a true compare-and-set, failures on demand, and a record
    of every value each credential ever had and lost."""

    kind = "memory"

    def __init__(self, value: str, blind: bool = False):
        self.value: Optional[str] = value
        self.blind = blind
        self.fail_next = False
        self.overwritten: Dict[str, Set[str]] = {}

    @classmethod
    def from_options(cls, options):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    @property
    def label(self) -> str:
        return "memory"

    def login_problem(self) -> Optional[str]:
        return None

    def environment(self, only=None):  # type: ignore[no-untyped-def]
        return {}

    def read(self, name: str) -> Snapshot:
        if self.fail_next:
            self.fail_next = False
            raise VaultError("down")
        return Snapshot(self.value, self.value)

    def write(self, name: str, value: str, expected: Snapshot) -> bool:
        if self.fail_next:
            self.fail_next = False
            raise VaultError("down")
        if not self.blind and self.value != expected.value:
            return False
        self.replace(value)
        return True

    def replace(self, value: str) -> None:
        old, new = creds_of(self.value), creds_of(value)
        for name, cred in old.items():
            if json.dumps(new.get(name), sort_keys=True) != json.dumps(cred, sort_keys=True):
                self.overwritten.setdefault(name, set()).add(json.dumps(cred, sort_keys=True))
        self.value = value

    def creds(self) -> Dict[str, dict]:
        return creds_of(self.value)


def creds_of(value: Optional[str]) -> Dict[str, dict]:
    return merge.parse_remote(value, FMT, "the secret").creds


@dataclass
class Run:
    name: str
    machine: Path
    syncer: Syncer
    session: SessionLock
    phase: str = "start"
    snapshot: Optional[Snapshot] = None
    plan: Optional[Plan] = None
    attempts: int = 0
    gave_up: bool = False


@dataclass
class World:
    rng: random.Random
    vault: MemoryVault
    machines: List[Path]
    runs: List[Run] = field(default_factory=list)
    clock: int = 10
    newest: int = 1
    logouts: bool = False
    violations: List[str] = field(default_factory=list)

    def file(self, machine: Path) -> Path:
        return machine / "auth.json"

    def settings(self, machine: Path) -> Settings:
        return Settings(
            name="test", secret="AUTH", file=self.file(machine), fmt=FMT, remove_on_exit=True, sync_interval=1
        )

    # -- the programs, and hand edits in the vault -------------------------------------------

    def program_write(self, machine: Path, change: str) -> None:
        lock = ToolLock(lock_dir=self.file(machine).with_name("auth.json.lock"))
        assert lock.acquire(1, steal=False)
        try:
            file = merge.parse_object(read_text(self.file(machine)), "file")
            self.clock += 1
            if change == "refresh":
                file[TIMED] = {"v": self.clock, "expires": self.clock}
                self.newest = self.clock
            elif change == "key":
                file[UNTIMED] = {"key": self.clock}
            elif change == "logout" and TIMED in file:
                del file[TIMED]
            atomic_write(self.file(machine), merge.dump_file(file))
        finally:
            lock.release()

    def hand_edit(self) -> None:
        self.clock += 1
        doc = json.loads(self.vault.value or "{}")
        doc.setdefault(FMT.envelope, {})[UNTIMED] = {"key": self.clock}
        self.vault.replace(json.dumps(doc))

    # -- one step of a run -----------------------------------------------------------------
    #
    # An operation (pull, a sync step, the finish) starts by taking the machine's sync
    # mutex without waiting; the scheduler only offers it while the mutex is free.

    def advance(self, run: Run) -> None:
        s = run.syncer
        phase = run.phase
        if phase == "start":
            if run.session.acquire_shared(wait=False):  # waits while the last user removes the file
                run.phase = "pull-begin"
        elif phase in ("pull-begin", "sync-begin", "exit-begin"):
            if not s.begin(0):
                if phase == "sync-begin":
                    run.phase = "running"  # busy: the next tick tries again
                return
            run.attempts = 0
            run.phase = {"pull-begin": "pull-read", "sync-begin": "sync-read", "exit-begin": "exit-read"}[
                phase
            ]
        elif phase == "pull-read":
            try:
                run.snapshot = s.fetch()
            except VaultError:
                s._assume_base()
                s.end()
                run.phase = "running"
                return
            run.phase = "pull"
        elif phase == "pull":
            assert run.snapshot is not None
            with self.watching(run.machine):
                s.merge_pulled(run.snapshot)
            s.end()
            run.phase = "running"
        elif phase in ("sync-read", "exit-read"):
            during = phase == "sync-read"
            try:
                run.snapshot = s.fetch()
            except VaultError:
                if during:
                    s.end()
                    run.phase = "running"
                else:
                    run.gave_up = True
                    s.end()
                    run.phase = "release"
                return
            run.phase = "sync-merge" if during else "exit-merge"
        elif phase in ("sync-merge", "exit-merge"):
            during = phase == "sync-merge"
            assert run.snapshot is not None
            with self.watching(run.machine):
                run.plan = s.reconcile(run.snapshot, write_file=during, wait=1, steal=False)
            if run.plan is None:
                s.end()
                run.phase = "running" if during else "release"
                return
            run.phase = "sync-write" if during else "exit-write"
        elif phase in ("sync-write", "exit-write"):
            during = phase == "sync-write"
            assert run.plan is not None
            outcome = s.publish(run.plan, during_run=during)
            run.attempts += 1
            if outcome == "conflict" and run.attempts < MAX_ATTEMPTS:
                run.phase = "sync-read" if during else "exit-read"
            elif during:
                s.end()
                run.phase = "running"
            elif outcome == "done":
                s.synced = True
                run.phase = "remove"
            else:
                run.gave_up = True
                s.end()
                run.phase = "release"
        elif phase == "remove":
            before = read_text(s.s.file)
            s.remove_if_last(run.session)
            s.end()
            if before and not s.s.file.exists():
                self.check_removal(before)
            run.phase = "release"
        elif phase == "release":
            run.session.release()
            run.phase = "done"

    def actions(self) -> List[object]:
        acts: List[object] = []
        programs = set()
        for run in self.runs:
            if run.phase == "done":
                continue
            if run.phase == "running":
                acts += [("sync", run), ("exit", run)]
            else:
                acts.append(("advance", run))
            # The command runs from the end of the pull until its run starts to exit,
            # also while the background sync is half-way through a step.
            if run.phase in ("running", "sync-begin", "sync-read", "sync-merge", "sync-write"):
                programs.add(run.machine)
        for machine in sorted(programs):
            acts += [("program", machine, "refresh"), ("program", machine, "key")]
            if self.logouts:
                acts.append(("program", machine, "logout"))
        if acts:
            acts += [("hand-edit",), ("fault",)]
        return acts

    def act(self, action: tuple) -> None:  # type: ignore[type-arg]
        kind = action[0]
        if kind == "advance":
            self.advance(action[1])
        elif kind == "sync":
            action[1].phase = "sync-begin"
            self.advance(action[1])
        elif kind == "exit":
            action[1].phase = "exit-begin"
        elif kind == "program":
            self.program_write(action[1], action[2])
        elif kind == "hand-edit" and self.rng.random() < 0.3:
            self.hand_edit()
        elif kind == "fault" and self.rng.random() < 0.2:
            self.vault.fail_next = True

    # -- the invariants ------------------------------------------------------------------

    def check(self) -> None:
        remote = self.vault.creds()
        if not self.logouts:
            holders = [remote.get(TIMED, {}).get("v", 0)]
            for machine in self.machines:
                file = merge.parse_object(read_text(self.file(machine)), "file")
                holders.append(file.get(TIMED, {}).get("v", 0))
            if self.newest > max(holders):
                self.violations.append(f"NoLostRefresh: version {self.newest} is gone")
        for name, cred in remote.items():
            if json.dumps(cred, sort_keys=True) in self.vault.overwritten.get(name, set()):
                self.violations.append(f"NoResurrection: {name} {cred} came back")

    @contextmanager
    def watching(self, machine: Path) -> Iterator[None]:
        """NoLostLocalChange: a sync replaces in the file only values the vault has had."""
        before = merge.parse_object(read_text(self.file(machine)), "file").get(UNTIMED)
        yield
        after = merge.parse_object(read_text(self.file(machine)), "file").get(UNTIMED)
        had = self.vault.overwritten.get(UNTIMED, set()) | {
            json.dumps(self.vault.creds().get(UNTIMED), sort_keys=True)
        }
        if before is not None and before != after and json.dumps(before, sort_keys=True) not in had:
            self.violations.append(f"NoLostLocalChange: {before} replaced by {after}")

    def check_removal(self, removed: str) -> None:
        file = merge.parse_object(removed, "file")
        now = self.vault.creds()
        for name, cred in file.items():
            if name == TIMED and now.get(name, {}).get("v", 0) < cred["v"]:
                self.violations.append(f"SafeRemoval: {name} v{cred['v']} removed, vault has {now.get(name)}")


def simulate(
    seed: int,
    tmp: Path,
    *,
    blind: bool = False,
    logouts: bool = False,
    steps: int = 80,
    per_run_state: bool = False,
) -> List[str]:
    rng = random.Random(seed)
    initial = json.dumps({FMT.envelope: {TIMED: {"v": 1, "expires": 1}, UNTIMED: {"key": 2}}})
    world = World(
        rng, MemoryVault(initial, blind=blind), [tmp / f"m{seed}a", tmp / f"m{seed}b"], logouts=logouts
    )
    for machine in world.machines:
        machine.mkdir()
    for i, machine in enumerate([world.machines[0], world.machines[0], world.machines[1]]):
        state = machine / ("state" if not per_run_state else f"state-{i}")
        state.mkdir(exist_ok=True)
        machine_state = MachineState(world.file(machine), directory=state)
        syncer = Syncer(world.settings(machine), world.vault, Messages("test", quiet=True), machine_state)
        world.runs.append(Run(f"r{i}", machine, syncer, SessionLock(machine)))
    for _ in range(steps):
        acts = world.actions()
        if not acts:
            break
        world.act(rng.choice(acts))
        world.check()
        if world.violations:
            return world.violations
    # Let every run finish, as each eventually does.
    for _ in range(10_000):
        if all(run.phase == "done" for run in world.runs):
            break
        for run in world.runs:
            if run.phase == "running":
                world.act(("exit", run))
            elif run.phase != "done":
                world.advance(run)
            world.check()
    else:
        world.violations.append("Termination: a run did not finish")
    if not logouts and not any(run.gave_up for run in world.runs):
        if world.vault.creds()[TIMED]["v"] != world.newest:
            world.violations.append("Converged: the vault does not hold the newest version")
    return world.violations


@pytest.fixture(autouse=True)
def fast_disk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(os, "fsync", lambda fd: None)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))


@pytest.mark.parametrize("block", range(8))
def test_model_no_lost_update(block: int, tmp_path: Path) -> None:
    for seed in range(block * 150, block * 150 + 150):
        assert simulate(seed, tmp_path, steps=120) == [], f"seed {seed}"


@pytest.mark.parametrize("block", range(4))
def test_model_with_logouts(block: int, tmp_path: Path) -> None:
    for seed in range(block * 150, block * 150 + 150):
        assert simulate(seed, tmp_path, logouts=True, steps=120) == [], f"seed {seed}"


def test_mutation_blind_writes_lose_updates(tmp_path: Path) -> None:
    """doppler-nix's unguarded `doppler secrets set`: some schedule loses a refresh."""
    found = [v for seed in range(400) for v in simulate(seed, tmp_path, blind=True)]
    assert any(v.startswith(("NoLostRefresh", "SafeRemoval", "Converged")) for v in found)


def test_mutation_old_base_resurrects_a_replaced_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """doppler-nix kept the old base after a failed write: some schedule writes back a
    value that the vault had already replaced."""

    def reference(self: Syncer, plan: Plan, vault_now: dict) -> None:
        if plan.pushed.value is not None and vault_now is plan.pushed.remote:
            return  # a failed write: keep the base
        self.base = merge.digests(plan.pushed.merged)

    monkeypatch.setattr(Syncer, "_rebase", reference)
    found = [v for seed in range(400) for v in simulate(seed, tmp_path)]
    assert any(v.startswith("NoResurrection") for v in found)


def test_mutation_a_base_per_run_undoes_a_vault_edit(tmp_path: Path) -> None:
    """doppler-nix kept one base and no sync mutex per run: some schedule has a run that
    had not synced for a while write back a value that another run had synced and the
    vault had since replaced."""
    found = [v for seed in range(400) for v in simulate(seed, tmp_path, per_run_state=True)]
    assert any(v.startswith("NoResurrection") for v in found)


# -- real processes ------------------------------------------------------------------------

REFRESHER = """
import random
f = H / ".pi/agent/auth.json"
lock = pathlib.Path(str(f) + ".lock")
me = sys.argv[1]
made = []
for i in range(int(sys.argv[2])):
    while True:  # pi's own lock on the file, as proper-lockfile takes it
        try:
            os.mkdir(lock); break
        except FileExistsError:
            time.sleep(0.01)
    try:
        text = f.read_text() if f.exists() else "{}"
        v = json.loads(text)  # a torn file would fail here
        stamp = time.time_ns()
        v["openai"] = {"access": me + str(i), "expires": stamp}
        v[me] = {"key": me + str(i)}
        save(f, v)
        made.append(stamp)
    finally:
        os.rmdir(lock)
    time.sleep(random.uniform(0.05, 0.4))
print(json.dumps(made))
"""


def test_processes_two_machines_lose_no_refresh(doppler, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """Two machines, two runs each, all refreshing the same credential while syncing every
    second: at the end the vault holds the newest refresh and each run's own key."""
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {"openai": {"access": "a0", "expires": 1}}}})
    processes = []
    for machine in ("a", "b"):
        home = tmp_path / machine
        home.mkdir()
        runner = Avlt(home, doppler)
        for run in ("1", "2"):
            name = f"{machine}{run}"
            processes.append(
                runner.popen(
                    "run", "--preset", "pi", "--sync-interval", "1", "--", *program(REFRESHER), name, "12"
                )
            )
    made = []
    for process in processes:
        out, err = process.communicate(timeout=120)
        assert process.returncode == 0, err
        assert "kept changing" not in err, err
        made += json.loads(out.strip().splitlines()[-1])
    final = doppler.doc("agents", "pi", "PI_AUTH_JSON")["piAuthJson"]
    assert final["openai"]["expires"] == max(made), "the newest refresh is in Doppler"
    assert {f"{m}{r}" for m in "ab" for r in "12"} <= set(final), "no run's own credential is lost"
    for machine in ("a", "b"):
        assert not (tmp_path / machine / ".pi/agent/auth.json").exists(), "removed after the last run"
