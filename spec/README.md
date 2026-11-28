# Formal verification

agent-vault's concurrent parts are specified in TLA+ and model-checked with TLC. Every
interleaving of the runs, programs, people and failures in a bounded model is explored;
the properties below hold in all of them. The same properties are then checked on the
Python code itself, in random interleavings (`tests/test_concurrency.py`).

| Spec | What it models |
| --- | --- |
| [`AgentVaultSync.tla`](AgentVaultSync.tla) | The sync protocol (`src/agent_vault/sync.py`): pull, sync during the run, write-back, removal, on several machines at once. |
| [`LockSteal.tla`](LockSteal.tla) | The tool's lock directory and the removal of one left by a process that died (`ToolLock` in `src/agent_vault/localfile.py`). |

## What is proven

`AgentVaultSync` checks these invariants in every reachable state:

| Property | Meaning |
| --- | --- |
| **NoLostRefresh** | The newest value a program made of each credential with a time key (an OAuth login: a rotated refresh token) is in the vault or in some machine's file. Nothing that one machine refreshed is lost because another machine wrote at the same time. |
| **NoResurrection** | A value the vault replaced never comes back to it: no run undoes a newer write by another run, another machine or a person. |
| **SafeRemoval** | A file is removed only when the vault holds everything in it. |
| **NoLostLocalChange** | A sync replaces, in a file, only values the vault has had; what a program changed reaches the vault or stays in the file. |
| **Converged** | Once every run has ended without giving up, the vault holds the newest value of each credential with a time key. |
| **OneSyncPerMachine** | At most one run of a machine is inside a sync operation (mutual exclusion of the sync mutex). |

`LockSteal` checks **MutualExclusion**: no two live processes hold the tool's lock at once,
even while lock directories left by dead processes are being removed.

The model: two machines, two runs on the first and one on the second, all able to start,
sync and exit in any order; one credential with a time key and one without; programs that
refresh, change and (in the `Logout` configurations) remove credentials while their run
syncs; people who edit the secret by hand; a vault read or write that fails;
compare-and-set conflicts and retries; and the removal of the file by the last run on a
machine. `MaxValue` bounds how many new credential values programs and people make.

Results with TLC 1.7.4, 4 cores (`spec/check.sh --deep`):

| Configuration | New values | Result | Distinct states | Time |
| --- | --- | --- | --- | --- |
| `AgentVaultSync` (CI) | 3 | holds | 5,175,599 | 71 s |
| `AgentVaultSyncDeep` | 4 | holds | 47,309,804 | 12 min |
| `AgentVaultSyncLogout` (CI) | 2 | holds | 9,749,341 | 2.5 min |
| `AgentVaultSyncLogoutDeep` | 3 | holds | 115,822,663 | 37 min |
| `LockSteal` | | holds | 70 | 1 s |

CI runs every configuration except the two deep ones.

## What TLC finds in doppler-nix

Each flag of the spec switches on one behaviour of doppler-nix. With it, TLC finds a
counterexample in about a second, and so does the Python harness when the same behaviour
is put back into the code (`test_mutation_*`). Each configuration checks only the property
of its story; with all of them checked, TLC reports the first violation it reaches, which
can be another one (`DopplerNix`, all flags off, does that):

| Configuration | doppler-nix's behaviour | Property violated | The race |
| --- | --- | --- | --- |
| `DopplerNixBlindWrites` | `doppler secrets set` writes whatever it merged | NoLostRefresh / SafeRemoval / Converged | Machine B reads the secret, machine A writes a refreshed token and removes its file, B writes its older copy over it. The provider has already rotated the token, so every machine must log in again. |
| `DopplerNixOldBase` | after a failed write the old base stays | NoResurrection | The merge pulls a newer API key from the vault into the file, the write fails, and at the next try that key counts as a local change and overwrites a later edit made in the vault. |
| `DopplerNixBasePerRun` | each run keeps its own base | NoResurrection | Run 1 and run 2 share a file. Run 1 syncs key X; someone edits it to Y in Doppler; run 2, which has not synced since, sees X as its own change and writes it back over Y. |
| `DopplerNixPullPerRun` | each run keeps its own base | NoLostLocalChange | Run 1's program changes an API key. Run 2 starts on the same machine before run 1 has synced it; run 2's pull has no base, so the vault's copy wins and the new key is gone. |
| `LockStealNaive` | the stale lock check and its `rmdir` are two steps | MutualExclusion | Two runs find pi's abandoned lock stale; the first removes it and takes a fresh one; the second's `rmdir` removes that fresh lock, and both hold the lock. |

With every invariant checked, TLC also finds that blind writes can put back an API key
that was edited in Doppler since (NoResurrection), and that doppler-nix's rule "after a
pull, the pulled file is the base", combined with a shared base, marks a key that never
reached the vault as synced (NoLostLocalChange).

agent-vault removes each: guarded writes (compare-and-set, retried on conflict), the
rebase rule (`merge.rebase`), one base per machine under a sync mutex (`MachineState`),
and the steal mutex (`ToolLock._steal_if_stale`).

## Assumptions

The proofs hold under these assumptions. Each is either a property of the platform or a
condition agent-vault cannot enforce; none is hidden in the model.

- **V1. The vault's guarded write is atomic.** Doppler applies a change request "only if
  the provided value matches what's found in Doppler" (its API reference). Its docs do not
  say what it answers when the guard fails, so the adapter reads the secret again to tell a
  conflict from an error; that read is part of the modelled conflict. Not tested against
  Doppler itself here: the tests use a stand-in that enforces the guard as documented.
- **V2. Creating the secret.** A secret that does not exist yet has no value to guard on.
  The adapter checks after creating it that it holds its own value, and merges again if
  not; a second creator that writes after that check is outside the model. This can only
  happen on the very first write-back of a secret.
- **T1. Time keys are in step with real time.** A refresh gets a later time key (`expires`,
  `last_refresh`) than every earlier one. Two machines whose clocks differ by more than a
  token's lifetime could break this; it is how doppler-nix picks the newer copy too.
- **P1. The program writes its file under its own lock**, as pi (proper-lockfile) and codex
  (flock `auth.lock`) do, and by replacing it whole. A program that writes without its lock
  can race a merge.
- **L1. A live holder's lock directory is never stale.** proper-lockfile touches it every 5
  seconds and agent-vault holds it for milliseconds; a holder suspended for 10 seconds
  while it holds the lock (a laptop put to sleep at that moment) breaks this, for any lock
  of this kind.
- **L2. The program and agent-vault do not remove the same stale lock directory at once.**
  agent-vault cannot make pi take its steal mutex. `LockStealToolSteals` shows the race
  that remains if they do, right after a process died holding the lock.
- **F1. Files are replaced atomically** (rename over the file), and the session lock and
  the mutexes are flocks, which the kernel releases when their holder dies. Linux drops a
  shared flock before it tries to make it exclusive; the model does the same.

Bounded model checking explores every behaviour up to the bounds in the `.cfg` files (two
to four new credential values, one failure, two compare-and-set attempts). The protocol does not count or
compare these bounds, so a counterexample would need a longer behaviour of the same
shape; the random tests run longer schedules on the real code.

## How the code maps to the spec

| Spec action | Code |
| --- | --- |
| `Start`, `Release` | `SessionLock.acquire_shared`, `.release` in `cli.run` |
| `Begin`, end of an operation | `Syncer.begin`, `Syncer.end` (`MachineState.acquire`, `load_base`, `save_base`) |
| `PullRead`, `SyncRead`, `ExitRead` | `Syncer.fetch` (`Vault.read`) |
| `PullMerge` | `Syncer.merge_pulled` (`merge.pull`, `merge.rebase`) |
| `SyncMerge`, `ExitMerge` | `Syncer.reconcile` with and without `write_file` (`merge.push`) |
| `SyncWrite`, `ExitWrite` | `Syncer.publish` (`Vault.write`, `merge.rebase`) and the retry loops of `Syncer.step` and `Syncer.write_back` |
| `Exit` | the command ends, `Background.stop` |
| `Remove` | `Syncer.remove_if_last` (`SessionLock.try_exclusive`) |
| `ProgramWrite`, `Logout` | pi or codex writing its `auth.json` under its lock |
| `HandEdit` | a person editing the secret in Doppler |
| `Newer`, `Merge`, `Kept`, `RebaseTo` | `merge.newer`, `merge.merge`, `merge.push`'s `kept`, `merge.rebase` |

Each action is atomic in the spec for a reason in the code: a vault read or write is one
request (V1); a merge holds the tool lock, which the program also takes (P1); the sync
mutex keeps the runs of a machine from interleaving their operations; the session lock is
one flock call (F1).

## Running the checks

```sh
spec/check.sh                  # every configuration but the deep ones; downloads TLC 1.7.4 (checked)
spec/check.sh --deep           # all of them (about 50 minutes on 4 cores)
spec/check.sh LockSteal        # only those whose name starts with LockSteal
```

`check.sh` passes when the agent-vault configurations hold and each doppler-nix
configuration fails on the property named above. CI runs it on every push.
