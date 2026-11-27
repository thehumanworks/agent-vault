# Agent Vault

`avlt <harness>`: run a coding agent with its login file shared across machines through
one secret in a vault. It is a port of the synced-file launcher of
[doppler-nix](https://github.com/thehumanworks/doppler-nix) that needs no Nix: Python 3.10+
and nothing else.

```sh
avlt pi                 # pi, with ~/.pi/agent/auth.json synced through agents/pi PI_AUTH_JSON
avlt codex resume       # codex resume, with ~/.codex/auth.json synced through agents/codex CODEX_AUTH_JSON
```

Log in once on any machine (`avlt pi`, then `pi auth login <provider>` inside it); every
other machine that runs `avlt pi` gets the login, and a refresh token that the provider
rotates stays current on all of them.

## Install

agent-vault has no dependencies beyond Python's standard library.

```sh
uv tool install git+https://github.com/thehumanworks/agent-vault
# or
pipx install git+https://github.com/thehumanworks/agent-vault
```

With [mise](https://mise.jdx.dev), the same through its pipx backend:
`mise use -g "pipx:git+https://github.com/thehumanworks/agent-vault"`.

Doppler auth is yours to choose: `DOPPLER_TOKEN` (a personal or service token), or
`doppler login` if the Doppler CLI is installed. The CLI is not needed otherwise. Without
a login the command still starts, without secrets, and says so.

## What a run does

1. **Before the command starts**, credentials that are newer in the vault are merged into
   the file.
2. **While it runs**, a change to the file is written back within 2 seconds, and the secret
   is read every `--sync-interval` seconds (30) for credentials newer than the file's.
   Messages wait until the command exits. A credential the command removes (a logout)
   stays out of the file, but the vault keeps it.
3. **After it exits** (also after Ctrl-C, SIGTERM or SIGHUP), credentials newer locally are
   written back. The later `--time-key` wins; a credential without one (an API key) wins
   only if it changed since the last sync on this machine. A sync never deletes a
   credential, so a logout lasts until the next run.
4. **With `--remove-on-exit`** (pi's preset), the file is removed once the vault holds all
   of it and no other run on the machine still uses it.

The secret holds `{"<envelope>": <file>, "meta": {"lastRefreshed": <ms>}}`, the same
layout as doppler-nix, so both tools can share a secret. A secret without `<envelope>`
(the file pasted into the vault as it is) is taken as the file and wrapped on the first
write-back.

## Concurrency

Runs on one machine, runs on many machines, the wrapped program and people editing the
vault by hand may all touch the file and the secret at once. agent-vault keeps them
consistent with:

- **Guarded writes.** Every write of the secret is a compare-and-set: Doppler applies it only
  if the secret still holds the value the merge was made from (`originalValue`). When
  another machine wrote first, agent-vault reads the secret again and merges once more.
- **One sync at a time per machine**, under agent-vault's own lock, with one record of the
  last sync per file shared by all runs (`~/.local/state/agent-vault/`, as SHA-256 digests,
  so no credential is copied there).
- **The program's own lock** (pi's `auth.json.lock`, codex's `auth.lock`) around every
  read-merge-write of the file, and **atomic replacement** of the file (write, fsync,
  rename), so no reader ever sees part of one.

These are model-checked with TLA+ in [`spec/`](spec/README.md), which lists what is proven,
under which assumptions, and the four races of doppler-nix the model checker finds and
agent-vault removes.

## Usage

```
avlt [OPTIONS] pi|codex [ARGS...]
avlt [OPTIONS] run [OPTIONS] [--] COMMAND [ARGS...]
avlt [OPTIONS] pull|push [OPTIONS]
```

| Option | Meaning |
| --- | --- |
| `--preset pi\|codex` | The settings below, for that tool (`avlt pi` implies `--preset pi`). |
| `--vault NAME` | The store: `doppler` (default) or `file`, or an adapter installed as a plugin. |
| `-p`, `-c` | Doppler project and config. |
| `--vault-option KEY=VALUE` | A setting of the store (the file vault: `path=...`). |
| `-s`, `--secret` | The secret that holds the file. |
| `-f`, `--file` | The file; a leading `~/` is the home directory. |
| `-e`, `--envelope` | The key the file is stored under in the secret. |
| `-t`, `--time-key` | The key whose later value marks the newer copy (default `expires`). |
| `--per-entry` / `--whole-file` | An object of credentials, each merged on its own (default), or one credential. |
| `--lock-dir`, `--lock-file` | The lock the program takes on the file: a lock directory (default `FILE.lock`) or an flock. |
| `--remove-on-exit` / `--keep-on-exit` | Remove the file at the end (default: keep). |
| `--sync-interval SECONDS` | Seconds between reads of the secret while the command runs (default 30); `0` syncs only before and after. |
| `--only-secrets NAME` | Pass only these secrets to the command (repeatable). |
| `--name NAME` | Prefix for messages. |

| Preset | Settings |
| --- | --- |
| `pi` | `agents/pi`, `PI_AUTH_JSON`, `${PI_CODING_AGENT_DIR:-~/.pi/agent}/auth.json`, envelope `piAuthJson`, per provider by `expires`, removed on exit. Log in with `pi auth login <provider>`: pi takes `pi login …` as a prompt. |
| `codex` | `agents/codex`, `CODEX_AUTH_JSON`, `${CODEX_HOME:-~/.codex}/auth.json`, envelope `codexAuthJson`, the whole file by `last_refresh`, flock `auth.lock`. |

`avlt run -p PROJECT -c CONFIG -- COMMAND` without `--secret`, `--file` and `--envelope`
only passes the config's secrets to the command, like `doppler run`.

For a shell that cannot be wrapped, `avlt ... pull` does step 1 and prints the file's
path; `avlt ... push` does steps 3 and 4. In bash:

```sh
file=$(avlt --preset pi pull) && export AGENT_VAULT_BASE=$(cat "$file")
trap 'avlt --preset pi push' EXIT
```

Steps 2 to 4 apply only to what the launcher runs. A login made with the program on its
own is synced by the next run if it carries a later time key, as an OAuth login does.

## Vaults

The core talks to a store only through the `Vault` interface in
[`src/agent_vault/vault.py`](src/agent_vault/vault.py): read a secret, write it if it
still holds what was read, and list secrets for the command's environment. Adapters:

| Name | Module | Notes |
| --- | --- | --- |
| `doppler` | [`vaults/doppler.py`](src/agent_vault/vaults/doppler.py) | Doppler's HTTP API: `GET /v3/configs/config/secret`, `GET /v3/configs/config/secrets/download`, `POST /v3/configs/config/secrets` with `change_requests[].originalValue`. `DOPPLER_API_HOST` overrides `https://api.doppler.com`. |
| `file` | [`vaults/file.py`](src/agent_vault/vaults/file.py) | A JSON file, for tests and machines that share a filesystem. |

Another store (GCP Secret Manager, Infisical, SOPS, ...) is a class with the five methods
of `Vault`, registered as an entry point; nothing in the core changes:

```toml
[project.entry-points."agent_vault.vaults"]
infisical = "my_package.infisical:InfisicalVault"
```

Its `write` must be a compare-and-set for the cross-machine guarantees to hold; a store
without one sets `atomic_write = False`.

## Differences from doppler-nix

- No Nix, no `doppler` CLI, no `jq`, `flock` or coreutils: Python only.
- Writes to Doppler are guarded, and a run reads and merges again when it loses a race;
  doppler-nix's `doppler secrets set` could overwrite another machine's newer refresh.
- The record of the last sync is per machine, not per run, so a run that has not synced
  for a while no longer undoes an edit made in the vault. With that record, `push` and the
  start of a run keep a credential changed in the file since the last sync instead of
  replacing it with the vault's copy.
- A stale lock directory is removed under a lock of agent-vault's own, so two runs never
  both take it over.
- If Doppler cannot be reached at the start, the command starts with the file as it is
  (doppler-nix's `doppler run` did not start it), and the change is synced once Doppler
  is back.
- SIGTERM and SIGHUP sent to `avlt` are passed on to the command.
- The shell hooks and the Home Manager and NixOS modules are not ported; `pull` and `push`
  are the building blocks for them.

## Development

```sh
pip install -e '.[test]'
pytest                 # against a stand-in for Doppler's API; nothing talks to Doppler
spec/check.sh          # TLC on every model (Java 11+)
```
