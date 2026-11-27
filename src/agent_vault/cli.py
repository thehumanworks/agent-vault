"""``avlt``: run a coding agent with its login file synced through a vault secret."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, NoReturn, Optional, Sequence

from . import __version__, merge
from .localfile import SessionLock, read_text
from .merge import Format, MergeError
from .presets import PRESETS
from .sync import Background, Messages, Settings, Syncer
from .vault import Vault, VaultError, open_vault

USAGE = """\
Usage: avlt [OPTIONS] pi|codex [ARGS...]
       avlt [OPTIONS] run [OPTIONS] [--] COMMAND [ARGS...]
       avlt [OPTIONS] pull|push [OPTIONS]

Runs a command with the secrets of one vault scope (a Doppler config), and
shares its login file (an auth.json) across machines through one secret there:

  - Before the command starts, credentials that are newer in the vault are
    merged into the file.
  - While it runs, a change to the file is written back within 2 seconds,
    and the secret is read every --sync-interval seconds for credentials
    newer than the file's, so a refresh token that the provider replaces at
    each refresh stays current on every machine. Messages wait until the
    command exits, and what the command removes from the file stays out of it.
  - After it exits (also after Ctrl-C, SIGTERM or SIGHUP), credentials that
    are newer locally are written back. The later --time-key wins; a
    credential without one (an API key) wins only if it changed since the
    last sync. A sync never deletes a credential, so a logout lasts until the
    next run.

Every write to the vault is a compare-and-set: when another machine wrote the
secret in between, the merge is done again on its copy, so no refreshed
credential is lost (see spec/README.md).

  pi, codex  run that tool with its preset: `avlt pi ARGS` is
             `avlt --preset pi run -- pi ARGS`
  run        run COMMAND; without --preset, --secret, --file and --envelope,
             only the scope's secrets are passed (no file is synced)
  pull       do only the first step, then print the file's path
  push       do only the last step (and --remove-on-exit). A credential without
             a later --time-key wins if it changed since the last sync on this
             machine; when none is recorded, if it differs from AGENT_VAULT_BASE
             (the file as it was after pull), or always when that is not set.

The secret holds {"<envelope>": <file>, "meta": {"lastRefreshed": <ms>}}. A
secret without <envelope> (the file pasted into the vault as it is) is taken as
the file and wrapped on the first write-back. Without a vault login
(Doppler: `doppler login` or DOPPLER_TOKEN), the command runs on its own.

Presets (options given explicitly win):
{presets}

Options:
      --preset NAME      pi or codex: the settings below, for that tool
      --vault NAME       the store: doppler (default) or file
  -p, --project NAME     Doppler project (the vault option project)
  -c, --config NAME      Doppler config (the vault option config)
      --vault-option KEY=VALUE  a setting of the store (repeatable)
  -s, --secret NAME      secret that holds the file
  -f, --file PATH        the login file (a leading ~/ is your home directory)
  -e, --envelope KEY     key the file is stored under in the secret
  -t, --time-key KEY     key whose later value marks the newer copy: a number
                         or an ISO 8601 UTC time (default: expires)
      --per-entry        the file is an object of credentials, each merged on
                         its own, e.g. one per provider (default)
      --whole-file       the whole file is one credential
      --lock-dir PATH    the lock directory the command takes on the file, as
                         proper-lockfile does (default: FILE.lock)
      --lock-file PATH   flock this file instead
      --remove-on-exit   delete the file after a successful write-back, unless
                         another run on this machine still uses it
      --keep-on-exit     keep the file (default)
      --sync-interval SECONDS  how often the secret is read while the command
                         runs (default 30); 0 syncs only before and after
      --only-secrets NAME  pass only these secrets to the command (repeatable)
      --name NAME        prefix for messages (default: the command's name)
  -h, --help             show this help
      --version          show the version

Environment: DOPPLER_TOKEN, DOPPLER_API_HOST (default https://api.doppler.com).

Examples:
  avlt pi
  alias codex='avlt codex'
  avlt --vault file --vault-option path=/srv/vault.json --preset pi pull
"""

MAX_DEPTH = 4
DEPTH_VARIABLE = "AGENT_VAULT_DEPTH"
BASE_VARIABLE = "AGENT_VAULT_BASE"


class UsageError(Exception):
    pass


@dataclass
class Options:
    preset: Optional[str] = None
    vault: Optional[str] = None
    vault_options: Dict[str, str] = field(default_factory=dict)
    secret: Optional[str] = None
    file: Optional[str] = None
    envelope: Optional[str] = None
    time_key: Optional[str] = None
    per_entry: Optional[bool] = None
    lock_dir: Optional[str] = None
    lock_file: Optional[str] = None
    remove_on_exit: Optional[bool] = None
    sync_interval: int = 30
    only: List[str] = field(default_factory=list)
    name: Optional[str] = None
    action: Optional[str] = None
    command: List[str] = field(default_factory=list)


VALUE_OPTIONS = {
    "--preset": "preset",
    "--vault": "vault",
    "-s": "secret",
    "--secret": "secret",
    "-f": "file",
    "--file": "file",
    "-e": "envelope",
    "--envelope": "envelope",
    "-t": "time_key",
    "--time-key": "time_key",
    "--lock-dir": "lock_dir",
    "--lock-file": "lock_file",
    "--name": "name",
}


def parse(argv: Sequence[str]) -> Options:
    opts = Options()
    args = list(argv)
    i = 0

    def value() -> str:
        nonlocal i
        if i + 1 >= len(args):
            raise UsageError(f"{args[i]} needs a value")
        i += 1
        return args[i]

    while i < len(args):
        arg = args[i]
        if arg in VALUE_OPTIONS:
            setattr(opts, VALUE_OPTIONS[arg], value())
        elif arg in ("-p", "--project"):
            opts.vault_options["project"] = value()
        elif arg in ("-c", "--config"):
            opts.vault_options["config"] = value()
        elif arg == "--vault-option":
            key, sep, val = value().partition("=")
            if not sep or not key:
                raise UsageError("--vault-option takes KEY=VALUE")
            opts.vault_options[key] = val
        elif arg == "--per-entry":
            opts.per_entry = True
        elif arg == "--whole-file":
            opts.per_entry = False
        elif arg == "--remove-on-exit":
            opts.remove_on_exit = True
        elif arg == "--keep-on-exit":
            opts.remove_on_exit = False
        elif arg == "--sync-interval":
            text = value()
            if not re.fullmatch(r"[0-9]{1,6}", text):
                raise UsageError("--sync-interval takes a whole number of seconds")
            opts.sync_interval = int(text)
        elif arg == "--only-secrets":
            opts.only.append(value())
        elif arg in ("-h", "--help"):
            opts.action = "help"
            return opts
        elif arg == "--version":
            opts.action = "version"
            return opts
        elif arg == "--":
            if opts.action not in (None, "run"):
                raise UsageError(f"{opts.action} takes no command")
            opts.action = "run"
            opts.command = args[i + 1 :]
            break
        elif arg.startswith("-") and arg != "-":
            raise UsageError(f"unknown option {arg} (see --help)")
        elif opts.action is None and arg in PRESETS:
            opts.action = "run"
            if opts.preset is None:
                opts.preset = arg
            opts.command = [PRESETS[arg].program] + args[i + 1 :]
            break
        elif opts.action is None and arg in ("run", "pull", "push"):
            opts.action = arg
        elif opts.action == "run":
            opts.command = args[i:]
            break
        elif opts.action in ("pull", "push"):
            raise UsageError(f"{opts.action} takes no command")
        else:
            raise UsageError(f"unknown command {arg} (see --help)")
        i += 1
    if opts.action is None:
        raise UsageError("no command given (see --help)")
    if opts.action == "run" and not opts.command:
        raise UsageError("no command given (see --help)")
    if opts.lock_dir and opts.lock_file:
        raise UsageError("--lock-dir and --lock-file exclude each other")
    return opts


def expand(path: str) -> Path:
    if path.startswith("~/"):
        return Path.home() / path[2:]
    return Path(path)


def resolve_file(path: Path) -> Path:
    """The file's absolute path, with its directory created and symlinks resolved: a
    symlinked file is locked and written at its target."""
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = path.parent.resolve() / path.name
    if path.exists():
        path = path.resolve()
    return path


@dataclass
class Invocation:
    vault_kind: str
    vault_options: Dict[str, str]
    name: str
    settings: Optional[Settings]


def prepare(opts: Options) -> Invocation:
    preset = PRESETS.get(opts.preset) if opts.preset else None
    if opts.preset and preset is None:
        raise UsageError(f"unknown preset {opts.preset} ({', '.join(PRESETS)})")
    vault_options = dict(preset.vault_options) if preset else {}
    vault_options.update(opts.vault_options)
    vault_kind = opts.vault or (preset.vault if preset else "doppler")
    command_name = os.path.basename(opts.command[0]) if opts.command else "avlt"
    name = opts.name or (preset.name if preset else command_name)

    secret = opts.secret or (preset.secret if preset else None)
    file = expand(opts.file) if opts.file else (preset.file() if preset else None)
    envelope = opts.envelope or (preset.envelope if preset else None)
    if preset is None and opts.action == "run" and not (secret or file or envelope):
        return Invocation(vault_kind, vault_options, name, None)
    for option, given in (("secret", secret), ("file", file), ("envelope", envelope)):
        if not given:
            raise UsageError(f"--{option} is required (or use --preset)")
    assert secret and file and envelope
    lock_dir = expand(opts.lock_dir) if opts.lock_dir else None
    lock_file = expand(opts.lock_file) if opts.lock_file else None
    if preset and lock_dir is None and lock_file is None:
        lock_file = preset.lock_file()
    resolved = resolve_file(file)
    settings = Settings(
        name=name,
        secret=secret,
        file=resolved,
        fmt=Format(
            envelope=envelope,
            time_key=opts.time_key or (preset.time_key if preset else "expires"),
            per_entry=opts.per_entry
            if opts.per_entry is not None
            else (preset.per_entry if preset else True),
        ),
        lock_dir=lock_dir.absolute() if lock_dir else None,
        lock_file=lock_file.absolute() if lock_file else None,
        remove_on_exit=(
            opts.remove_on_exit
            if opts.remove_on_exit is not None
            else (preset.remove_on_exit if preset else False)
        ),
        sync_interval=opts.sync_interval,
    )
    return Invocation(vault_kind, vault_options, name, settings)


def usage() -> str:
    presets = "\n".join(f"  {p.name:<6} {p.description}" for p in PRESETS.values())
    return USAGE.replace("{presets}", presets)


def die(message: str, name: str = "avlt") -> NoReturn:
    print(f"{name}: {message}", file=sys.stderr)
    sys.exit(2)


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        opts = parse(sys.argv[1:] if argv is None else argv)
        if opts.action == "help":
            print(usage(), end="")
            return 0
        if opts.action == "version":
            print(f"avlt {__version__}")
            return 0
        invocation = prepare(opts)
        vault = open_vault(invocation.vault_kind, invocation.vault_options)
    except (UsageError, ValueError) as e:
        die(str(e))
    except OSError as e:
        die(f"cannot prepare the file: {e.strerror or e}")
    depth = _depth()
    if depth >= MAX_DEPTH:
        die(
            f"nested {MAX_DEPTH} levels deep; is {opts.command[0] if opts.command else 'the command'} "
            "a wrapper that calls avlt again?",
            invocation.name,
        )
    say = Messages(invocation.name)
    if opts.action == "run":
        return run(invocation, vault, opts, say, depth)
    assert invocation.settings is not None
    if opts.action == "pull":
        return pull(invocation.settings, vault, say)
    return push(invocation.settings, vault, say)


def _depth() -> int:
    try:
        return int(os.environ.get(DEPTH_VARIABLE, "0"))
    except ValueError:
        return 0


def _child_env(
    vault: Vault, opts: Options, settings: Optional[Settings], say: Messages, depth: int
) -> Dict[str, str]:
    env = dict(os.environ)
    env.pop(BASE_VARIABLE, None)
    env[DEPTH_VARIABLE] = str(depth + 1)
    try:
        secrets = vault.environment(opts.only or None)
    except VaultError:
        say(f"could not read {vault.label} from {vault.kind}; starting without its secrets")
        secrets = {}
    env.update(secrets)
    if settings is not None:
        env.pop(settings.secret, None)  # the command reads the file, not this variable
    return env


def run(invocation: Invocation, vault: Vault, opts: Options, say: Messages, depth: int) -> int:
    command = opts.command
    problem = vault.login_problem()
    if problem:
        say(f"{problem}; starting without {vault.label} secrets")
        return _exec(command, dict(os.environ, **{DEPTH_VARIABLE: str(depth + 1)}), say)
    settings = invocation.settings
    env = _child_env(vault, opts, settings, say, depth)
    if settings is None:
        return _exec(command, env, say)

    session = SessionLock(settings.file.parent)
    session.acquire_shared()
    syncer = Syncer(settings, vault, say)
    if syncer.pull() == "unreadable":
        say(f"could not read {settings.secret} from {vault.kind}; starting with {settings.file} as it is")

    background = None
    if settings.sync_interval > 0:
        syncer.seen = read_text(settings.file)
        syncer.seen_remote = syncer.pulled.value if syncer.pulled else None
        say.quiet = True
        background = Background(syncer)
        background.start()

    status = _run_child(command, env, say)

    if background is not None:
        background.stop()
        say.flush()
        if background.crashed:
            say("the sync during the run stopped early; syncing now")
    with _exit_signals():
        syncer.finish(session)
    session.release()
    return status


def pull(settings: Settings, vault: Vault, say: Messages) -> int:
    problem = vault.login_problem()
    if problem:
        say(f"{problem}; not syncing {settings.file}")
        return 0
    syncer = Syncer(settings, vault, say)
    if syncer.pull() == "unreadable":
        say(f"could not read {settings.secret} from {vault.kind}; left {settings.file} as it is")
    print(settings.file)
    return 0


def push(settings: Settings, vault: Vault, say: Messages) -> int:
    problem = vault.login_problem()
    if problem:
        say(f"{problem}; not syncing {settings.file}")
        return 0
    session = SessionLock(settings.file.parent)
    session.acquire_shared()
    syncer = Syncer(settings, vault, say)
    # The machine's base wins when a run here has synced the file (begin() loads it);
    # otherwise the file as it was after `avlt pull`, or none: then the local copy wins.
    try:
        syncer.base = merge.base_of(os.environ.get(BASE_VARIABLE, ""), settings.fmt)
    except MergeError:
        syncer.base = {}
    with _exit_signals():
        syncer.finish(session)
    session.release()
    return 0


def _exec(command: Sequence[str], env: Dict[str, str], say: Messages) -> int:
    try:
        os.execvpe(command[0], list(command), env)
    except OSError as e:
        say(f"cannot run {command[0]}: {e.strerror or e}")
        return 127
    return 0  # not reached


def _run_child(command: Sequence[str], env: Dict[str, str], say: Messages) -> int:
    """Run the command to its end, outliving the signals that end it so its credentials
    are still written back. Ctrl-C reaches the command from the terminal; SIGTERM and
    SIGHUP sent to agent-vault are passed on to it."""
    child: Optional[subprocess.Popen[bytes]] = None
    pending: List[int] = []

    def forward(signum: int, _frame: object) -> None:
        if child is None:
            pending.append(signum)
        else:
            try:
                child.send_signal(signum)
            except OSError:
                pass

    def ignore(_signum: int, _frame: object) -> None:
        pass

    # Handlers, not SIG_IGN: an ignored signal would stay ignored in the command.
    previous = {
        signal.SIGINT: signal.signal(signal.SIGINT, ignore),
        signal.SIGQUIT: signal.signal(signal.SIGQUIT, ignore),
        signal.SIGTERM: signal.signal(signal.SIGTERM, forward),
        signal.SIGHUP: signal.signal(signal.SIGHUP, forward),
    }
    try:
        try:
            child = subprocess.Popen(list(command), env=env)
        except OSError as e:
            say.flush()
            say(f"cannot run {command[0]}: {e.strerror or e}")
            return 127
        for signum in pending:
            forward(signum, None)
        code = child.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 128 - code if code < 0 else code


class _exit_signals:
    """During the write-back, SIGTERM and SIGHUP end agent-vault through an exception, so
    the tool lock is released on the way out."""

    def __enter__(self) -> None:
        def stop(signum: int, _frame: object) -> None:
            raise SystemExit(128 + signum)

        self.previous = {s: signal.signal(s, stop) for s in (signal.SIGTERM, signal.SIGHUP)}

    def __exit__(self, *exc: object) -> None:
        for signum, handler in self.previous.items():
            signal.signal(signum, handler)
