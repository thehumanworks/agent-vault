"""The merge of a login file with the vault's copy of it.

A port of the jq program in doppler-nix's ``doppler-auth-sync``. The functions here are
pure: they take text and return text, so the concurrency model in ``spec/`` can treat a
merge as one step.

The vault's secret holds ``{"<envelope>": <file>, "meta": {"lastRefreshed": <ms>}}``. A
secret without ``<envelope>`` (the file pasted into the vault as it is) is taken as the
file and wrapped on the first write-back.

A file is split into *credentials* by name. With ``per_entry`` each top-level entry is
one credential (pi: one per provider); otherwise the whole file is one credential
(codex), stored under the name ``""``.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

Credentials = Dict[str, Any]
Digests = Dict[str, str]
"""A base: for each credential, the SHA-256 of its value when the file and the vault last
held the same value. Digests, not values, so the base never puts a credential on disk."""


class MergeError(Exception):
    """The data cannot be merged. The message never quotes the data."""


@dataclass(frozen=True)
class Format:
    """How the file and the secret are laid out."""

    envelope: str
    time_key: str = "expires"
    per_entry: bool = True


def _reject_constant(name: str) -> Any:
    raise ValueError(name)


def parse_object(text: Optional[str], what: str) -> Dict[str, Any]:
    """Blank text is ``{}``; anything else must be a JSON object."""
    if text is None or not text.strip():
        return {}
    try:
        value = json.loads(text, parse_constant=_reject_constant)
    except ValueError:
        value = None
    if not isinstance(value, dict):
        raise MergeError(f"{what} is not a JSON object")
    return value


def split(value: Dict[str, Any], fmt: Format, what: str) -> Credentials:
    if fmt.per_entry:
        if not all(isinstance(entry, dict) for entry in value.values()):
            raise MergeError(f"{what} is not an object of credentials")
        return dict(value)
    if not value:
        return {}
    return {"": value}


def join(creds: Credentials, fmt: Format) -> Dict[str, Any]:
    if fmt.per_entry:
        return dict(creds)
    return creds.get("", {})


_ISO = re.compile(r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(\.[0-9]+)?Z$")


def stamp(value: Any) -> Optional[float]:
    """A time to compare: a number as it is, or an ISO 8601 UTC time in seconds."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        match = _ISO.match(value)
        if match:
            try:
                seconds = calendar.timegm(time.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                return None
            return seconds + float("0" + (match.group(2) or ""))
    return None


def json_equal(a: Any, b: Any) -> bool:
    """Equality as jq has it: numbers by value, but ``true`` is not ``1``."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if type(a) is not type(b):
        return False
    return bool(a == b)


def _canonical(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def digest(value: Any) -> str:
    """A digest that is equal for two values exactly when :func:`json_equal` says so."""
    text = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode()).hexdigest()


def digests(creds: Credentials) -> Digests:
    return {name: digest(cred) for name, cred in creds.items()}


def base_of(text: Optional[str], fmt: Format) -> Digests:
    """The base of a file as text (``AGENT_VAULT_BASE``): every credential in it."""
    return digests(split(parse_object(text, "the synced file"), fmt, "the synced file"))


def newer(local: Any, remote: Any, base: Optional[str], time_key: str) -> Any:
    """The copy to keep of one credential (``None``: absent).

    A refreshing credential records when in ``time_key`` (an expiry or a refresh time):
    the later one wins, since it holds the current refresh token. Any other difference
    (an API key, equal times) goes to the local copy only if it changed since the file
    and the vault last held the same value (``base``, a digest); otherwise the vault's
    copy wins. A credential missing on one side is kept: a sync never deletes one.
    """
    if remote is None:
        return local
    if local is None:
        return remote
    lt = stamp(local.get(time_key))
    rt = stamp(remote.get(time_key))
    if lt is not None and rt is not None and lt != rt:
        return local if lt > rt else remote
    if digest(local) != base:
        return local
    return remote


def merge(local: Credentials, remote: Credentials, base: Digests, time_key: str) -> Credentials:
    names = sorted(set(local) | set(remote))
    return {
        name: newer(local.get(name), remote.get(name), base.get(name), time_key)
        for name in names
    }


def creds_equal(a: Credentials, b: Credentials) -> bool:
    return json_equal(a, b)


@dataclass(frozen=True)
class Remote:
    """The vault's secret, read as credentials."""

    creds: Credentials
    wrapped: bool
    last_refreshed: Any


def parse_remote(text: Optional[str], fmt: Format, what: str) -> Remote:
    doc = parse_object(text, what)
    wrapped = fmt.envelope in doc
    inner = doc[fmt.envelope] if wrapped else doc
    if not isinstance(inner, dict):
        raise MergeError(f"{fmt.envelope} in {what} is not a JSON object")
    meta = doc.get("meta") if wrapped else None
    refreshed = meta.get("lastRefreshed") if isinstance(meta, dict) else None
    return Remote(split(inner, fmt, what), wrapped, refreshed)


@dataclass(frozen=True)
class Pulled:
    file: Dict[str, Any]
    merged: Credentials
    changed: bool
    remote: Credentials
    last_refreshed: Any


def pull(
    local_text: Optional[str],
    remote_text: Optional[str],
    fmt: Format,
    vault: str,
    base: Optional[Digests] = None,
) -> Pulled:
    """Newer credentials from the vault, merged into the file.

    Without a base (no run on this machine has synced the file yet), every credential
    in the vault wins over the file's copy unless the file's has a later time, as in
    doppler-nix. With one, a credential changed in the file since the last sync is kept.
    """
    local = split(parse_object(local_text, "the local file"), fmt, "the local file")
    remote = parse_remote(remote_text, fmt, f"the {vault} secret")
    merged = merge(local, remote.creds, digests(local) if base is None else base, fmt.time_key)
    return Pulled(join(merged, fmt), merged, not creds_equal(merged, local), remote.creds, remote.last_refreshed)


@dataclass(frozen=True)
class Pushed:
    merged: Credentials
    """Every credential after the merge: what the vault holds once ``value`` is stored."""
    kept: Credentials
    """``merged`` without what the command removed."""
    local: Credentials
    """The file as read."""
    file: Dict[str, Any]
    """The file to keep on disk: ``merged`` without what the command removed."""
    changed: bool
    """Whether ``file`` differs from the file as read."""
    value: Optional[str]
    """The secret to store, or ``None`` when the vault already holds ``merged``."""
    remote: Credentials
    last_refreshed: Any


def push(
    local_text: Optional[str],
    remote_text: Optional[str],
    base: Digests,
    fmt: Format,
    vault: str,
    now_ms: Optional[int] = None,
) -> Pushed:
    """Merge the file into the vault's copy, given the base."""
    local = split(parse_object(local_text, "the local file"), fmt, "the local file")
    remote = parse_remote(remote_text, fmt, f"the {vault} secret")
    merged = merge(local, remote.creds, base, fmt.time_key)
    # A credential the command removed since the last sync (a logout) stays out of the
    # file while the command runs; the vault keeps it, since a sync never deletes one.
    gone = {name for name in base if name not in local}
    kept = {name: cred for name, cred in merged.items() if name not in gone}
    value = None
    if not creds_equal(merged, remote.creds) or (not remote.wrapped and merged):
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        value = dump_secret(join(merged, fmt), fmt, now_ms)
    return Pushed(
        merged=merged,
        kept=kept,
        local=local,
        file=join(kept, fmt),
        changed=not creds_equal(kept, local),
        value=value,
        remote=remote.creds,
        last_refreshed=remote.last_refreshed,
    )


def rebase(base: Optional[Digests], file: Credentials, vault: Credentials) -> Digests:
    """The base once the file holds ``file`` and the vault holds ``vault``.

    A credential whose copies are equal is in step: its base becomes that value. Any other
    keeps its base, so a copy still to be written back still counts as changed here, and
    one the command removed still counts as removed. doppler-nix kept the whole old base
    after a failed write instead, so a credential it had just pulled from the vault
    counted as a local change at the next try and could undo a newer edit made in the
    vault (spec/README.md).
    """
    base = base or {}
    result: Digests = {}
    for name in sorted(set(base) | set(file)):
        here, there = file.get(name), vault.get(name)
        if here is not None and there is not None and json_equal(here, there):
            result[name] = digest(here)
        elif name in base:
            result[name] = base[name]
    return result


def dump_secret(file: Dict[str, Any], fmt: Format, now_ms: int) -> str:
    return dump_compact({fmt.envelope: file, "meta": {"lastRefreshed": now_ms}})


def dump_compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def dump_file(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def last_refreshed_of(value: str) -> Any:
    try:
        doc = json.loads(value)
    except ValueError:
        return None
    meta = doc.get("meta") if isinstance(doc, dict) else None
    return meta.get("lastRefreshed") if isinstance(meta, dict) else None
