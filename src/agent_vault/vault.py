"""The interface between agent-vault and a secret store.

The core (``sync``, ``cli``) talks to a store only through :class:`Vault`. An adapter
lives in its own module and is found by name: the built-in ones below, or any package
that declares an ``agent_vault.vaults`` entry point::

    [project.entry-points."agent_vault.vaults"]
    infisical = "my_package.infisical:InfisicalVault"

The one guarantee the core relies on is that :meth:`Vault.write` is a compare-and-set:
it stores a value only if the secret still holds what :meth:`Vault.read` returned. With
that, the sync protocol in ``spec/AgentVaultSync.tla`` loses no update across machines.
A store without such a write sets ``atomic_write = False``; agent-vault then still syncs,
but only the guarantees for runs on one machine hold.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Dict, Mapping, Optional, Sequence, Type


class VaultError(Exception):
    """The store could not be reached or refused a request. The message holds no secret."""


@dataclass(frozen=True)
class Snapshot:
    """A secret as read: its value (``None`` when it does not exist) and a version token.

    The token is opaque to the core; an adapter puts in it whatever its compare-and-set
    needs (Doppler: the value itself; another store: a version number or an etag).
    """

    value: Optional[str]
    token: Any = None


class Vault(abc.ABC):
    """A secret store holding named string secrets in one scope (a Doppler config)."""

    kind: str = "vault"
    """A name for messages: ``"Doppler"``."""

    atomic_write: bool = True
    """Whether :meth:`write` is a compare-and-set (see the module docstring)."""

    @classmethod
    @abc.abstractmethod
    def from_options(cls, options: Mapping[str, str]) -> "Vault":
        """Build the adapter from ``--vault-option KEY=VALUE`` settings.

        ``-p/--project`` and ``-c/--config`` arrive as ``project`` and ``config``. Raise
        ``ValueError`` with a short message for a missing or unknown option.
        """

    @property
    @abc.abstractmethod
    def label(self) -> str:
        """The scope, for messages: ``agents/pi``."""

    @abc.abstractmethod
    def login_problem(self) -> Optional[str]:
        """``None`` when the store can be used, else why not (``"no Doppler login"``).

        Without a login the command still runs, without secrets, as in doppler-nix.
        """

    @abc.abstractmethod
    def environment(self, only: Optional[Sequence[str]] = None) -> Dict[str, str]:
        """The secrets to put in the command's environment: all, or only these names."""

    @abc.abstractmethod
    def read(self, name: str) -> Snapshot:
        """The secret ``name`` now. Raises :class:`VaultError`."""

    @abc.abstractmethod
    def write(self, name: str, value: str, expected: Snapshot) -> bool:
        """Store ``value`` as ``name`` if the secret still matches ``expected``.

        Returns ``True`` when stored, ``False`` when the secret changed since ``expected``
        was read (the caller reads it again and merges). Raises :class:`VaultError` for
        anything else.
        """


BUILTIN: Dict[str, str] = {
    "doppler": "agent_vault.vaults.doppler:DopplerVault",
    "file": "agent_vault.vaults.file:FileVault",
}


def _load(target: str) -> Type[Vault]:
    module, _, attr = target.partition(":")
    cls = getattr(import_module(module), attr)
    if not (isinstance(cls, type) and issubclass(cls, Vault)):
        raise ValueError(f"{target} is not a Vault")
    return cls


def adapter(kind: str) -> Type[Vault]:
    """The adapter class registered as ``kind``."""
    if kind in BUILTIN:
        return _load(BUILTIN[kind])
    from importlib.metadata import entry_points

    for entry in entry_points(group="agent_vault.vaults"):
        if entry.name == kind:
            return _load(entry.value)
    known = ", ".join(sorted(BUILTIN))
    raise ValueError(f"unknown vault {kind} ({known}, or an agent_vault.vaults entry point)")


def open_vault(kind: str, options: Mapping[str, str]) -> Vault:
    return adapter(kind).from_options(options)
