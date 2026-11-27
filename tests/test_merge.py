"""The merge, against the behaviour of doppler-nix's jq program."""

from __future__ import annotations

import json
import random

import pytest

from agent_vault import merge
from agent_vault.merge import Format, MergeError

PI = Format(envelope="piAuthJson", time_key="expires", per_entry=True)
CODEX = Format(envelope="codexAuthJson", time_key="last_refresh", per_entry=False)


def wrapped(fmt: Format, file: dict, refreshed: int = 1) -> str:
    return json.dumps({fmt.envelope: file, "meta": {"lastRefreshed": refreshed}})


def test_stamp() -> None:
    assert merge.stamp(100) == 100
    assert merge.stamp(1.5) == 1.5
    assert merge.stamp(True) is None
    assert merge.stamp("2026-01-01T00:00:00Z") == 1767225600
    assert merge.stamp("2026-02-01T00:00:00.5Z") == 1769904000.5
    assert merge.stamp("2026-02-01T00:00:00+00:00") is None
    assert merge.stamp("2026-13-01T00:00:00Z") is None
    assert merge.stamp(None) is None
    assert merge.stamp({"a": 1}) is None


def test_json_equal_is_jq_equality() -> None:
    assert merge.json_equal({"a": 1}, {"a": 1.0})
    assert not merge.json_equal({"a": True}, {"a": 1})
    assert not merge.json_equal([1, 2], [2, 1])
    assert merge.json_equal({"a": [1, {"b": None}]}, {"a": [1, {"b": None}]})


def test_newer() -> None:
    d = merge.digest
    old, new = {"access": "a1", "expires": 100}, {"access": "a2", "expires": 200}
    assert merge.newer(old, new, d(old), "expires") == new
    assert merge.newer(new, old, d(old), "expires") == new
    assert merge.newer(None, old, None, "expires") == old
    assert merge.newer(old, None, None, "expires") == old
    key1, key2, key3 = {"key": "k1"}, {"key": "k2"}, {"key": "k3"}
    assert merge.newer(key1, key2, d(key1), "expires") == key2  # unchanged here: the vault's wins
    assert merge.newer(key3, key2, d(key1), "expires") == key3  # changed here: the local one wins
    assert merge.newer(key3, key2, None, "expires") == key3  # no base: changed here
    same = {"access": "x", "expires": 100}
    assert merge.newer(same, old, d(same), "expires") == old  # equal times: as for a key


def test_digest_matches_json_equal() -> None:
    assert merge.digest({"a": 1, "b": [1.0]}) == merge.digest({"b": [1], "a": 1.0})
    assert merge.digest({"a": True}) != merge.digest({"a": 1})


def test_pull_merges_newer_credentials_into_the_file() -> None:
    local = json.dumps({"openai": {"access": "a2", "expires": 200}, "anthropic": {"key": "sk"}})
    remote = wrapped(PI, {"openai": {"access": "a3", "expires": 300}, "anthropic": {"key": "sk2"}})
    pulled = merge.pull(local, remote, PI, "Doppler")
    assert pulled.file == {"anthropic": {"key": "sk2"}, "openai": {"access": "a3", "expires": 300}}
    assert pulled.changed
    assert pulled.last_refreshed == 1


def test_pull_takes_a_pasted_file_as_it_is() -> None:
    pasted = json.dumps({"tokens": {"id": "t1"}, "last_refresh": "2026-01-01T00:00:00Z"})
    pulled = merge.pull("", pasted, CODEX, "Doppler")
    assert pulled.file == {"tokens": {"id": "t1"}, "last_refresh": "2026-01-01T00:00:00Z"}
    assert pulled.last_refreshed is None


def test_push_writes_back_wrapped() -> None:
    local = json.dumps({"openai": {"access": "a2", "expires": 200}, "anthropic": {"key": "sk"}})
    base = json.dumps({"openai": {"access": "a1", "expires": 100}})
    remote = json.dumps({"openai": {"access": "a1", "expires": 100}})  # pasted, unwrapped
    pushed = merge.push(local, remote, merge.base_of(base, PI), PI, "Doppler", now_ms=42)
    assert pushed.value is not None
    assert json.loads(pushed.value) == {
        "piAuthJson": {"anthropic": {"key": "sk"}, "openai": {"access": "a2", "expires": 200}},
        "meta": {"lastRefreshed": 42},
    }
    assert not pushed.changed


def test_push_without_changes_writes_nothing() -> None:
    file = {"openai": {"access": "a1", "expires": 100}}
    pushed = merge.push(json.dumps(file), wrapped(PI, file), merge.digests(file), PI, "Doppler")
    assert pushed.value is None
    assert not pushed.changed


def test_push_wraps_a_pasted_secret_even_when_equal() -> None:
    file = {"openai": {"access": "a1", "expires": 100}}
    pushed = merge.push(json.dumps(file), json.dumps(file), merge.digests(file), PI, "Doppler")
    assert pushed.value is not None and "piAuthJson" in json.loads(pushed.value)


def test_push_keeps_a_removed_credential_out_of_the_file_but_in_the_vault() -> None:
    base = {"openai": {"access": "a2", "expires": 200}, "other": {"access": "o1", "expires": 100}}
    local = {"other": {"access": "o1", "expires": 100}}
    pushed = merge.push(json.dumps(local), wrapped(PI, base), merge.digests(base), PI, "Doppler")
    assert pushed.file == local
    assert pushed.merged == base
    assert pushed.value is None


def test_errors_do_not_quote_the_data() -> None:
    secret = "sk-very-secret"
    with pytest.raises(MergeError) as e:
        merge.pull(f'{{"x": "{secret}"', "", PI, "Doppler")
    assert secret not in str(e.value)
    assert str(e.value) == "the local file is not a JSON object"
    with pytest.raises(MergeError, match="the Doppler secret is not a JSON object"):
        merge.pull("", f'["{secret}"]', PI, "Doppler")
    with pytest.raises(MergeError, match="is not an object of credentials"):
        merge.pull(json.dumps({"openai": secret}), "", PI, "Doppler")
    with pytest.raises(MergeError, match="piAuthJson in the Doppler secret is not a JSON object"):
        merge.pull("", json.dumps({"piAuthJson": secret}), PI, "Doppler")
    with pytest.raises(MergeError):
        merge.pull("NaN", "", CODEX, "Doppler")


def test_whole_file_is_one_credential() -> None:
    old = {"tokens": {"id": "t1"}, "last_refresh": "2026-01-01T00:00:00Z"}
    new = {"tokens": {"id": "t2"}, "last_refresh": "2026-02-01T00:00:00.5Z"}
    pushed = merge.push(
        json.dumps(new), json.dumps(old), merge.base_of(json.dumps(old), CODEX), CODEX, "Doppler"
    )
    assert json.loads(pushed.value or "{}")["codexAuthJson"] == new
    assert merge.pull("{}", "", CODEX, "Doppler").file == {}


def test_rebase_after_a_failed_write() -> None:
    """What the merge took from the vault becomes base; what must still reach it does not."""
    base = {"key": {"key": "k1"}, "openai": {"access": "a1", "expires": 100}}
    local = {"key": {"key": "k1"}, "openai": {"access": "a2", "expires": 200}}
    remote = {"key": {"key": "k2"}, "openai": {"access": "a1", "expires": 100}}
    pushed = merge.push(json.dumps(local), wrapped(PI, remote), merge.digests(base), PI, "Doppler")
    assert pushed.file == {"key": {"key": "k2"}, "openai": {"access": "a2", "expires": 200}}
    # The file now holds the merge; the write failed, so the vault still holds `remote`.
    after = merge.rebase(merge.digests(base), pushed.kept, pushed.remote)
    assert after == merge.digests({"key": {"key": "k2"}, "openai": {"access": "a1", "expires": 100}})
    # The next try, after the vault moved on to k3: the file's k2 is not a local change.
    remote3 = dict(remote, key={"key": "k3"})
    again = merge.push(json.dumps(pushed.file), wrapped(PI, remote3), after, PI, "Doppler")
    assert again.merged["key"] == {"key": "k3"}
    assert again.merged["openai"] == {"access": "a2", "expires": 200}


def test_rebase_keeps_a_logout_and_a_stale_file() -> None:
    base = merge.digests({"gone": {"key": "g"}, "kept": {"key": "k"}})
    after = merge.rebase(base, {"kept": {"key": "k2"}}, {})
    assert "gone" in after, "still counts as removed by the command at the next try"
    assert after["kept"] == base["kept"], "k2 still has to reach the vault"
    # The write-back does not write the file: a newer copy in the vault does not move the base.
    stale = merge.rebase(
        merge.digests({"main": {"key": "k1"}}), {"main": {"key": "k1"}}, {"main": {"key": "k2"}}
    )
    assert stale == merge.digests({"main": {"key": "k1"}})


# -- randomized properties ------------------------------------------------------------------

NAMES = ["openai", "anthropic", "google"]


def random_file(rng: random.Random) -> dict:
    file = {}
    for name in NAMES:
        roll = rng.random()
        if roll < 0.3:
            continue
        if roll < 0.7:
            file[name] = {"access": f"a{rng.randint(0, 3)}", "expires": rng.randint(0, 3)}
        else:
            file[name] = {"key": f"k{rng.randint(0, 2)}"}
    return file


@pytest.mark.parametrize("seed", range(20))
def test_properties(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(300):
        local, remote, base_file = random_file(rng), random_file(rng), random_file(rng)
        base = merge.digests(base_file)
        merged = merge.merge(local, remote, base, "expires")
        # A sync never deletes a credential.
        assert set(merged) == set(local) | set(remote)
        for name, cred in merged.items():
            # The result is one of the two copies.
            assert cred in (local.get(name), remote.get(name))
            lt = merge.stamp((local.get(name) or {}).get("expires"))
            rt = merge.stamp((remote.get(name) or {}).get("expires"))
            got = merge.stamp(cred.get("expires"))
            # A later time always wins.
            if lt is not None and rt is not None:
                assert got == max(lt, rt)
            # An unchanged local copy never overrides the vault's.
            if (
                name in remote
                and local.get(name) == base_file.get(name)
                and (lt is None or rt is None or lt == rt)
            ):
                assert cred == remote[name]
        # Merging again changes nothing (idempotent), from either side.
        assert merge.merge(merged, remote, base, "expires") == merged
        # For credentials with two different times, the side does not matter.
        swapped = merge.merge(remote, local, base, "expires")
        for name in merged:
            lt = merge.stamp((local.get(name) or {}).get("expires"))
            rt = merge.stamp((remote.get(name) or {}).get("expires"))
            if lt is not None and rt is not None and lt != rt:
                assert swapped[name] == merged[name]
