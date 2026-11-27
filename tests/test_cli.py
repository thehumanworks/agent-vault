"""The behaviour of doppler-nix's tests/run.sh, ported to avlt, against the fake Doppler.

Each block names the doppler-nix section it reproduces.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import time
from pathlib import Path

from conftest import Avlt, compact, program, py, wait_for
from fake_doppler import TOKEN, FakeDoppler

PI_FILE = ".pi/agent/auth.json"
CODEX_FILE = ".codex/auth.json"
TOOL = ["-p", "app", "-c", "dev", "-s", "TOOL_AUTH", "-f", "~/.tool/auth.json", "-e", "toolAuth"]


def pi_secret(doppler: FakeDoppler) -> dict:
    return doppler.doc("agents", "pi", "PI_AUTH_JSON")


# == withSecrets: a command with the secrets of one config ===================================


def test_all_secrets_reach_the_program(avlt: Avlt, home: Path) -> None:
    out = home / "out"
    code = f"import os; open({str(out)!r}, 'w').write(os.environ['API_KEY'] + '/' + os.environ['OTHER'] + '/' + os.environ['DOPPLER_CONFIG'])"
    result = avlt("run", "-p", "app", "-c", "dev", "--", *py(code))
    assert result.returncode == 0, result.stderr
    assert out.read_text() == "key-1/other-1/dev"


def test_only_the_listed_secrets_and_arguments_kept(avlt: Avlt, home: Path) -> None:
    out = home / "out"
    code = f"import os, sys; open({str(out)!r}, 'w').write(os.environ['API_KEY'] + '/' + os.environ.get('OTHER', 'unset') + '/' + sys.argv[1])"
    avlt("run", "-p", "app", "-c", "dev", "--only-secrets", "API_KEY", "--", *py(code), "arg", check=True)
    assert out.read_text() == "key-1/unset/arg"


def test_the_programs_exit_status(avlt: Avlt) -> None:
    assert avlt("run", "-p", "app", "-c", "dev", "--", *py("raise SystemExit(7)")).returncode == 7


def test_no_login_runs_the_program_without_secrets(avlt: Avlt, home: Path) -> None:
    out = home / "out"
    code = f"import os; open({str(out)!r}, 'w').write(os.environ.get('API_KEY', 'unset'))"
    result = avlt("--name", "all", "run", "-p", "app", "-c", "dev", "--", *py(code), env={"DOPPLER_TOKEN": ""})
    assert out.read_text() == "unset"
    assert "all: no Doppler login; starting without app/dev secrets" in result.stderr


def test_doppler_down_at_start_runs_the_program_without_secrets(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.down = True
    out = home / "out"
    code = f"import os; open({str(out)!r}, 'w').write(os.environ.get('API_KEY', 'unset'))"
    result = avlt("--name", "all", "run", "-p", "app", "-c", "dev", "--", *py(code))
    assert result.returncode == 0
    assert out.read_text() == "unset"
    assert "all: could not read app/dev from Doppler; starting without its secrets" in result.stderr


# == withSyncedFile: pi (per provider, removed on exit) =====================================


def test_pi(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"openai": {"access": "a1", "expires": 100}}, "PI_KEY": "k"})
    out = home / "out"
    body = f"""
f = H / {PI_FILE!r}
open({str(out)!r}, "w").write(json.dumps([load(f), os.environ["PI_KEY"], os.environ.get("PI_AUTH_JSON", "unset"), os.environ.get("AGENT_VAULT_BASE", "unset")]))
v = load(f); v["openai"] = {{"access": "a2", "expires": 200}}; v["anthropic"] = {{"key": "sk"}}; save(f, v)
"""
    result = avlt("run", "--preset", "pi", "--", *program(body))
    assert result.returncode == 0, result.stderr
    assert json.loads(out.read_text()) == [{"openai": {"access": "a1", "expires": 100}}, "k", "unset", "unset"]
    doc = pi_secret(doppler)
    assert doc["piAuthJson"] == {"anthropic": {"key": "sk"}, "openai": {"access": "a2", "expires": 200}}
    assert isinstance(doc["meta"]["lastRefreshed"], int)
    assert compact(home / PI_FILE) is None, "the file is removed"
    assert "pi: wrote newer credentials back to PI_AUTH_JSON" in result.stderr


def test_pi_harness_form(avlt: Avlt, doppler: FakeDoppler, home: Path, tmp_path: Path) -> None:
    """`avlt pi ARGS` runs `pi ARGS` from PATH with the pi preset."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_pi = bin_dir / "pi"
    fake_pi.write_text(f"#!/bin/sh\necho \"$@\" > {home}/args\n")
    fake_pi.chmod(0o755)
    result = avlt("pi", "--model", "x", env={"PATH": f"{bin_dir}:{os.environ['PATH']}"})
    assert result.returncode == 0, result.stderr
    assert (home / "args").read_text() == "--model x\n"


def test_a_later_expiry_in_doppler_replaces_the_local_one(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {
        "openai": {"access": "a3", "expires": 300}, "anthropic": {"key": "sk"}}}})
    f = home / PI_FILE
    f.parent.mkdir(parents=True)
    f.write_text(json.dumps({"openai": {"access": "a2", "expires": 200}, "anthropic": {"key": "sk"}}))
    out = home / "out"
    avlt("run", "--preset", "pi", "--", *program(f"open({str(out)!r}, 'w').write(load(H / {PI_FILE!r})['openai']['access'])"), check=True)
    assert out.read_text() == "a3"


def test_doppler_down_at_exit_keeps_the_file(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    body = f"""
doppler_down(True)
save(H / {PI_FILE!r}, {{"openai": {{"access": "a4", "expires": 400}}}})
"""
    result = avlt("run", "--preset", "pi", "--", *program(body))
    assert compact(home / PI_FILE) == {"openai": {"access": "a4", "expires": 400}}
    assert "pi: could not read PI_AUTH_JSON from Doppler; newer credentials stay in" in result.stderr


# == withSyncedFile: codex (one login, kept) ===============================================


def test_codex(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("agents", "codex", {"CODEX_AUTH_JSON": {"tokens": {"id": "t1"}, "last_refresh": "2026-01-01T00:00:00Z"}})
    out = home / "out"
    body = f"""
f = H / {CODEX_FILE!r}
open({str(out)!r}, "w").write(load(f)["tokens"]["id"])
save(f, {{"tokens": {{"id": "t2"}}, "last_refresh": "2026-02-01T00:00:00.5Z"}})
"""
    avlt("run", "--preset", "codex", "--", *program(body), check=True)
    assert out.read_text() == "t1", "the pasted file is taken as it is"
    assert doppler.doc("agents", "codex", "CODEX_AUTH_JSON")["codexAuthJson"]["tokens"]["id"] == "t2"
    assert compact(home / CODEX_FILE)["tokens"]["id"] == "t2", "the file is kept"
    assert (home / ".codex/auth.lock").exists(), "codex's own flock file is the lock"


# == withSyncedFile: own settings ==========================================================


def test_own_settings(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    out = home / "out"
    body = f"""
open({str(out)!r}, "w").write(os.environ["API_KEY"] + "/" + os.environ.get("OTHER", "unset") + "/" + os.environ["PATH"].split(":")[0])
(H / ".tool").mkdir(exist_ok=True); save(H / ".tool/auth.json", {{"main": {{"key": "k1"}}}})
"""
    env = {"PATH": "/caller/bin:" + os.environ["PATH"]}
    avlt("run", *TOOL, "--only-secrets", "API_KEY", "--", *program(body), env=env, check=True)
    assert out.read_text() == "key-1/unset//caller/bin"
    assert doppler.doc("app", "dev", "TOOL_AUTH")["toolAuth"] == {"main": {"key": "k1"}}, "a new secret is created"
    assert compact(home / ".tool/auth.json") == {"main": {"key": "k1"}}, "~/ is the home directory; kept"
    result = avlt("run", *TOOL, "--", *py(f"open({str(out)!r}, 'w').write('ran')"), env={"DOPPLER_TOKEN": ""})
    assert out.read_text() == "ran"
    assert result.returncode == 0


def test_the_file_is_private_and_written_at_a_symlinks_target(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("app", "dev", {"TOOL_AUTH": {"toolAuth": {"main": {"key": "k1"}}}})
    real = home / "real" / "auth.json"
    real.parent.mkdir()
    real.write_text("{}")
    (home / ".tool").mkdir()
    (home / ".tool/auth.json").symlink_to(real)
    avlt("run", *TOOL, "--", *py("pass"), check=True)
    assert (home / ".tool/auth.json").is_symlink()
    assert compact(real) == {"main": {"key": "k1"}}
    assert stat.S_IMODE(real.stat().st_mode) == 0o600


# == doppler-auth-sync while the command runs ================================================

LIVE = ["--preset", "pi", "--sync-interval", "1"]


def test_sync_while_the_command_runs(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {
        "openai": {"access": "a1", "expires": 100}, "other": {"access": "o1", "expires": 100}}}})
    out = home / "out"
    body = f"""
f = H / {PI_FILE!r}
got = []
v = load(f); v["openai"] = {{"access": "a2", "expires": 200}}; save(f, v)
got.append(until(lambda: remote("agents", "pi", "PI_AUTH_JSON")["piAuthJson"]["openai"]["access"], "a2"))
doc = remote("agents", "pi", "PI_AUTH_JSON"); doc["piAuthJson"]["other"] = {{"access": "o3", "expires": 300}}
remote_set("agents", "pi", "PI_AUTH_JSON", doc)
got.append(until(lambda: load(f)["other"]["access"], "o3"))
v = load(f); del v["openai"]; save(f, v)
time.sleep(2.5)
got.append(sorted(load(f)))
open({str(out)!r}, "w").write(json.dumps(got))
print("the command ends", file=sys.stderr, flush=True)
"""
    result = avlt("run", *LIVE, "--", *program(body))
    assert result.returncode == 0, result.stderr
    got = json.loads(out.read_text())
    assert got[0] == "a2", "a change to the file reaches Doppler while the command runs"
    assert got[1] == "o3", "a newer credential in Doppler reaches the file while it runs"
    assert got[2] == ["other"], "a credential the command removed stays out of the file while it runs"
    assert pi_secret(doppler)["piAuthJson"]["openai"]["access"] == "a2", "and Doppler keeps it"
    assert result.stderr.splitlines()[0] == "the command ends", "messages wait until the command exits"
    assert "pi: wrote newer credentials back to PI_AUTH_JSON during the run" in result.stderr


def test_a_key_changed_in_doppler_after_the_last_sync_is_not_undone_at_exit(avlt: Avlt, doppler: FakeDoppler) -> None:
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {"anthropic": {"key": "k1"}}}})
    body = f"""
save(H / {PI_FILE!r}, {{"anthropic": {{"key": "k2"}}}})
until(lambda: remote("agents", "pi", "PI_AUTH_JSON")["piAuthJson"]["anthropic"]["key"], "k2")
doc = remote("agents", "pi", "PI_AUTH_JSON"); doc["piAuthJson"]["anthropic"]["key"] = "k3"
remote_set("agents", "pi", "PI_AUTH_JSON", doc)
"""
    avlt("run", *LIVE, "--", *program(body), check=True)
    assert pi_secret(doppler)["piAuthJson"]["anthropic"]["key"] == "k3"


def test_doppler_unreachable_for_a_while(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {"openai": {"access": "a1", "expires": 100}}}})
    out = home / "out"
    body = f"""
doppler_down(True)
save(H / {PI_FILE!r}, {{"openai": {{"access": "a2", "expires": 200}}}})
time.sleep(5)  # longer than the adapter's own retries
doppler_down(False)
open({str(out)!r}, "w").write(str(until(lambda: remote("agents", "pi", "PI_AUTH_JSON")["piAuthJson"]["openai"]["access"], "a2")))
"""
    result = avlt("run", *LIVE, "--", *program(body))
    assert out.read_text() == "a2", "the change is written back once Doppler is back"
    assert "pi: could not read PI_AUTH_JSON from Doppler during the run" in result.stderr


def test_no_sync_outlives_the_run(avlt: Avlt) -> None:
    started = time.monotonic()
    avlt("run", *LIVE, "--", *py("import time; time.sleep(1.5)"), check=True)
    assert time.monotonic() - started < 8


def test_sync_interval_zero_syncs_only_before_and_after(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {"openai": {"access": "a1", "expires": 100}}}})
    out = home / "out"
    body = f"""
save(H / {PI_FILE!r}, {{"openai": {{"access": "a2", "expires": 200}}}})
time.sleep(2.5)
open({str(out)!r}, "w").write(remote("agents", "pi", "PI_AUTH_JSON")["piAuthJson"]["openai"]["access"])
"""
    avlt("run", "--preset", "pi", "--sync-interval", "0", "--", *program(body), check=True)
    assert out.read_text() == "a1", "nothing is written back during the run"
    assert pi_secret(doppler)["piAuthJson"]["openai"]["access"] == "a2", "only at exit"


def test_a_fractional_sync_interval_is_refused(avlt: Avlt) -> None:
    result = avlt("--preset", "pi", "--sync-interval", "1.5", "run", "--", "true")
    assert (result.returncode, result.stderr) == (2, "avlt: --sync-interval takes a whole number of seconds\n")


# == doppler-auth-sync --pull and --push ===================================================


def test_pull_and_push(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    f = home / ".tool/auth.json"
    doppler.put("app", "dev", {"TOOL_AUTH": {"toolAuth": {"main": {"key": "k1"}}}})
    result = avlt(*TOOL, "pull", check=True)
    assert result.stdout == f"{f}\n", "pull prints the path"
    assert compact(f) == {"main": {"key": "k1"}}
    base = f.read_text()

    doppler.put("app", "dev", {"TOOL_AUTH": {"toolAuth": {"main": {"key": "k2"}}}})
    avlt(*TOOL, "push", env={"AGENT_VAULT_BASE": base}, check=True)
    assert doppler.doc("app", "dev", "TOOL_AUTH")["toolAuth"]["main"]["key"] == "k2", "an unchanged local copy does not undo Doppler's"

    f.write_text(json.dumps({"main": {"key": "k3"}}))
    avlt(*TOOL, "push", env={"AGENT_VAULT_BASE": base}, check=True)
    assert doppler.doc("app", "dev", "TOOL_AUTH")["toolAuth"]["main"]["key"] == "k3", "a changed local copy wins"

    doppler.put("app", "dev", {"TOOL_AUTH": {"toolAuth": {"main": {"key": "k4"}}}})
    avlt(*TOOL, "push", check=True)
    assert doppler.doc("app", "dev", "TOOL_AUTH")["toolAuth"]["main"]["key"] == "k4", (
        "without AGENT_VAULT_BASE, this machine's record of the last sync (k3) still says k3 is not new")

    shutil.rmtree(home / ".local/state/agent-vault")
    avlt(*TOOL, "push", "--remove-on-exit", check=True)
    assert doppler.doc("app", "dev", "TOOL_AUTH")["toolAuth"]["main"]["key"] == "k3", "without any base the local copy wins"
    assert compact(f) is None, "--remove-on-exit removes the file"
    assert not list((home / ".local/state/agent-vault").glob("*.base")), "and the record of its last sync"


def test_pull_with_a_command_is_refused(avlt: Avlt) -> None:
    result = avlt(*TOOL, "pull", "--", "true")
    assert (result.returncode, result.stderr) == (2, "avlt: pull takes no command\n")


def test_pull_without_a_login_does_nothing(avlt: Avlt, home: Path) -> None:
    result = avlt(*TOOL, "pull", env={"DOPPLER_TOKEN": ""})
    assert result.stdout == ""
    assert not (home / ".tool/auth.json").exists()


# == beyond doppler-nix =======================================================================


def test_no_secret_in_any_url(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {"openai": {"access": "secret-a1", "expires": 100}}}})
    body = f"""save(H / {PI_FILE!r}, {{"openai": {{"access": "secret-a2", "expires": 200}}}})"""
    avlt("run", *LIVE, "--", *program(body), check=True)
    avlt("run", "-p", "app", "-c", "dev", "--", "true", check=True)
    log = "\n".join(doppler.log)
    for value in ("secret-a1", "secret-a2", "key-1", TOKEN):
        assert value not in log
    assert any(line.startswith("POST /v3/configs/config/secrets") for line in doppler.log)


def test_the_write_is_guarded_and_a_lost_race_merges_again(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    """Another machine writes the secret between our read and our write: Doppler refuses
    ours, and avlt merges again on top of the other machine's copy."""
    doppler.put("agents", "pi", {"PI_AUTH_JSON": {"piAuthJson": {
        "openai": {"access": "a1", "expires": 100}, "google": {"access": "g1", "expires": 100}}}})

    def other_machine(fake: FakeDoppler) -> None:
        doc = json.loads(fake.configs[("agents", "pi")]["PI_AUTH_JSON"])
        doc["piAuthJson"]["google"] = {"access": "g2", "expires": 200}
        fake.configs[("agents", "pi")]["PI_AUTH_JSON"] = json.dumps(doc)

    doppler.before_write = other_machine
    body = f"""save(H / {PI_FILE!r}, {{"openai": {{"access": "a2", "expires": 200}}, "google": {{"access": "g1", "expires": 100}}}})"""
    result = avlt("run", "--preset", "pi", "--sync-interval", "0", "--", *program(body))
    assert result.returncode == 0, result.stderr
    assert doppler.refused == 1
    doc = pi_secret(doppler)["piAuthJson"]
    assert doc["openai"]["access"] == "a2", "ours is written"
    assert doc["google"]["access"] == "g2", "and the other machine's is not lost"
    change = doppler.bodies[0]["change_requests"][0]
    assert set(change) == {"originalName", "name", "originalValue", "value"}


def test_sigterm_reaches_the_command_and_the_write_back_still_runs(avlt: Avlt, doppler: FakeDoppler, home: Path) -> None:
    ready = home / "ready"
    body = f"""
import signal
def bye(*_):
    sys.exit(0)
signal.signal(signal.SIGTERM, bye)
save(H / {PI_FILE!r}, {{"openai": {{"access": "a9", "expires": 900}}}})
open({str(ready)!r}, "w").write("1")
time.sleep(60)
"""
    process = avlt.popen("run", "--preset", "pi", "--sync-interval", "0", "--", *program(body))
    assert wait_for(ready.exists)
    process.send_signal(signal.SIGTERM)
    _, stderr = process.communicate(timeout=30)
    assert process.returncode == 0, stderr
    assert pi_secret(doppler)["piAuthJson"]["openai"]["access"] == "a9"


def test_a_wrapper_that_calls_avlt_again_is_stopped(avlt: Avlt) -> None:
    result = avlt("run", "-p", "app", "-c", "dev", "--", "true", env={"AGENT_VAULT_DEPTH": "4"})
    assert result.returncode == 2
    assert "nested 4 levels deep" in result.stderr


def test_unknown_options_and_presets(avlt: Avlt) -> None:
    assert avlt("--bogus", "pi").returncode == 2
    assert "unknown preset nope" in avlt("--preset", "nope", "run", "--", "true").stderr
    assert "--file is required" in avlt("-p", "a", "-c", "b", "-s", "S", "-e", "e", "pull").stderr
    assert "unknown vault nope" in avlt("--vault", "nope", "--preset", "pi", "pull").stderr
    assert "--lock-dir and --lock-file exclude each other" in avlt(
        "--preset", "pi", "--lock-dir", "a", "--lock-file", "b", "pull").stderr
