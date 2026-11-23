"""Tests for the entry point (scripts/harness/cli.py): version gate, fail-closed hooks, dispatch."""

import json
import subprocess
import sys
import types
from collections.abc import Sequence
from pathlib import Path

import cli
import hook
import pytest
from payload_fixtures import raw

ROOT = cli.REPO_ROOT
CLI = ROOT / "scripts" / "harness" / "cli.py"
HOOKS_JSON = ROOT / ".claude" / "settings.json"
PRE = ["hook", "pre", "--agent", "claude"]
OTHER_EVENTS = ("post", "stop", "session-start", "pre-invocation", "post-invocation")


def deny_reason(output: str) -> str:
    return output


def not_recovered(_exc: BaseException) -> tuple[bool, str]:
    return False, "no recent matching snapshot; recovery remains fail-closed"


def recovered(_exc: BaseException) -> tuple[bool, str]:
    return True, "restored the last known-good bytes for guards.py"


def simulate_python_310(monkeypatch: pytest.MonkeyPatch) -> None:
    real = cli.check_version

    def old_interpreter(_version: Sequence[int], argv: Sequence[str]) -> tuple[int, str] | None:
        return real((3, 10), argv)

    monkeypatch.setattr(cli, "check_version", old_interpreter)


def run_cli(
    args: Sequence[str], stdin: str, cwd: Path = ROOT, script: Sequence[str] = (str(CLI),)
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *script, *args],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=cwd,
    )


def test_supported_version_passes() -> None:
    assert cli.check_version((3, 11), PRE) is None
    assert cli.check_version((3, 13), ["verify"]) is None


def test_old_python_blocks_pre_hooks_and_warns_elsewhere() -> None:
    pre = cli.check_version((3, 10), PRE)
    stop = cli.check_version((3, 10), ["hook", "stop", "--agent", "claude"])
    other = cli.check_version((3, 10), ["verify"])

    assert pre is not None and pre[0] == 2
    assert stop is not None and stop[0] == 1
    assert other is not None and other[0] == 1
    assert "3.11" in pre[1]


def test_old_python_denies_pre_hooks_with_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    simulate_python_310(monkeypatch)

    assert cli.main(PRE) == 2
    assert "3.11" in capsys.readouterr().err


@pytest.mark.parametrize("args", [["verify", "--fast"], ["hook", "stop", "--agent", "claude"]])
def test_old_python_only_warns_elsewhere(
    args: list[str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    simulate_python_310(monkeypatch)

    assert cli.main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "3.11" in captured.err


def test_pre_hook_fails_closed_with_json_deny_when_the_harness_cannot_import(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "hook", None)  # `import hook` now raises ImportError
    monkeypatch.setattr(cli, "recover_integrity_snapshot", not_recovered)

    assert cli.main(PRE) == 2
    assert "BLOCKED" in capsys.readouterr().err


@pytest.mark.parametrize("event", OTHER_EVENTS)
def test_other_hooks_only_warn_when_the_harness_cannot_import(
    event: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "hook", None)
    monkeypatch.setattr(cli, "recover_integrity_snapshot", not_recovered)

    assert cli.main(["hook", event, "--agent", "claude"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "WARNING" in captured.err


def test_recovered_import_blocks_current_pre_call(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "hook", None)
    monkeypatch.setattr(cli, "recover_integrity_snapshot", recovered)

    assert cli.main(PRE) == 2
    reason = capsys.readouterr().err
    assert "guards.py" in reason
    assert "was not run" in reason


def test_recovered_post_import_reports_the_rollback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "hook", None)
    monkeypatch.setattr(cli, "recover_integrity_snapshot", recovered)

    assert cli.main(["hook", "post", "--agent", "claude"]) == 1
    assert "guards.py" in capsys.readouterr().err


def test_runtime_hook_failure_does_not_activate_recovery(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    called: list[BaseException] = []

    def crash(_argv: Sequence[str] | None = None) -> int:
        raise ZeroDivisionError("runtime crash")

    def recover(exc: BaseException) -> tuple[bool, str]:
        called.append(exc)
        return False, "not recovered"

    monkeypatch.setattr(hook, "main", crash)
    monkeypatch.setattr(cli, "recover_integrity_snapshot", recover)

    assert cli.main(PRE) == 2
    assert "runtime crash" in capsys.readouterr().err
    assert called == []


def test_system_exit_inside_a_pre_hook_still_denies(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def leave(_argv: Sequence[str] | None = None) -> int:
        raise SystemExit(3)

    monkeypatch.setattr(hook, "main", leave)

    assert cli.main(PRE) == 2
    assert "SystemExit" in capsys.readouterr().err


@pytest.mark.parametrize("args", [["bogus"], []])
def test_unknown_command_prints_usage_and_returns_1(
    args: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(args) == 1
    assert "usage" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["doctor", "verify", "init"])
def test_commands_dispatch_to_their_module(command: str, monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[list[str]] = []

    def fake_main(args: list[str]) -> int:
        called.append(args)
        return 7

    monkeypatch.setitem(sys.modules, command, types.SimpleNamespace(main=fake_main))

    assert cli.main([command, "--fast"]) == 7
    assert called == [["--fast"]]


def test_cli_allows_a_harmless_pre_call_with_empty_stdout() -> None:
    completed = run_cli(PRE, raw("claude", "read"))

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == ""


def test_cli_denies_an_unreadable_pre_payload() -> None:
    completed = run_cli(PRE, "{broken")

    assert completed.returncode == 2, completed.stderr
    assert "could not read the hook payload" in completed.stderr


def test_cli_rejects_an_unknown_command() -> None:
    completed = run_cli(["bogus"], "")

    assert completed.returncode == 1
    assert "usage" in completed.stderr


def test_hooks_json_commands_run_from_the_agents_directory() -> None:
    document = json.loads(HOOKS_JSON.read_text(encoding="utf-8"))
    assert "hooks" in document
