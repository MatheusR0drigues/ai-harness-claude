"""Tests for transactional recovery of hook-critical harness modules (cli.py + guards.py)."""

import importlib.util
import json
import re
from pathlib import Path

import cli
import guards
from payload import Event


def critical_file(root: Path, name: str = "guards.py") -> Path:
    target = root / "scripts" / "harness" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("VALUE = 1\n", encoding="utf-8")
    return target


def import_failure(path: Path) -> BaseException:
    """Import `path` as a throwaway module and return the import-time exception it raises."""
    spec = importlib.util.spec_from_file_location(f"broken_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # the import failure is the test input
        return exc
    raise AssertionError(f"{path} imported without error")


def no_import() -> None:
    return None


def test_recover_restores_preimage_after_name_error(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    target.write_text("MISSING_NAME\n", encoding="utf-8")
    error = import_failure(target)

    recovered, message = cli.recover_integrity_snapshot(
        error, root, state, now=101.0, import_fn=no_import
    )

    assert recovered
    assert "guards.py" in message
    assert target.read_text(encoding="utf-8") == "VALUE = 1\n"
    assert not list(state.glob("integrity-*.json"))


def test_recover_restores_preimage_after_regex_error(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    target.write_text("import re\nBROKEN = re.compile('[')\n", encoding="utf-8")
    error = import_failure(target)

    recovered, _ = cli.recover_integrity_snapshot(
        error, root, state, now=101.0, import_fn=no_import
    )

    assert recovered
    assert target.read_text(encoding="utf-8") == "VALUE = 1\n"


def test_recover_restores_within_the_30_second_window(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    target.write_text("MISSING_NAME\n", encoding="utf-8")

    recovered, _ = cli.recover_integrity_snapshot(
        import_failure(target), root, state, now=100.0 + cli.SNAPSHOT_TTL, import_fn=no_import
    )

    assert cli.SNAPSHOT_TTL == 30.0
    assert recovered
    assert target.read_text(encoding="utf-8") == "VALUE = 1\n"


def test_recover_rejects_expired_snapshot(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    target.write_text("MISSING_NAME\n", encoding="utf-8")
    error = import_failure(target)

    recovered, message = cli.recover_integrity_snapshot(
        error, root, state, now=100.0 + cli.SNAPSHOT_TTL + 1, import_fn=no_import
    )

    assert not recovered
    assert "recent" in message
    assert target.read_text(encoding="utf-8") == "MISSING_NAME\n"


def test_recover_rejects_tampered_snapshot(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    journal = next(state.glob("integrity-*.json"))
    data = json.loads(journal.read_text(encoding="utf-8"))
    data["files"][0]["data"] = "dGFtcGVyZWQ="
    journal.write_text(json.dumps(data), encoding="utf-8")
    target.write_text("MISSING_NAME\n", encoding="utf-8")
    error = import_failure(target)

    recovered, message = cli.recover_integrity_snapshot(
        error, root, state, now=101.0, import_fn=no_import
    )

    assert not recovered
    assert "valid" in message
    assert target.read_text(encoding="utf-8") == "MISSING_NAME\n"


def test_recover_ignores_failure_from_another_file(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    other = critical_file(root, "config.py")
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    target.write_text("MISSING_NAME\n", encoding="utf-8")
    other.write_text("OTHER_MISSING_NAME\n", encoding="utf-8")
    error = import_failure(other)

    recovered, _ = cli.recover_integrity_snapshot(
        error, root, state, now=101.0, import_fn=no_import
    )

    assert not recovered
    assert target.read_text(encoding="utf-8") == "MISSING_NAME\n"


def test_recover_rejects_path_traversal_in_journal(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    journal = next(state.glob("integrity-*.json"))
    data = json.loads(journal.read_text(encoding="utf-8"))
    data["files"][0]["path"] = "../guards.py"
    journal.write_text(json.dumps(data), encoding="utf-8")
    target.write_text("MISSING_NAME\n", encoding="utf-8")
    error = import_failure(target)

    recovered, _ = cli.recover_integrity_snapshot(
        error, root, state, now=101.0, import_fn=no_import
    )

    assert not recovered
    assert target.read_text(encoding="utf-8") == "MISSING_NAME\n"
    assert not (root / "scripts" / "guards.py").exists()


def test_recover_rejects_ambiguous_session_journals(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session-a", root, state, now=100.0)
    cli.prepare_integrity_snapshot((str(target),), "session-b", root, state, now=100.0)
    target.write_text("MISSING_NAME\n", encoding="utf-8")
    error = import_failure(target)

    recovered, _ = cli.recover_integrity_snapshot(
        error, root, state, now=101.0, import_fn=no_import
    )

    assert not recovered
    assert target.read_text(encoding="utf-8") == "MISSING_NAME\n"


def test_recover_rejects_valid_and_corrupt_concurrent_journals(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session-a", root, state, now=100.0)
    cli.prepare_integrity_snapshot((str(target),), "session-b", root, state, now=100.0)
    corrupt = [path for path in state.glob("integrity-*.json") if "session-b" in path.name][0]
    corrupt.write_text("{broken", encoding="utf-8")
    target.write_text("MISSING_NAME\n", encoding="utf-8")
    error = import_failure(target)

    recovered, _ = cli.recover_integrity_snapshot(
        error, root, state, now=101.0, import_fn=no_import
    )

    assert not recovered
    assert target.read_text(encoding="utf-8") == "MISSING_NAME\n"


def test_recover_reports_a_restore_that_still_cannot_import(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    cli.prepare_integrity_snapshot((str(target),), "session", root, state, now=100.0)
    target.write_text("MISSING_NAME\n", encoding="utf-8")

    def still_broken() -> None:
        raise ImportError("hook still broken")

    recovered, message = cli.recover_integrity_snapshot(
        import_failure(target), root, state, now=101.0, import_fn=still_broken
    )

    assert not recovered
    assert "still cannot import" in message
    assert target.read_text(encoding="utf-8") == "VALUE = 1\n"


def test_integrity_guard_blocks_invalid_full_write(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    event = Event(
        "claude",
        "pre",
        "write_to_file",
        "write",
        (str(target),),
        "def broken(:\n",
        session_id="s",
    )

    reason = guards.harness_integrity(event, root=root, state_dir=state, now=100.0)

    assert reason is not None
    assert "syntax" in reason.lower()
    assert not list(state.glob("integrity-*.json"))


def test_integrity_guard_snapshots_incremental_edit(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root)
    event = Event(
        "claude",
        "pre",
        "replace_file_content",
        "write",
        (str(target),),
        "VALUE = 2",
        session_id="s",
    )

    reason = guards.harness_integrity(event, root=root, state_dir=state, now=100.0)

    assert reason is None
    assert len(list(state.glob("integrity-*.json"))) == 1


def test_integrity_guard_snapshots_valid_full_write(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root, "hook.py")
    event = Event(
        "claude",
        "pre",
        "write_to_file",
        "write",
        (str(target),),
        "VALUE = 2\n",
        session_id="s",
    )

    reason = guards.harness_integrity(event, root=root, state_dir=state, now=100.0)

    assert reason is None
    assert len(list(state.glob("integrity-*.json"))) == 1


def test_integrity_guard_ignores_unprotected_files(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    other = root / "src" / "app.py"
    other.parent.mkdir(parents=True)
    other.write_text("VALUE = 1\n", encoding="utf-8")
    event = Event("claude", "pre", "write_to_file", "write", (str(other),), "def broken(:\n")

    assert guards.harness_integrity(event, root=root, state_dir=state, now=100.0) is None
    assert not state.exists()


def test_integrity_guard_blocks_every_incremental_cli_write(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root, "cli.py")
    event = Event(
        "claude",
        "pre",
        "multi_replace_file_content",
        "write",
        (str(target),),
        "VALUE = 2",
        session_id="s",
    )

    reason = guards.harness_integrity(event, root=root, state_dir=state, now=100.0)

    assert reason is not None
    assert "human" in reason


def test_integrity_guard_blocks_full_cli_write(tmp_path: Path) -> None:
    root, state = tmp_path / "repo", tmp_path / "state"
    target = critical_file(root, "cli.py")
    event = Event(
        "claude",
        "pre",
        "write_to_file",
        "write",
        (str(target),),
        "VALUE = 2\n",
        session_id="s",
    )

    reason = guards.harness_integrity(event, root=root, state_dir=state, now=100.0)

    assert reason is not None
    assert "human" in reason
    assert not list(state.glob("integrity-*.json"))


def test_integrity_guard_blocks_dot_relative_shell_write_from_harness_cwd(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    critical_file(root, "cli.py")
    event = Event(
        "claude",
        "pre",
        "run_command",
        "shell",
        command=r"mv .\cli.py cli.py.bak",
        cwd=str(root / "scripts" / "harness"),
    )

    reason = guards.harness_integrity(event, root=root)

    assert reason is not None
    assert "human" in reason


def test_protected_modules_cover_the_dispatcher_without_sync_adapters() -> None:
    required = {
        "scripts/harness/cli.py",
        "scripts/harness/hook.py",
        "scripts/harness/guards.py",
        "scripts/harness/payload.py",
        "scripts/harness/config.py",
        "scripts/harness/check_secrets.py",
        "scripts/harness/check_untrusted.py",
        "scripts/harness/check_structure.py",
        "scripts/harness/check_controls.py",
        "scripts/harness/verify.py",
    }

    assert required <= set(cli.PROTECTED_MODULES)
    assert "scripts/harness/sync_adapters.py" not in cli.PROTECTED_MODULES


def test_import_failure_helper_exercises_regex_error(tmp_path: Path) -> None:
    broken = tmp_path / "broken_regex.py"
    broken.write_text("import re\nre.compile('[')\n", encoding="utf-8")

    assert isinstance(import_failure(broken), re.error)
