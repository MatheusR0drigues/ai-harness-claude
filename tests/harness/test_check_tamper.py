"""Tests for the deterministic SHA-256 tamper baseline sensor (scripts/harness/check_tamper.py)."""

from __future__ import annotations

import json
from pathlib import Path

import check_controls
import check_tamper
import hook
import pytest
from config_fixtures import write_core
from payload import Event


def _seed_harness(root: Path, core_text: str | None = None) -> None:
    (root / ".claude").mkdir(parents=True, exist_ok=True)
    (root / ".claude" / "settings.json").write_text('{"hooks": {}}\n', encoding="utf-8")
    write_core(
        root,
        core_text if core_text is not None else "[controls]\nrequired_gates = []\n",
    )
    (root / "scripts" / "harness").mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "harness" / "guards.py").write_text("ALL = ()\n", encoding="utf-8")


def test_digest_bytes_normalizes_crlf_and_lf() -> None:
    assert check_tamper.digest_bytes(b"line1\r\nline2\r") == check_tamper.digest_bytes(
        b"line1\nline2\n"
    )


def test_write_and_verify_roundtrip(tmp_path: Path) -> None:
    _seed_harness(tmp_path)

    target, count = check_tamper.write_baseline(tmp_path)

    assert target == tmp_path / "harness" / "baseline.json"
    assert count == 3
    assert check_tamper.verify(tmp_path) == []
    assert check_tamper.notice(tmp_path) is None


def test_verify_detects_missing_baseline(tmp_path: Path) -> None:
    _seed_harness(tmp_path)

    findings = check_tamper.verify(tmp_path)

    assert len(findings) == 1
    assert "missing tamper baseline" in findings[0]


@pytest.mark.parametrize(
    "relative",
    [".claude/settings.json", "harness/core.toml", "scripts/harness/guards.py"],
)
def test_verify_detects_modified_protected_files(tmp_path: Path, relative: str) -> None:
    _seed_harness(tmp_path)
    check_tamper.write_baseline(tmp_path)

    (tmp_path / relative).write_text("# tampered\n", encoding="utf-8")

    findings = check_tamper.verify(tmp_path)
    assert findings == [f"modified protected harness file: {relative}"]


def test_verify_detects_deleted_and_added_files(tmp_path: Path) -> None:
    _seed_harness(tmp_path)
    check_tamper.write_baseline(tmp_path)

    (tmp_path / "harness" / "core.toml").unlink()
    (tmp_path / "scripts" / "harness" / "rogue.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "scripts" / "harness" / "hook").mkdir()
    (tmp_path / "scripts" / "harness" / "hook" / "__init__.py").write_text(
        "x = 1\n", encoding="utf-8"
    )

    findings = check_tamper.verify(tmp_path)
    assert "missing protected harness file: harness/core.toml" in findings
    assert "unexpected harness file added: scripts/harness/rogue.py" in findings
    assert "unexpected harness file added: scripts/harness/hook/__init__.py" in findings


@pytest.mark.parametrize(
    "raw_baseline",
    [
        "{broken",
        json.dumps({"version": 99, "files": {"harness/core.toml": "a" * 64}}),
        json.dumps({"version": 2, "files": {"../escape.py": "a" * 64}}),
        json.dumps({"version": 2, "files": {"scripts/harness/../escape.py": "a" * 64}}),
        json.dumps({"version": 2, "files": {"harness/core.toml": "not-a-sha"}}),
    ],
)
def test_verify_rejects_corrupt_baseline(tmp_path: Path, raw_baseline: str) -> None:
    _seed_harness(tmp_path)
    (tmp_path / "harness" / "baseline.json").write_text(raw_baseline, encoding="utf-8")

    findings = check_tamper.verify(tmp_path)
    assert len(findings) == 1
    assert "invalid tamper baseline" in findings[0]


def test_cli_update_and_check_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _seed_harness(tmp_path)

    assert check_tamper.main(["--update"], root=tmp_path) == 0
    assert "TAMPER BASELINE UPDATED" in capsys.readouterr().out

    assert check_tamper.main([], root=tmp_path) == 0
    assert "TAMPER CHECK PASSED (3 file(s) verified)" in capsys.readouterr().out

    (tmp_path / "scripts" / "harness" / "guards.py").write_text(
        "ALL = ('tampered',)\n", encoding="utf-8"
    )
    assert check_tamper.main([], root=tmp_path) == 1
    assert "TAMPER CHECK FAILED:" in capsys.readouterr().out


def test_session_start_stop_and_controls_react_to_tampering(tmp_path: Path) -> None:
    core_text = (
        '[controls]\nrequired_gates = ["secrets"]\nrequired_guards = ["secret_in_write"]\n\n'
        '[[gates]]\nname = "secrets"\ncommand = ["python", "-V"]\n'
        'hint = "Fix secret."\ngroup = "core"\nfast = true\n'
    )
    _seed_harness(tmp_path, core_text=core_text)
    project_cfg = tmp_path / "harness.toml"
    project_cfg.write_text('[project]\nname = "demo"\n', encoding="utf-8")
    check_tamper.write_baseline(tmp_path)

    # Clean repository passes tamper checks; tampering surfaces in SessionStart, Stop & controls.
    assert hook.default_config_notice(config_path=project_cfg) is None
    assert hook.default_tamper_notice(tmp_path) is None

    # Invalid JSON is tampering in every dialect (req. 2.7); third-party edits are not (req. 2.4).
    (tmp_path / ".claude" / "settings.json").write_text("# tampered\n", encoding="utf-8")

    start_notice = hook.default_config_notice(config_path=project_cfg)
    assert start_notice is not None and ".claude/settings.json" in start_notice

    stop_event = Event(agent="claude", event="stop", kind="other", session_id="tamper-1")
    stop_resp = hook.handle_stop(
        stop_event,
        lambda: (True, "ALL GATES PASSED"),
        tmp_path,
        tamper_fn=lambda: check_tamper.notice(tmp_path),
    )
    assert "tamper baseline" in stop_resp.stderr

    assert check_controls.main([], root=tmp_path, config_path=project_cfg) == 1

    # Deleting harness/baseline.json inside a repo with .claude/settings.json must fail too.
    (tmp_path / "harness" / "baseline.json").unlink()
    assert check_controls.main([], root=tmp_path, config_path=project_cfg) == 1
    assert hook.default_tamper_notice(tmp_path) is not None
