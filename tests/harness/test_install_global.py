"""Tests for the install-global command.

Covers scripts/harness/install_global.py.
"""

from __future__ import annotations

from pathlib import Path

import install_global
import pytest


def test_install_global_dry_run_writes_nothing(tmp_path: Path) -> None:
    target = tmp_path / "claude_home"
    code = install_global.main(["--target", str(target), "--dry-run"])
    assert code == 0
    assert not target.exists()


def test_install_global_copies_plugin_artifacts(tmp_path: Path) -> None:
    target = tmp_path / "claude_home"
    code = install_global.main(["--target", str(target)])
    assert code == 0
    assert (target / "CLAUDE.md").is_file()
    assert not (target / "rules" / "CLAUDE.md").exists()
    assert (target / "rules" / "ai-security.md").is_file()
    assert (target / "agents" / "code-reviewer.md").is_file()
    assert (target / "skills" / "spec-driven" / "SKILL.md").is_file()
    assert (target / "scripts" / "validate_spec.py").is_file()


def test_install_global_preserves_existing_settings_json(tmp_path: Path) -> None:
    target = tmp_path / "claude_home"
    target.mkdir()
    settings = target / "settings.json"
    settings.write_text('{"user": true}\n', encoding="utf-8")
    code = install_global.main(["--target", str(target)])
    assert code == 0
    assert settings.read_text(encoding="utf-8") == '{"user": true}\n'


def test_install_global_refuses_target_inside_repo() -> None:
    inside = install_global.SOURCE_ROOT / "subfolder"
    code = install_global.main(["--target", str(inside)])
    assert code != 0


def test_install_global_skips_modified_unless_forced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "claude_home"
    assert install_global.main(["--target", str(target)]) == 0
    claude_md = target / "CLAUDE.md"
    original = claude_md.read_text(encoding="utf-8")
    claude_md.write_text("# local edit\n", encoding="utf-8")
    capsys.readouterr()

    assert install_global.main(["--target", str(target)]) == 0
    assert claude_md.read_text(encoding="utf-8") == "# local edit\n"
    assert "skip:" in capsys.readouterr().err

    assert install_global.main(["--target", str(target), "--force"]) == 0
    assert claude_md.read_text(encoding="utf-8") == original


def test_install_global_refuses_gemini_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    gemini = home / ".gemini" / "config"
    gemini.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    assert install_global.main(["--target", str(gemini)]) != 0
