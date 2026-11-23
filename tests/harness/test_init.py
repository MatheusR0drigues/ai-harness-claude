"""Tests for the local kit installer (scripts/harness/init.py, `cli.py init`)."""

import json
import subprocess
import sys
from pathlib import Path

import check_structure
import cli
import config
import init
import pytest

SOURCE = init.SOURCE_ROOT
KIT_SCRIPTS = sorted(p.name for p in (SOURCE / "scripts" / "harness").glob("*.py"))
PROJECT_OWNED = (
    "CLAUDE.md",
    "harness.toml",
    ".claude/rules/anti-patterns.md",
    ".claude/rules/product.md",
    ".claude/rules/structure.md",
    ".claude/rules/tech.md",
    "docs/adr/0000-template.md",
)


def make_target(tmp_path: Path, name: str = "projeto-demo") -> Path:
    target = tmp_path / name
    target.mkdir()
    (target / ".git").mkdir()  # anchors validate_spec's repository discovery inside tmp_path
    return target


def run_init(target: Path, *args: str) -> int:
    return init.main(["--target", str(target), *args], source=SOURCE, cwd=target)


def files_under(root: Path) -> set[str]:
    return {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and ".git" not in p.relative_to(root).parts
    }


def test_init_projects_the_complete_local_kit(tmp_path: Path) -> None:
    target = make_target(tmp_path)

    assert run_init(target) == 0

    for name in KIT_SCRIPTS:
        copied = target / "scripts" / "harness" / name
        assert copied.read_bytes() == (SOURCE / "scripts" / "harness" / name).read_bytes()
    assert (target / "harness" / "core.toml").read_bytes() == (
        SOURCE / "harness" / "core.toml"
    ).read_bytes()
    assert (target / ".claude" / "settings.json").read_bytes() == (
        SOURCE / "harness" / "templates" / "settings.claude.json"
    ).read_bytes()
    for relative in PROJECT_OWNED:
        assert (target / relative).is_file(), relative
    assert not (target / "harness" / "packs").exists()


def test_init_projects_exactly_the_kit_and_no_repository_history(tmp_path: Path) -> None:
    """Requisito 1.3: ADRs 0001+, research and local [untrusted] exemptions stay in ai-harness."""
    target = make_target(tmp_path)

    assert run_init(target) == 0

    expected = {f"scripts/harness/{name}" for name in KIT_SCRIPTS}
    expected |= {
        "harness/core.toml",
        "harness/baseline.json",
        ".claude/settings.json",
        *PROJECT_OWNED,
    }
    assert files_under(target) == expected
    cfg = config.load(target / "harness.toml")
    assert cfg.untrusted.exempt_paths == ()
    assert cfg.exempt_paths == ()


def test_plugin_carries_no_repository_history_or_research() -> None:
    plugin = SOURCE / "plugin"
    files = [p.relative_to(plugin).as_posix().lower() for p in plugin.rglob("*") if p.is_file()]
    history = {"adr", "docs", "research", "specs", "raw"}

    assert [f for f in files if history & set(f.split("/")[:-1])] == []
    assert [f for f in files if Path(f).name.startswith(("0001-", "adr-"))] == []


def test_init_never_generates_distribution_artifacts(tmp_path: Path) -> None:
    target = make_target(tmp_path)

    assert run_init(target, "--packs", "python,node,web-ui,research-guard") == 0

    written = files_under(target)
    assert ".github/workflows/propagate.yml" not in written
    assert not any(path.startswith((".harness/", ".github/")) for path in written)
    assert not any(part in path for path in written for part in (".agents", ".kiro", ".codex"))


def test_rendered_harness_toml_names_the_project_and_enables_the_packs(tmp_path: Path) -> None:
    target = make_target(tmp_path, "meu-servico")

    assert run_init(target, "--packs", "python,web-ui") == 0

    cfg = config.load(target / "harness.toml")
    assert cfg.project_name == "meu-servico"
    assert cfg.packs == ("python", "web-ui")
    assert any(gate.name == "py-lint" for gate in cfg.gates)


def test_render_harness_toml_accepts_a_crlf_template(tmp_path: Path) -> None:
    """A Windows checkout (core.autocrlf=true) must not hide the `$`-anchored placeholders."""
    template = (SOURCE / "harness" / "templates" / "harness.toml").read_bytes()
    source = tmp_path / "source"
    (source / "harness" / "templates").mkdir(parents=True)
    crlf = template.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    (source / "harness" / "templates" / "harness.toml").write_bytes(crlf)

    rendered = init.render_harness_toml(source, "meu-servico", ("python",))

    assert b"\r" not in rendered
    assert b'name = "meu-servico"\n' in rendered
    assert b'enabled = ["python"]\n' in rendered


def test_only_the_requested_packs_are_installed(tmp_path: Path) -> None:
    target = make_target(tmp_path)

    assert run_init(target, "--packs", "python") == 0

    assert (target / "harness" / "packs" / "python" / "pack.toml").is_file()
    assert (target / ".claude" / "rules" / "python.md").is_file()
    assert not (target / "harness" / "packs" / "node").exists()
    assert not (target / "harness" / "packs" / "research-guard").exists()
    assert not any(p.suffix == ".pyc" for p in (target / "harness").rglob("*"))


def test_pack_hooks_are_registered_without_double_quotes(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    assert run_init(target, "--packs", "research-guard") == 0
    data = json.loads((target / ".claude" / "settings.json").read_text(encoding="utf-8"))
    entries = data["hooks"]["PreToolUse"][0]["hooks"]
    commands = [h["command"] for h in entries]
    pack_cmd = next(c for c in commands if "research_guard.py" in c)
    assert pack_cmd.startswith("python harness/packs/research-guard/")
    assert '"' not in pack_cmd
    assert (target / Path(pack_cmd.split()[1])).resolve().is_file()
    links = (target / "docs" / "links.txt").read_text(encoding="utf-8")
    assert all(line.startswith("#") for line in links.splitlines() if line.strip())
    assert "hooks" in data


@pytest.mark.parametrize(
    "packs",
    [(), ("python", "node", "web-ui", "research-guard", "data-engineering", "bi-pbip")],
)
def test_projected_repository_passes_check_structure(tmp_path: Path, packs: tuple[str]) -> None:
    target = make_target(tmp_path)
    args = ("--packs", ",".join(packs)) if packs else ()

    assert run_init(target, *args) == 0

    assert check_structure.check_all(target) == []


def test_projected_repository_passes_its_core_gates(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    assert run_init(target, "--packs", "python,research-guard") == 0

    completed = subprocess.run(
        [sys.executable, str(target / "scripts" / "harness" / "verify.py"), "--group", "core"],
        cwd=target,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "ALL GATES PASSED" in completed.stdout


def test_dry_run_reports_the_plan_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = make_target(tmp_path)

    assert run_init(target, "--packs", "node", "--dry-run") == 0

    out = capsys.readouterr().out
    assert "dry-run" in out
    assert "create: scripts/harness/cli.py" in out
    assert "create: harness/packs/node/pack.toml" in out
    assert files_under(target) == set()


def test_second_run_is_idempotent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = make_target(tmp_path)
    assert run_init(target) == 0
    capsys.readouterr()

    assert run_init(target) == 0

    out = capsys.readouterr().out
    assert "create:" not in out
    assert "overwrite:" not in out
    assert "HARNESS INIT DONE: 0 file(s) written" in out


def test_changed_kit_file_is_a_conflict_and_nothing_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = make_target(tmp_path)
    assert run_init(target) == 0
    guards = target / "scripts" / "harness" / "guards.py"
    guards.write_text("# local edit\n", encoding="utf-8")
    (target / "harness" / "core.toml").unlink()
    capsys.readouterr()

    assert run_init(target) == 1

    out = capsys.readouterr().out
    assert "conflict: scripts/harness/guards.py" in out
    assert "nothing was written" in out
    assert guards.read_text(encoding="utf-8") == "# local edit\n"
    assert not (target / "harness" / "core.toml").exists()


def test_force_overwrites_kit_files_but_keeps_project_files(tmp_path: Path) -> None:
    target = make_target(tmp_path)
    assert run_init(target) == 0
    guards = target / "scripts" / "harness" / "guards.py"
    guards.write_text("# local edit\n", encoding="utf-8")
    agents = target / "CLAUDE.md"
    agents.write_text("# Contrato do projeto\n", encoding="utf-8")

    assert run_init(target, "--force") == 0

    assert guards.read_bytes() == (SOURCE / "scripts" / "harness" / "guards.py").read_bytes()
    assert agents.read_text(encoding="utf-8") == "# Contrato do projeto\n"


def test_kept_harness_toml_warns_about_packs_it_does_not_enable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = make_target(tmp_path)
    (target / "harness.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")

    assert run_init(target, "--packs", "node") == 0

    out = capsys.readouterr().out
    assert "kept: harness.toml" in out
    assert 'add "node" to [packs].enabled' in out
    assert (target / "harness.toml").read_text(encoding="utf-8") == '[project]\nname = "x"\n'


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--packs", "rust"], "unsupported pack `rust`"),
        (["--packs"], "--packs needs a value"),
        (["--bogus"], "unknown argument `--bogus`"),
    ],
)
def test_invalid_arguments_fail_with_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], args: list[str], message: str
) -> None:
    target = make_target(tmp_path)

    assert run_init(target, *args) == 1

    assert message in capsys.readouterr().out
    assert files_under(target) == set()


def test_missing_target_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run_init(tmp_path / "missing") == 1
    assert "not an existing directory" in capsys.readouterr().out


def test_the_kit_source_is_never_a_target(capsys: pytest.CaptureFixture[str]) -> None:
    assert init.main(["--dry-run"], source=SOURCE, cwd=SOURCE) == 1
    assert "own source repository" in capsys.readouterr().out


def test_a_folder_inside_the_kit_source_is_never_a_target(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "kit"
    inner = source / "tests" / "sandbox"
    inner.mkdir(parents=True)

    assert init.main(["--target", str(inner), "--dry-run"], source=source, cwd=inner) == 1

    assert "own source repository" in capsys.readouterr().out


def test_global_antigravity_config_is_never_a_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    target = home / ".gemini" / "config"
    target.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)

    assert run_init(target) == 1

    assert "~/.gemini/" in capsys.readouterr().out
    assert files_under(target) == set()


def test_cli_dispatches_init(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = make_target(tmp_path)

    assert cli.main(["init", "--target", str(target), "--dry-run"]) == 0

    assert "HARNESS INIT (dry-run" in capsys.readouterr().out
