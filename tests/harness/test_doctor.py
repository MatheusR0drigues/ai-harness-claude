"""Tests for the explicit harness environment diagnostics (scripts/harness/doctor.py)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import doctor
import pytest
from config import Gate, HarnessConfig
from config_fixtures import write_core, write_pack
from verify import RunResult

UV_GATES = """
[[gates]]
name = "lint"
command = ["uv", "run", "ruff", "check", "."]
hint = "h"
group = "harness"
"""


class FakeRunner:
    def __init__(self, results: dict[tuple[str, ...], RunResult] | None = None) -> None:
        self.results = results or {}
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str], timeout: int) -> RunResult:
        assert timeout == doctor.PROBE_TIMEOUT
        key = tuple(command)
        self.calls.append(key)
        return self.results.get(key, RunResult(0, "tool 1.0\n"))


def harness_config(*gates: Gate) -> HarnessConfig:
    return HarnessConfig("demo", (), (), tuple(gates))


def gate(name: str, command: tuple[str, ...], group: str = "harness") -> Gate:
    return Gate(name, command, "fix it", group)


def only_uv(name: str) -> str | None:
    return "C:/tools/uv.exe" if name == "uv" else None


def write_repo(root: Path, project: str = "", hooks: str = "{}") -> Path:
    """A repository with harness/core.toml, harness.toml, .claude/settings.json and .venv."""
    write_core(root)
    (root / ".venv").mkdir()
    (root / ".claude").mkdir()
    (root / ".claude" / "settings.json").write_text(hooks, encoding="utf-8")
    path = root / "harness.toml"
    path.write_text(project, encoding="utf-8")
    return path


def by_name(checks: Sequence[doctor.Check]) -> dict[str, doctor.Check]:
    return {check.name: check for check in checks}


def test_diagnose_probes_only_allowlisted_harness_tools(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    cfg = harness_config(
        gate("lint", ("uv", "run", "ruff", "check", ".")),
        gate("types", ("uv", "run", "pyright")),
        gate("tests", ("uv", "run", "pytest")),
        gate("custom", ("uv", "run", "mytool")),
        gate("node", ("npm", "test"), group="stack"),
        gate("specs", ("python", "scripts/harness/validate_spec.py")),
    )
    runner = FakeRunner()
    found = {"uv": "C:/tools/uv.exe", "npm": "C:/tools/npm.cmd"}

    checks = doctor.diagnose(cfg, runner=runner, which=found.get, root=tmp_path)

    assert all(check.ok for check in checks)
    assert [check.name for check in checks] == [
        "executable:npm",
        "executable:uv",
        "uv",
        "venv",
        "pyright",
        "pytest",
        "ruff",
    ]
    assert runner.calls == [
        ("uv", "--version"),
        ("uv", "run", "--no-sync", "pyright", "--version"),
        ("uv", "run", "--no-sync", "pytest", "--version"),
        ("uv", "run", "--no-sync", "ruff", "--version"),
    ]


def test_diagnose_reports_stale_uv_shim_with_reinstall_hint(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    cfg = harness_config(gate("types", ("uv", "run", "pyright")))
    command = ("uv", "run", "--no-sync", "pyright", "--version")
    runner = FakeRunner({command: RunResult(1, "Failed to canonicalize script path")})

    checks = doctor.diagnose(cfg, runner=runner, which=only_uv, root=tmp_path)

    failed = [check for check in checks if not check.ok]
    assert len(failed) == 1
    assert "stale" in failed[0].detail
    assert "uv sync --reinstall" in failed[0].hint


def test_diagnose_reports_a_failing_probe(tmp_path: Path) -> None:
    (tmp_path / ".venv").mkdir()
    cfg = harness_config(gate("lint", ("uv", "run", "ruff", "check")))
    runner = FakeRunner({("uv", "--version"): RunResult(2, "\n  broken install\n")})

    checks = by_name(doctor.diagnose(cfg, runner=runner, which=only_uv, root=tmp_path))

    assert not checks["uv"].ok
    assert checks["uv"].detail == "probe failed with exit code 2: broken install"


def test_diagnose_reports_missing_venv_without_probing_tools(tmp_path: Path) -> None:
    cfg = harness_config(gate("types", ("uv", "run", "pyright")))
    runner = FakeRunner()

    checks = by_name(doctor.diagnose(cfg, runner=runner, which=only_uv, root=tmp_path))

    assert not checks["venv"].ok
    assert "uv sync" in checks["venv"].hint
    assert runner.calls == [("uv", "--version")]


def test_diagnose_reports_missing_stack_executable_without_running_it(tmp_path: Path) -> None:
    cfg = harness_config(gate("node", ("npm", "test"), group="stack"))
    runner = FakeRunner()

    checks = doctor.diagnose(cfg, runner=runner, which=lambda _name: None, root=tmp_path)

    assert checks == (
        doctor.Check(
            "executable:npm", False, "not found on PATH", "Install `npm` or fix the gate command."
        ),
    )
    assert runner.calls == []


@pytest.mark.parametrize(("version", "ok"), [((3, 11), True), ((3, 13), True), ((3, 10), False)])
def test_python_version_floor(version: tuple[int, int], ok: bool) -> None:
    check = doctor.check_python(version, "C:/Python/python.exe")

    assert check.ok is ok
    assert check.detail == f"{version[0]}.{version[1]} at C:/Python/python.exe"
    assert bool(check.hint) is not ok


def test_hooks_file_is_checked(tmp_path: Path) -> None:
    hooks = tmp_path / ".claude" / "settings.json"

    assert doctor.check_hooks_file(tmp_path).detail == ".claude/settings.json is missing"
    hooks.parent.mkdir()
    hooks.write_text("{", encoding="utf-8")
    assert doctor.check_hooks_file(tmp_path).detail.startswith(
        ".claude/settings.json does not parse"
    )
    hooks.write_text("[]", encoding="utf-8")
    assert not doctor.check_hooks_file(tmp_path).ok
    hooks.write_text(json.dumps({"a": {}, "b": {}}), encoding="utf-8")
    assert doctor.check_hooks_file(tmp_path) == doctor.Check(
        "hooks", True, ".claude/settings.json parses (2 group(s))"
    )


def test_run_checks_passes_on_a_healthy_repository(tmp_path: Path) -> None:
    path = write_repo(tmp_path, UV_GATES)
    runner = FakeRunner()

    checks = doctor.run_checks(
        runner=runner,
        which=only_uv,
        root=tmp_path,
        config_path=path,
        version=(3, 11),
        executable="python",
    )

    assert [check.name for check in checks] == [
        "python",
        "config",
        "hooks",
        "local-agents",
        "executable:uv",
        "uv",
        "venv",
        "ruff",
    ]
    assert all(check.ok for check in checks)
    assert checks[1].detail == "harness/core.toml + harness.toml loaded (1 gate(s), packs: none)"


def test_enabled_pack_must_be_installed(tmp_path: Path) -> None:
    path = write_repo(tmp_path, '[packs]\nenabled = ["python", "node"]\n')
    write_pack(tmp_path, "python")

    checks = by_name(
        doctor.run_checks(runner=FakeRunner(), which=only_uv, root=tmp_path, config_path=path)
    )

    assert not checks["config"].ok
    assert "harness/packs/node/pack.toml does not exist" in checks["config"].detail
    assert checks["pack:python"].ok
    assert not checks["pack:node"].ok
    assert checks["pack:node"].hint == "Run `python scripts/harness/cli.py init --packs node`."


def test_installed_packs_pass(tmp_path: Path) -> None:
    path = write_repo(tmp_path, '[packs]\nenabled = ["python"]\n')
    write_pack(tmp_path, "python")

    checks = by_name(
        doctor.run_checks(runner=FakeRunner(), which=only_uv, root=tmp_path, config_path=path)
    )

    assert checks["config"].ok
    assert checks["config"].detail.endswith("(0 gate(s), packs: python)")
    assert checks["pack:python"].detail == "harness/packs/python/pack.toml"


def test_missing_core_config_is_reported(tmp_path: Path) -> None:
    path = write_repo(tmp_path)
    (tmp_path / "harness" / "core.toml").unlink()

    checks = by_name(
        doctor.run_checks(runner=FakeRunner(), which=only_uv, root=tmp_path, config_path=path)
    )

    assert not checks["config"].ok
    assert "harness/core.toml does not exist" in checks["config"].detail


@pytest.mark.parametrize("text", ["[[gates]\n", "packs = 1\n", '[packs]\nenabled = "python"\n'])
def test_enabled_packs_reader_is_lenient(tmp_path: Path, text: str) -> None:
    path = tmp_path / "harness.toml"
    path.write_text(text, encoding="utf-8")

    assert doctor.enabled_packs(path) == ()
    assert doctor.enabled_packs(tmp_path / "missing.toml") == ()


def test_main_reports_failures_with_fix_hints(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_repo(tmp_path, hooks="{")

    code = doctor.main([], runner=FakeRunner(), which=only_uv, root=tmp_path, config_path=path)

    out = capsys.readouterr().out
    assert code == 1
    assert "[FAIL] hooks: .claude/settings.json does not parse" in out
    assert "  Fix: Restore .claude/settings.json" in out
    assert out.splitlines()[-1] == "DOCTOR FAILED"


def test_main_passes_on_a_healthy_repository(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_repo(tmp_path)

    code = doctor.main([], runner=FakeRunner(), which=only_uv, root=tmp_path, config_path=path)

    assert code == 0
    assert capsys.readouterr().out.splitlines()[-1] == "DOCTOR PASSED"


def test_main_rejects_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert doctor.main(["--fix"]) == 1
    assert "usage: doctor.py" in capsys.readouterr().out


def test_report_ends_with_deterministic_status() -> None:
    passed = doctor.render((doctor.Check("python", True, "3.11"),))
    failed = doctor.render((doctor.Check("python", False, "too old", "install it"),))

    assert passed.splitlines() == ["[PASS] python: 3.11", "DOCTOR PASSED"]
    assert failed.splitlines() == ["[FAIL] python: too old", "  Fix: install it", "DOCTOR FAILED"]


def test_local_agents_check_pass_and_fail(tmp_path: Path) -> None:
    clean = doctor.check_local_agents(tmp_path)
    assert clean.ok is True
    assert clean.name == "local-agents"

    agents_dir = tmp_path / ".claude" / "agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "researcher.md").write_text("---\nname: researcher\n---\n", encoding="utf-8")

    failing = doctor.check_local_agents(tmp_path)
    assert failing.ok is False
    assert failing.name == "local-agents"
    assert "researcher" in failing.detail
    assert "allow_override" in failing.hint

    (tmp_path / "harness.toml").write_text(
        '[agents]\nallow_override = ["researcher"]\n', encoding="utf-8"
    )
    overridden = doctor.check_local_agents(tmp_path)
    assert overridden.ok is True

    (agents_dir / "self.md").write_text("# self\n", encoding="utf-8")
    reserved = doctor.check_local_agents(tmp_path)
    assert reserved.ok is False
    assert "self" in reserved.detail


def test_main_external_repo_root_and_config_passes_without_local_hooks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "external_target"
    target.mkdir()
    ext_cfg = tmp_path / "external-harness.toml"
    ext_cfg.write_text('[project]\nname = "ext"\n', encoding="utf-8")

    code = doctor.main(
        ["--repo-root", str(target), "--config", str(ext_cfg)],
        runner=FakeRunner(),
        which=only_uv,
    )

    out = capsys.readouterr().out
    assert code == 0
    assert "[PASS] hooks: external mode" in out
    assert out.splitlines()[-1] == "DOCTOR PASSED"
