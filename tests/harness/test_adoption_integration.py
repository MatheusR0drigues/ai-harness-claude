"""Adoption of the kit by a Claude Code project (Requisito 12).

Claude counterpart of the source test_adoption_integration.py, which the export replaces with
this file. The synthetic adopter repository (Fixture de adotante) is created under pytest's
temporary directories with `git init`: its own .claude/settings.json ($schema, permissions, env
and third-party handlers), a CLAUDE.md that only imports AGENTS.md, a local agent with an MCP
tool and no model, a git-ignored folder holding a file the untrusted scanner would reject and a
legacy spec folder outside the validator format. The kit is projected with this repository's
`cli.py init --force` and the target's own sensors run as subprocesses from the target.
Everything is local: `git` and `sys.executable` only.
"""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_CLI = REPO_ROOT / "scripts" / "harness" / "cli.py"
AGENTS_TEMPLATE = REPO_ROOT / "harness" / "templates" / "CLAUDE.md"
HOOKS_REL = ".claude/settings.json"
HOOKS_TAMPER = f"modified protected harness file: {HOOKS_REL}"
KIT_PRE_COMMAND = "python scripts/harness/cli.py hook pre --agent claude"
THIRD_PARTY_PRE: dict[str, Any] = {
    "matcher": "Bash",
    "hooks": [
        {
            "type": "command",
            "command": 'python "${CLAUDE_PROJECT_DIR}/.claude/hooks/hook.py" pre',
            "timeout": 10,
        }
    ],
}
THIRD_PARTY_PROMPT: list[Any] = [
    {
        "hooks": [
            {
                "type": "command",
                "command": 'python "${CLAUDE_PROJECT_DIR}/.claude/hooks/hook.py" prompt',
                "timeout": 10,
            }
        ]
    }
]
PROJECT_KEYS: dict[str, Any] = {
    "$schema": "https://json.schemastore.org/claude-code-settings.json",
    "permissions": {"deny": ["Read(./.env)", "Read(./secrets/**)", "Bash(curl:*)"]},
    "env": {"PROJETO_DEMO": "1"},
}
CLAUDE_MD = "@AGENTS.md\n"
LOCAL_AGENT = ".claude/agents/leitor-github.md"
LOCAL_AGENT_TEXT = (
    "---\n"
    "name: leitor-github\n"
    "description: Le arquivos de repositorios remotos. Use quando o pedido citar o GitHub.\n"
    "tools: Read, Grep, mcp__github-ro__get_file_contents\n"
    "---\n\n"
    "# leitor-github\n\n"
    "Ao concluir, reporte com VEREDITO PASS ou FAIL e use [blocker | major | minor].\n"
)
IGNORED_NOTE = "ignored/nota.md"
LEGACY_SPEC = "specs/_legado/requirements.md"
GIT_TIMEOUT = 60
RUN_TIMEOUT = 300
SECOND_RUN_DONE = "HARNESS INIT DONE: 0 file(s) written"
SENSORS = (
    ("check_structure.py",),
    ("check_controls.py",),
    ("check_untrusted.py",),
    ("validate_spec.py", "--all"),
)

Doc = dict[str, Any]


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, timeout=GIT_TIMEOUT, check=True
    )


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=RUN_TIMEOUT,
        check=False,
    )


def _run_init(target: Path) -> subprocess.CompletedProcess[str]:
    return _run(target, str(SOURCE_CLI), "init", "--target", str(target), "--force")


def _run_sensor(target: Path, script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return _run(target, f"scripts/harness/{script}", *args)


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8"))


def _read_hooks(target: Path) -> Doc:
    return cast(Doc, json.loads((target / HOOKS_REL).read_text(encoding="utf-8")))


def _project_settings() -> Doc:
    doc: Doc = copy.deepcopy(PROJECT_KEYS)
    doc["hooks"] = {
        "PreToolUse": [copy.deepcopy(THIRD_PARTY_PRE)],
        "UserPromptSubmit": copy.deepcopy(THIRD_PARTY_PROMPT),
    }
    return doc


def build_claude_adopter(root: Path) -> Path:
    """Fixture de adotante, Claude dialect (Requisito 12.2), before any `init`."""
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    _write(root, HOOKS_REL, json.dumps(_project_settings(), indent=2) + "\n")
    _write(root, ".claude/hooks/hook.py", "import sys\n\nsys.exit(0)\n")
    _write(root, "CLAUDE.md", CLAUDE_MD)
    # The project guidance is the kit template itself, renamed: it has every required section.
    agents = AGENTS_TEMPLATE.read_text(encoding="utf-8").replace("# CLAUDE.md", "# AGENTS.md", 1)
    _write(root, "AGENTS.md", agents)
    _write(root, LOCAL_AGENT, LOCAL_AGENT_TEXT)
    _write(root, ".gitignore", "ignored/\n")
    # A zero-width space the untrusted scanner reports, built at runtime (no literal in this file).
    _write(root, IGNORED_NOTE, f"# Nota local\n\nTexto{chr(0x200B)}oculto.\n")
    _write(root, LEGACY_SPEC, "# Spec antiga\n\nTexto livre, sem criterios EARS.\n")
    return root


@pytest.fixture
def claude_adopter(tmp_path: Path) -> Path:
    return build_claude_adopter(tmp_path / "projeto-adotante")


@pytest.fixture(scope="module")
def adopted(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The adopter after `init --force`, with every file staged; tests only read it."""
    target = build_claude_adopter(tmp_path_factory.mktemp("adoption") / "projeto-adotante")
    proc = _run_init(target)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    _git(target, "add", "-A")
    return target


@pytest.fixture
def adopted_copy(adopted: Path, tmp_path: Path) -> Path:
    """A private copy of the adopted target for tests that change it."""
    copy_root = tmp_path / "projeto-adotante"
    shutil.copytree(adopted, copy_root)
    return copy_root


def _change_kit_timeout(target: Path) -> None:
    doc = _read_hooks(target)
    kit_handlers = [
        handler
        for group in doc["hooks"]["PreToolUse"]
        for handler in group["hooks"]
        if handler.get("command") == KIT_PRE_COMMAND
    ]
    kit_handlers[0]["timeout"] = 1
    _write(target, HOOKS_REL, json.dumps(doc, indent=2) + "\n")


def test_fixture_ignored_file_fails_when_explicit(adopted: Path) -> None:
    proc = _run_sensor(adopted, "check_untrusted.py", IGNORED_NOTE)

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert IGNORED_NOTE in proc.stdout


def test_init_force_twice_writes_nothing(claude_adopter: Path) -> None:
    first = _run_init(claude_adopter)
    assert first.returncode == 0, first.stdout + first.stderr

    second = _run_init(claude_adopter)

    assert second.returncode == 0, second.stdout + second.stderr
    assert SECOND_RUN_DONE in second.stdout


def test_init_keeps_project_content(claude_adopter: Path) -> None:
    settings_before = _read_hooks(claude_adopter)
    claude_md_before = (claude_adopter / "CLAUDE.md").read_bytes()
    agent_before = (claude_adopter / LOCAL_AGENT).read_bytes()

    proc = _run_init(claude_adopter)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    settings = _read_hooks(claude_adopter)
    assert {key: settings[key] for key in PROJECT_KEYS} == {
        key: settings_before[key] for key in PROJECT_KEYS
    }
    assert settings_before["hooks"]["PreToolUse"][0] in settings["hooks"]["PreToolUse"]
    assert settings["hooks"]["UserPromptSubmit"] == settings_before["hooks"]["UserPromptSubmit"]
    assert "kept: CLAUDE.md" in proc.stdout
    assert (claude_adopter / "CLAUDE.md").read_bytes() == claude_md_before
    assert (claude_adopter / LOCAL_AGENT).read_bytes() == agent_before


@pytest.mark.parametrize("sensor", SENSORS, ids=lambda sensor: sensor[0])
def test_sensors_pass_after_init(adopted: Path, sensor: tuple[str, ...]) -> None:
    script, *args = sensor

    proc = _run_sensor(adopted, script, *args)

    assert proc.returncode == 0, f"{script} failed:\n{proc.stdout}\n{proc.stderr}"


def test_tamper_passes_after_init(adopted: Path) -> None:
    proc = _run_sensor(adopted, "check_tamper.py")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "TAMPER CHECK PASSED" in proc.stdout


def test_controls_fail_on_kit_timeout_change(adopted_copy: Path) -> None:
    _change_kit_timeout(adopted_copy)

    proc = _run_sensor(adopted_copy, "check_controls.py")

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert HOOKS_TAMPER in proc.stdout


def test_verify_controls_gate_fails_on_kit_change(adopted_copy: Path) -> None:
    _change_kit_timeout(adopted_copy)

    proc = _run_sensor(adopted_copy, "verify.py", "--group", "core")

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "GATE FAILED: controls" in proc.stdout
