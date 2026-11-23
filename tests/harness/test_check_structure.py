"""Tests for check_structure.py in Claude Code."""

from __future__ import annotations

import json
from pathlib import Path

import check_structure as cs
import pytest
from config_fixtures import write_pack
from test_check_hooks import write_hook_configs

SECTIONS = "\n\n".join(cs.REQUIRED_SECTIONS)
SKILL = "---\nname: {name}\ndescription: {description}\n---\n\n# Skill\n"
LONG_DESCRIPTION = "Faz uma coisa. Use quando o usuario pedir essa coisa neste repositorio."
AGENT = """---
name: {name}
description: {description}
model: inherit
tools: {tools}
---

# {name}

Ao concluir, reporte com VEREDITO PASS ou FAIL e use [blocker | major | minor].
"""
AGENT_TOOLS = {
    "researcher": "Read, Grep, Glob",
    "planner": "Read, Grep, Glob, WebSearch, WebFetch",
    "implementer": "Read, Grep, Glob, Edit, MultiEdit, Write, Bash",
    "code-reviewer": "Read, Grep, Glob, Bash",
    "security-auditor": "Read, Grep, Glob, Bash",
}
PLUGIN_SKILL = (
    "---\nname: spec-driven\ndescription: {description}\n---\n\n# Spec\n\n"
    "Valide com `../../scripts/validate_spec.py specs/x` e veja "
    "[o scanner](../../scripts/check_secrets.py#uso).\n"
)


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def agent(name: str, tools: str | None = None, description: str = LONG_DESCRIPTION) -> str:
    return AGENT.format(name=name, description=description, tools=tools or AGENT_TOOLS[name])


def make_plugin(root: Path) -> Path:
    manifest: dict[str, object] = {
        "name": "ai-harness",
        "displayName": "AI Harness",
        "version": "0.1.0",
        "description": "Regras, skills e subagentes do harness.",
        "suggestedPrompts": [],
    }
    write(root, "plugin/plugin.json", json.dumps(manifest))
    write(root, "plugin/rules/CLAUDE.md", "# CLAUDE.md\n\nMapa operacional universal.\n")
    write(root, "plugin/rules/security.md", "# Seguranca\n")
    write(
        root,
        "plugin/rules/testing.md",
        '---\npaths:\n  - "tests/**"\n---\n\n# Testes\n',
    )
    write(
        root,
        "plugin/skills/spec-driven/SKILL.md",
        PLUGIN_SKILL.format(description=LONG_DESCRIPTION),
    )
    write(root, "plugin/skills/spec-driven/resources/tasks.md", "# Tarefas\n")
    for name in cs.SHARED_SCRIPTS:
        write(root, f"scripts/harness/{name}", f"# canonical {name}\n")
        write(root, f"plugin/scripts/{name}", f"# canonical {name}\n")
    for name in AGENT_TOOLS:
        write(root, f"plugin/agents/{name}.md", agent(name))
    return root


def make_repo(root: Path) -> Path:
    write(root, "CLAUDE.md", f"# CLAUDE.md\n\n{SECTIONS}\n")
    write(root, cs.AGENTS_TEMPLATE, f"# CLAUDE.md\n\n{SECTIONS}\n")
    write(
        root,
        ".claude/skills/demo/SKILL.md",
        SKILL.format(name="demo", description=LONG_DESCRIPTION),
    )
    write(root, ".claude/rules/security.md", "# Security\n")
    write(root, "docs/guide.md", "Veja `.claude/rules/security.md` e `specs/<feature>/`.\n")
    write_pack(root, "python")
    write_hook_configs(root)
    return make_plugin(root)


def test_minimal_repo_is_valid(tmp_path: Path) -> None:
    assert cs.check_all(make_repo(tmp_path)) == []


def test_optional_directories_may_be_absent(tmp_path: Path) -> None:
    write(tmp_path, "CLAUDE.md", SECTIONS)
    write_hook_configs(tmp_path)
    assert cs.check_all(tmp_path) == []


def test_skill_folder_without_skill_md_is_reported(tmp_path: Path) -> None:
    (tmp_path / ".claude" / "skills" / "empty").mkdir(parents=True)
    assert cs.check_skills(tmp_path) == [".claude/skills/empty: SKILL.md is missing"]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("---\ntrigger: sometimes\n---\n", "trigger is forbidden"),
        ("---\nglobs: tests/**\n---\n", "globs is forbidden"),
        ("---\npaths: []\n---\n", "paths must be a non-empty list"),
    ],
)
def test_invalid_rule_is_reported(tmp_path: Path, text: str, message: str) -> None:
    write(tmp_path, ".claude/rules/r.md", text)
    assert any(message in e for e in cs.check_rules(tmp_path))


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("subagent: true\n", "subagent field is forbidden"),
        ("mainAgent: false\n", "mainAgent field is forbidden"),
        ("send_message", "send_message is forbidden"),
    ],
)
def test_invalid_agent_front_matter_and_body_are_reported(
    tmp_path: Path, text: str, message: str
) -> None:
    make_plugin(tmp_path)
    if "send_message" in text:
        content = agent("researcher") + "\n" + text
    else:
        content = agent("researcher").replace("model: inherit\n", f"model: inherit\n{text}")
    write(tmp_path, "plugin/agents/researcher.md", content)
    errors = cs.check_plugin(tmp_path)
    assert any(message in e for e in errors)


def test_invalid_agent_tools_are_reported(tmp_path: Path) -> None:
    make_plugin(tmp_path)
    write(tmp_path, "plugin/agents/researcher.md", agent("researcher", tools="Read, Bash"))
    plugin_errors = cs.check_plugin(tmp_path)
    assert any("researcher" in e for e in plugin_errors)

    write(tmp_path, "plugin/agents/researcher.md", agent("researcher"))
    write(tmp_path, ".claude/agents/researcher.md", agent("researcher", tools="Read, Write"))
    local_errors = cs.check_agents(tmp_path)
    assert any("researcher" in e for e in local_errors)


LOCAL_AGENT = ".claude/agents/leitor-github.md"
MCP_TOOL = "mcp__github-ro__get_file_contents"


def test_local_agent_without_model_passes(tmp_path: Path) -> None:
    text = agent("leitor-github", tools="Read, Grep").replace("model: inherit\n", "")
    write(tmp_path, LOCAL_AGENT, text)

    assert "model" not in text
    assert cs.check_agents(tmp_path) == []


def test_invalid_model_fails(tmp_path: Path) -> None:
    text = agent("leitor-github", tools="Read, Grep").replace("model: inherit", "model: opus")
    write(tmp_path, LOCAL_AGENT, text)

    assert cs.check_agents(tmp_path) == [
        f"{LOCAL_AGENT}: model `opus` must be haiku, sonnet or inherit"
    ]


@pytest.mark.parametrize("folder", [".claude/agents", "plugin/agents"])
def test_mcp_tool_accepted(tmp_path: Path, folder: str) -> None:
    make_plugin(tmp_path)
    text = agent("leitor-github", tools=f"Read, {MCP_TOOL}")
    write(tmp_path, f"{folder}/leitor-github.md", text)

    assert cs.check_agents(tmp_path) + cs.check_plugin(tmp_path) == []


@pytest.mark.parametrize("tool", ["mcp__a", "mcp__a__", "mcp__a b__c"])
def test_malformed_mcp_tool_fails(tmp_path: Path, tool: str) -> None:
    write(tmp_path, LOCAL_AGENT, agent("leitor-github", tools=f"Read, {tool}"))
    known = ", ".join(sorted(cs.ANY_AGENT_TOOLS))

    assert cs.check_agents(tmp_path) == [f"{LOCAL_AGENT}: unknown tools {tool} (known: {known})"]


@pytest.mark.parametrize("folder", [".claude/agents", "plugin/agents"])
@pytest.mark.parametrize("name", ["code-reviewer", "security-auditor"])
def test_reviewer_with_mcp_tool_fails(tmp_path: Path, name: str, folder: str) -> None:
    make_plugin(tmp_path)
    where = f"{folder}/{name}.md"
    write(tmp_path, where, agent(name, tools=f"{AGENT_TOOLS[name]}, {MCP_TOOL}"))

    errors = cs.check_agents(tmp_path) + cs.check_plugin(tmp_path)

    assert f"{where}: review agent {name} must not use MCP tool {MCP_TOOL}" in errors


def test_guidance_files_includes_claude_md(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    names = [p.name for p in cs.guidance_files(repo)]
    assert "CLAUDE.md" in names


def test_sections_found_across_imports(tmp_path: Path) -> None:
    half = len(cs.REQUIRED_SECTIONS) // 2
    head = "\n\n".join(cs.REQUIRED_SECTIONS[:half])
    tail = "\n\n".join(cs.REQUIRED_SECTIONS[half:])
    write(tmp_path, "CLAUDE.md", f"# CLAUDE.md\n\n{head}\n\n@docs/contrato.md\n")
    write(tmp_path, "docs/contrato.md", f"# Contrato\n\n{tail}\n")

    assert cs.check_agents_md(tmp_path) == []


def test_claude_md_with_only_agents_import_passes(tmp_path: Path) -> None:
    write(tmp_path, "CLAUDE.md", "@AGENTS.md\n")
    write(tmp_path, "AGENTS.md", f"# AGENTS.md\n\n{SECTIONS}\n")

    assert cs.check_agents_md(tmp_path) == []


def test_missing_section_in_import_set_fails(tmp_path: Path) -> None:
    *present, missing = cs.REQUIRED_SECTIONS
    write(tmp_path, "CLAUDE.md", "@AGENTS.md\n")
    write(tmp_path, "AGENTS.md", "# AGENTS.md\n\n" + "\n\n".join(present) + "\n")

    assert cs.check_agents_md(tmp_path) == [f"CLAUDE.md: missing section `{missing}`"]


@pytest.mark.parametrize("long_file", ["CLAUDE.md", "AGENTS.md"])
def test_imported_file_over_200_lines_fails(tmp_path: Path, long_file: str) -> None:
    texts = {"CLAUDE.md": "@AGENTS.md\n", "AGENTS.md": f"# AGENTS.md\n\n{SECTIONS}\n"}
    texts[long_file] += "detalhe\n" * cs.AGENTS_MAX_LINES
    for name, text in texts.items():
        write(tmp_path, name, text)
    lines = len(texts[long_file].splitlines())

    errors = cs.check_agents_md(tmp_path)

    assert len(errors) == 1
    assert errors[0].startswith(f"{long_file}: {lines} lines; the limit is {cs.AGENTS_MAX_LINES}.")
