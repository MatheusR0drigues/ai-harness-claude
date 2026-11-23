"""Tests for Claude Code hook check.

Covers check_structure.check_hooks against .claude/settings.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import check_structure as cs
import pytest

SETTINGS = ".claude/settings.json"
RESEARCH_GUARD = "python harness/packs/research-guard/scripts/research_guard.py"
RESEARCH_GUARD_SCRIPT = "harness/packs/research-guard/scripts/research_guard.py"
THIRD_PARTY_COMMAND = 'python "${CLAUDE_PROJECT_DIR}/.claude/hooks/hook.py" pre'


def default_hooks() -> dict[str, object]:
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python scripts/harness/cli.py hook pre --agent claude",
                            "timeout": 30,
                        }
                    ],
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python scripts/harness/cli.py hook post --agent claude",
                            "timeout": 60,
                        }
                    ],
                }
            ],
            "SessionStart": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": (
                                "python scripts/harness/cli.py hook session-start --agent claude"
                            ),
                            "timeout": 30,
                        }
                    ]
                }
            ],
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": "python scripts/harness/cli.py hook stop --agent claude",
                            "timeout": 300,
                        }
                    ]
                }
            ],
        }
    }


def write_hook_configs(root: Path, data: object | None = None) -> None:
    (root / cs.CLI).parent.mkdir(parents=True, exist_ok=True)
    (root / cs.CLI).write_text("# stub\n", encoding="utf-8")
    settings = root / cs.HOOKS_FILE
    settings.parent.mkdir(parents=True, exist_ok=True)
    payload = default_hooks() if data is None else data
    settings.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_complete_config_is_valid(tmp_path: Path) -> None:
    write_hook_configs(tmp_path)
    assert cs.check_hooks(tmp_path) == []


def test_missing_file_is_reported(tmp_path: Path) -> None:
    assert cs.check_hooks(tmp_path) == [
        (
            ".claude/settings.json: file is missing "
            "(project it with `python scripts/harness/cli.py init`)"
        )
    ]


def test_missing_events_are_reported(tmp_path: Path) -> None:
    data = default_hooks()
    hooks_map = data["hooks"]
    assert isinstance(hooks_map, dict)
    del hooks_map["Stop"]
    write_hook_configs(tmp_path, data)
    assert cs.check_hooks(tmp_path) == [
        ".claude/settings.json: missing harness events: Stop (hook stop)"
    ]


def test_wrong_agent_flag_is_reported(tmp_path: Path) -> None:
    data = default_hooks()
    hooks_map = data["hooks"]
    assert isinstance(hooks_map, dict)
    hooks_map["Stop"] = [
        {
            "hooks": [
                {
                    "type": "command",
                    "command": "python scripts/harness/cli.py hook stop --agent antigravity",
                }
            ]
        }
    ]
    write_hook_configs(tmp_path, data)
    errors = cs.check_hooks(tmp_path)
    assert any("expected --agent claude" in e for e in errors)


def test_invalid_json_is_reported(tmp_path: Path) -> None:
    (tmp_path / cs.HOOKS_FILE).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / cs.HOOKS_FILE).write_text("{", encoding="utf-8")
    errors = cs.check_hooks(tmp_path)
    assert len(errors) == 1
    assert ".claude/settings.json: not valid JSON" in errors[0]


def test_double_quotes_are_reported(tmp_path: Path) -> None:
    data = default_hooks()
    hooks_map = data["hooks"]
    assert isinstance(hooks_map, dict)
    hooks_map["PreToolUse"] = [
        {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": 'python "scripts/harness/cli.py" hook pre --agent claude',
                }
            ],
        }
    ]
    write_hook_configs(tmp_path, data)
    errors = cs.check_hooks(tmp_path)
    assert any("commands must contain no double quotes" in e for e in errors)


def test_nonexistent_script_is_reported(tmp_path: Path) -> None:
    data = kit_settings()
    data["hooks"]["PreToolUse"][0]["hooks"].append(command_handler(RESEARCH_GUARD))
    write_hook_configs(tmp_path, data)
    errors = cs.check_hooks(tmp_path)
    assert any("does not exist" in e for e in errors)


def cmd(event: str, agent: str = "claude") -> str:
    return f"python scripts/harness/cli.py hook {event} --agent {agent}"


def command_handler(command: str) -> dict[str, object]:
    return {"type": "command", "command": command}


def kit_settings() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(json.dumps(default_hooks())))


def write_file(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_top_level_keys_besides_hooks_are_ignored(tmp_path: Path) -> None:
    data = kit_settings()
    data["$schema"] = "https://json.schemastore.org/claude-code-settings.json"
    data["permissions"] = {"allow": ["Bash(uv run pytest:*)"], "deny": ["WebFetch"]}
    data["env"] = {"HARNESS_DEMO": "1"}
    data["disableAllHooks"] = False
    data["x-meta"] = {"owner": "time-dados"}
    write_hook_configs(tmp_path, data)

    assert cs.check_hooks(tmp_path) == []


@pytest.mark.parametrize(
    "data",
    [
        pytest.param({"permissions": {"allow": []}}, id="missing"),
        pytest.param({"hooks": []}, id="list"),
        pytest.param({"hooks": "PreToolUse"}, id="string"),
    ],
)
def test_missing_or_non_object_hooks_fails(tmp_path: Path, data: dict[str, object]) -> None:
    write_hook_configs(tmp_path, data)

    errors = cs.check_hooks(tmp_path)

    assert any(e.startswith(f"{SETTINGS}:") and "hooks" in e for e in errors)


def test_disable_all_hooks_true_fails(tmp_path: Path) -> None:
    data = kit_settings()
    data["disableAllHooks"] = True
    write_hook_configs(tmp_path, data)

    errors = cs.check_hooks(tmp_path)

    assert any(e.startswith(f"{SETTINGS}:") and "disableAllHooks" in e for e in errors)


@pytest.mark.parametrize(
    ("entry", "label"),
    [
        pytest.param("python tools/hook.py", "hooks.PreToolUse[1]", id="not-an-object"),
        pytest.param({"matcher": "Bash"}, "hooks.PreToolUse[1]", id="group-without-hooks-list"),
        pytest.param(
            {"matcher": "Bash", "hooks": [{"type": "shell", "command": "echo"}]},
            "hooks.PreToolUse[1].hooks[0]",
            id="unknown-type",
        ),
        pytest.param(
            {"matcher": "Bash", "hooks": [{"type": "command"}]},
            "hooks.PreToolUse[1].hooks[0]",
            id="command-missing",
        ),
        pytest.param(
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "  "}]},
            "hooks.PreToolUse[1].hooks[0]",
            id="command-blank",
        ),
    ],
)
def test_invalid_third_party_entry_fails(tmp_path: Path, entry: object, label: str) -> None:
    data = kit_settings()
    data["hooks"]["PreToolUse"].append(entry)
    write_hook_configs(tmp_path, data)

    errors = cs.check_hooks(tmp_path)

    assert any(e.startswith(f"{SETTINGS} {label}:") for e in errors)


KIT_PRE_HANDLER = command_handler(cmd("pre"))
THIRD_PARTY_HANDLER = command_handler(THIRD_PARTY_COMMAND)


@pytest.mark.parametrize(
    "pre_tool_use",
    [
        pytest.param(
            [{"matcher": "", "hooks": [KIT_PRE_HANDLER, THIRD_PARTY_HANDLER]}],
            id="kit-matcher-group",
        ),
        pytest.param(
            [
                {"matcher": "", "hooks": [KIT_PRE_HANDLER]},
                {"matcher": "Bash", "hooks": [THIRD_PARTY_HANDLER]},
            ],
            id="own-matcher-group",
        ),
    ],
)
def test_third_party_quotes_with_project_dir_accepted(
    tmp_path: Path, pre_tool_use: list[object]
) -> None:
    data = kit_settings()
    data["hooks"]["PreToolUse"] = pre_tool_use
    write_hook_configs(tmp_path, data)

    assert cs.check_hooks(tmp_path) == []


@pytest.mark.parametrize(
    "command",
    [
        'python "scripts/harness/cli.py" hook pre --agent claude',
        'python "${CLAUDE_PROJECT_DIR}/scripts/harness/cli.py" hook pre --agent claude',
    ],
    ids=["quoted-cli", "quoted-project-dir-cli"],
)
def test_harness_command_with_quotes_fails(tmp_path: Path, command: str) -> None:
    data = kit_settings()
    data["hooks"]["PreToolUse"][0]["hooks"].append(command_handler(command))
    write_hook_configs(tmp_path, data)

    errors = cs.check_hooks(tmp_path)

    label = f"{SETTINGS} hooks.PreToolUse[0].hooks[1]"
    assert any(e.startswith(f"{label}: commands must contain no double quotes") for e in errors)


@pytest.mark.parametrize("event", ["UserPromptSubmit", "PreCompact"])
def test_third_party_in_non_rendered_known_event_accepted(tmp_path: Path, event: str) -> None:
    data = kit_settings()
    data["hooks"][event] = [{"hooks": [command_handler(THIRD_PARTY_COMMAND)]}]
    write_hook_configs(tmp_path, data)

    assert cs.check_hooks(tmp_path) == []


def test_unknown_event_fails(tmp_path: Path) -> None:
    data = kit_settings()
    data["hooks"]["PreTooluse"] = [{"matcher": "", "hooks": [command_handler(cmd("pre"))]}]
    write_hook_configs(tmp_path, data)

    errors = cs.check_hooks(tmp_path)

    assert len(errors) == 1
    assert errors[0].startswith(f"{SETTINGS} hooks.PreTooluse: unknown Claude Code hook event")


@pytest.mark.parametrize(("event", "cli_event"), list(cs.HOOK_EVENTS.items()))
def test_missing_kit_event_names_event(tmp_path: Path, event: str, cli_event: str) -> None:
    data = kit_settings()
    del data["hooks"][event]
    write_hook_configs(tmp_path, data)

    assert cs.check_hooks(tmp_path) == [
        f"{SETTINGS}: missing harness events: {event} (hook {cli_event})"
    ]


@pytest.mark.parametrize(
    ("pre_tool_use", "expected"),
    [
        pytest.param(
            [{"matcher": "", "hooks": [KIT_PRE_HANDLER, KIT_PRE_HANDLER]}],
            [f"{SETTINGS}: PreToolUse has 2 harness entries; keep exactly one"],
            id="same-matcher-group",
        ),
        pytest.param(
            [
                {"matcher": "", "hooks": [KIT_PRE_HANDLER]},
                {"matcher": "", "hooks": [KIT_PRE_HANDLER]},
            ],
            [f"{SETTINGS}: PreToolUse has 2 harness entries; keep exactly one"],
            id="second-matcher-group",
        ),
        pytest.param(
            [{"matcher": "", "hooks": [KIT_PRE_HANDLER, command_handler(RESEARCH_GUARD)]}],
            [],
            id="research-guard-pack-not-counted",
        ),
    ],
)
def test_duplicate_harness_call_fails(
    tmp_path: Path, pre_tool_use: list[object], expected: list[str]
) -> None:
    data = kit_settings()
    data["hooks"]["PreToolUse"] = pre_tool_use
    write_hook_configs(tmp_path, data)
    write_file(tmp_path, RESEARCH_GUARD_SCRIPT, "# stub\n")

    assert cs.check_hooks(tmp_path) == expected


@pytest.mark.parametrize(("event", "cli_event"), [("PreToolUse", "pre"), ("PostToolUse", "post")])
def test_kit_tool_event_requires_empty_matcher(tmp_path: Path, event: str, cli_event: str) -> None:
    data = kit_settings()
    data["hooks"][event] = [{"matcher": "*", "hooks": [command_handler(cmd(cli_event))]}]
    write_hook_configs(tmp_path, data)

    assert cs.check_hooks(tmp_path) == [
        f"{SETTINGS} hooks.{event}[0].hooks[0]: {event} entries calling the harness must use "
        '"matcher": "" so every tool (including MCP tools) passes through the guards',
        f"{SETTINGS}: missing harness events: {event} (hook {cli_event})",
    ]


@pytest.mark.parametrize(
    ("command", "message"),
    [
        pytest.param(
            cmd("post"), "Stop must call `hook stop`, not `hook post`", id="event-swapped"
        ),
        pytest.param(
            cmd("stop", agent="antigravity"),
            "command uses --agent antigravity; expected --agent claude",
            id="wrong-agent",
        ),
        pytest.param(
            cmd("stop") + " --verbose",
            "harness call must be exactly `python scripts/harness/cli.py hook stop --agent claude`",
            id="extra-argument",
        ),
    ],
)
def test_kit_command_format_rules(tmp_path: Path, command: str, message: str) -> None:
    data = kit_settings()
    data["hooks"]["Stop"] = [{"hooks": [command_handler(command)]}]
    write_hook_configs(tmp_path, data)

    assert cs.check_hooks(tmp_path) == [
        f"{SETTINGS} hooks.Stop[0].hooks[0]: {message}",
        f"{SETTINGS}: missing harness events: Stop (hook stop)",
    ]
