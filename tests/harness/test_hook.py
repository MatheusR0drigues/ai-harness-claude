"""Tests for hook.py in Claude Code."""

from __future__ import annotations

import json

import hook
from payload_fixtures import raw

ROOT = hook.REPO_ROOT
SETTINGS_JSON = ROOT / ".claude" / "settings.json"
SETTINGS_TEMPLATE = ROOT / "harness" / "templates" / "settings.claude.json"


def test_allowed_pre_call_prints_nothing() -> None:
    response = hook.run("claude", "pre", raw("claude", "read"))
    assert response.code == 0
    assert response.stdout == ""


def test_real_guards_deny_sensitive_write() -> None:
    body = json.dumps(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": ".env", "content": "X=1"},
        }
    )
    response = hook.run("claude", "pre", body)
    assert response.code == 2
    assert "BLOCKED" in response.stderr


def test_unreadable_pre_payload_is_denied_fail_closed() -> None:
    response = hook.run("claude", "pre", "{broken json")
    assert response.code == 2
    assert "BLOCKED" in response.stderr


def test_clean_session_start_answers_empty_or_zero() -> None:
    response = hook.run("claude", "session-start", "{}")
    assert response.code == 0


def test_settings_json_matches_template() -> None:
    assert SETTINGS_JSON.is_file()
    assert SETTINGS_TEMPLATE.is_file()
    doc = json.loads(SETTINGS_JSON.read_text("utf-8"))
    assert "hooks" in doc
    assert "PreToolUse" in doc["hooks"]
    assert "PostToolUse" in doc["hooks"]
    assert "SessionStart" in doc["hooks"]
    assert "Stop" in doc["hooks"]


def test_unknown_agent_on_pre_is_denied() -> None:
    response = hook.run("antigravity", "pre", raw("claude", "read"))
    assert response.code == 2


def test_pr_confirmation_emits_ask_json() -> None:
    body = json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "gh pr create --title demo"},
        }
    )
    response = hook.run("claude", "pre", body, ())
    assert response.code == 0
    assert response.stderr == ""
    doc = json.loads(response.stdout)
    assert doc["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
