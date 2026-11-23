"""Tests for payload.py in Claude Code."""

from __future__ import annotations

import json

import payload
import pytest
from payload import PayloadError
from payload_fixtures import raw


@pytest.mark.parametrize(
    ("name", "tool", "kind"),
    [
        ("write", "Write", "write"),
        ("multi_replace", "MultiEdit", "write"),
        ("bash", "Bash", "shell"),
        ("read", "Read", "read"),
        ("grep", "Grep", "search"),
        ("glob", "Glob", "search"),
    ],
)
def test_pre_tool_payloads_are_normalized(name: str, tool: str, kind: str) -> None:
    event = payload.parse("claude", "pre", raw("claude", name))
    assert (event.agent, event.event, event.tool, event.kind) == ("claude", "pre", tool, kind)


def test_stop_fields_extract_claude_variants() -> None:
    stop_raw = raw("claude", "stop")
    ev = payload.parse("claude", "stop", stop_raw)
    assert ev.agent == "claude"
    assert ev.continuation_active is False
    assert ev.cwd == "/workspace/repo"


@pytest.mark.parametrize(
    ("raw_payload", "message"),
    [
        ("{not json", "not valid JSON"),
        ("[1, 2]", "not a JSON object"),
        ("{}", "no tool name"),
        (json.dumps({"tool_name": "Write"}), "without a target path"),
    ],
)
def test_unreadable_or_incomplete_payloads_raise(raw_payload: str, message: str) -> None:
    with pytest.raises(PayloadError, match=message):
        payload.parse("claude", "pre", raw_payload)
