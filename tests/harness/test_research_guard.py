"""Tests for research_guard.py in Claude Code."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import research_guard
from research_guard import Entry, load_allowlist, parse_links

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "harness" / "packs" / "research-guard" / "scripts" / "research_guard.py"
LINKS = "https://docs.example.dev/; https://kb.example.org/guide\n# https://evil.test/\npypi.org\n"


def payload(tool: str, **args: object) -> str:
    return json.dumps({"tool_name": tool, "tool_input": args})


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    links = tmp_path / "docs" / "links.txt"
    links.parent.mkdir(parents=True)
    links.write_text(LINKS, encoding="utf-8")
    return tmp_path


def test_parse_links_accepts_separators_and_comments() -> None:
    assert parse_links(LINKS) == [
        Entry("docs.example.dev", ""),
        Entry("kb.example.org", "/guide"),
        Entry("pypi.org", ""),
    ]


def test_load_allowlist_missing_file_is_empty(tmp_path: Path) -> None:
    assert load_allowlist(tmp_path) == []


def test_search_web_is_denied(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = research_guard.main([], repo, stdin=payload("WebSearch", query="claude hooks"))
    assert code == 2
    assert "BLOCKED web search" in capsys.readouterr().err


def test_read_url_unlisted_is_denied(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = research_guard.main([], repo, stdin=payload("WebFetch", url="https://evil.test/x"))
    assert code == 2
    assert "BLOCKED WebFetch" in capsys.readouterr().err


def test_read_url_listed_is_allowed(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = research_guard.main([], repo, stdin=payload("WebFetch", url="https://docs.example.dev/"))
    assert code == 0
    assert capsys.readouterr().err == ""


def test_shell_unlisted_url_is_denied(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = research_guard.main([], repo, stdin=payload("Bash", command="curl https://evil.test/x"))
    assert code == 2
    assert "BLOCKED" in capsys.readouterr().err


def test_shell_listed_url_is_allowed(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = research_guard.main(
        [], repo, stdin=payload("Bash", command="curl https://docs.example.dev/api")
    )
    assert code == 0


@pytest.mark.parametrize("bad_name", [123, True, None, ""])
def test_non_string_tool_name_is_denied_fail_closed(repo: Path, bad_name: object) -> None:
    raw_body = json.dumps({"tool_name": bad_name, "tool_input": {}})
    assert research_guard.main([], repo, stdin=raw_body) == 2
