"""Hooks-file merge of `cli.py init` in Claude Code (Requisito 1).

Claude counterpart of the merge tests of the source test_init.py, which the export leaves out:
kit entries are the handlers whose command is a kit command. Third-party entries are synthetic.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import init
import pytest

SOURCE = init.SOURCE_ROOT
HOOKS_REL = ".claude/settings.json"
SETTINGS_TEMPLATE = SOURCE / "harness" / "templates" / "settings.claude.json"
RESEARCH_GUARD = "python harness/packs/research-guard/scripts/research_guard.py"
KIT_COMMANDS = frozenset(
    {
        "python scripts/harness/cli.py hook pre --agent claude",
        "python scripts/harness/cli.py hook post --agent claude",
        "python scripts/harness/cli.py hook session-start --agent claude",
        "python scripts/harness/cli.py hook stop --agent claude",
        RESEARCH_GUARD,
    }
)
THIRD_PARTY_HANDLER: dict[str, Any] = {
    "type": "command",
    "command": 'python "${CLAUDE_PROJECT_DIR}/.claude/hooks/meu_hook.py" pre',
    "timeout": 10,
}
BASH_GROUP: dict[str, Any] = {"matcher": "Bash", "hooks": [THIRD_PARTY_HANDLER]}
PROMPT_GROUPS: list[Any] = [{"hooks": [{"type": "prompt", "prompt": "Resuma o pedido."}]}]
PROJECT_KEYS: dict[str, Any] = {
    "$schema": "https://json.schemastore.org/claude-code-settings.json",
    "permissions": {"allow": ["Bash(uv run pytest:*)"], "deny": ["WebFetch"]},
    "env": {"HARNESS_DEMO": "1"},
    "x-meta": {"owner": "time-dados"},
}

Doc = dict[str, Any]


def make_target(tmp_path: Path) -> Path:
    target = tmp_path / "projeto-demo"
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


def snapshot(root: Path) -> dict[str, bytes]:
    return {relative: (root / relative).read_bytes() for relative in files_under(root)}


def template_settings() -> Doc:
    return cast(Doc, json.loads(SETTINGS_TEMPLATE.read_text(encoding="utf-8")))


def read_settings(target: Path) -> Doc:
    return cast(Doc, json.loads((target / HOOKS_REL).read_text(encoding="utf-8")))


def write_settings(target: Path, doc: object, indent: int = 2) -> None:
    path = target / HOOKS_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(doc, indent=indent) + "\n").encode("utf-8"))


def with_project_entries(doc: Doc) -> Doc:
    """`doc` plus project keys, a third-party matcher group and a non-rendered event."""
    merged: Doc = {**copy.deepcopy(PROJECT_KEYS), **copy.deepcopy(doc)}
    hooks = merged.setdefault("hooks", {})
    hooks.setdefault("PreToolUse", []).append(copy.deepcopy(BASH_GROUP))
    hooks["UserPromptSubmit"] = copy.deepcopy(PROMPT_GROUPS)
    return merged


def commands(doc: Doc) -> list[str]:
    return [
        str(handler.get("command", ""))
        for groups in doc.get("hooks", {}).values()
        for group in groups
        for handler in group["hooks"]
    ]


def kit_items(doc: Doc) -> list[str]:
    """Sorted canonical kit items (event, matcher, handler) of `doc` (design, Modelo de Dados)."""
    return sorted(
        json.dumps(
            {"event": event, "matcher": group.get("matcher"), "handler": handler},
            sort_keys=True,
        )
        for event, groups in doc.get("hooks", {}).items()
        for group in groups
        for handler in group["hooks"]
        if str(handler.get("command", "")).strip() in KIT_COMMANDS
    )


def assert_project_entries_kept(doc: Doc) -> None:
    assert {key: doc[key] for key in PROJECT_KEYS} == PROJECT_KEYS
    assert BASH_GROUP in doc["hooks"]["PreToolUse"]
    assert doc["hooks"]["UserPromptSubmit"] == PROMPT_GROUPS


def test_init_creates_settings_when_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = make_target(tmp_path)
    packs = init.load_packs(SOURCE, ("research-guard",))

    assert run_init(target, "--packs", "research-guard") == 0

    assert f"create: {HOOKS_REL}" in capsys.readouterr().out
    assert (target / HOOKS_REL).read_bytes() == init.render_hooks(SOURCE, packs)


@pytest.mark.parametrize("args", [(), ("--force",)], ids=["without-force", "with-force"])
def test_init_merges_settings_when_kit_entries_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], args: tuple[str, ...]
) -> None:
    target = make_target(tmp_path)
    write_settings(target, with_project_entries({}))

    assert run_init(target, *args) == 0

    assert f"merge: {HOOKS_REL}" in capsys.readouterr().out
    doc = read_settings(target)
    assert_project_entries_kept(doc)
    assert kit_items(doc) == kit_items(template_settings())
    assert list(doc) == [*PROJECT_KEYS, "hooks"]


def _drop_stop_event(doc: Doc) -> None:
    del doc["hooks"]["Stop"]


def _diverge_kit_pre_timeout(doc: Doc) -> None:
    doc["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 5


@pytest.mark.parametrize(
    ("change", "args"),
    [(_drop_stop_event, ()), (_diverge_kit_pre_timeout, ("--force",))],
    ids=["missing-kit-event", "diverged-kit-handler-with-force"],
)
def test_init_keeps_third_party_handler_in_kit_matcher_group(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    change: Callable[[Doc], None],
    args: tuple[str, ...],
) -> None:
    """Requisito 1.4: a third-party handler next to a kit handler survives the merge."""
    target = make_target(tmp_path)
    doc = template_settings()
    doc["hooks"]["PreToolUse"][0]["hooks"].append(copy.deepcopy(THIRD_PARTY_HANDLER))
    change(doc)
    write_settings(target, doc)

    assert run_init(target, *args) == 0

    assert f"merge: {HOOKS_REL}" in capsys.readouterr().out
    merged = read_settings(target)
    kit_pre = template_settings()["hooks"]["PreToolUse"][0]["hooks"][0]
    assert merged["hooks"]["PreToolUse"] == [
        {"matcher": "", "hooks": [kit_pre, THIRD_PARTY_HANDLER]}
    ]
    assert kit_items(merged) == kit_items(template_settings())


def test_init_reports_unchanged_when_settings_matches_merge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = make_target(tmp_path)
    assert run_init(target) == 0
    write_settings(target, with_project_entries(template_settings()), indent=4)
    before = (target / HOOKS_REL).read_bytes()
    written: list[Path] = []
    # The spy wraps the private writer the design names (Requisito 1.5); no public seam exists.
    original_write = init._atomic_write  # pyright: ignore[reportPrivateUsage]

    def spy(path: Path, data: bytes) -> None:
        written.append(path)
        original_write(path, data)

    monkeypatch.setattr(init, "_atomic_write", spy)
    capsys.readouterr()

    assert run_init(target) == 0

    assert f"unchanged: {HOOKS_REL}" in capsys.readouterr().out
    assert target / HOOKS_REL not in written
    assert (target / HOOKS_REL).read_bytes() == before


def test_init_force_twice_is_idempotent_with_third_party_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = make_target(tmp_path)
    write_settings(target, with_project_entries({}))
    assert run_init(target, "--force") == 0
    first_settings = (target / HOOKS_REL).read_bytes()
    first_baseline = (target / "harness" / "baseline.json").read_bytes()
    capsys.readouterr()

    assert run_init(target, "--force") == 0

    out = capsys.readouterr().out
    assert f"unchanged: {HOOKS_REL}" in out
    assert "unchanged: harness/baseline.json" in out
    assert (target / HOOKS_REL).read_bytes() == first_settings
    assert (target / "harness" / "baseline.json").read_bytes() == first_baseline
    assert_project_entries_kept(read_settings(target))


def _change_timeout(doc: Doc) -> None:
    doc["hooks"]["Stop"][0]["hooks"][0]["timeout"] = 5


def _change_matcher(doc: Doc) -> None:
    doc["hooks"]["PreToolUse"][0]["matcher"] = "Edit"


def _change_type(doc: Doc) -> None:
    doc["hooks"]["SessionStart"][0]["hooks"][0]["type"] = "http"


def _copy_to_other_event(doc: Doc) -> None:
    stop_handler = copy.deepcopy(doc["hooks"]["Stop"][0]["hooks"][0])
    doc["hooks"]["PostToolUse"][0]["hooks"].append(stop_handler)


def _duplicate_handler(doc: Doc) -> None:
    doc["hooks"]["Stop"][0]["hooks"].append(copy.deepcopy(doc["hooks"]["Stop"][0]["hooks"][0]))


# The command is the kit identity in Claude Code: a changed command is a third-party handler.
KIT_ENTRY_CHANGES = pytest.mark.parametrize(
    "change",
    [_change_timeout, _change_matcher, _change_type, _copy_to_other_event, _duplicate_handler],
    ids=["timeout", "matcher", "type", "other-event", "duplicate"],
)


@KIT_ENTRY_CHANGES
def test_init_reports_conflict_when_kit_entry_differs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: Callable[[Doc], None]
) -> None:
    target = make_target(tmp_path)
    assert run_init(target) == 0
    doc = with_project_entries(template_settings())
    change(doc)
    write_settings(target, doc)
    (target / "harness" / "core.toml").unlink()
    before = snapshot(target)
    capsys.readouterr()

    assert run_init(target) == 1

    out = capsys.readouterr().out
    assert f"conflict: {HOOKS_REL}" in out
    assert "nothing was written" in out
    assert snapshot(target) == before


@KIT_ENTRY_CHANGES
def test_init_force_replaces_only_kit_entries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], change: Callable[[Doc], None]
) -> None:
    target = make_target(tmp_path)
    assert run_init(target) == 0
    doc = with_project_entries(template_settings())
    change(doc)
    write_settings(target, doc)
    capsys.readouterr()

    assert run_init(target, "--force") == 0

    assert f"merge: {HOOKS_REL}" in capsys.readouterr().out
    merged = read_settings(target)
    assert kit_items(merged) == kit_items(template_settings())
    assert_project_entries_kept(merged)


@pytest.mark.parametrize(
    ("args", "code", "status", "pack_kept"),
    [(("--force",), 0, "merge", False), ((), 1, "conflict", True)],
    ids=["with-force", "without-force"],
)
def test_init_handles_retired_pack_entries(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    args: tuple[str, ...],
    code: int,
    status: str,
    pack_kept: bool,
) -> None:
    target = make_target(tmp_path)
    assert run_init(target, "--packs", "research-guard") == 0
    write_settings(target, with_project_entries(read_settings(target)))
    capsys.readouterr()

    assert run_init(target, *args) == code

    assert f"{status}: {HOOKS_REL}" in capsys.readouterr().out
    doc = read_settings(target)
    assert (RESEARCH_GUARD in commands(doc)) is pack_kept
    assert_project_entries_kept(doc)


@pytest.mark.parametrize("args", [(), ("--force",)], ids=["without-force", "with-force"])
@pytest.mark.parametrize(
    "content",
    [b"{not json\n", b"[]\n", b'{"hooks": []}\n'],
    ids=["invalid-json", "top-list", "hooks-list"],
)
def test_init_fails_on_invalid_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: bytes, args: tuple[str, ...]
) -> None:
    target = make_target(tmp_path)
    (target / ".claude").mkdir()
    (target / HOOKS_REL).write_bytes(content)

    assert run_init(target, *args) == 1

    failures = [
        line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("HARNESS INIT FAILED:")
    ]
    assert any(HOOKS_REL in line for line in failures)
    assert files_under(target) == {HOOKS_REL}
    assert (target / HOOKS_REL).read_bytes() == content


@pytest.mark.parametrize("args", [(), ("--force",)], ids=["without-force", "with-force"])
def test_init_fails_on_non_list_kit_event_in_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], args: tuple[str, ...]
) -> None:
    """Valid JSON whose `hooks.<Event>` is not a list fails cleanly, without a traceback."""
    target = make_target(tmp_path)
    content = b'{"hooks": {"PreToolUse": "x"}}\n'
    (target / ".claude").mkdir()
    (target / HOOKS_REL).write_bytes(content)

    assert run_init(target, *args) == 1

    failures = [
        line
        for line in capsys.readouterr().out.splitlines()
        if line.startswith("HARNESS INIT FAILED:")
    ]
    assert any(HOOKS_REL in line for line in failures)
    assert files_under(target) == {HOOKS_REL}
    assert (target / HOOKS_REL).read_bytes() == content


def test_init_dry_run_lists_merge(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = make_target(tmp_path)
    write_settings(target, with_project_entries({}))
    before = snapshot(target)

    assert run_init(target, "--dry-run") == 0

    assert f"merge: {HOOKS_REL}" in capsys.readouterr().out
    assert snapshot(target) == before


def summary_line(report: str) -> str:
    return next(line for line in report.splitlines() if line.startswith("Summary: "))


def test_report_summary_counts_merge(tmp_path: Path) -> None:
    actions = [
        init.Action("CLAUDE.md", "create", b""),
        init.Action(HOOKS_REL, "merge", b""),
    ]

    report = init.render_report(tmp_path, actions, init.Options(target=tmp_path))

    assert summary_line(report) == (
        "Summary: 1 create, 0 overwrite, 0 unchanged, 0 kept, 0 conflict, 1 merge, 0 skipped"
    )


def test_report_summary_counts_skipped(tmp_path: Path) -> None:
    actions = [
        init.Action(".claude/rules/product.md", "skipped", b""),
        init.Action("CLAUDE.md", "unchanged", b""),
    ]

    report = init.render_report(tmp_path, actions, init.Options(target=tmp_path))

    assert summary_line(report) == (
        "Summary: 0 create, 0 overwrite, 1 unchanged, 0 kept, 0 conflict, 0 merge, 1 skipped"
    )
