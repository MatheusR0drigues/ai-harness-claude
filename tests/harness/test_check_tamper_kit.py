"""Tamper digest of .claude/settings.json kit entries (Requisito 2).

Claude counterpart of the kit-entry digest tests of the source test_check_tamper.py, which the
export leaves out. Third-party entries are synthetic.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import check_tamper
import pytest
from config_fixtures import write_core

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS_TEMPLATE = REPO_ROOT / "harness" / "templates" / "settings.claude.json"
HOOKS_REL = ".claude/settings.json"
HOOKS_TAMPER = f"modified protected harness file: {HOOKS_REL}"
PACK_HANDLER: dict[str, Any] = {
    "type": "command",
    "command": "python harness/packs/research-guard/scripts/research_guard.py",
    "timeout": 30,
}
THIRD_PARTY_HANDLER: dict[str, Any] = {
    "type": "command",
    "command": 'python "${CLAUDE_PROJECT_DIR}/.claude/hooks/meu_hook.py" pre',
    "timeout": 10,
}
VERSION_1_MESSAGE = (
    "invalid tamper baseline (`harness/baseline.json`: version 1 predates kit-entry digests; "
    "ask the human to run `python scripts/harness/cli.py init --force` or "
    "`check_tamper.py --update`)"
)

Doc = dict[str, Any]


def _canonical(value: object) -> bytes:
    """Serializacao canonica (glossary of specs/kit-adoption-compat/requirements.md)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _template_doc() -> Doc:
    return cast(Doc, json.loads(SETTINGS_TEMPLATE.read_text(encoding="utf-8")))


def _adopter_doc() -> Doc:
    """The template plus project keys and a third-party handler in the kit matcher group."""
    doc: Doc = {
        "$schema": "https://json.schemastore.org/claude-code-settings.json",
        "permissions": {"allow": ["Bash(uv run pytest:*)"]},
        "env": {"HARNESS_DEMO": "1"},
        **_template_doc(),
    }
    doc["hooks"]["PreToolUse"][0]["hooks"].append(copy.deepcopy(THIRD_PARTY_HANDLER))
    return doc


def _dump(doc: Doc) -> bytes:
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _seed_adopter(root: Path) -> Path:
    write_core(root, "[controls]\nrequired_gates = []\n")
    guards = root / "scripts" / "harness" / "guards.py"
    guards.parent.mkdir(parents=True, exist_ok=True)
    guards.write_text("ALL = ()\n", encoding="utf-8")
    hooks = root / HOOKS_REL
    hooks.parent.mkdir(parents=True, exist_ok=True)
    hooks.write_bytes(_dump(_adopter_doc()))
    return hooks


def _kit_pre_group(doc: Doc) -> Doc:
    return doc["hooks"]["PreToolUse"][0]


def _reversed_keys(value: object) -> object:
    """Same JSON value with every object's key order reversed (list order is kept)."""
    if isinstance(value, dict):
        items = list(cast(dict[str, object], value).items())
        return {key: _reversed_keys(item) for key, item in reversed(items)}
    if isinstance(value, list):
        return [_reversed_keys(item) for item in cast(list[object], value)]
    return value


def _add_third_party_group(doc: Doc) -> bytes:
    doc["hooks"]["PreToolUse"].append({"matcher": "Bash", "hooks": [THIRD_PARTY_HANDLER]})
    return _dump(doc)


def _change_third_party_handler(doc: Doc) -> bytes:
    _kit_pre_group(doc)["hooks"][1]["timeout"] = 99
    return _dump(doc)


def _remove_third_party_handler(doc: Doc) -> bytes:
    _kit_pre_group(doc)["hooks"].pop()
    return _dump(doc)


def _add_non_rendered_event(doc: Doc) -> bytes:
    doc["hooks"]["UserPromptSubmit"] = [{"hooks": [{"type": "prompt", "prompt": "Resuma."}]}]
    return _dump(doc)


def _change_permissions(doc: Doc) -> bytes:
    doc["permissions"] = {"deny": ["WebFetch"]}
    return _dump(doc)


def _change_schema_and_env(doc: Doc) -> bytes:
    doc["$schema"] = "https://example.invalid/settings.schema.json"
    doc["env"] = {}
    return _dump(doc)


def _reorder_keys(doc: Doc) -> bytes:
    return _dump(cast(Doc, _reversed_keys(doc)))


def _reformat_whitespace(doc: Doc) -> bytes:
    text = json.dumps(doc, indent="\t", separators=(", ", " : "))
    return text.replace("\n", "\r\n").encode("utf-8")


def _change_kit_command(doc: Doc) -> bytes:
    _kit_pre_group(doc)["hooks"][0]["command"] = (
        "python scripts/harness/cli.py hook post --agent claude"
    )
    return _dump(doc)


def _change_kit_timeout(doc: Doc) -> bytes:
    _kit_pre_group(doc)["hooks"][0]["timeout"] = 1
    return _dump(doc)


def _change_kit_matcher(doc: Doc) -> bytes:
    _kit_pre_group(doc)["matcher"] = "Bash"
    return _dump(doc)


def test_hooks_digest_is_canonical_kit_entries() -> None:
    doc = _adopter_doc()
    _kit_pre_group(doc)["hooks"].append(copy.deepcopy(PACK_HANDLER))
    data = _dump(doc)
    kit_items: list[object] = [
        {"event": event, "matcher": group.get("matcher"), "handler": handler}
        for event, groups in _template_doc()["hooks"].items()
        for group in groups
        for handler in group["hooks"]
    ]
    kit_items.append({"event": "PreToolUse", "matcher": "", "handler": PACK_HANDLER})
    expected = hashlib.sha256(_canonical(sorted(kit_items, key=_canonical))).hexdigest()
    core = b"[controls]\r\nrequired_gates = []\r\n"

    assert check_tamper.hooks_digest(data) == expected
    assert check_tamper.digest_for(HOOKS_REL, data) == expected
    assert check_tamper.digest_for("harness/core.toml", core) == check_tamper.digest_bytes(core)


def test_update_writes_same_digest_as_init(tmp_path: Path) -> None:
    data = _seed_adopter(tmp_path).read_bytes()
    rendered = json.loads(check_tamper.render_baseline({HOOKS_REL: data}))

    target, _ = check_tamper.write_baseline(tmp_path)

    written = json.loads(target.read_text(encoding="utf-8"))
    assert written["files"][HOOKS_REL] == rendered["files"][HOOKS_REL]
    assert written["files"][HOOKS_REL] == check_tamper.hooks_digest(data)


@pytest.mark.parametrize(
    "mutate",
    [
        _add_third_party_group,
        _change_third_party_handler,
        _remove_third_party_handler,
        _add_non_rendered_event,
        _change_permissions,
        _change_schema_and_env,
        _reorder_keys,
        _reformat_whitespace,
    ],
    ids=[
        "add-third-party-group",
        "change-third-party-handler",
        "remove-third-party-handler",
        "add-non-rendered-event",
        "change-permissions",
        "change-schema-and-env",
        "reorder-keys",
        "indentation-and-line-breaks",
    ],
)
def test_third_party_changes_keep_tamper_green(
    tmp_path: Path, mutate: Callable[[Doc], bytes]
) -> None:
    hooks = _seed_adopter(tmp_path)
    check_tamper.write_baseline(tmp_path)

    hooks.write_bytes(mutate(_adopter_doc()))

    assert check_tamper.verify(tmp_path) == []


@pytest.mark.parametrize(
    "mutate",
    [_change_kit_command, _change_kit_timeout, _change_kit_matcher],
    ids=["command", "timeout", "matcher"],
)
def test_kit_entry_change_is_tamper(tmp_path: Path, mutate: Callable[[Doc], bytes]) -> None:
    hooks = _seed_adopter(tmp_path)
    check_tamper.write_baseline(tmp_path)

    hooks.write_bytes(mutate(_adopter_doc()))

    assert check_tamper.verify(tmp_path) == [HOOKS_TAMPER]


def test_kit_entry_removal_is_tamper(tmp_path: Path) -> None:
    hooks = _seed_adopter(tmp_path)
    check_tamper.write_baseline(tmp_path)
    doc = _adopter_doc()
    del doc["hooks"]["Stop"]

    hooks.write_bytes(_dump(doc))

    assert check_tamper.verify(tmp_path) == [HOOKS_TAMPER]


@pytest.mark.parametrize(
    "raw_hooks",
    [b'{"hooks": {\n', b"[]\n", b'{"hooks": []}\n'],
    ids=["invalid-json", "top-level-list", "hooks-list"],
)
def test_invalid_settings_is_tamper(tmp_path: Path, raw_hooks: bytes) -> None:
    hooks = _seed_adopter(tmp_path)
    check_tamper.write_baseline(tmp_path)

    hooks.write_bytes(raw_hooks)

    assert check_tamper.verify(tmp_path) == [HOOKS_TAMPER]


def test_version_1_baseline_reports_upgrade_message(tmp_path: Path) -> None:
    _seed_adopter(tmp_path)
    (tmp_path / "harness" / "baseline.json").write_text(
        json.dumps({"version": 1, "files": {"harness/core.toml": "a" * 64}}), encoding="utf-8"
    )

    findings = check_tamper.verify(tmp_path)

    assert findings == [VERSION_1_MESSAGE]


@pytest.mark.parametrize(
    "raw_hooks", [b'{"hooks": {\n', b'{"hooks": []}\n'], ids=["invalid-json", "hooks-list"]
)
def test_update_fails_on_invalid_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], raw_hooks: bytes
) -> None:
    hooks = _seed_adopter(tmp_path)
    hooks.write_bytes(raw_hooks)

    exit_code = check_tamper.main(["--update"], root=tmp_path)

    assert exit_code == 1
    assert f"TAMPER BASELINE UPDATE FAILED: {HOOKS_REL}" in capsys.readouterr().out


def test_new_module_is_monitored() -> None:
    assert check_tamper.is_monitored_path("scripts/harness/dialect.py")
    assert "scripts/harness/dialect.py" in check_tamper.collect_blobs(REPO_ROOT)
