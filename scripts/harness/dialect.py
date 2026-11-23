"""Claude Code hooks-file dialect: kit entries and merge of `.claude/settings.json` (stdlib).

Same contract as scripts/harness/dialect.py (ADR-0022): init.py, check_tamper.py and
check_structure.py call it instead of hard-coding the agent format. The Claude export copies
this file byte for byte as scripts/harness/dialect.py. A kit entry is a handler whose
`command.strip()` is a kit command; every other key, matcher group and handler is the project's.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

import config

DIALECT = "claude"
HOOKS_REL = ".claude/settings.json"
AGENT = "claude"
CLI = "scripts/harness/cli.py"
RENDERED_EVENTS: dict[str, str] = {  # Claude Code hook event -> harness CLI event
    "PreToolUse": "pre",
    "PostToolUse": "post",
    "SessionStart": "session-start",
    "Stop": "stop",
}
# Claude Code hook events, from https://code.claude.com/docs/en/hooks (consulted 2026-11-18).
KNOWN_EVENTS: frozenset[str] = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "PermissionRequest",
        "PermissionDenied",
        "UserPromptSubmit",
        "UserPromptExpansion",
        "Notification",
        "Stop",
        "StopFailure",
        "SubagentStart",
        "SubagentStop",
        "SessionStart",
        "SessionEnd",
        "Setup",
        "PreCompact",
        "PostCompact",
        "InstructionsLoaded",
        "ConfigChange",
        "CwdChanged",
        "DirectoryAdded",
        "FileChanged",
        "WorktreeCreate",
        "WorktreeRemove",
        "TeammateIdle",
        "TaskCreated",
        "TaskCompleted",
        "PostToolBatch",
        "MessageDisplay",
        "PreModelSwitch",
        "PostModelSwitch",
        "Elicitation",
        "ElicitationResult",
    }
)
IMPORT_LINE = re.compile(r"^@(\S+)$")  # CLAUDE.md import, after strip()
DRIVE_LETTER = re.compile(r"^[A-Za-z]:")
TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse"})
HANDLER_TYPES = frozenset({"command", "http", "mcp_tool", "prompt", "agent"})
QUOTES_RULE_APPLIES_TO_THIRD_PARTY = False  # Claude Code runs hooks without cmd.exe re-quoting
# Hook commands of every supported pack that declares hooks, as rendered in Claude Code (CWD =
# repository root). A literal table, not pack.toml read at import: the target repository only
# holds the enabled packs, but a retired pack's handler must still count as a kit entry, and
# check_tamper imports this module on every hook. tests/harness/test_claude_dialect.py checks
# the table against the pack manifests.
PACK_HOOK_COMMANDS: dict[str, tuple[str, ...]] = {
    "research-guard": ("python harness/packs/research-guard/scripts/research_guard.py",),
}
KIT_COMMANDS: frozenset[str] = frozenset(
    {f"python {CLI} hook {cli_event} --agent {AGENT}" for cli_event in RENDERED_EVENTS.values()}
    | {command for pack in config.SUPPORTED_PACKS for command in PACK_HOOK_COMMANDS.get(pack, ())}
)


@dataclass(frozen=True)
class HookEntry:
    event: str
    label: str
    raw: object
    owner: Literal["kit", "third"]
    matcher: str | None
    commands: tuple[str, ...]


class HooksFileError(Exception):
    """The hooks file is not a settings object; the message never quotes the file content."""


def _unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """JSON object hook: a repeated key at any depth is an error, not "last value wins"."""
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise HooksFileError(f"{HOOKS_REL}: duplicate key `{key}`")
        obj[key] = value
    return obj


def load(data: bytes) -> dict[str, object]:
    try:
        loaded: object = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_keys)
    except UnicodeDecodeError as exc:
        raise HooksFileError(f"{HOOKS_REL}: not valid JSON (not UTF-8 text)") from exc
    except json.JSONDecodeError as exc:
        raise HooksFileError(f"{HOOKS_REL}: not valid JSON ({exc.msg}, line {exc.lineno})") from exc
    except RecursionError as exc:
        raise HooksFileError(f"{HOOKS_REL}: not valid JSON (nesting too deep)") from exc
    if not isinstance(loaded, dict):
        raise HooksFileError(
            f'{HOOKS_REL}: top level must be a settings object {{"hooks": {{Event: [...]}}}}'
        )
    doc = cast(dict[str, object], loaded)
    if "hooks" in doc and not isinstance(doc["hooks"], dict):
        raise HooksFileError(f'{HOOKS_REL}: "hooks" must be an object {{Event: [matcher groups]}}')
    return doc


def _hooks_map(doc: dict[str, object]) -> dict[str, object]:
    hooks = doc.get("hooks")
    return cast(dict[str, object], hooks) if isinstance(hooks, dict) else {}


def _as_map(value: object) -> dict[str, object] | None:
    return cast(dict[str, object], value) if isinstance(value, dict) else None


def _is_kit_handler(handler: object) -> bool:
    handler_map = _as_map(handler)
    command = handler_map.get("command") if handler_map is not None else None
    return isinstance(command, str) and command.strip() in KIT_COMMANDS


def _kit_handlers(doc: dict[str, object]) -> Iterator[tuple[str, object, object]]:
    """(event, raw matcher, handler) of every kit handler, in document order."""
    for event, groups in _hooks_map(doc).items():
        if not isinstance(groups, list):
            continue
        for group in cast(list[object], groups):
            if not isinstance(group, dict):
                continue
            group_map = cast(dict[str, object], group)
            handlers = group_map.get("hooks")
            if not isinstance(handlers, list):
                continue
            for handler in cast(list[object], handlers):
                if _is_kit_handler(handler):
                    yield event, group_map.get("matcher"), handler


def kit_items(doc: dict[str, object]) -> list[dict[str, object]]:
    """One `{"event", "matcher", "handler"}` item per kit handler (`matcher` None when absent)."""
    return [
        {"event": event, "matcher": matcher, "handler": handler}
        for event, matcher, handler in _kit_handlers(doc)
    ]


def _strip_groups(groups: list[object]) -> tuple[list[object], bool]:
    """Groups without kit handlers; a group is dropped only when it held kit handlers only."""
    kept: list[object] = []
    had_kit = False
    for group in groups:
        group_map = _as_map(group)
        handlers = group_map.get("hooks") if group_map is not None else None
        if group_map is None or not isinstance(handlers, list):
            kept.append(group)
            continue
        others = [h for h in cast(list[object], handlers) if not _is_kit_handler(h)]
        if len(others) == len(cast(list[object], handlers)):
            kept.append(group)
            continue
        had_kit = True
        if others:
            kept.append({**group_map, "hooks": others})
    return kept, had_kit


def strip_kit(doc: dict[str, object]) -> dict[str, object]:
    """Copy of `doc` without kit handlers; top-level key order is kept.

    A matcher group (or event) left empty is removed only when it held a kit handler.
    """
    stripped = dict(doc)
    if not isinstance(doc.get("hooks"), dict):
        return stripped
    hooks: dict[str, object] = {}
    for event, groups in _hooks_map(doc).items():
        if not isinstance(groups, list):
            hooks[event] = groups
            continue
        kept, had_kit = _strip_groups(cast(list[object], groups))
        if kept or not had_kit:
            hooks[event] = kept
    stripped["hooks"] = hooks
    return stripped


def insert_kit(stripped: dict[str, object], rendered: dict[str, object]) -> dict[str, object]:
    """`stripped` plus the kit handlers of `rendered`, keeping every other key in place.

    The kit handlers of one (event, matcher) go, in rendered order, to the start of the first
    group with the same matcher; without such a group, a new group is appended to the event.
    """
    bundles: dict[tuple[str, str], tuple[object, list[object]]] = {}
    for event, matcher, handler in _kit_handlers(rendered):
        key = (event, json.dumps(matcher))
        bundles.setdefault(key, (matcher, []))[1].append(handler)
    merged = dict(stripped)
    current = merged.get("hooks", {})
    if not isinstance(current, dict):
        raise HooksFileError(f'{HOOKS_REL}: "hooks" must be an object {{Event: [matcher groups]}}')
    hooks = dict(cast(dict[str, object], current))
    for (event, _), (matcher, handlers) in bundles.items():
        raw_groups = hooks.get(event, [])
        if not isinstance(raw_groups, list):
            raise HooksFileError(f"{HOOKS_REL} hooks.{event}: must be a list of matcher groups")
        groups = list(cast(list[object], raw_groups))
        for index, group in enumerate(groups):
            if not isinstance(group, dict):
                continue
            group_map = cast(dict[str, object], group)
            current_handlers = group_map.get("hooks")
            if group_map.get("matcher") == matcher and isinstance(current_handlers, list):
                groups[index] = {
                    **group_map,
                    "hooks": [*handlers, *cast(list[object], current_handlers)],
                }
                break
        else:
            new_group: dict[str, object] = {} if matcher is None else {"matcher": matcher}
            new_group["hooks"] = list(handlers)
            groups.append(new_group)
        hooks[event] = groups
    merged["hooks"] = hooks
    return merged


def add_pack_hooks(doc: dict[str, object], packs: Sequence[config.Pack]) -> None:
    """Register the pack hooks in the template `doc` (in place) under `hooks.<Event>`."""
    raw_hooks = doc.setdefault("hooks", {})
    if not isinstance(raw_hooks, dict):
        raise HooksFileError('"hooks" must be an object')
    hooks = cast(dict[str, object], raw_hooks)
    for pack in packs:
        for hook in pack.hooks:
            raw_groups = hooks.setdefault(hook.event, [])
            if not isinstance(raw_groups, list):
                raise HooksFileError(f"event `{hook.event}` must be a list of matcher groups")
            groups = cast(list[object], raw_groups)
            handler: dict[str, object] = {
                "type": "command",
                "command": hook.command,
                "timeout": hook.timeout,
            }
            target: dict[str, object] | None = None
            if hook.event in TOOL_EVENTS:
                for group in groups:
                    group_map = cast(dict[str, object], group) if isinstance(group, dict) else {}
                    if group_map.get("matcher", "") == hook.matcher and isinstance(
                        group_map.get("hooks"), list
                    ):
                        target = group_map
                        break
            if target is not None:
                cast(list[object], target["hooks"]).append(handler)
            elif hook.event in TOOL_EVENTS or hook.matcher:
                groups.append({"matcher": hook.matcher, "hooks": [handler]})
            else:
                groups.append({"hooks": [handler]})


def dump(doc: dict[str, object]) -> bytes:
    """Same serialization as init.render_hooks."""
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _walk_groups(event: str, groups: list[object], label: str) -> tuple[list[HookEntry], list[str]]:
    entries: list[HookEntry] = []
    errors: list[str] = []
    for index, group in enumerate(groups):
        group_label = f"{label}[{index}]"
        if not isinstance(group, dict):
            errors.append(f"{group_label}: must be an object")
            continue
        group_map = cast(dict[str, object], group)
        handlers = group_map.get("hooks")
        if not isinstance(handlers, list):
            errors.append(f"{group_label}: must have a `hooks` list of handlers")
            continue
        matcher = group_map.get("matcher")
        for position, raw in enumerate(cast(list[object], handlers)):
            entry_label = f"{group_label}.hooks[{position}]"
            handler = _as_map(raw)
            if handler is None:
                errors.append(f"{entry_label}: must be an object")
                continue
            command = handler.get("command")
            entries.append(
                HookEntry(
                    event=event,
                    label=entry_label,
                    raw=handler,
                    owner="kit" if _is_kit_handler(handler) else "third",
                    matcher=matcher if isinstance(matcher, str) else None,
                    commands=(command,) if isinstance(command, str) else (),
                )
            )
    return entries, errors


def walk(doc: dict[str, object]) -> tuple[list[HookEntry], list[str]]:
    """Every handler under `hooks.<Event>[i].hooks[j]`; other top-level keys are not hooks."""
    entries: list[HookEntry] = []
    errors: list[str] = []
    for event, groups in _hooks_map(doc).items():
        label = f"{HOOKS_REL} hooks.{event}"
        if event not in KNOWN_EVENTS:
            errors.append(
                f"{label}: unknown Claude Code hook event (expected a documented event such as "
                f"{', '.join(RENDERED_EVENTS)})"
            )
            continue
        if not isinstance(groups, list):
            errors.append(f"{label}: must be a list of matcher groups")
            continue
        found, problems = _walk_groups(event, cast(list[object], groups), label)
        entries += found
        errors += problems
    return entries, errors


def top_level_errors(doc: dict[str, object]) -> list[str]:
    errors: list[str] = []
    if "hooks" not in doc:
        errors.append(f'{HOOKS_REL}: missing "hooks" object (project it with `python {CLI} init`)')
    elif not isinstance(doc["hooks"], dict):
        errors.append(f'{HOOKS_REL}: "hooks" must be an object {{Event: [matcher groups]}}')
    if doc.get("disableAllHooks") is True:
        errors.append(
            f"{HOOKS_REL}: disableAllHooks is true, which turns off every harness hook; "
            "remove it or set it to false"
        )
    return errors


def third_party_errors(entry: HookEntry) -> list[str]:
    handler = _as_map(entry.raw) or {}
    kind = handler.get("type")
    if not isinstance(kind, str) or kind not in HANDLER_TYPES:
        return [f"{entry.label}: `type` must be one of {', '.join(sorted(HANDLER_TYPES))}"]
    if kind == "command" and not any(command.strip() for command in entry.commands):
        return [f"{entry.label}: declares no `command`"]
    return []


def _is_link(path: Path) -> bool:
    return path.is_symlink()


def _real_path(path: Path) -> Path:
    """The path with every link and NTFS junction followed (`is_symlink()` misses junctions)."""
    return path.resolve()


def _import_lines(text: str) -> list[str]:
    """Paths of the `@<path>` lines outside fenced blocks (``` or ~~~), in file order."""
    imports: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        marker = stripped[:3]
        if fence is None and marker in ("```", "~~~"):
            fence = marker
        elif fence is not None:
            if stripped.startswith(fence):
                fence = None
        elif match := IMPORT_LINE.match(stripped):
            imports.append(match.group(1))
    return imports


def _resolve_import(raw: str, base: Path, root: Path) -> tuple[Path | None, str | None]:
    """(target, None) for a valid import, else (None, reason).

    Pure-path rules first; then the real path (links and junctions followed) must stay in root.
    """
    if raw.startswith(("/", "\\", "~")) or DRIVE_LETTER.match(raw) or os.path.isabs(raw):
        return None, "escapes the repository root"
    root_path = Path(os.path.normpath(root))
    target = Path(os.path.normpath(base / raw))
    if not target.is_relative_to(root_path):
        return None, "escapes the repository root"
    prefix = root_path
    for part in target.relative_to(root_path).parts:
        prefix = prefix / part
        if _is_link(prefix):
            return None, "is a symbolic link"
    if not _real_path(target).is_relative_to(_real_path(root_path)):
        return None, "escapes the repository root"
    if not target.is_file():
        return None, "does not exist"
    return target, None


def guidance_set(path: Path, root: Path) -> tuple[list[Path], list[str]]:
    """The guidance file plus its valid `@<path>` imports (one level; imports are not followed).

    Read only. An import that is absolute, leaves the root, crosses a symbolic link or names
    no file is reported and left out of the set.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return [path], []  # check_structure reads and reports the file itself
    try:
        where = path.relative_to(root).as_posix()
    except ValueError:
        where = path.name
    paths = [path]
    errors: list[str] = []
    for raw in _import_lines(text):
        target, reason = _resolve_import(raw, path.parent, root)
        if target is None:
            errors.append(f"{where}: import `{raw}` {reason}")
        elif target not in paths:
            paths.append(target)
    return paths, errors
