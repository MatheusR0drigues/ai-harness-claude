"""Install global ai-harness artifacts into ~/.claude (or a custom --target).

Usage:
  python scripts/harness/cli.py install-global [--target PATH] [--dry-run] [--force]
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = SOURCE_ROOT / "plugin"
USAGE = "usage: cli.py install-global [--target PATH] [--dry-run] [--force]"


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary, str(path))
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def check_target(source: Path, target: Path) -> Path:
    if target.is_symlink():
        raise ValueError("refusing to install into a symlink target")
    resolved = target.resolve()
    source_resolved = source.resolve()
    if resolved == source_resolved or _is_within(resolved, source_resolved):
        raise ValueError(
            "refusing to install into the source repository; pass `--target <home directory>`"
        )
    gemini = (Path.home() / ".gemini").resolve()
    if resolved == gemini or _is_within(resolved, gemini):
        raise ValueError("refusing to install into `~/.gemini/`; pass `--target ~/.claude`")
    return resolved


def _validate_destinations(plan: Sequence[tuple[Path, bytes]], target: Path) -> None:
    for dest, _ in plan:
        if dest.is_symlink():
            raise ValueError(f"refusing to overwrite symlink `{dest}`")
        cur = dest.parent
        while cur != target and cur != cur.parent:
            if cur.is_symlink():
                raise ValueError(f"refusing to traverse symlink `{cur}`")
            cur = cur.parent
        anc = dest.parent
        while anc != target and not anc.exists() and anc != anc.parent:
            anc = anc.parent
        if anc.exists():
            resolved_anc = anc.resolve()
            if resolved_anc != target and not _is_within(resolved_anc, target):
                raise ValueError(f"refusing to write outside target directory: {dest}")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    target_path = Path.home() / ".claude"
    dry_run = False
    force = False

    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--target":
            if index + 1 >= len(args) or args[index + 1].startswith("--"):
                sys.stderr.write("error: --target requires a value\n")
                return 1
            target_path = Path(args[index + 1])
            index += 2
            continue
        if arg == "--dry-run":
            dry_run = True
        elif arg == "--force":
            force = True
        else:
            sys.stderr.write(f"error: unknown argument `{arg}`\n{USAGE}\n")
            return 1
        index += 1

    try:
        target = check_target(SOURCE_ROOT, target_path)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    plan: list[tuple[Path, bytes]] = []

    claude_md = PLUGIN_DIR / "rules" / "CLAUDE.md"
    if claude_md.is_file():
        plan.append((target / "CLAUDE.md", claude_md.read_bytes()))

    rules_dir = PLUGIN_DIR / "rules"
    if rules_dir.is_dir():
        for rule_path in sorted(rules_dir.glob("*.md")):
            if rule_path.name != "CLAUDE.md":
                plan.append((target / "rules" / rule_path.name, rule_path.read_bytes()))

    agents_dir = PLUGIN_DIR / "agents"
    if agents_dir.is_dir():
        for agent_path in sorted(agents_dir.glob("*.md")):
            plan.append((target / "agents" / agent_path.name, agent_path.read_bytes()))

    skills_dir = PLUGIN_DIR / "skills"
    if skills_dir.is_dir():
        for path in sorted(skills_dir.rglob("*")):
            if not path.is_file():
                continue
            if any(part in ("__pycache__", ".pytest_cache", ".ruff_cache") for part in path.parts):
                continue
            rel = path.relative_to(skills_dir)
            plan.append((target / "skills" / rel, path.read_bytes()))

    scripts_dir = PLUGIN_DIR / "scripts"
    if scripts_dir.is_dir():
        for script_path in sorted(scripts_dir.glob("*.py")):
            plan.append((target / "scripts" / script_path.name, script_path.read_bytes()))

    if dry_run:
        print(f"install-global (dry run): {len(plan)} files would be written to {target}")
        return 0

    try:
        _validate_destinations(plan, target)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    target.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    for dest, data in plan:
        if dest.name == "settings.json":
            continue
        if dest.exists():
            if dest.read_bytes() == data:
                continue
            if not force:
                sys.stderr.write(
                    f"skip: {dest} differs from plugin source (pass --force to overwrite)\n"
                )
                skipped += 1
                continue
        _atomic_write(dest, data)
        written += 1

    print(f"install-global: {written} files written, {skipped} skipped in {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
