"""Shared access to hook payload fixtures (tests/fixtures/payloads/)."""

import json
from pathlib import Path
from typing import cast

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "payloads"


def raw(agent: str, name: str) -> str:
    return (FIXTURES / agent / f"{name}.json").read_text(encoding="utf-8")


def load(agent: str, name: str) -> dict[str, object]:
    return cast(dict[str, object], json.loads(raw(agent, name)))


def names(agent: str) -> tuple[str, ...]:
    """Every captured fixture of `agent`, so a test can cover each real payload shape."""
    return tuple(sorted(path.stem for path in (FIXTURES / agent).glob("*.json")))
