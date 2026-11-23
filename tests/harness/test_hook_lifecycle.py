"""Stop lifecycle of the dispatcher for Claude Code.

Covers verification, block decisions, continuation limits, and counter resets.
"""

from __future__ import annotations

import json
from pathlib import Path

import hook
from payload_fixtures import load

FAIL_REPORT = "GATE FAILED: ruff-lint (exit code 1)"


class FakeVerify:
    def __init__(self, *results: bool) -> None:
        self.results = list(results)
        self.calls = 0

    def __call__(self) -> tuple[bool, str]:
        self.calls += 1
        ok = self.results.pop(0) if self.results else True
        return ok, "ALL GATES PASSED" if ok else FAIL_REPORT


def stop_payload(session: str = "s1", active: bool | None = None) -> str:
    data: dict[str, object] = {**load("claude", "stop"), "session_id": session}
    if active is not None:
        data["stop_hook_active"] = active
    return json.dumps(data)


def stop(verify: FakeVerify, state: Path, raw_payload: str | None = None) -> hook.Response:
    body = stop_payload() if raw_payload is None else raw_payload
    return hook.run("claude", "stop", body, verify_fn=verify, state_dir=state)


def test_passing_verify_lets_the_session_stop(tmp_path: Path) -> None:
    verify = FakeVerify(True)
    response = stop(verify, tmp_path)
    assert response.code == 0
    assert response.stdout == ""
    assert verify.calls == 1


def test_failing_verify_blocks_with_the_report(tmp_path: Path) -> None:
    response = stop(FakeVerify(False), tmp_path)
    assert response.code == 0
    data = json.loads(response.stdout)
    assert data["decision"] == "block"
    assert "verify --fast" in data["reason"] or FAIL_REPORT in data["reason"]


def test_continuations_are_capped_then_giving_up(tmp_path: Path) -> None:
    verify = FakeVerify(False, False, False)
    first = stop(verify, tmp_path, stop_payload(active=True))
    assert json.loads(first.stdout)["decision"] == "block"

    second = stop(verify, tmp_path, stop_payload(active=True))
    assert json.loads(second.stdout)["decision"] == "block"

    third = stop(verify, tmp_path, stop_payload(active=True))
    assert third.code == 0
    assert third.stdout == ""
    assert "continuation" in third.stderr.lower() or "limit" in third.stderr.lower()


def test_stop_hook_active_false_resets_the_counter(tmp_path: Path) -> None:
    verify = FakeVerify(False, False, False)
    first = stop(verify, tmp_path, stop_payload(active=True))
    assert json.loads(first.stdout)["decision"] == "block"

    reset_call = stop(verify, tmp_path, stop_payload(active=False))
    assert json.loads(reset_call.stdout)["decision"] == "block"


def test_passing_verify_resets_the_counter(tmp_path: Path) -> None:
    verify = FakeVerify(False, True, False)
    first = stop(verify, tmp_path, stop_payload(active=True))
    assert json.loads(first.stdout)["decision"] == "block"

    passed = stop(verify, tmp_path, stop_payload(active=True))
    assert passed.stdout == ""

    again = stop(verify, tmp_path, stop_payload(active=True))
    assert json.loads(again.stdout)["decision"] == "block"
