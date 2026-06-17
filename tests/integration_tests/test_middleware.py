"""Tests for :class:`qovaris.integrations.langchain.middleware.QovarisMiddleware`.

These exercise the real LangChain v1 middleware API, so they are skipped
automatically when ``langchain>=1.0`` is not installed (e.g. on Python 3.9,
where the SDK core still works but the middleware extra is unavailable).
"""

import pytest

# Skip the whole module unless the v1 agents framework is importable.
pytest.importorskip("langchain.agents.middleware")
from langchain.tools.tool_node import ToolCallRequest  # noqa: E402

from qovaris import QovarisGuard, SecurityBlockException  # noqa: E402
from qovaris.integrations.langchain.middleware import QovarisMiddleware  # noqa: E402


def _request(name: str, args: dict) -> ToolCallRequest:
    """Build a minimal ToolCallRequest the way the agent runtime would."""
    return ToolCallRequest(
        tool_call={"name": name, "args": args, "id": "call_1", "type": "tool_call"},
        tool=None,
        state={"messages": []},
        runtime=None,
    )


def _embedded_guard(**kwargs) -> QovarisGuard:
    # report=False keeps the test fully offline (no dashboard POST threads).
    return QovarisGuard(mode="embedded", report=False, **kwargs)


def test_allows_aligned_call_and_runs_handler():
    guard = _embedded_guard(spend_threshold=1000)
    mw = QovarisMiddleware(guard, allowed_intents={"buy": "Purchase books under $50"})

    called = {}

    def handler(req):
        called["args"] = req.tool_call["args"]
        return "ok"

    with guard.session("Buy a Python book under $35"):
        result = mw.wrap_tool_call(_request("buy", {"item": "Clean Code", "price": 24.99}), handler)

    assert result == "ok"
    assert called["args"]["item"] == "Clean Code"


def test_blocks_overspend_before_handler():
    guard = _embedded_guard(spend_limit=100)
    mw = QovarisMiddleware(guard)

    handler_ran = {"v": False}

    def handler(req):
        handler_ran["v"] = True
        return "ok"

    with guard.session("Buy office supplies"):
        with pytest.raises(SecurityBlockException):
            mw.wrap_tool_call(_request("buy", {"item": "laptop", "price": 5000}), handler)

    assert handler_ran["v"] is False  # handler must never run on a blocked call


def test_blocked_keyword_is_denied():
    guard = _embedded_guard(blocked_keywords=["drop"])
    mw = QovarisMiddleware(guard)

    with guard.session("Read order counts"):
        with pytest.raises(SecurityBlockException):
            mw.wrap_tool_call(_request("run_sql", {"sql": "DROP TABLE orders"}), lambda r: "ran")


def test_per_tool_allowed_intent_is_passed_through():
    guard = _embedded_guard()
    mw = QovarisMiddleware(guard, allowed_intents={"buy": "only books"})
    payload = mw._build_payload("buy", {"item": "x"})
    assert payload["allowed_intent"] == "only books"
    # A tool without a configured intent gets an empty constraint, not a KeyError.
    assert mw._build_payload("other", {})["allowed_intent"] == ""


def test_policy_fields_travel_in_payload():
    guard = _embedded_guard(spend_threshold=42, spend_limit=99, blocked_keywords=["x"], agent_id="proc")
    mw = QovarisMiddleware(guard)
    with guard.session("obj"):
        p = mw._build_payload("buy", {"a": 1})
    assert p["spend_threshold"] == 42
    assert p["spend_limit"] == 99
    assert p["blocked_keywords"] == ["x"]
    assert p["agent_id"] == "proc"
    assert p["original_intent"] == "obj"


def test_async_wrap_runs_verification_then_handler():
    import asyncio

    guard = _embedded_guard(spend_threshold=1000)
    mw = QovarisMiddleware(guard)

    def handler(req):
        return "done"

    async def run():
        with guard.session("Buy a book under $30"):
            return await mw.awrap_tool_call(_request("buy", {"item": "book", "price": 9.99}), handler)

    assert asyncio.run(run()) == "done"


def test_async_wrap_blocks_overspend():
    import asyncio

    guard = _embedded_guard(spend_limit=100)
    mw = QovarisMiddleware(guard)

    async def run():
        with guard.session("Buy supplies"):
            await mw.awrap_tool_call(_request("buy", {"item": "laptop", "price": 5000}), lambda r: "ran")

    with pytest.raises(SecurityBlockException):
        asyncio.run(run())
