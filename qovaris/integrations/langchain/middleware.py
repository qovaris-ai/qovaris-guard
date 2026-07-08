"""
Qovaris — LangChain Agent Middleware
==========================================

Provides :class:`QovarisMiddleware`, an :class:`AgentMiddleware` that routes
**every** tool call made by a ``create_agent`` agent through the Qovaris Sentinel
gateway for intent-verification before execution.

This is the recommended integration: unlike
:class:`~qovaris.integrations.langchain.QovarisSecureTool` (which wraps tools one-by-one),
a single middleware instance protects the whole agent — you don't have to wrap
each tool yourself.

Requires ``langchain >= 1.0`` (the v1 agents framework, where the middleware API
lives).  Import errors are surfaced clearly so the core SDK still works without
it installed.

Example
-------
::

    from langchain.agents import create_agent
    from qovaris import QovarisGuard
    from qovaris.integrations.langchain.middleware import QovarisMiddleware

    guard = QovarisGuard(api_key="nx_free_dev_key")

    agent = create_agent(
        model="claude-opus-4-8",
        tools=[search, buy],
        middleware=[
            QovarisMiddleware(
                guard,
                allowed_intents={"buy": "Purchase office supplies under $50"},
            )
        ],
    )

    with guard.session("Buy a Python book under $35"):
        agent.invoke({"messages": [("user", "Order Clean Code")]})
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Dict, Optional

try:
    from langchain.agents.middleware import AgentMiddleware
    from langchain.tools.tool_node import ToolCallRequest
except ImportError as _exc:  # pragma: no cover - exercised only without langchain
    raise ImportError(
        "langchain>=1.0 is required for QovarisMiddleware. "
        "Install it with:  pip install 'qovaris[middleware]'  "
        "(or  pip install 'langchain>=1.0' )"
    ) from _exc

from ...guard import QovarisGuard

__all__ = ["QovarisMiddleware"]


class QovarisMiddleware(AgentMiddleware):
    """Agent middleware that verifies every tool call through the Qovaris gateway.

    Drop a single instance into ``create_agent(..., middleware=[...])`` and every
    tool invocation is checked against the agent's stated objective before it
    runs.  Denied calls raise :class:`~qovaris.guard.SecurityBlockException`
    (the same contract as the rest of the SDK), unless ``guard.fail_open`` is
    ``True`` and the gateway is unreachable.

    Parameters
    ----------
    guard : QovarisGuard
        An initialised Qovaris instance (remote or embedded mode).
    allowed_intents : dict[str, str] | None
        Optional per-tool plain-English constraints, keyed by tool name, e.g.
        ``{"buy": "Purchase office supplies under $50"}``.  Tools not listed are
        verified against the session intent alone.
    """

    def __init__(
        self,
        guard: QovarisGuard,
        allowed_intents: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__()
        self.guard = guard
        self.allowed_intents = allowed_intents or {}

    # ------------------------------------------------------------------ #
    #  Verification helper
    # ------------------------------------------------------------------ #

    def _build_payload(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Build the verification payload, mirroring ``guard._build_payload``.

        Includes the guard's policy-as-code fields so both embedded and remote
        modes enforce exactly what's configured on the guard.
        """
        return {
            "original_intent": self.guard.current_intent,
            "tool_name": name,
            "arguments": args,
            "allowed_intent": self.allowed_intents.get(name, ""),
            "agent_id": self.guard.agent_id,
            "spend_threshold": self.guard.spend_threshold,
            "spend_limit": self.guard.spend_limit,
            "blocked_keywords": self.guard.blocked_keywords,
        }

    def _verify(self, request: "ToolCallRequest") -> None:
        """Authorise a tool call; raises ``SecurityBlockException`` if denied."""
        name = request.tool_call["name"]
        args = request.tool_call.get("args", {}) or {}
        self.guard._authorize(self._build_payload(name, args), name)

    # ------------------------------------------------------------------ #
    #  AgentMiddleware hooks
    # ------------------------------------------------------------------ #

    def wrap_tool_call(
        self,
        request: "ToolCallRequest",
        handler: Callable[["ToolCallRequest"], Any],
    ) -> Any:
        """Verify the call, then delegate to the next handler if approved."""
        self._verify(request)
        return handler(request)

    async def awrap_tool_call(
        self,
        request: "ToolCallRequest",
        handler: Callable[["ToolCallRequest"], Any],
    ) -> Any:
        """Async variant — runs the blocking verification in an executor."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._verify, request)
        result = handler(request)
        if asyncio.iscoroutine(result):
            return await result
        return result
