"""
Qovaris — LangGraph / LangChain Callback Integration
==========================================================

Provides :class:`QovarisCallback`, a :class:`BaseCallbackHandler` that
streams tool invocation and error events to the Qovaris Sentinel gateway for
observability.

This handler is **non-blocking** — it logs events but never prevents tool
execution.  Use :class:`~qovaris.integrations.langchain.QovarisSecureTool` for active
verification and blocking.

Requires ``langchain-core >= 0.3.0``.  Import errors are surfaced clearly so
the core SDK can still be used without LangChain installed.

Example
-------
::

    from qovaris import QovarisGuard
    from qovaris.integrations.langchain import QovarisCallback

    guard = QovarisGuard(api_key="nx_key")
    callback = QovarisCallback(guard=guard)

    # Pass to your LangChain / LangGraph agent as a callback:
    agent.run("Do something", callbacks=[callback])
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Union

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as _exc:
    raise ImportError(
        "langchain-core is required for QovarisCallback. "
        "Install it with:  pip install 'langchain-core>=0.3.0'"
    ) from _exc

from ...core import QovarisGuard

__all__ = ["QovarisCallback"]

logger = logging.getLogger(__name__)


class QovarisCallback(BaseCallbackHandler):
    """LangChain callback handler that logs tool events to the Qovaris gateway.

    This is purely for **observability** — it sends structured event payloads
    to ``/api/callback_log`` on the Sentinel gateway so operators can monitor
    agent behaviour in the dashboard.

    Errors during logging are captured and written to the module logger at
    ``DEBUG`` level; they never propagate to the agent.

    Parameters
    ----------
    guard : QovarisGuard
        An initialised Qovaris instance providing gateway URL and API key.
    """

    def __init__(self, guard: QovarisGuard) -> None:
        super().__init__()
        self.guard = guard

    # ------------------------------------------------------------------ #
    #  Private helpers
    # ------------------------------------------------------------------ #

    def _post_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Fire-and-forget POST to the gateway callback-log endpoint.

        Errors are logged but **never** raised — observability must not break
        the agent's execution flow.
        """
        payload = {
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "api_key": self.guard.api_key,
            "agent_id": getattr(self.guard, "agent_id", ""),
            **data,
        }

        url = f"{self.guard.gateway_url}/api/callback_log"
        req_data = json.dumps(payload, default=str).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.guard.api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp.read()  # drain response body
        except (urllib.error.URLError, OSError) as exc:
            logger.debug("Qovaris callback_log POST failed (non-fatal): %s", exc)

    # ------------------------------------------------------------------ #
    #  BaseCallbackHandler overrides
    # ------------------------------------------------------------------ #

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running.

        Sends a ``tool_start`` event to the gateway with the tool's serialised
        metadata and input string.
        """
        self._post_event(
            "tool_start",
            {
                "tool_name": serialized.get("name", "unknown"),
                "tool_description": serialized.get("description", ""),
                "input": input_str,
                # Send under `arguments` too so the dashboard can render it.
                "arguments": {"input": input_str},
                "run_id": str(kwargs.get("run_id", "")),
                "parent_run_id": str(kwargs.get("parent_run_id", "")),
            },
        )

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors out.

        Sends a ``tool_error`` event to the gateway containing the error
        message so operators can diagnose failures in the dashboard.
        """
        self._post_event(
            "tool_error",
            {
                "error_type": type(error).__name__,
                "error_message": str(error),
                "run_id": str(kwargs.get("run_id", "")),
                "parent_run_id": str(kwargs.get("parent_run_id", "")),
            },
        )
