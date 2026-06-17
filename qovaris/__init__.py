"""
Qovaris — The Security SDK for Autonomous AI Agents
========================================================

Layout
------
- ``core``          — the central module: decision engine + ``QovarisGuard``.
- ``internal/``     — shared libraries (e.g. ``mpp`` — Stripe Machine Payments
  Protocol firewall). Zero extra dependencies.
- ``integrations/`` — one subpackage per framework:
    - ``langchain``  — LangChain / LangGraph (tool wrapper, callback, middleware).
    - ``openclaw``   — coming soon.
    - ``claude``     — coming soon.

Core (always available, stdlib-only)
------------------------------------
- :class:`QovarisGuard` — main guard client for wrapping tool functions.
- :class:`SecurityBlockException` — raised when a tool call is denied.
- :func:`evaluate_intent` — full decision engine (rules + optional Gemini).
- :func:`fallback_evaluate` — pure rule-based evaluator, no LLM required.

Internal / shared
-----------------
- :class:`MPPGuard` — firewall for HTTP-402 ``Payment`` purchase intents.
- :class:`PaymentChallenge` / :func:`parse_payment_challenge` — challenge parsing.

LangChain / LangGraph integration (requires ``langchain-core >= 0.3.0``)
-------------------------------------------------------------------------
- :class:`QovarisSecureTool` — LangChain ``BaseTool`` wrapper with verification.
- :class:`QovarisCallback` — LangChain/LangGraph observability callback.
- :class:`QovarisMiddleware` — ``create_agent`` middleware that verifies
  every tool call (requires ``langchain >= 1.0``). Recommended over per-tool
  wrapping.
"""

from .core import (
    DEFAULT_HITL_THRESHOLD,
    QovarisGuard,
    SecurityBlockException,
    evaluate_intent,
    fallback_evaluate,
)
from .internal.mpp import MPPGuard, PaymentChallenge, parse_payment_challenge

__version__ = "0.1.0"

__all__ = [
    "QovarisGuard",
    "SecurityBlockException",
    "evaluate_intent",
    "fallback_evaluate",
    "DEFAULT_HITL_THRESHOLD",
    "MPPGuard",
    "PaymentChallenge",
    "parse_payment_challenge",
    "QovarisSecureTool",
    "QovarisCallback",
    "QovarisMiddleware",
    "__version__",
]


# Lazy imports for optional framework integrations.
# Users without langchain installed can still use the core guard.
def __getattr__(name: str):
    if name == "QovarisSecureTool":
        from .integrations.langchain import QovarisSecureTool
        return QovarisSecureTool
    if name == "QovarisCallback":
        from .integrations.langchain import QovarisCallback
        return QovarisCallback
    if name == "QovarisMiddleware":
        from .integrations.langchain import QovarisMiddleware
        return QovarisMiddleware
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
