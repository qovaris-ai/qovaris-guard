"""
Nexus Guard — The Security SDK for Autonomous AI Agents
========================================================

Nexus Guard provides a lightweight, zero-dependency security layer that
validates every tool invocation against the Nexus Sentinel gateway before
execution.

Core Classes
------------
- :class:`NexusFinOpsGuard` — Main guard client for wrapping tool functions.
- :class:`SecurityBlockException` — Raised when a tool call is denied.

Stripe Machine Payments Protocol (zero extra dependencies)
----------------------------------------------------------
- :class:`MPPGuard` — firewall for HTTP-402 / ``Payment`` scheme purchase intents.
- :class:`PaymentChallenge` / :func:`parse_payment_challenge` — challenge parsing.

Optional Integrations (require ``langchain-core >= 0.3.0``)
-----------------------------------------------------------
- :class:`NexusSecureTool` — LangChain ``BaseTool`` wrapper with verification.
- :class:`NexusSentinelCallback` — LangChain/LangGraph callback for observability.
"""

from .guard import NexusFinOpsGuard, SecurityBlockException
from .mpp import MPPGuard, PaymentChallenge, parse_payment_challenge

__version__ = "0.1.0"

__all__ = [
    "NexusFinOpsGuard",
    "SecurityBlockException",
    "MPPGuard",
    "PaymentChallenge",
    "parse_payment_challenge",
    "__version__",
]


# Lazy imports for optional LangChain integrations.
# Users without langchain-core installed can still use the core guard.
def __getattr__(name: str):
    if name == "NexusSecureTool":
        from .langchain import NexusSecureTool
        return NexusSecureTool
    if name == "NexusSentinelCallback":
        from .langgraph import NexusSentinelCallback
        return NexusSentinelCallback
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
