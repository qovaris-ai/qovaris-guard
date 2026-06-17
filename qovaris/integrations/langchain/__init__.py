"""LangChain / LangGraph integration.

- :class:`QovarisSecureTool` (``tool``) — ``BaseTool`` wrapper with verification
  (requires ``langchain-core >= 0.3.0``).
- :class:`QovarisCallback` (``callback``) — observability callback for
  LangChain / LangGraph (requires ``langchain-core >= 0.3.0``).
- :class:`QovarisMiddleware` (``middleware``) — ``create_agent`` middleware
  that verifies every tool call (requires ``langchain >= 1.0``).
"""

__all__ = ["QovarisSecureTool", "QovarisCallback", "QovarisMiddleware"]


# Lazy so that e.g. QovarisSecureTool (langchain-core only) works without
# langchain>=1.0, which only the middleware needs.
def __getattr__(name: str):
    if name == "QovarisSecureTool":
        from .tool import QovarisSecureTool
        return QovarisSecureTool
    if name == "QovarisCallback":
        from .callback import QovarisCallback
        return QovarisCallback
    if name == "QovarisMiddleware":
        from .middleware import QovarisMiddleware
        return QovarisMiddleware
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
