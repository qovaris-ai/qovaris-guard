"""
Backward-compatible shim.

Original imports like ``from sdk.guard import QovarisGuard`` continue to
work by redirecting to ``sdk.qovaris.guard``.
"""

from .qovaris.guard import QovarisGuard, SecurityBlockException

__all__ = ["QovarisGuard", "SecurityBlockException"]
