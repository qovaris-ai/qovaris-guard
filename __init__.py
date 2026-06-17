"""
Backward-compatible shim.

Original imports like ``from sdk.guard import QovarisGuard`` continue to
work by redirecting to ``sdk.qovaris.core``.
"""

from .qovaris.core import QovarisGuard, SecurityBlockException

__all__ = ["QovarisGuard", "SecurityBlockException"]
