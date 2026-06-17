"""
Backward-compatible shim.

Original imports like ``from sdk.guard import NexusFinOpsGuard`` continue to
work by redirecting to ``sdk.nexus_guard.guard``.
"""

from .nexus_guard.guard import NexusFinOpsGuard, SecurityBlockException

__all__ = ["NexusFinOpsGuard", "SecurityBlockException"]
