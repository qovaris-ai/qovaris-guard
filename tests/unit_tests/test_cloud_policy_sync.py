"""Tests for embedded-mode cloud policy sync (dashboard-managed policies)."""

import json

import pytest

from qovaris import core
from qovaris import QovarisGuard, SecurityBlockException


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _patch_backend(monkeypatch, payload):
    """Make the guard's policy fetch return ``payload`` without any network."""
    monkeypatch.setattr(
        core.urllib.request, "urlopen",
        lambda req, timeout=None: _FakeResponse(payload),
    )


def test_guard_merges_cloud_policy_strictest_wins(monkeypatch):
    _patch_backend(monkeypatch, {
        "enabled": True,
        "spend_threshold": 40.0,
        "spend_limit": 200.0,
        "blocked_keywords": ["gift card", "Refund"],
    })
    guard = QovarisGuard(
        mode="embedded", report=False,
        spend_threshold=1000.0, spend_limit=500.0,
        blocked_keywords=["refund"],
    )
    assert guard.spend_threshold == 40.0          # cloud stricter than 1000
    assert guard.spend_limit == 200.0             # cloud stricter than 500
    assert guard.blocked_keywords == ["refund", "gift card"]  # case-insensitive union


def test_guard_keeps_local_policy_when_stricter(monkeypatch):
    _patch_backend(monkeypatch, {
        "enabled": True, "spend_threshold": 900.0,
        "spend_limit": None, "blocked_keywords": [],
    })
    guard = QovarisGuard(mode="embedded", report=False,
                         spend_threshold=25.0, spend_limit=100.0)
    assert guard.spend_threshold == 25.0
    assert guard.spend_limit == 100.0


def test_free_plan_leaves_policy_untouched(monkeypatch):
    _patch_backend(monkeypatch, {
        "enabled": False, "spend_threshold": 1.0,
        "spend_limit": 1.0, "blocked_keywords": ["everything"],
    })
    guard = QovarisGuard(mode="embedded", report=False, spend_threshold=1000.0)
    assert guard.spend_threshold == 1000.0
    assert guard.spend_limit is None
    assert guard.blocked_keywords is None


def test_backend_unreachable_is_silent(monkeypatch):
    def _boom(req, timeout=None):
        raise OSError("connection refused")
    monkeypatch.setattr(core.urllib.request, "urlopen", _boom)
    guard = QovarisGuard(mode="embedded", report=False, spend_threshold=77.0)
    assert guard.spend_threshold == 77.0


def test_sync_policy_false_skips_fetch(monkeypatch):
    def _boom(req, timeout=None):
        raise AssertionError("should not fetch when sync_policy=False")
    monkeypatch.setattr(core.urllib.request, "urlopen", _boom)
    guard = QovarisGuard(mode="embedded", report=False, sync_policy=False)
    assert guard.spend_threshold == core.DEFAULT_HITL_THRESHOLD


def test_synced_policy_is_enforced(monkeypatch):
    _patch_backend(monkeypatch, {
        "enabled": True, "spend_threshold": 1000.0,
        "spend_limit": 200.0, "blocked_keywords": ["gift card"],
    })
    guard = QovarisGuard(mode="embedded", report=False)

    @guard.wrap_tool(allowed_intent="Buy office supplies")
    def buy(item: str, price: float):
        return "ok"

    with guard.session("Buy a stapler"):
        # Over the cloud hard cap → blocked outright
        with pytest.raises(SecurityBlockException, match="spend limit"):
            buy(item="espresso machine", price=300.0)
        # Cloud-blocked keyword in the arguments → blocked
        with pytest.raises(SecurityBlockException, match="gift card"):
            buy(item="a gift card", price=10.0)
        # Clean call under all limits → allowed
        assert buy(item="stapler", price=12.0) == "ok"
