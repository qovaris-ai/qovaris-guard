"""
Qovaris — Guard
===============

The central place for **final decisions**: :class:`QovarisGuard` wraps agent
tool calls and *enforces* the policy engine's verdicts, either in-process
(``mode="embedded"``) or via the backend ``/verify`` endpoint
(``mode="remote"``).  Raises :class:`SecurityBlockException` on denial.

All policy definitions and evaluation logic live in
:mod:`qovaris.policy_engine`; every integration (``integrations/langchain``,
``internal/mpp``, …) builds on this module.  Zero external dependencies —
standard library only.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import warnings
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional

from .policy_engine import DEFAULT_HITL_THRESHOLD, _extract_vendor, evaluate_intent

__all__ = [
    "QovarisGuard",
    "SecurityBlockException",
]


class SecurityBlockException(Exception):
    """Raised when the Qovaris Sentinel gateway blocks a tool invocation.

    This may happen because:
    - The semantic intent check failed (tool action misaligns with the
      agent's stated objective).
    - A spending / budget policy was violated.
    - A prompt-injection attack was detected.
    - The gateway is unreachable and ``fail_open`` is ``False``.
    """


class QovarisGuard:
    """Developer SDK client — wraps agent tool calls with Sentinel verification.

    Sends every tool invocation to the Qovaris backend ``/verify`` endpoint
    over HTTP before allowing execution. Raises :class:`SecurityBlockException`
    if denied.

    Parameters
    ----------
    api_key : str
        API key for the backend (use ``nx_free_dev_key`` for local dev).
    gateway_url : str
        Base URL of the Qovaris backend (default ``http://localhost:8005``).
    fail_open : bool
        When ``True``, if the backend is unreachable the call is **allowed**
        with a warning.  When ``False`` (default), raises
        :class:`SecurityBlockException`.
    mode : str
        ``"remote"`` (default) sends every call to the backend ``/verify``
        endpoint over HTTP.  ``"embedded"`` runs the rule/LLM engine
        **in-process** with zero network calls — ideal for tests, notebooks,
        air-gapped deployments, and the bundled examples.
    spend_threshold : float
        Per-transaction value above which an otherwise-valid purchase requires
        human review (embedded mode only).  Defaults to
        :data:`DEFAULT_HITL_THRESHOLD`.
    spend_limit : float | None
        Hard budget ceiling (embedded mode only).  Any proposed spend above this
        is **blocked outright**, regardless of intent.  ``None`` (default) means
        no hard cap — only ``spend_threshold`` review applies.
    blocked_keywords : list[str] | None
        Keywords that block a tool call outright when found in its arguments
        (embedded mode only), e.g. ``["delete", "drop", "rm -rf"]``.  Matched
        case-insensitively.
    transaction_max : float | None
        Per-transaction maximum (embedded mode only).  Any single tool call
        whose extracted price exceeds this is blocked outright.  Distinct from
        ``spend_limit`` — cloud policies can scope it per agent/vendor/category.
    vendor_rules : list[dict] | None
        Vendor allow/block rules (embedded mode only), each shaped
        ``{"vendors": [...], "action": "block"|"review"|"allow"}``.
    category_rules : list[dict] | None
        Merchant-category rules (embedded mode only), each shaped
        ``{"categories": [...], "action": "block"|"review"|"allow"|"limit", "limit": float}``.
        Entries are 4-digit MCC codes or category slugs.
    hitl_handler : Callable[[dict, dict], bool] | None
        Embedded-mode hook invoked when a call needs human review.  Receives
        ``(payload, decision)`` and returns ``True`` to approve or ``False`` to
        deny.  If omitted, review-required calls are denied (secure default).
    agent_id : str
        Human-readable identifier for the agent making the calls (e.g.
        ``"procurement-agent"``).  Surfaced on every dashboard event so you can
        tell *which* agent triggered a check.  If empty, the backend falls back
        to the API token's name.
    report : bool
        In **embedded** mode, fire-and-forget every decision (approved *and*
        blocked) to the backend ``/api/log`` endpoint so they appear in the
        dashboard.  Non-blocking and silent on failure.  Default ``True``;
        ignored in remote mode (the backend logs there already).
    sync_policy : bool
        In **embedded** mode, fetch the account's dashboard-managed cloud
        policy from the backend (``GET /api/policy/effective``) once at
        construction and merge it with the in-code policy — the strictest
        wins (lowest threshold/limit; keyword lists are unioned).  Cloud
        policies are a Pro feature; free accounts and unreachable backends
        leave the in-code policy untouched (silent, 3s timeout).  Default
        ``True``; ignored in remote mode (the backend merges there already).

    Example
    -------
    ::

        # Remote (talks to the backend gateway)
        guard = QovarisGuard(api_key="nx_free_dev_key")

        # Embedded (no backend required), reporting to the dashboard
        guard = QovarisGuard(
            mode="embedded", spend_threshold=1000,
            agent_id="procurement-agent", api_key="nx_live_...",
        )

        @guard.wrap_tool(allowed_intent="Purchase office supplies under $50")
        def buy(item: str, price: float):
            ...

        with guard.session("Buy a Python book under $35"):
            buy(item="Clean Code", price=24.99)
    """

    def __init__(
        self,
        api_key: str = "nx_free_dev_key",
        gateway_url: str = "http://localhost:8005",
        fail_open: bool = False,
        mode: str = "remote",
        spend_threshold: float = DEFAULT_HITL_THRESHOLD,
        spend_limit: Optional[float] = None,
        blocked_keywords: Optional[List[str]] = None,
        hitl_handler: Optional[Callable[[Dict[str, Any], Dict[str, Any]], bool]] = None,
        agent_id: str = "",
        report: bool = True,
        sync_policy: bool = True,
        transaction_max: Optional[float] = None,
        vendor_rules: Optional[List[dict]] = None,
        category_rules: Optional[List[dict]] = None,
    ) -> None:
        if mode not in ("remote", "embedded"):
            raise ValueError("mode must be 'remote' or 'embedded'")
        self.api_key = api_key
        self.gateway_url = gateway_url.rstrip("/")
        self.fail_open = fail_open
        self.mode = mode
        self.spend_threshold = spend_threshold
        self.spend_limit = spend_limit
        self.blocked_keywords = blocked_keywords
        self.transaction_max = transaction_max
        self.vendor_rules = vendor_rules
        self.category_rules = category_rules
        self.hitl_handler = hitl_handler
        self.agent_id = agent_id
        self.report = report
        self.sync_policy = sync_policy
        self._local = threading.local()

        # Embedded guards evaluate in-process, so dashboard-managed cloud
        # policies must be pulled client-side.  Remote guards skip this — the
        # backend merges cloud policy into every /verify decision.
        if mode == "embedded" and sync_policy and api_key and self.gateway_url:
            self._sync_cloud_policy()

    # ── Cloud policy sync (embedded mode) ────────────────────────────────

    def _sync_cloud_policy(self) -> None:
        """Fetch the account's effective cloud policy and merge it in.

        Silent on any failure (backend down, free plan, bad key): the guard
        simply keeps its in-code policy.  Never raises.
        """
        url = f"{self.gateway_url}/api/policy/effective"
        if self.agent_id:
            # Let the backend resolve agent-scoped policies for this guard.
            url += f"?agent_id={urllib.parse.quote(self.agent_id)}"
        try:
            req = urllib.request.Request(
                url,
                headers={"X-API-Key": self.api_key},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                cloud = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return
        if not isinstance(cloud, dict) or not cloud.get("enabled"):
            return
        self._apply_cloud_policy(cloud)

    def _apply_cloud_policy(self, cloud: Dict[str, Any]) -> None:
        """Merge a cloud policy dict into this guard — the strictest wins."""
        threshold = cloud.get("spend_threshold")
        if isinstance(threshold, (int, float)) and not isinstance(threshold, bool):
            self.spend_threshold = min(self.spend_threshold, float(threshold))

        limit = cloud.get("spend_limit")
        if isinstance(limit, (int, float)) and not isinstance(limit, bool):
            self.spend_limit = (
                float(limit) if self.spend_limit is None
                else min(self.spend_limit, float(limit))
            )

        keywords = cloud.get("blocked_keywords")
        if isinstance(keywords, list):
            merged = list(self.blocked_keywords or [])
            seen = {str(k).lower() for k in merged}
            for kw in keywords:
                kw = str(kw).strip()
                if kw and kw.lower() not in seen:
                    merged.append(kw)
                    seen.add(kw.lower())
            if merged:
                self.blocked_keywords = merged

        tx_max = cloud.get("transaction_max")
        if isinstance(tx_max, (int, float)) and not isinstance(tx_max, bool):
            self.transaction_max = (
                float(tx_max) if self.transaction_max is None
                else min(self.transaction_max, float(tx_max))
            )

        # Cloud vendor/category rules can't be reduced to a scalar — they are
        # appended, so both in-code and dashboard rules are enforced.
        for attr in ("vendor_rules", "category_rules"):
            rules = cloud.get(attr)
            if isinstance(rules, list):
                merged_rules = list(getattr(self, attr) or [])
                merged_rules.extend(r for r in rules if isinstance(r, dict))
                if merged_rules:
                    setattr(self, attr, merged_rules)

    # ── Session / intent management ────────────────────────────────────────

    @contextmanager
    def session(self, original_intent: str):
        """Scope the agent's current high-level objective.

        All tool calls made inside the ``with`` block inherit this intent,
        which is sent to the backend for semantic alignment verification.
        """
        old = getattr(self._local, "current_intent", None)
        self._local.current_intent = original_intent
        try:
            yield
        finally:
            self._local.current_intent = old

    @property
    def current_intent(self) -> str:
        """Return the active session intent."""
        return getattr(
            self._local,
            "current_intent",
            "No active agent session objective set.",
        )

    # ── Internal helpers ───────────────────────────────────────────────────

    def _build_payload(
        self,
        func: Callable,
        args: tuple,
        kwargs: Dict[str, Any],
        allowed_intent: Optional[str],
    ) -> Dict[str, Any]:
        """Build the JSON verification payload, mapping positional args by name."""
        sig = inspect.signature(func)
        param_names = list(sig.parameters.keys())

        func_args: Dict[str, Any] = {}
        for idx, val in enumerate(args):
            name = param_names[idx] if idx < len(param_names) else f"arg_{idx}"
            func_args[name] = val
        func_args.update(kwargs)

        return {
            "original_intent": self.current_intent,
            "tool_name": func.__name__,
            "arguments": func_args,
            "allowed_intent": allowed_intent or "",
            "agent_id": self.agent_id,
            # Vendor context so the backend can resolve vendor-scoped policies.
            "vendor": _extract_vendor(func_args),
            # Policy-as-code: the guard's configured policy travels with every
            # request so the backend enforces exactly what's defined here.
            "spend_threshold": self.spend_threshold,
            "spend_limit": self.spend_limit,
            "blocked_keywords": self.blocked_keywords,
        }

    def _authorize(
        self,
        payload: Dict[str, Any],
        tool_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Authorize a tool call, dispatching to the embedded or remote engine.

        Returns the decision dict on success.  Raises
        :class:`SecurityBlockException` if the call is denied.  This is the
        single enforcement entry point shared by every integration (core
        decorators, LangChain ``QovarisSecureTool``, MPP guard).
        """
        if self.mode == "embedded":
            return self._authorize_embedded(payload, tool_name)
        return self._send_verification(payload, tool_name)

    def _authorize_embedded(
        self,
        payload: Dict[str, Any],
        tool_name: str,
    ) -> Dict[str, Any]:
        """In-process evaluation — no HTTP. Honours an optional HITL handler."""
        decision = evaluate_intent(
            original_intent=payload.get("original_intent", ""),
            tool_name=payload.get("tool_name", tool_name),
            arguments=payload.get("arguments", {}),
            allowed_intent=payload.get("allowed_intent", ""),
            spend_threshold=self.spend_threshold,
            spend_limit=self.spend_limit,
            blocked_keywords=self.blocked_keywords,
            transaction_max=self.transaction_max,
            vendor_rules=self.vendor_rules,
            category_rules=self.category_rules,
            vendor=payload.get("vendor"),
        )

        # Give the HITL handler a chance to upgrade a review to an approval
        # before we settle on the final decision (so the dashboard reflects it).
        if (
            not decision.get("approved")
            and decision.get("requires_hitl")
            and self.hitl_handler is not None
            and self.hitl_handler(payload, decision)
        ):
            decision = {
                **decision,
                "approved": True,
                "reason": f"Approved by HITL handler. ({decision.get('reason', '')})",
            }

        # Report both approvals and blocks to the dashboard (fire-and-forget).
        self._report_decision(payload, decision)

        if decision.get("approved"):
            return decision

        if decision.get("requires_hitl"):
            raise SecurityBlockException(
                f"Blocked execution of '{tool_name}' (human review required): "
                f"{decision.get('reason', 'Manual approval needed.')}"
            )

        raise SecurityBlockException(
            f"Blocked execution of '{tool_name}': "
            f"{decision.get('reason', 'Security policy violation.')}"
        )

    def _report_decision(
        self,
        payload: Dict[str, Any],
        decision: Dict[str, Any],
    ) -> None:
        """Fire-and-forget a decision to the backend so it shows in the dashboard.

        Embedded mode only.  Never blocks the agent and never raises — if the
        backend is unreachable the event is simply dropped.
        """
        if not (self.report and self.api_key and self.gateway_url):
            return

        if decision.get("approved"):
            status = "APPROVED"
        elif decision.get("requires_hitl"):
            status = "PENDING_HITL"
        else:
            status = "BLOCKED"

        body = {
            "event_type": "decision",
            "tool_name": payload.get("tool_name", ""),
            "arguments": payload.get("arguments", {}),
            "intent": payload.get("original_intent", ""),
            "allowed_intent": payload.get("allowed_intent", ""),
            "status": status,
            "reason": decision.get("reason", ""),
            "category": decision.get("category", ""),
            "agent_id": payload.get("agent_id") or self.agent_id,
        }
        threading.Thread(target=self._post_log, args=(body,), daemon=True).start()

    def _post_log(self, body: Dict[str, Any]) -> None:
        """Blocking POST to /api/log — only ever called from a daemon thread."""
        try:
            req = urllib.request.Request(
                f"{self.gateway_url}/api/log",
                data=json.dumps(body, default=str).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-API-Key": self.api_key},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                resp.read()
        except Exception:
            pass  # observability must never break (or slow) the agent

    def _send_verification(
        self,
        payload: Dict[str, Any],
        tool_name: str,
    ) -> Optional[Dict[str, Any]]:
        """POST payload to the backend /verify endpoint."""
        url = f"{self.gateway_url}/verify"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self.api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            if self.fail_open:
                warnings.warn(
                    f"Qovaris backend unreachable ({exc}); fail_open=True — "
                    f"allowing execution of '{tool_name}'.",
                    RuntimeWarning,
                    stacklevel=4,
                )
                return None
            raise SecurityBlockException(
                f"Sentinel Gateway Unreachable: {exc}. "
                f"Securely blocked tool invocation."
            ) from exc

        if not res_data.get("approved", False):
            reason = res_data.get("reason", "Unknown security policy violation.")
            raise SecurityBlockException(
                f"Blocked execution of '{tool_name}': {reason}"
            )

        return res_data

    # ── Synchronous decorator ──────────────────────────────────────────────

    def wrap_tool(self, allowed_intent: str = None):
        """Decorator that secures a synchronous tool function.

        Every call is verified with the Qovaris backend before execution.
        Raises :class:`SecurityBlockException` if denied.
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                payload = self._build_payload(func, args, kwargs, allowed_intent)
                self._authorize(payload, func.__name__)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    # ── Asynchronous decorator ─────────────────────────────────────────────

    def wrap_tool_async(self, allowed_intent: str = None):
        """Decorator that secures an async tool function.

        The blocking HTTP verification runs in a thread-pool executor so the
        event loop is never blocked.
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                payload = self._build_payload(func, args, kwargs, allowed_intent)
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    self._authorize,
                    payload,
                    func.__name__,
                )
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                return func(*args, **kwargs)
            return wrapper
        return decorator
