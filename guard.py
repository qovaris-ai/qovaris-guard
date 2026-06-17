import json
import urllib.request
import urllib.error
import threading
import functools
from contextlib import contextmanager

class SecurityBlockException(Exception):
    """Exception raised when the Sentinel/Nexus Gateway blocks a tool invocation."""
    pass

class NexusFinOpsGuard:
    def __init__(self, api_key: str = "nx_free_dev", gateway_url: str = "http://localhost:8005"):
        self.api_key = api_key
        self.gateway_url = gateway_url.rstrip("/")
        self._local = threading.local()

    @contextmanager
    def session(self, original_intent: str):
        """Context manager to scope the agent's current high-level objective."""
        old_intent = getattr(self._local, "current_intent", None)
        self._local.current_intent = original_intent
        try:
            yield
        finally:
            self._local.current_intent = old_intent

    @property
    def current_intent(self) -> str:
        return getattr(self._local, "current_intent", "No active agent session objective set.")

    def wrap_tool(self, allowed_intent: str = None):
        """
        Decorator to secure and log a tool function.
        allowed_intent: optional additional static constraint for this tool (e.g. 'Max spend $50')
        """
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Map arguments to name-value dictionary
                # For simplicity, convert positional args to indexed strings, and merge kwargs
                func_args = {}
                for idx, val in enumerate(args):
                    func_args[f"arg_{idx}"] = val
                func_args.update(kwargs)

                payload = {
                    "original_intent": self.current_intent,
                    "tool_name": func.__name__,
                    "arguments": func_args,
                    "allowed_intent": allowed_intent or "",
                    "api_key": self.api_key
                }

                # Send validation request to local gateway
                url = f"{self.gateway_url}/verify"
                req_data = json.dumps(payload).encode("utf-8")
                
                req = urllib.request.Request(
                    url,
                    data=req_data,
                    headers={
                        "Content-Type": "application/json",
                        "X-API-Key": self.api_key
                    },
                    method="POST"
                )

                try:
                    # This call will block if the gateway halts execution for human-in-the-loop review
                    with urllib.request.urlopen(req) as response:
                        res_data = json.loads(response.read().decode("utf-8"))
                except urllib.error.URLError as e:
                    # In case of network errors, default to secure block in production,
                    # but print error warning.
                    raise SecurityBlockException(
                        f"Sentinel Gateway Unreachable: {e}. Securely blocked tool invocation."
                    )

                if not res_data.get("approved", False):
                    reason = res_data.get("reason", "Unknown security policy violation.")
                    raise SecurityBlockException(
                        f"Blocked execution of '{func.__name__}': {reason}"
                    )

                # Gateway approved, run the actual tool function
                return func(*args, **kwargs)

            return wrapper
        return decorator
