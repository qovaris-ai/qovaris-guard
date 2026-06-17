"""Standard LangChain **unit** tests for ``QovarisSecureTool``.

``QovarisSecureTool`` is a ``BaseTool`` wrapper, so it can run against LangChain's
standard tool test suite (``langchain_tests``). Middleware has no standard test
base class — those live in ``tests/integration_tests/test_middleware.py``.

Skipped automatically when ``langchain-tests`` is not installed.
"""

from typing import Any, Dict, Type

import pytest

pytest.importorskip("langchain_tests")
from langchain_core.tools import BaseTool, tool  # noqa: E402
from langchain_tests.unit_tests import ToolsUnitTests  # noqa: E402

from qovaris import QovarisGuard  # noqa: E402
from qovaris.integrations.langchain import QovarisSecureTool  # noqa: E402


@tool
def echo(text: str) -> str:
    """Echo the input text back."""
    return f"echo: {text}"


class TestQovarisSecureToolUnit(ToolsUnitTests):
    @property
    def tool_constructor(self) -> Type[BaseTool]:
        return QovarisSecureTool

    @property
    def tool_constructor_params(self) -> Dict[str, Any]:
        # Embedded + permissive so verification never blocks the benign example
        # call; report=False keeps the suite fully offline (no dashboard POST).
        return {
            "wrapped_tool": echo,
            "guard": QovarisGuard(mode="embedded", report=False),
            "allowed_intent": "Echo arbitrary text",
        }

    @property
    def tool_invoke_params_example(self) -> Dict[str, Any]:
        return {"text": "hello"}
