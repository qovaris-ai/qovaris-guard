"""Standard LangChain **integration** tests for ``QovarisSecureTool``.

Runs LangChain's standard ``ToolsIntegrationTests`` against the security wrapper:
it constructs the tool and verifies that real ``invoke`` / ``ainvoke`` calls
(both ToolCall and raw-dict forms) return valid ``ToolMessage`` content without
erroring. The guard is in embedded mode, so no external service is contacted.

Skipped automatically when ``langchain-tests`` is not installed.
"""

from typing import Any, Dict, Type

import pytest

pytest.importorskip("langchain_tests")
from langchain_core.tools import BaseTool, tool  # noqa: E402
from langchain_tests.integration_tests import ToolsIntegrationTests  # noqa: E402

from qovaris import QovarisGuard  # noqa: E402
from qovaris.integrations.langchain import QovarisSecureTool  # noqa: E402


@tool
def echo(text: str) -> str:
    """Echo the input text back."""
    return f"echo: {text}"


class TestQovarisSecureToolIntegration(ToolsIntegrationTests):
    @property
    def tool_constructor(self) -> Type[BaseTool]:
        return QovarisSecureTool

    @property
    def tool_constructor_params(self) -> Dict[str, Any]:
        return {
            "wrapped_tool": echo,
            "guard": QovarisGuard(mode="embedded", report=False),
            "allowed_intent": "Echo arbitrary text",
        }

    @property
    def tool_invoke_params_example(self) -> Dict[str, Any]:
        return {"text": "hello"}
