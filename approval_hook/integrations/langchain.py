"""LangChain integration: gate any LangChain tool behind the approval guard.

``guard_langchain_tool(tool)`` returns a drop-in replacement tool with the same
name, description and argument schema, but every invocation is first shown to a
human for approval. If rejected, the wrapped tool never runs.

LangChain is an *optional* dependency — importing this module without it
installed raises a clear, actionable error instead of a cryptic ImportError.
"""

from __future__ import annotations

from typing import Any, Optional

from ..guard import ApprovalGuard
from .decorator import PlanRejected

try:
    from langchain_core.tools import BaseTool, StructuredTool

    _HAS_LANGCHAIN = True
except ImportError:  # pragma: no cover - exercised only without langchain
    _HAS_LANGCHAIN = False


def _require_langchain() -> None:
    if not _HAS_LANGCHAIN:
        raise ImportError(
            "LangChain is required for this integration. Install it with:\n"
            "    pip install langchain-core"
        )


def guard_langchain_tool(
    tool: "BaseTool",
    *,
    guard: Optional[ApprovalGuard] = None,
    title: Optional[str] = None,
) -> "StructuredTool":
    """Wrap a LangChain ``BaseTool`` so each call requires human approval.

    The returned tool preserves ``name``, ``description`` and ``args_schema``,
    so it can be swapped into an agent's toolset transparently. On rejection a
    :class:`~approval_hook.integrations.decorator.PlanRejected` is raised, which
    surfaces to the agent as a tool error.

    Example::

        from langchain_core.tools import tool
        from approval_hook.integrations.langchain import guard_langchain_tool

        @tool
        def delete_file(path: str) -> str:
            '''Delete a file.'''
            ...

        safe = guard_langchain_tool(delete_file)
    """
    _require_langchain()
    resolved = guard or ApprovalGuard()
    review_title = title or f"Tool call: {tool.name}"

    def _wrapped(**kwargs: Any) -> Any:
        call = {
            "tool": tool.name,
            "args": kwargs,
            "description": f"{tool.name}: " + ", ".join(f"{k}={v}" for k, v in kwargs.items()),
        }
        decision = resolved.review([call], title=review_title)
        if not decision.proceed:
            raise PlanRejected(decision)
        return tool.invoke(kwargs)

    return StructuredTool(
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        func=_wrapped,
    )
