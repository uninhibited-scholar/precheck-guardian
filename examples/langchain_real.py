"""A *real* LangChain tool gated by PreCheck Guardian.

Requires:  pip install langchain-core
Run:       python examples/langchain_real.py

This wraps an actual `langchain_core` tool. In a live agent, the wrapped tool is
a drop-in replacement — the agent calls it exactly as before, but a human is
asked to approve each invocation first.
"""

from langchain_core.tools import tool

from approval_hook import ApprovalConfig, ApprovalGuard
from approval_hook.integrations.langchain import guard_langchain_tool
from approval_hook.integrations.decorator import PlanRejected


@tool
def delete_path(path: str) -> str:
    """Delete a file or directory at the given path."""
    return f"deleted {path}"


def main() -> None:
    # block_critical=True → a `rm -rf`-style call is auto-rejected, never run.
    guard = ApprovalGuard(ApprovalConfig(block_critical=True, audit_path=None))
    safe_delete = guard_langchain_tool(delete_path, guard=guard)

    print(f"Wrapped tool name : {safe_delete.name}")
    print(f"Description       : {safe_delete.description}\n")

    try:
        result = safe_delete.invoke({"path": "rm -rf /important/data"})
        print("result:", result)
    except PlanRejected as exc:
        print("✋ blocked by guard:", exc)


if __name__ == "__main__":
    main()
