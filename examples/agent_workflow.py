"""End-to-end: a multi-step agent workflow with every tool call gated.

This mirrors what a real ReAct agent does — decide a tool, call it, observe,
repeat — but each tool is wrapped with PreCheck Guardian. Benign steps proceed;
the destructive step is caught and blocked before it runs.

Requires:  pip install langchain-core
Run:       python examples/agent_workflow.py

The guard here is configured to auto-approve low/medium-risk steps and to
HARD-BLOCK critical ones, so the whole thing runs unattended for the demo. In
production you'd drop `non_interactive_default` and a human would decide.
"""

from langchain_core.tools import tool

from approval_hook import ApprovalConfig, ApprovalGuard
from approval_hook.integrations.decorator import PlanRejected
from approval_hook.integrations.langchain import guard_langchain_tool


# --- the agent's real tools -------------------------------------------------
@tool
def query_users(status: str) -> str:
    """Query users by status."""
    return f"42 users with status={status}"


@tool
def export_csv(path: str) -> str:
    """Export the current result set to a CSV file."""
    return f"wrote 42 rows to {path}"


@tool
def run_sql(statement: str) -> str:
    """Run an arbitrary SQL statement."""
    return f"executed: {statement}"


def main() -> None:
    guard = ApprovalGuard(
        ApprovalConfig(
            block_critical=True,            # destructive steps are auto-rejected
            non_interactive_default="approve",  # demo: auto-approve the rest
            audit_path="approval_audit.jsonl",
            actor="demo-agent",
        )
    )

    # Wrap every tool — the agent calls these exactly as the originals.
    tools = {
        "query_users": guard_langchain_tool(query_users, guard=guard),
        "export_csv": guard_langchain_tool(export_csv, guard=guard),
        "run_sql": guard_langchain_tool(run_sql, guard=guard),
    }

    # A scripted "agent plan": the sequence of tool calls it wants to make.
    agent_steps = [
        ("query_users", {"status": "active"}),
        ("export_csv", {"path": "/tmp/active_users.csv"}),
        ("run_sql", {"statement": "DROP TABLE users_staging"}),   # 🚨 destructive
        ("export_csv", {"path": "/tmp/report.csv"}),
    ]

    print("Agent starting multi-step job...\n")
    for i, (name, args) in enumerate(agent_steps, 1):
        print(f"── Step {i}: agent wants to call {name}({args})")
        try:
            result = tools[name].invoke(args)
            print(f"   ✅ ran → {result}\n")
        except PlanRejected:
            print("   ⛔ blocked by guard — agent must replan or stop.\n")
            break

    print("Done. See approval_audit.jsonl for the decision log.")


if __name__ == "__main__":
    main()
