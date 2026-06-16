"""Wiring the guard into an agent loop as a pre-execution hook.

This shows the framework-agnostic pattern: whatever your agent uses to plan,
hand the plan to ``guard.review`` *before* you execute the tools. The example
uses a tiny fake agent, but the same call works with LangChain, a custom
ReAct loop, or any tool-calling framework.

Run:  python examples/langchain_style_hook.py
"""

from approval_hook import ApprovalConfig, ApprovalGuard
from approval_hook.models.approval_record import Decision


def fake_agent_plan() -> list[dict]:
    """Pretend an agent produced these structured tool calls."""
    return [
        {"tool": "read_data", "args": {"path": "/data/input.csv"}, "description": "Load input CSV"},
        {"tool": "http_request", "args": {"method": "POST", "url": "https://api.x/import"},
         "description": "POST the rows to the import API"},
        {"tool": "file_delete", "args": {"path": "/data/input.csv"},
         "description": "rm -rf /data/input.csv after import"},
    ]


def execute(tool_calls: list[dict]) -> None:
    for call in tool_calls:
        print(f"   running {call['tool']}({call['args']})")


def run_agent() -> None:
    # Auto-approve LOW; prompt for MEDIUM+, but hard-block CRITICAL.
    guard = ApprovalGuard(ApprovalConfig(block_critical=False, actor="ci-bot"))

    plan = fake_agent_plan()
    decision = guard.review(plan, title="Data import job")

    if decision is Decision.APPROVE:
        print("\n▶ Executing approved plan:")
        execute(plan)
    elif decision is Decision.EDIT:
        print("\n↩ Operator wants to edit — hand control back to the planner.")
    else:
        print("\n✋ Aborted by operator.")


if __name__ == "__main__":
    run_agent()
