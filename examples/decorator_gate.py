"""Add an approval checkpoint to existing code with a one-line decorator.

Run:  python examples/decorator_gate.py
"""

from approval_hook.integrations import PlanRejected, gate_plan, guard_callable


# 1) Gate a function whose *input* is a plan ---------------------------------
@gate_plan("plan")
def execute_plan(plan: str) -> None:
    print("   ▶ executing:", plan.splitlines()[0], "...")


# 2) Gate a single dangerous tool — every call is reviewed -------------------
def delete_file(path: str) -> str:
    return f"deleted {path}"


safe_delete = guard_callable(delete_file, tool_name="delete_file")


def main() -> None:
    print("Example A — gate a plan-executing function:")
    execute_plan(
        """\
1. Read /tmp/report.csv
2. rm -rf /tmp/report.csv
"""
    )

    print("\nExample B — gate a single tool call:")
    try:
        print("   result:", safe_delete("/tmp/important.db"))
    except PlanRejected as exc:
        print("   blocked:", exc)


if __name__ == "__main__":
    main()
