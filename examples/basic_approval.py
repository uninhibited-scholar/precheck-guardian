"""Basic approval flow: parse agent text, show it, ask the operator.

Run:  python examples/basic_approval.py
"""

from approval_hook import ApprovalConfig, ApprovalGuard

AGENT_PLAN = """\
I will perform the following steps:
1. Query the users table: SELECT * FROM users WHERE status = 'active'
2. Export the results to /tmp/active_users.csv
3. Remove the temporary table: DROP TABLE users_temp
4. Clean the build directory: rm -rf /tmp/build
"""


def main() -> None:
    guard = ApprovalGuard(ApprovalConfig(audit_path="approval_audit.jsonl"))
    decision = guard.review(AGENT_PLAN)

    if decision.proceed:
        print("\n✅ Approved — the agent would now execute the plan.")
    elif decision.name == "EDIT":
        print("\n✏️  Operator chose to edit — return to the planning step.")
    else:
        print("\n❌ Rejected — execution aborted.")


if __name__ == "__main__":
    main()
