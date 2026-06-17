"""Full-screen TUI approval, powered by Textual.

Requires:  pip install "precheck-guardian[tui]"
Run:       python examples/tui_approval.py

Opens an interactive approval screen: arrow keys scroll the steps, then press
[a]pprove / [e]dit / [r]eject (or click the buttons).
"""

from approval_hook import ApprovalConfig, ApprovalGuard
from approval_hook.ui.tui import TextualApprovalUI

AGENT_PLAN = """\
1. Query active users: SELECT * FROM users WHERE status = 'active'
2. Export results to /tmp/active_users.csv
3. Update billing flags: UPDATE accounts SET billed = 1 WHERE month = '2026-06'
4. Drop the staging table: DROP TABLE users_staging
5. Clean build artifacts: rm -rf /tmp/build
"""


def main() -> None:
    guard = ApprovalGuard(ApprovalConfig(audit_path="approval_audit.jsonl"),
                          ui=TextualApprovalUI())
    decision = guard.review(AGENT_PLAN, title="Nightly data job")
    print(f"\nDecision: {decision.value.upper()}")
    if decision.proceed:
        print("✅ Would execute the plan.")
    else:
        print("✋ Execution halted.")


if __name__ == "__main__":
    main()
