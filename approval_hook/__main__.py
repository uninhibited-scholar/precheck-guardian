"""``python -m approval_hook`` — render a sample plan to showcase the output.

Useful for a quick look without writing any code. Pipe your own plan in::

    echo "1. rm -rf /tmp/x" | python -m approval_hook
"""

from __future__ import annotations

import sys

from .core import formatter
from .core.plan_parser import PlanParser

_DEMO = """\
1. Query active users: SELECT * FROM users WHERE status = 'active'
2. Export results to /tmp/active_users.csv
3. Update billing flags: UPDATE accounts SET billed = 1 WHERE month = '2026-06'
4. Drop the staging table: DROP TABLE users_staging
5. Clean build artifacts: rm -rf /tmp/build
6. Force-push the release branch: git push --force origin release
"""


def main() -> None:
    if not sys.stdin.isatty():
        text = sys.stdin.read().strip()
    else:
        text = ""
    plan = PlanParser().parse(text or _DEMO, title="Demo Plan")
    formatter.render(plan)
    print(f"\nMax risk in this plan: {plan.max_risk.label.upper()}")


if __name__ == "__main__":
    main()
