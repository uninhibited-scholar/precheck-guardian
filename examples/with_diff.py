"""Diff two plans — e.g. the operator edited the plan and wants to see what changed.

Run:  python examples/with_diff.py
"""

from approval_hook import PlanParser
from approval_hook.diff.diff_engine import DiffEngine

OLD = """\
1. Read /etc/app/config.yaml
2. Update the cache: UPDATE cache SET value = 1 WHERE key = 'x'
3. Restart the service
"""

NEW = """\
1. Read /etc/app/config.yaml
2. Update the cache: UPDATE cache SET value = 2 WHERE key = 'x'
3. Restart the service
4. Delete old logs: rm -rf /var/log/app/old
"""


def main() -> None:
    parser = PlanParser()
    old_plan = parser.parse(OLD)
    new_plan = parser.parse(NEW)

    engine = DiffEngine()
    print("=== Change summary ===")
    print(engine.summary(old_plan, new_plan))

    print("\n=== Unified diff ===")
    print(engine.highlight(engine.unified_diff(old_plan, new_plan)))


if __name__ == "__main__":
    main()
