"""``precheck`` / ``python -m approval_hook`` command-line entry point.

Two subcommands:

* (default) render a plan — piped in or a built-in demo::

      echo "1. rm -rf /tmp/x" | precheck

* ``audit`` — summarise the JSON-Lines approval log::

      precheck audit --summary
      precheck audit --path approval_audit.jsonl --limit 5
"""

from __future__ import annotations

import argparse
import sys

from .audit.logger import AuditLogger, summarize_records
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

_RISK_ORDER = ["low", "medium", "high", "critical"]
_RISK_ICON = {"low": "🟢", "medium": "🟡", "high": "🔴", "critical": "⛔"}


def cmd_render() -> None:
    text = sys.stdin.read().strip() if not sys.stdin.isatty() else ""
    plan = PlanParser().parse(text or _DEMO, title="Demo Plan")
    formatter.render(plan)
    print(f"\nMax risk in this plan: {plan.max_risk.label.upper()}")


def cmd_audit(path: str, limit: int) -> int:
    records = AuditLogger(path).read_all()
    if not records:
        print(f"No audit records found at {path!r}.")
        return 0

    stats = summarize_records(records)
    print(f"Audit summary — {path}")
    print(f"  total decisions : {stats['total']}")
    print(f"  approved        : {stats['by_decision'].get('approve', 0)}")
    print(f"  rejected        : {stats['by_decision'].get('reject', 0)}")
    print(f"  edited          : {stats['by_decision'].get('edit', 0)}")
    print(f"  approval rate   : {stats['approval_rate']:.0%}")
    print("  by max risk     :")
    for level in _RISK_ORDER:
        count = stats["by_risk"].get(level, 0)
        if count:
            print(f"    {_RISK_ICON[level]} {level:<8} {count}")

    if limit > 0:
        print(f"\n  last {limit} decisions:")
        for r in records[-limit:]:
            print(f"    {r.get('iso_time', '?')}  {r.get('decision', '?'):<7} "
                  f"{r.get('max_risk', '?'):<8} {r.get('plan_id', '')}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="precheck", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    p_audit = sub.add_parser("audit", help="summarise the approval audit log")
    p_audit.add_argument("--path", default="approval_audit.jsonl",
                         help="path to the JSON-Lines audit log")
    p_audit.add_argument("--summary", action="store_true",
                         help="print aggregate stats (default action)")
    p_audit.add_argument("--limit", type=int, default=0,
                         help="also show the last N decisions")

    args = parser.parse_args()
    if args.command == "audit":
        raise SystemExit(cmd_audit(args.path, args.limit))
    cmd_render()


if __name__ == "__main__":
    main()
