"""``precheck`` / ``python -m approval_hook`` command-line entry point.

Two subcommands:

* (default) render a plan — piped in or a built-in demo::

      echo "1. rm -rf /tmp/x" | precheck

* ``audit`` — summarise the JSON-Lines approval log::

      precheck audit --summary
      precheck audit --path approval_audit.jsonl --limit 5

* ``check`` — lint a script/SQL/shell file for dangerous lines::

      precheck check deploy.sh
      precheck check migration.sql --fail-on critical --rules team_rules.yaml
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Tuple

from .audit.logger import AuditLogger, summarize_records
from .core import formatter
from .core.plan_parser import PlanParser
from .core.risk_annotator import RiskAnnotator
from .models.plan import ActionStep, RiskLevel

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
    if stats.get("top_rules"):
        print("  most-triggered rules:")
        for name, hits in stats["top_rules"][:5]:
            print(f"    {hits:>4}×  {name}")

    if limit > 0:
        print(f"\n  last {limit} decisions:")
        for r in records[-limit:]:
            print(f"    {r.get('iso_time', '?')}  {r.get('decision', '?'):<7} "
                  f"{r.get('max_risk', '?'):<8} {r.get('plan_id', '')}")
    return 0


_COMMENT_PREFIXES = ("#", "--", "//", ";", "/*", "*")


def scan_text(
    text: str, annotator: RiskAnnotator, *, min_level: RiskLevel = RiskLevel.MEDIUM
) -> List[Tuple[int, RiskLevel, str, list]]:
    """Flag each non-comment line that matches a risk rule at ``min_level``+.

    Returns ``(line_number, max_level, line_text, matched_rules)`` for every
    line that triggered a rule of at least ``min_level`` (benign LOW read-only
    matches are skipped by default, to keep linter output signal-rich).
    """
    flagged: List[Tuple[int, RiskLevel, str, list]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith(_COMMENT_PREFIXES):
            continue
        step = ActionStep(step_id=lineno, title=line[:60], description=line)
        matches = annotator.matched_rules(step)
        if not matches:
            continue
        level = max(rule.level for rule in matches)
        if level >= min_level:
            flagged.append((lineno, level, line, matches))
    return flagged


def _read_source(path: str) -> Tuple[str, str]:
    if path == "-":
        return sys.stdin.read(), "<stdin>"
    with open(path, encoding="utf-8") as fh:
        return fh.read(), path


def cmd_check(files, fail_on: str, rules_path: str | None) -> int:
    """Lint one or more files. Returns 0 (clean), 1 (over threshold), 2 (read error)."""
    if isinstance(files, str):
        files = [files]
    annotator = RiskAnnotator.from_file(rules_path) if rules_path else RiskAnnotator()
    threshold = None if fail_on == "never" else RiskLevel[fail_on.upper()]

    rc = 0
    any_flag = False
    for path in files:
        try:
            text, label = _read_source(path)
        except OSError as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            rc = max(rc, 2)
            continue

        flagged = scan_text(text, annotator)
        if not flagged:
            continue
        any_flag = True
        print(f"{label}: {len(flagged)} risky line(s)\n")
        for lineno, level, line, matches in flagged:
            names = ", ".join(sorted({m.name for m in matches}))
            print(f"  {_RISK_ICON[level.label]} {level.label.upper():<8} "
                  f"line {lineno}: {line}")
            print(f"      rules: {names}")
        print()
        if threshold is not None and max(lv for _, lv, _, _ in flagged) >= threshold:
            rc = max(rc, 1)

    if not any_flag and rc == 0:
        print("✓ no risky lines found.")
    return rc


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

    p_check = sub.add_parser("check", help="lint file(s) for dangerous lines")
    p_check.add_argument("file", nargs="+", help="file(s) to scan ('-' for stdin)")
    p_check.add_argument("--fail-on", default="high",
                         choices=["low", "medium", "high", "critical", "never"],
                         help="exit non-zero if a line reaches this level (default: high)")
    p_check.add_argument("--rules", default=None,
                         help="optional JSON/YAML custom rules file")

    args = parser.parse_args()
    if args.command == "audit":
        raise SystemExit(cmd_audit(args.path, args.limit))
    if args.command == "check":
        raise SystemExit(cmd_check(args.file, args.fail_on, args.rules))
    cmd_render()


if __name__ == "__main__":
    main()
