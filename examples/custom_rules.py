"""Load team-specific risk rules from a config file.

Run:  python examples/custom_rules.py

Teams can maintain their own high-risk patterns (production names, PII tables,
feature flags, ...) in YAML/JSON instead of editing code. Here we load the
sibling `custom_rules.yaml` (which *extends* the 75 built-in rules) and feed the
resulting annotator to the guard.
"""

import os

from approval_hook import ApprovalConfig, ApprovalGuard, RiskAnnotator

HERE = os.path.dirname(__file__)

PLAN = """\
1. Read the staging config from /etc/app/staging.yaml
2. Run flags.enable('new-checkout') for 10% of users
3. Export the customers table to /tmp/customers.csv
4. Deploy the build to the production cluster
"""


def main() -> None:
    annotator = RiskAnnotator.from_file(os.path.join(HERE, "custom_rules.yaml"))
    guard = ApprovalGuard(ApprovalConfig(audit_path=None), annotator=annotator)
    plan = guard.build_plan(PLAN)
    from approval_hook.core import formatter

    formatter.render(plan)
    print(f"\nMax risk: {plan.max_risk.label.upper()} "
          f"(custom rules flagged production + PII)")


if __name__ == "__main__":
    main()
