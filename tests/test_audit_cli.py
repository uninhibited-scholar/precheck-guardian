from approval_hook.audit.logger import summarize_records
from approval_hook.config import ApprovalConfig
from approval_hook.guard import ApprovalGuard
from approval_hook.models.approval_record import Decision
from approval_hook import __main__ as cli


class FakeUI:
    def __init__(self, decision):
        self.decision = decision

    def prompt_approval(self):
        return self.decision

    def prompt_confirm(self, message="Confirm?"):
        return self.decision.proceed


def test_summarize_records_counts():
    records = [
        {"decision": "approve", "max_risk": "low"},
        {"decision": "approve", "max_risk": "high"},
        {"decision": "reject", "max_risk": "critical"},
    ]
    stats = summarize_records(records)
    assert stats["total"] == 3
    assert stats["by_decision"] == {"approve": 2, "reject": 1}
    assert stats["blocked"] == 1
    assert stats["by_risk"]["critical"] == 1
    assert round(stats["approval_rate"], 2) == 0.67


def test_summarize_empty():
    stats = summarize_records([])
    assert stats["total"] == 0
    assert stats["approval_rate"] == 0.0
    assert stats["top_rules"] == []


def test_summarize_top_rules_from_snapshots():
    records = [
        {"decision": "approve", "max_risk": "critical",
         "plan_snapshot": {"steps": [{"matched_rules": ["rm_recursive_force", "rm_root"]}]}},
        {"decision": "reject", "max_risk": "critical",
         "plan_snapshot": {"steps": [{"matched_rules": ["rm_recursive_force"]}]}},
    ]
    stats = summarize_records(records)
    assert stats["top_rules"][0] == ("rm_recursive_force", 2)


def test_audit_cli_reads_real_log(tmp_path, capsys):
    path = str(tmp_path / "audit.jsonl")
    guard = ApprovalGuard(ApprovalConfig(audit_path=path), ui=FakeUI(Decision.APPROVE))
    guard.review("1. SELECT * FROM t", force_plain=True)          # auto-approve, low
    guard.review("1. rm -rf /data", force_plain=True)             # approve, critical

    rc = cli.cmd_audit(path, limit=2)
    out = capsys.readouterr().out
    assert rc == 0
    assert "total decisions : 2" in out
    assert "approval rate   : 100%" in out
    assert "critical" in out
    assert "last 2 decisions" in out


def test_audit_cli_missing_file(tmp_path, capsys):
    rc = cli.cmd_audit(str(tmp_path / "nope.jsonl"), limit=0)
    assert rc == 0
    assert "No audit records" in capsys.readouterr().out
