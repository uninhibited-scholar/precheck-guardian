import json

from approval_hook.config import ApprovalConfig
from approval_hook.guard import ApprovalGuard
from approval_hook.models.approval_record import Decision
from approval_hook.models.plan import RiskLevel


class FakeUI:
    """Deterministic UI stub for tests."""

    def __init__(self, decision):
        self.decision = decision
        self.prompted = False

    def prompt_approval(self):
        self.prompted = True
        return self.decision

    def prompt_confirm(self, message="Confirm?"):
        return self.decision.proceed


def test_low_risk_is_auto_approved_without_prompt(tmp_path):
    ui = FakeUI(Decision.REJECT)  # would reject if prompted
    cfg = ApprovalConfig(audit_path=str(tmp_path / "a.jsonl"))
    guard = ApprovalGuard(cfg, ui=ui)
    decision = guard.review("1. SELECT * FROM users")
    assert decision is Decision.APPROVE
    assert ui.prompted is False  # never bothered the operator


def test_high_risk_prompts_operator(tmp_path):
    ui = FakeUI(Decision.APPROVE)
    cfg = ApprovalConfig(audit_path=str(tmp_path / "a.jsonl"))
    guard = ApprovalGuard(cfg, ui=ui)
    decision = guard.review("1. rm -rf /tmp/build", force_plain=True)
    assert ui.prompted is True
    assert decision is Decision.APPROVE


def test_block_critical_auto_rejects(tmp_path, capsys):
    ui = FakeUI(Decision.APPROVE)  # would approve if prompted
    cfg = ApprovalConfig(block_critical=True, audit_path=str(tmp_path / "a.jsonl"))
    guard = ApprovalGuard(cfg, ui=ui)
    decision = guard.review("1. DROP DATABASE prod", force_plain=True)
    assert decision is Decision.REJECT
    assert ui.prompted is False


def test_audit_log_is_written(tmp_path):
    path = tmp_path / "audit.jsonl"
    ui = FakeUI(Decision.APPROVE)
    guard = ApprovalGuard(ApprovalConfig(audit_path=str(path)), ui=ui)
    guard.review("1. rm -rf /data", force_plain=True)
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["decision"] == "approve"
    assert rec["max_risk"] == "critical"
    assert rec["plan_snapshot"]["steps"][0]["risk_level"] == "critical"


def test_secrets_are_redacted_in_snapshot(tmp_path):
    path = tmp_path / "audit.jsonl"
    guard = ApprovalGuard(ApprovalConfig(audit_path=str(path)), ui=FakeUI(Decision.APPROVE))
    guard.review(
        [{"tool": "http_request", "args": {"api_key": "SECRET123"}, "description": "call api"}],
        force_plain=True,
    )
    raw = path.read_text()
    assert "SECRET123" not in raw
    assert "redacted" in raw


class FullUI:
    """A UI that renders the plan itself (like the TUI)."""

    def __init__(self, decision):
        self.decision = decision
        self.got_plan = None

    def render_and_prompt(self, plan):
        self.got_plan = plan
        return self.decision


def test_full_ui_render_and_prompt_is_used(tmp_path):
    ui = FullUI(Decision.EDIT)
    guard = ApprovalGuard(ApprovalConfig(audit_path=None), ui=ui)
    decision = guard.review("1. rm -rf /tmp/x")
    assert decision is Decision.EDIT
    assert ui.got_plan is not None
    assert ui.got_plan.max_risk is RiskLevel.CRITICAL


def test_is_approved_boolean_wrapper():
    guard = ApprovalGuard(ApprovalConfig(audit_path=None), ui=FakeUI(Decision.REJECT))
    assert guard.is_approved("1. rm -rf /", force_plain=True) is False
