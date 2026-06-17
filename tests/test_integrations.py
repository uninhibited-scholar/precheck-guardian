import pytest

from approval_hook.config import ApprovalConfig
from approval_hook.guard import ApprovalGuard
from approval_hook.integrations import PlanRejected, gate_plan, guard_callable, review_result
from approval_hook.models.approval_record import Decision


class FakeUI:
    def __init__(self, decision):
        self.decision = decision

    def prompt_approval(self):
        return self.decision

    def prompt_confirm(self, message="Confirm?"):
        return self.decision.proceed


def make_guard(decision):
    return ApprovalGuard(ApprovalConfig(audit_path=None), ui=FakeUI(decision))


def test_gate_plan_runs_when_approved():
    calls = []

    @gate_plan("plan", guard=make_guard(Decision.APPROVE))
    def execute(plan):
        calls.append(plan)
        return "ran"

    assert execute("1. rm -rf /tmp/x") == "ran"
    assert calls == ["1. rm -rf /tmp/x"]


def test_gate_plan_skips_when_rejected():
    calls = []

    @gate_plan("plan", guard=make_guard(Decision.REJECT))
    def execute(plan):
        calls.append(plan)

    assert execute("1. rm -rf /tmp/x") is None
    assert calls == []  # body never ran


def test_gate_plan_on_reject_callback():
    @gate_plan("plan", guard=make_guard(Decision.REJECT), on_reject=lambda d: f"blocked:{d.value}")
    def execute(plan):
        return "ran"

    assert execute(plan="1. DROP TABLE t") == "blocked:reject"


def test_gate_plan_works_with_positional_arg():
    @gate_plan("plan", guard=make_guard(Decision.APPROVE))
    def execute(plan):
        return "ok"

    assert execute("1. SELECT 1") == "ok"


def test_review_result_raises_on_reject():
    @review_result(guard=make_guard(Decision.REJECT))
    def plan():
        return "1. rm -rf /"

    with pytest.raises(PlanRejected):
        plan()


def test_review_result_returns_on_approve():
    @review_result(guard=make_guard(Decision.APPROVE))
    def plan():
        return "1. rm -rf /"

    assert plan() == "1. rm -rf /"


def test_guard_callable_blocks_rejected_tool():
    ran = []

    def delete_file(path):
        ran.append(path)
        return "deleted"

    safe = guard_callable(delete_file, tool_name="delete_file", guard=make_guard(Decision.REJECT))
    with pytest.raises(PlanRejected):
        safe("/tmp/important")
    assert ran == []


def test_guard_callable_runs_approved_tool():
    def add(a, b):
        return a + b

    safe = guard_callable(add, guard=make_guard(Decision.APPROVE))
    assert safe(2, 3) == 5
