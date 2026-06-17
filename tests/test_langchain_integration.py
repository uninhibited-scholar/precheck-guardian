import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import tool  # noqa: E402

from approval_hook.config import ApprovalConfig  # noqa: E402
from approval_hook.guard import ApprovalGuard  # noqa: E402
from approval_hook.integrations.decorator import PlanRejected  # noqa: E402
from approval_hook.integrations.langchain import guard_langchain_tool  # noqa: E402
from approval_hook.models.approval_record import Decision  # noqa: E402


class FakeUI:
    def __init__(self, decision):
        self.decision = decision

    def prompt_approval(self):
        return self.decision

    def prompt_confirm(self, message="Confirm?"):
        return self.decision.proceed


@tool
def delete_path(path: str) -> str:
    """Delete a file or directory at the given path."""
    return f"deleted {path}"


def guard(decision):
    return ApprovalGuard(ApprovalConfig(audit_path=None), ui=FakeUI(decision))


def test_wrapped_tool_preserves_name_and_schema():
    safe = guard_langchain_tool(delete_path, guard=guard(Decision.APPROVE))
    assert safe.name == "delete_path"
    assert "Delete a file" in safe.description
    assert safe.args_schema is delete_path.args_schema


def test_approved_call_delegates_to_inner_tool():
    safe = guard_langchain_tool(delete_path, guard=guard(Decision.APPROVE))
    assert safe.invoke({"path": "/tmp/scratch"}) == "deleted /tmp/scratch"


def test_rejected_call_raises_and_does_not_run():
    safe = guard_langchain_tool(delete_path, guard=guard(Decision.REJECT))
    with pytest.raises(PlanRejected):
        safe.invoke({"path": "/etc/passwd"})


def test_block_critical_policy_blocks_dangerous_call():
    g = ApprovalGuard(ApprovalConfig(block_critical=True, audit_path=None),
                      ui=FakeUI(Decision.APPROVE))  # would approve, but policy blocks
    safe = guard_langchain_tool(delete_path, guard=g)
    with pytest.raises(PlanRejected):
        safe.invoke({"path": "rm -rf /data"})
