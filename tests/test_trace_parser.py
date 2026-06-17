import json

from approval_hook.config import ApprovalConfig
from approval_hook.core.plan_parser import PlanParser
from approval_hook.guard import ApprovalGuard
from approval_hook.models.approval_record import Decision
from approval_hook.models.plan import RiskLevel


class FakeUI:
    def __init__(self, decision):
        self.decision = decision

    def prompt_approval(self):
        return self.decision

    def prompt_confirm(self, message="Confirm?"):
        return self.decision.proceed


# --- OpenAI-style tool calls (arguments as a JSON string) -------------------
OPENAI_CALLS = [
    {"id": "c1", "type": "function",
     "function": {"name": "query_users", "arguments": json.dumps({"status": "active"})}},
    {"id": "c2", "type": "function",
     "function": {"name": "run_sql", "arguments": json.dumps({"statement": "DROP TABLE staging"})}},
]


def test_parses_openai_tool_calls_list():
    plan = PlanParser().parse_tool_call_trace(OPENAI_CALLS)
    assert len(plan.steps) == 2
    assert plan.steps[0].tool_name == "query_users"
    assert plan.steps[0].tool_params == {"status": "active"}
    assert plan.steps[1].risk_level is RiskLevel.CRITICAL  # DROP TABLE


def test_parses_full_chat_completion_response():
    response = {
        "choices": [
            {"message": {"role": "assistant", "tool_calls": OPENAI_CALLS}}
        ]
    }
    plan = PlanParser().parse_tool_call_trace(response)
    assert len(plan.steps) == 2
    assert plan.max_risk is RiskLevel.CRITICAL


def test_parses_message_list():
    messages = [
        {"role": "user", "content": "clean up"},
        {"role": "assistant", "tool_calls": OPENAI_CALLS},
    ]
    plan = PlanParser().parse_tool_call_trace(messages)
    assert len(plan.steps) == 2


def test_parses_langchain_style_name_args():
    calls = [{"name": "delete_path", "args": {"path": "rm -rf /data"}}]
    plan = PlanParser().parse_tool_call_trace(calls)
    assert plan.steps[0].tool_name == "delete_path"
    assert plan.steps[0].risk_level is RiskLevel.CRITICAL


def test_malformed_arguments_do_not_crash():
    calls = [{"type": "function", "function": {"name": "x", "arguments": "{not json"}}]
    plan = PlanParser().parse_tool_call_trace(calls)
    assert plan.steps[0].tool_params == {"_raw": "{not json"}


def test_guard_auto_detects_native_trace():
    guard = ApprovalGuard(ApprovalConfig(audit_path=None, block_critical=True),
                          ui=FakeUI(Decision.APPROVE))
    # passes the OpenAI-shaped list straight to review(); guard should route it
    decision = guard.review(OPENAI_CALLS, force_plain=True)
    assert decision is Decision.REJECT  # blocked: contains DROP TABLE (critical)
