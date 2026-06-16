from approval_hook.core.plan_parser import PlanParser
from approval_hook.models.plan import RiskLevel


def test_parses_numbered_list():
    text = """I will:
1. Query the users table with SELECT * FROM users
2. Export results to /tmp/users.csv
3. Drop the temp table: DROP TABLE users_temp
"""
    plan = PlanParser().parse(text)
    assert len(plan.steps) == 3
    assert plan.steps[0].tool_name == "sql_query"
    assert plan.steps[2].risk_level is RiskLevel.CRITICAL  # DROP TABLE


def test_parses_paren_and_step_prefix():
    plan = PlanParser().parse("Step 1: do a thing\n2) do another thing")
    assert len(plan.steps) == 2


def test_parses_bullets():
    plan = PlanParser().parse("- read the config\n* write the output file")
    assert len(plan.steps) == 2


def test_unstructured_text_becomes_single_step():
    plan = PlanParser().parse("just delete everything in /data")
    assert len(plan.steps) == 1


def test_extracts_path_and_url_params():
    plan = PlanParser().parse("1. POST to https://api.example.com/users from /tmp/data.json")
    params = plan.steps[0].tool_params
    assert params.get("url") == "https://api.example.com/users"
    assert params.get("path") == "/tmp/data.json"


def test_parse_structured_tool_calls():
    calls = [
        {"tool": "sql_query", "args": {"q": "SELECT 1"}, "description": "ping db"},
        {"tool": "file_delete", "args": {"path": "/tmp/x"}, "description": "rm -rf /tmp/x"},
    ]
    plan = PlanParser().parse_tool_calls(calls)
    assert len(plan.steps) == 2
    assert plan.steps[1].risk_level is RiskLevel.CRITICAL


def test_total_duration_is_summed():
    plan = PlanParser().parse("1. SELECT * FROM t\n2. scan the network for vulnerabilities")
    assert plan.total_estimated_duration == sum(
        s.estimated_duration_seconds for s in plan.steps
    )
