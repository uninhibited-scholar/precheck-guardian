from approval_hook.core.plan_parser import PlanParser
from approval_hook.diff.diff_engine import DiffEngine


def _plans():
    parser = PlanParser()
    old = parser.parse("1. read /tmp/a\n2. write /tmp/b")
    new = parser.parse("1. read /tmp/a\n2. write /tmp/c\n3. rm -rf /tmp/b")
    return old, new


def test_unified_diff_has_changes():
    old, new = _plans()
    diff = DiffEngine().unified_diff(old, new)
    assert "plan(before)" in diff and "plan(after)" in diff
    assert any(line.startswith("+") for line in diff.splitlines())


def test_step_changes_detects_add_and_modify():
    old, new = _plans()
    changes = {c.kind for c in DiffEngine().step_changes(old, new)}
    assert "added" in changes
    assert "modified" in changes


def test_summary_skips_unchanged():
    old, new = _plans()
    summary = DiffEngine().summary(old, new)
    assert "step 3" in summary  # the added step
    assert "step 1" not in summary  # unchanged


def test_readable_format_renders_steps():
    old, _ = _plans()
    text = old.to_readable_format()
    assert "Step 1" in text
    assert "Risk breakdown" in text


def test_format_duration():
    from approval_hook.models.plan import ExecutionPlan
    assert ExecutionPlan._format_duration(45) == "45s"
    assert ExecutionPlan._format_duration(125) == "2m 5s"
    assert ExecutionPlan._format_duration(3700).startswith("1h")
