import json

import pytest

from approval_hook.core.risk_annotator import (
    DEFAULT_RULES,
    RiskAnnotator,
    load_rules_config,
    rule_from_dict,
)
from approval_hook.models.plan import ActionStep, RiskLevel


def make_step(desc):
    return ActionStep(step_id=1, title=desc[:40], description=desc)


def test_rule_from_dict_minimal():
    rule = rule_from_dict({"name": "no_prod", "pattern": r"\bprod\b", "level": "critical"})
    assert rule.name == "no_prod"
    assert rule.level is RiskLevel.CRITICAL
    assert rule.pattern.search("deploy to prod")


def test_rule_from_dict_missing_key():
    with pytest.raises(ValueError, match="missing required key"):
        rule_from_dict({"name": "x", "pattern": "y"})  # no level


def test_rule_from_dict_bad_regex():
    with pytest.raises(ValueError, match="invalid regex"):
        rule_from_dict({"name": "x", "pattern": "([", "level": "low"})


def test_rule_from_dict_bad_level():
    with pytest.raises(ValueError, match="unknown risk level"):
        rule_from_dict({"name": "x", "pattern": "y", "level": "nuclear"})


def test_load_rules_extend_mode():
    rules = load_rules_config({"rules": [{"name": "a", "pattern": "z", "level": "high"}]})
    assert len(rules) == len(DEFAULT_RULES) + 1


def test_load_rules_replace_mode():
    rules = load_rules_config(
        {"mode": "replace", "rules": [{"name": "a", "pattern": "z", "level": "high"}]}
    )
    assert len(rules) == 1


def test_load_rules_bad_mode():
    with pytest.raises(ValueError, match="mode must be"):
        load_rules_config({"mode": "nope", "rules": []})


def test_from_config_detects_custom_rule():
    ann = RiskAnnotator.from_config(
        {"mode": "replace",
         "rules": [{"name": "no_prod", "pattern": r"\bprod\b", "level": "critical",
                    "warning": "Touches production."}]}
    )
    step = ann.annotate_step(make_step("deploy to prod cluster"))
    assert step.risk_level is RiskLevel.CRITICAL
    assert "Touches production." in step.warnings
    # replace mode: built-in rm -rf rule is gone
    benign = ann.annotate_step(make_step("rm -rf /tmp/x"))
    assert benign.risk_level is not RiskLevel.CRITICAL


def test_from_file_json(tmp_path):
    cfg = {"rules": [{"name": "no_prod", "pattern": r"\bprod\b", "level": "high"}]}
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(cfg))
    ann = RiskAnnotator.from_file(p)
    assert ann.annotate_step(make_step("touch prod db")).risk_level >= RiskLevel.HIGH


def test_from_file_yaml(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "rules.yaml"
    p.write_text(
        "mode: replace\n"
        "rules:\n"
        "  - name: no_prod\n"
        "    pattern: '\\bprod\\b'\n"
        "    level: critical\n"
    )
    ann = RiskAnnotator.from_file(p)
    assert ann.annotate_step(make_step("ship to prod")).risk_level is RiskLevel.CRITICAL
