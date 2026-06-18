import json

from approval_hook import __main__ as cli
from approval_hook.core.risk_annotator import RiskAnnotator
from approval_hook.models.plan import RiskLevel

SCRIPT = """\
#!/bin/bash
# deploy script
echo "starting"
SELECT * FROM users
rm -rf /tmp/build
chmod 777 /var/www
-- this is a sql comment
"""


def test_scan_text_flags_dangerous_lines_only():
    flagged = cli.scan_text(SCRIPT, RiskAnnotator())
    levels = {lineno: level for lineno, level, _, _ in flagged}
    # comments, blanks, echo and the SELECT (low) are not "high-risk" flags...
    text_by_line = {lineno: line for lineno, _, line, _ in flagged}
    assert any("rm -rf" in t for t in text_by_line.values())
    assert any("chmod 777" in t for t in text_by_line.values())
    # comment lines are skipped
    assert not any(t.startswith(("#", "--")) for t in text_by_line.values())


def test_check_fails_on_critical(tmp_path, capsys):
    p = tmp_path / "deploy.sh"
    p.write_text(SCRIPT)
    rc = cli.cmd_check(str(p), fail_on="high", rules_path=None)
    out = capsys.readouterr().out
    assert rc == 1                      # rm -rf is critical >= high
    assert "risky line(s)" in out
    assert "CRITICAL" in out
    assert "rules:" in out


def test_check_passes_when_clean(tmp_path, capsys):
    p = tmp_path / "ok.sh"
    p.write_text("echo hello\nls -la\n# nothing dangerous\n")
    rc = cli.cmd_check(str(p), fail_on="high", rules_path=None)
    assert rc == 0
    assert "no risky lines" in capsys.readouterr().out


def test_check_fail_on_never_always_zero(tmp_path):
    p = tmp_path / "deploy.sh"
    p.write_text("rm -rf /\n")
    assert cli.cmd_check(str(p), fail_on="never", rules_path=None) == 0


def test_check_threshold_respected(tmp_path):
    p = tmp_path / "mild.sh"
    p.write_text("pip install requests\n")     # medium only
    assert cli.cmd_check(str(p), fail_on="high", rules_path=None) == 0
    assert cli.cmd_check(str(p), fail_on="medium", rules_path=None) == 1


def test_check_missing_file_returns_2(tmp_path, capsys):
    rc = cli.cmd_check(str(tmp_path / "nope.sh"), fail_on="high", rules_path=None)
    assert rc == 2
    assert "cannot read" in capsys.readouterr().err


def test_check_with_custom_rules(tmp_path):
    rules = {"mode": "replace",
             "rules": [{"name": "no_prod", "pattern": r"\bprod\b", "level": "critical"}]}
    rp = tmp_path / "rules.json"
    rp.write_text(json.dumps(rules))
    script = tmp_path / "s.sh"
    script.write_text("deploy to prod\nrm -rf /tmp/x\n")
    rc = cli.cmd_check(str(script), fail_on="critical", rules_path=str(rp))
    assert rc == 1   # 'prod' matches; rm -rf does NOT (replace mode dropped built-ins)
