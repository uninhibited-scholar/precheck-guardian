# Contributing to PreCheck Guardian

Thanks for helping make agents safer! Contributions of all sizes are welcome.

## Development setup

```bash
git clone https://github.com/uninhibited-scholar/precheck-guardian
cd precheck-guardian
pip install -e ".[dev]"
pytest -q
```

## Good first contributions

- **New risk rules.** The highest-leverage contribution. Add a `_rule(...)` to
  `DEFAULT_RULES` in [`approval_hook/core/risk_annotator.py`](approval_hook/core/risk_annotator.py)
  and a matching test in `tests/test_risk_annotator.py`. Each rule needs a
  regex, a `RiskLevel`, a warning, and (ideally) a mitigation.
- **New parser formats.** Teach `PlanParser` to recognise another way agents
  describe plans (e.g. JSON tool-call traces from a specific framework).
- **Framework adapters.** Thin wrappers in `approval_hook/integrations/` that
  make wiring the guard into a specific framework a one-liner.

## Adding a risk rule — example

```python
# in DEFAULT_RULES
_rule("npm_global", r"\bnpm\s+install\s+-g\b", RiskLevel.MEDIUM,
      "Global npm install affects the whole machine.",
      "Prefer a local/project install."),
```

```python
# in tests/test_risk_annotator.py
def test_detects_global_npm_install():
    step = RiskAnnotator().annotate_step(make_step("npm install -g leftpad"))
    assert step.risk_level is RiskLevel.MEDIUM
```

## Guidelines

- **Conservative by default.** When a rule is ambiguous, score *higher*. The
  cost of an extra prompt is far lower than a missed `rm -rf`.
- **Keep the core dependency-free.** `rich` and `questionary` must stay optional.
- **Every behaviour change needs a test.** Run `pytest -q` before opening a PR.
- Match the surrounding style; keep functions small and documented.

## Reporting issues

Found a dangerous operation we don't flag? Open an issue with the exact command
and the risk level you'd expect — that's a perfect bug report.
