# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Custom risk rules from a config file: `RiskAnnotator.from_file()` (JSON via
  stdlib, YAML via the optional `[yaml]` extra) and `from_config()`, with
  `extend`/`replace` modes. Helpers `load_rules_config()` and `rule_from_dict()`
  validate specs (regex, level, required keys). Example in `examples/`.

## [0.1.1] — 2026-06-18

### Added
- `precheck audit --summary [--limit N] [--path FILE]` — CLI report over the
  JSON-Lines approval log (totals, approval rate, breakdown by max risk, recent
  decisions). Backing helper `summarize_records()` is importable.

## [0.1.0] — 2026-06-17

### Added
- `ApprovalGuard` — one-call entry point: parse → risk-score → display →
  prompt → audit.
- `RiskAnnotator` with 75 rule-based detectors across destruction, privilege,
  system control, RCE/supply-chain, infrastructure, secrets and network.
- `PlanParser` for numbered/bulleted agent text, structured tool calls, and
  native OpenAI/LangChain tool-call traces (`parse_tool_call_trace`).
- Policy gates via `ApprovalConfig`: auto-approve LOW, prompt MEDIUM+,
  optional hard-block of CRITICAL, safe REJECT default with no TTY.
- `DiffEngine` — unified diff and per-step change summary between two plans.
- JSON-Lines audit log with automatic secret redaction.
- Optional `rich` table rendering and `questionary` menus; zero required deps.
- Integrations: `gate_plan`, `review_result`, `guard_callable` decorators.
- LangChain integration: `guard_langchain_tool` wraps any LangChain tool into
  an approval-gated drop-in replacement (optional `[langchain]` extra).
- Textual TUI: `TextualApprovalUI` — a full-screen approve/edit/reject screen,
  pluggable into the guard via `ApprovalGuard(ui=TextualApprovalUI())` (optional
  `[tui]` extra).
- `python -m approval_hook` demo CLI and runnable `examples/`.
- 75 risk rules; 67 tests.
