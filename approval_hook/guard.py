"""The high-level entry point: ``ApprovalGuard``.

This is what an agent loop wires in. Give it raw plan text (or structured tool
calls) and it parses, risk-annotates, displays, prompts the operator, records
the decision to the audit log, and returns whether to proceed.

Framework-agnostic by design — it does not depend on any particular agent
framework. Adapters (e.g. a `before_planning` hook) just call ``review``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from .audit.logger import AuditLogger
from .config import ApprovalConfig
from .core import formatter
from .core.plan_parser import PlanParser
from .core.risk_annotator import RiskAnnotator
from .models.approval_record import ApprovalRecord, Decision
from .models.plan import ExecutionPlan, RiskLevel


class ApprovalGuard:
    """Orchestrates parse → annotate → display → approve → audit."""

    def __init__(
        self,
        config: Optional[ApprovalConfig] = None,
        *,
        parser: Optional[PlanParser] = None,
        annotator: Optional[RiskAnnotator] = None,
        ui: Optional[Any] = None,
    ) -> None:
        self.config = config or ApprovalConfig()
        self.annotator = annotator or RiskAnnotator()
        self.parser = parser or PlanParser(annotator=self.annotator)
        self.audit = AuditLogger(self.config.audit_path) if self.config.audit_path else None

        # Lazily import the UI so the package works without questionary/TTY.
        if ui is not None:
            self.ui = ui
        else:
            from .ui.interactive import ApprovalUI

            default = (
                Decision(self.config.non_interactive_default)
                if self.config.non_interactive_default
                else None
            )
            self.ui = ApprovalUI(non_interactive_default=default)

    # -- main API -----------------------------------------------------------
    def review(
        self,
        plan: Union[str, ExecutionPlan, List[Dict[str, Any]]],
        *,
        title: str = "Agent Execution Plan",
        force_plain: bool = False,
    ) -> Decision:
        """Review *plan* and return the operator's :class:`Decision`.

        *plan* may be raw agent text, a list of structured tool calls, or an
        already-built :class:`ExecutionPlan`.
        """
        execution_plan = self._coerce_plan(plan, title=title)
        max_risk = execution_plan.max_risk

        # Hard stop on CRITICAL when configured.
        if self.config.block_critical and max_risk is RiskLevel.CRITICAL:
            formatter.render(execution_plan, force_plain=force_plain)
            print("\n⛔ Plan contains a CRITICAL step and policy blocks it. Auto-rejected.")
            return self._finalise(execution_plan, Decision.REJECT, reason="blocked: critical")

        # Auto-approve low-risk plans without bothering the operator.
        if not self.config.needs_prompt(max_risk):
            return self._finalise(
                execution_plan, Decision.APPROVE, reason="auto-approved: low risk"
            )

        # A "full" UI (e.g. the Textual TUI) renders the plan itself; otherwise
        # we render with the formatter and use the simple prompt.
        if hasattr(self.ui, "render_and_prompt"):
            decision = self.ui.render_and_prompt(execution_plan)
        else:
            formatter.render(execution_plan, force_plain=force_plain)
            decision = self.ui.prompt_approval()
        return self._finalise(execution_plan, decision, reason="operator decision")

    def is_approved(self, plan: Union[str, ExecutionPlan, List[Dict[str, Any]]], **kw) -> bool:
        """Convenience boolean wrapper around :meth:`review`."""
        return self.review(plan, **kw).proceed

    def build_plan(
        self, plan: Union[str, List[Dict[str, Any]]], *, title: str = "Agent Execution Plan"
    ) -> ExecutionPlan:
        """Parse + annotate without prompting (useful for tests/previews)."""
        return self._coerce_plan(plan, title=title)

    # -- internals ----------------------------------------------------------
    def _coerce_plan(self, plan, *, title: str) -> ExecutionPlan:
        if isinstance(plan, ExecutionPlan):
            self.annotator.annotate_plan(plan)
            return plan
        if isinstance(plan, str):
            return self.parser.parse(plan, title=title)
        if isinstance(plan, list):
            return self.parser.parse_tool_calls(plan, title=title)
        raise TypeError(f"Unsupported plan type: {type(plan).__name__}")

    def _finalise(self, plan: ExecutionPlan, decision: Decision, *, reason: str) -> Decision:
        if self.audit is not None:
            self.audit.record(
                ApprovalRecord(
                    plan_id=plan.plan_id,
                    decision=decision,
                    max_risk=plan.max_risk.label,
                    step_count=len(plan.steps),
                    actor=self.config.actor,
                    reason=reason,
                    plan_snapshot=plan.to_dict(),
                )
            )
        return decision
