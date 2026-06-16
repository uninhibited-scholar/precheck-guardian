"""Configuration for the approval gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models.plan import RiskLevel


@dataclass
class ApprovalConfig:
    """Tunable policy for when and how approval is required.

    Attributes:
        require_above: steps at or below this risk level are auto-approved
            without prompting. Set to ``None`` to always prompt. Default
            :attr:`RiskLevel.LOW` means "prompt for MEDIUM and up".
        block_critical: if True, CRITICAL steps are auto-rejected and never
            offered for approval (a hard stop).
        audit_path: where to write the JSON-Lines audit log. ``None`` disables.
        actor: identity recorded in the audit log (e.g. an operator name).
        non_interactive_default: decision used when there is no TTY. ``None``
            falls back to a safe REJECT.
    """

    require_above: Optional[RiskLevel] = RiskLevel.LOW
    block_critical: bool = False
    audit_path: Optional[str] = "approval_audit.jsonl"
    actor: str = "operator"
    non_interactive_default: Optional[str] = None  # "approve" | "reject" | "edit"

    def needs_prompt(self, max_risk: RiskLevel) -> bool:
        """Whether a plan at *max_risk* should be shown for approval."""
        if self.require_above is None:
            return True
        return max_risk > self.require_above
