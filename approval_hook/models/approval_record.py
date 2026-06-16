"""Audit-trail record produced by every approval decision."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Decision(Enum):
    """Outcome of an approval prompt."""

    APPROVE = "approve"
    REJECT = "reject"
    EDIT = "edit"

    @property
    def proceed(self) -> bool:
        """Whether the agent should continue executing the plan."""
        return self is Decision.APPROVE


@dataclass
class ApprovalRecord:
    """An immutable record of a single approval decision, for audit logs."""

    plan_id: str
    decision: Decision
    max_risk: str
    step_count: int
    timestamp: float = field(default_factory=time.time)
    actor: str = "unknown"
    reason: str = ""
    plan_snapshot: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "iso_time": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(self.timestamp)
            ),
            "plan_id": self.plan_id,
            "decision": self.decision.value,
            "max_risk": self.max_risk,
            "step_count": self.step_count,
            "actor": self.actor,
            "reason": self.reason,
            "plan_snapshot": self.plan_snapshot,
        }
