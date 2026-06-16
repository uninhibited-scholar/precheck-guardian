"""Core data structures for execution plans and action steps."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering
from typing import Any, Dict, List, Optional


@total_ordering
class RiskLevel(Enum):
    """Risk classification for an action step.

    Fully ordered, so levels can be compared (``RiskLevel.HIGH > RiskLevel.LOW``).
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __lt__(self, other: "RiskLevel") -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value < other.value

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def icon(self) -> str:
        return {
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🔴",
            RiskLevel.CRITICAL: "⛔",
        }[self]


# Parameter keys whose values must never be displayed in cleartext.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "credential",
        "credentials",
        "authorization",
    }
)


def _redact(key: str, value: Any) -> Any:
    """Mask values for sensitive keys (case-insensitive, substring match)."""
    lowered = key.lower()
    if any(s in lowered for s in _SENSITIVE_KEYS):
        return "***redacted***"
    return value


@dataclass
class ActionStep:
    """A single step the agent intends to perform."""

    step_id: int
    title: str
    description: str
    tool_name: str = "generic_tool"
    tool_params: Dict[str, Any] = field(default_factory=dict)
    expected_output: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    estimated_duration_seconds: int = 0
    can_be_interrupted: bool = True
    warnings: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def format_params(self) -> str:
        """Render parameters as a single line, redacting secrets."""
        if not self.tool_params:
            return "(none)"
        return ", ".join(f"{k}={_redact(k, v)!r}" for k, v in self.tool_params.items())

    def to_readable_format(self) -> str:
        """Human-readable plain-text rendering of this step."""
        duration = (
            f"~{self.estimated_duration_seconds}s"
            if self.estimated_duration_seconds > 0
            else "unknown"
        )
        lines = [
            f"  [Step {self.step_id}] {self.title}",
            f"    risk     : {self.risk_level.icon} {self.risk_level.label.upper()}",
            f"    duration : {duration}",
            f"    action   : {self.description}",
            f"    tool     : {self.tool_name}({self.format_params()})",
        ]
        if self.expected_output:
            lines.append(f"    expects  : {self.expected_output}")
        for warning in self.warnings:
            lines.append(f"    ⚠ {warning}")
        for mitigation in self.mitigations:
            lines.append(f"    → {mitigation}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "description": self.description,
            "tool_name": self.tool_name,
            "tool_params": {k: _redact(k, v) for k, v in self.tool_params.items()},
            "expected_output": self.expected_output,
            "risk_level": self.risk_level.label,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "can_be_interrupted": self.can_be_interrupted,
            "warnings": list(self.warnings),
            "mitigations": list(self.mitigations),
        }


@dataclass
class ExecutionPlan:
    """A complete, ordered set of steps awaiting approval."""

    steps: List[ActionStep]
    plan_id: str = field(default_factory=lambda: f"plan_{int(time.time() * 1000)}")
    title: str = "Agent Execution Plan"
    description: str = ""
    resource_estimate: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_estimated_duration(self) -> int:
        return sum(max(0, s.estimated_duration_seconds) for s in self.steps)

    @property
    def max_risk(self) -> RiskLevel:
        if not self.steps:
            return RiskLevel.LOW
        return max(s.risk_level for s in self.steps)

    def get_risk_summary(self) -> Dict[str, int]:
        summary = {level.label: 0 for level in RiskLevel}
        for step in self.steps:
            summary[step.risk_level.label] += 1
        return summary

    @staticmethod
    def _format_duration(seconds: int) -> str:
        if seconds <= 0:
            return "unknown"
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"

    def to_readable_format(self) -> str:
        summary = self.get_risk_summary()
        header = [
            "=" * 64,
            "  Agent Execution Plan — Approval Required",
            "=" * 64,
            f"  id          : {self.plan_id}",
            f"  title       : {self.title}",
        ]
        if self.description:
            header.append(f"  description : {self.description}")
        header += [
            "",
            "  Risk breakdown:",
            f"    🟢 low {summary['low']}   🟡 medium {summary['medium']}   "
            f"🔴 high {summary['high']}   ⛔ critical {summary['critical']}",
            f"  Estimated duration: {self._format_duration(self.total_estimated_duration)}",
        ]
        if self.resource_estimate:
            parts = ", ".join(f"{k}={v}" for k, v in self.resource_estimate.items())
            header.append(f"  Resource estimate: {parts}")
        header += ["", "  Steps:"]

        body = [step.to_readable_format() for step in self.steps]
        return "\n".join(header + body + ["", "=" * 64])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "title": self.title,
            "description": self.description,
            "max_risk": self.max_risk.label,
            "risk_summary": self.get_risk_summary(),
            "total_estimated_duration": self.total_estimated_duration,
            "resource_estimate": self.resource_estimate,
            "steps": [s.to_dict() for s in self.steps],
        }
