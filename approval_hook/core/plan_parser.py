"""Parse free-form agent output into a structured :class:`ExecutionPlan`.

Agents describe plans in many shapes. The parser recognises the common ones:

* numbered lists      ``1. do X`` / ``1) do X`` / ``Step 1: do X``
* bullet lists        ``- do X`` / ``* do X``
* a structured list of dicts (already-parsed tool calls)

Anything it cannot structure becomes a single best-effort step, so the
approval gate never silently drops work.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ..models.plan import ActionStep, ExecutionPlan, RiskLevel
from .risk_annotator import RiskAnnotator

# Lines like "1. ...", "1) ...", "Step 1: ...", "- ...", "* ..."
_NUMBERED = re.compile(r"^\s*(?:step\s*)?(\d+)\s*[.)\:-]\s+(.*\S)\s*$", re.IGNORECASE)
_BULLET = re.compile(r"^\s*[-*•]\s+(.*\S)\s*$")

# Heuristic tool inference: first matching pattern wins.
_TOOL_PATTERNS: List[Tuple[str, str]] = [
    (r"\b(select|insert|update|delete|drop|truncate|alter|grant|revoke)\b.*\b(from|into|table|database)\b", "sql_query"),
    (r"\b(rm|del|rmdir|unlink|delete|remove)\b.*\b(file|dir|folder|/|\.\w+)", "file_delete"),
    (r"\b(chmod|chown|icacls|setuid|permission|privilege)\b", "change_permission"),
    (r"\b(curl|wget|http|https|request|fetch|api|webhook)\b", "http_request"),
    (r"\b(git)\b", "git"),
    (r"\b(docker|kubectl|terraform|aws|gcloud|az)\b", "cloud_cli"),
    (r"\b(scan|nmap|exploit|vulnerab|pentest)\b", "security_scan"),
    (r"\b(write|create|save|export|generate)\b.*\b(file|csv|json|report)\b", "file_write"),
    (r"\b(read|cat|open|load|query|fetch|list)\b", "read_data"),
]

# Rough per-tool duration estimates (seconds).
_DURATION_BY_TOOL: Dict[str, int] = {
    "sql_query": 2,
    "file_delete": 1,
    "file_write": 2,
    "read_data": 1,
    "http_request": 5,
    "git": 3,
    "cloud_cli": 15,
    "change_permission": 1,
    "security_scan": 60,
    "generic_tool": 5,
}


class PlanParser:
    """Turns agent output into an :class:`ExecutionPlan`."""

    def __init__(self, annotator: Optional[RiskAnnotator] = None) -> None:
        self.annotator = annotator or RiskAnnotator()

    # -- public API ---------------------------------------------------------
    def parse(self, agent_output: str, *, title: str = "Agent Execution Plan") -> ExecutionPlan:
        """Parse text output into an annotated plan."""
        steps = self._extract_steps(agent_output)
        if not steps:
            steps = [self._build_step(1, agent_output.strip() or "(empty plan)")]

        plan = ExecutionPlan(
            steps=steps,
            title=title,
            description=self._summarise(agent_output),
            resource_estimate={"memory_mb": 256, "disk_mb": 512},
        )
        self.annotator.annotate_plan(plan)
        return plan

    def parse_tool_calls(
        self, tool_calls: List[Dict[str, Any]], *, title: str = "Agent Execution Plan"
    ) -> ExecutionPlan:
        """Build a plan from already-structured tool calls.

        Each item should look like::

            {"tool": "sql_query", "args": {...}, "description": "..."}
        """
        steps: List[ActionStep] = []
        for i, call in enumerate(tool_calls, start=1):
            tool = call.get("tool") or call.get("name") or "generic_tool"
            params = call.get("args") or call.get("params") or {}
            desc = call.get("description") or f"{tool}({params})"
            steps.append(
                ActionStep(
                    step_id=i,
                    title=desc[:60],
                    description=desc,
                    tool_name=tool,
                    tool_params=dict(params),
                    estimated_duration_seconds=_DURATION_BY_TOOL.get(tool, 5),
                )
            )
        plan = ExecutionPlan(steps=steps or [self._build_step(1, "(no tool calls)")], title=title)
        self.annotator.annotate_plan(plan)
        return plan

    # -- internals ----------------------------------------------------------
    def _extract_steps(self, text: str) -> List[ActionStep]:
        steps: List[ActionStep] = []
        counter = 0
        for line in text.splitlines():
            m = _NUMBERED.match(line)
            if m:
                counter = int(m.group(1))
                steps.append(self._build_step(counter, m.group(2)))
                continue
            b = _BULLET.match(line)
            if b:
                counter += 1
                steps.append(self._build_step(counter, b.group(1)))
        return steps

    def _build_step(self, step_id: int, description: str) -> ActionStep:
        description = description.strip()
        tool = self._infer_tool(description)
        return ActionStep(
            step_id=step_id,
            title=(description[:57] + "...") if len(description) > 60 else description,
            description=description,
            tool_name=tool,
            tool_params=self._extract_params(description),
            estimated_duration_seconds=_DURATION_BY_TOOL.get(tool, 5),
        )

    @staticmethod
    def _infer_tool(description: str) -> str:
        for pattern, tool in _TOOL_PATTERNS:
            if re.search(pattern, description, re.IGNORECASE):
                return tool
        return "generic_tool"

    @staticmethod
    def _extract_params(description: str) -> Dict[str, Any]:
        """Pull obvious operands (paths, URLs) out of the description."""
        params: Dict[str, Any] = {}
        # Extract URLs first, then strip them so the path regex doesn't latch
        # onto the "//host/..." portion of a URL.
        url = re.search(r"https?://[^\s'\"]+", description)
        remainder = description
        if url:
            params["url"] = url.group(0)
            remainder = description.replace(url.group(0), " ")
        path = re.search(r"(/[\w./\-]+|[A-Za-z]:\\[\w\\.\-]+)", remainder)
        if path:
            params["path"] = path.group(1)
        return params

    @staticmethod
    def _summarise(text: str) -> str:
        flat = " ".join(text.split())
        return (flat[:117] + "...") if len(flat) > 120 else flat
