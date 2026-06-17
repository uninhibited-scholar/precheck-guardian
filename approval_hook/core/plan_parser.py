"""Parse free-form agent output into a structured :class:`ExecutionPlan`.

Agents describe plans in many shapes. The parser recognises the common ones:

* numbered lists      ``1. do X`` / ``1) do X`` / ``Step 1: do X``
* bullet lists        ``- do X`` / ``* do X``
* a structured list of dicts (already-parsed tool calls)

Anything it cannot structure becomes a single best-effort step, so the
approval gate never silently drops work.
"""

from __future__ import annotations

import json
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

    def parse_tool_call_trace(
        self, trace: Any, *, title: str = "Agent Execution Plan"
    ) -> ExecutionPlan:
        """Parse a native OpenAI / LangChain tool-call trace into a plan.

        Accepts the shapes agents actually emit, so you can hand the raw thing
        straight from the API to the guard:

        * a list of OpenAI tool-call dicts
          ``[{"type": "function", "function": {"name": ..., "arguments": "{...}"}}]``
          (``arguments`` may be a JSON string or an already-parsed dict)
        * a single assistant message dict containing ``tool_calls``
        * a full chat-completion response dict (``choices[].message.tool_calls``)
        * a list of chat messages (tool calls are gathered from every assistant
          message, in order)
        * LangChain-style ``[{"name": ..., "args": {...}}]``
        """
        normalized = [self._normalize_call(tc) for tc in self._collect_calls(trace)]
        return self.parse_tool_calls(normalized, title=title)

    # -- internals ----------------------------------------------------------
    def _collect_calls(self, trace: Any) -> List[Dict[str, Any]]:
        """Dig tool calls out of whatever container shape was passed."""
        if isinstance(trace, dict):
            if "choices" in trace:  # full chat-completion response
                calls: List[Dict[str, Any]] = []
                for choice in trace.get("choices", []):
                    msg = choice.get("message", {})
                    calls.extend(msg.get("tool_calls") or [])
                return calls
            if "tool_calls" in trace:  # a single assistant message
                return list(trace.get("tool_calls") or [])
            if "message" in trace:
                return list(trace["message"].get("tool_calls") or [])
            return [trace]  # assume it's already a single call
        if isinstance(trace, list):
            # Either a list of messages, or a list of tool-call dicts.
            if any(isinstance(x, dict) and "tool_calls" in x for x in trace):
                calls = []
                for msg in trace:
                    if isinstance(msg, dict):
                        calls.extend(msg.get("tool_calls") or [])
                return calls
            return list(trace)
        return []

    @staticmethod
    def _normalize_call(tc: Dict[str, Any]) -> Dict[str, Any]:
        """Reduce one tool call (OpenAI or LangChain shape) to {tool, args}."""
        fn = tc.get("function", tc) if isinstance(tc, dict) else {}
        name = fn.get("name") or tc.get("name") or tc.get("tool") or "generic_tool"
        raw = fn.get("arguments")
        if raw is None:
            raw = tc.get("args") or tc.get("arguments") or {}
        if isinstance(raw, str):
            try:
                args = json.loads(raw) if raw.strip() else {}
            except (json.JSONDecodeError, ValueError):
                args = {"_raw": raw}
        elif isinstance(raw, dict):
            args = raw
        else:
            args = {"value": raw}
        return {"tool": name, "args": args, "description": f"{name}({args})"}


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
