"""Compute and present differences between two execution plans."""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from typing import List

from ..models.plan import ExecutionPlan


@dataclass
class StepChange:
    """A high-level, per-step description of what changed."""

    kind: str  # "added" | "removed" | "modified" | "unchanged"
    step_id: int
    detail: str


class DiffEngine:
    """Diff two plans both as text and as a structured step-level summary."""

    def unified_diff(self, old: ExecutionPlan, new: ExecutionPlan) -> str:
        diff = difflib.unified_diff(
            old.to_readable_format().splitlines(),
            new.to_readable_format().splitlines(),
            fromfile="plan(before)",
            tofile="plan(after)",
            lineterm="",
        )
        return "\n".join(diff)

    def highlight(self, unified: str) -> str:
        """Prefix added/removed lines with icons for terminal display."""
        out: List[str] = []
        for line in unified.splitlines():
            if line.startswith(("+++", "---")):
                out.append(line)
            elif line.startswith("+"):
                out.append(f"✓ {line[1:]}")
            elif line.startswith("-"):
                out.append(f"✗ {line[1:]}")
            elif line.startswith("@@"):
                out.append(f"\n📍 {line}")
            else:
                out.append(f"  {line}")
        return "\n".join(out)

    def step_changes(self, old: ExecutionPlan, new: ExecutionPlan) -> List[StepChange]:
        """Structured, step-keyed summary of additions/removals/modifications."""
        old_by_id = {s.step_id: s for s in old.steps}
        new_by_id = {s.step_id: s for s in new.steps}
        changes: List[StepChange] = []

        for sid in sorted(set(old_by_id) | set(new_by_id)):
            o, n = old_by_id.get(sid), new_by_id.get(sid)
            if o and not n:
                changes.append(StepChange("removed", sid, o.description))
            elif n and not o:
                changes.append(StepChange("added", sid, n.description))
            elif o and n and (o.description != n.description or o.tool_name != n.tool_name
                              or o.tool_params != n.tool_params):
                changes.append(
                    StepChange("modified", sid, f"{o.description!r} → {n.description!r}")
                )
            else:
                changes.append(StepChange("unchanged", sid, n.description if n else ""))
        return changes

    def summary(self, old: ExecutionPlan, new: ExecutionPlan) -> str:
        """One-line-per-change human summary, skipping unchanged steps."""
        icons = {"added": "➕", "removed": "➖", "modified": "✎"}
        lines = [
            f"{icons[c.kind]} step {c.step_id}: {c.detail}"
            for c in self.step_changes(old, new)
            if c.kind != "unchanged"
        ]
        return "\n".join(lines) if lines else "(no changes)"
