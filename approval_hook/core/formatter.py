"""Render plans for display. Uses `rich` when available, else plain text."""

from __future__ import annotations

from ..models.plan import ExecutionPlan, RiskLevel

try:  # optional dependency
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    _HAS_RICH = True
except ImportError:  # pragma: no cover - exercised only without rich
    _HAS_RICH = False


_RICH_STYLE = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold white on red",
}


def render_plain(plan: ExecutionPlan) -> str:
    """Plain-text rendering — always available."""
    return plan.to_readable_format()


def render(plan: ExecutionPlan, *, force_plain: bool = False) -> None:
    """Print *plan* to the terminal using the richest renderer available."""
    if force_plain or not _HAS_RICH:
        print(render_plain(plan))
        return

    console = Console()
    summary = plan.get_risk_summary()
    header = Text()
    header.append(f"{plan.title}\n", style="bold")
    header.append(f"id: {plan.plan_id}\n", style="dim")
    if plan.description:
        header.append(f"{plan.description}\n", style="italic dim")
    header.append(
        f"🟢 {summary['low']}  🟡 {summary['medium']}  "
        f"🔴 {summary['high']}  ⛔ {summary['critical']}    "
        f"⏱ {ExecutionPlan._format_duration(plan.total_estimated_duration)}"
    )
    console.print(Panel(header, title="Approval Required", border_style="cyan"))

    table = Table(show_lines=True, expand=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("Risk", width=10)
    table.add_column("Action")
    table.add_column("Tool / params")
    for step in plan.steps:
        notes = ""
        if step.warnings:
            notes = "\n".join(f"⚠ {w}" for w in step.warnings)
        action = step.description + (f"\n{notes}" if notes else "")
        table.add_row(
            str(step.step_id),
            Text(step.risk_level.label.upper(), style=_RICH_STYLE[step.risk_level]),
            action,
            f"{step.tool_name}\n{step.format_params()}",
        )
    console.print(table)
