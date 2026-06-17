"""A full-screen Textual approval UI.

An optional, visually rich alternative to the inline prompt. Plug it into the
guard::

    from approval_hook import ApprovalGuard
    from approval_hook.ui.tui import TextualApprovalUI

    guard = ApprovalGuard(ui=TextualApprovalUI())
    guard.review(agent_plan)   # opens the TUI

Requires the optional extra:  pip install "precheck-guardian[tui]"
"""

from __future__ import annotations

from typing import Optional

from ..models.approval_record import Decision
from ..models.plan import ExecutionPlan, RiskLevel

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, VerticalScroll
    from textual.widgets import Button, DataTable, Footer, Label, Static

    _HAS_TEXTUAL = True
except ImportError:  # pragma: no cover - exercised only without textual
    _HAS_TEXTUAL = False


_RISK_COLOR = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bright_white on red",
}


if _HAS_TEXTUAL:

    class ApprovalApp(App):
        """Textual application that displays a plan and captures a decision."""

        CSS = """
        Screen { align: center top; }
        #title { padding: 1 2 0 2; text-style: bold; }
        #summary { padding: 0 2 1 2; color: $text-muted; }
        DataTable { height: 1fr; margin: 0 1; }
        #buttons { height: auto; padding: 1 2; align: center middle; }
        Button { margin: 0 1; }
        #approve { background: $success; }
        #reject { background: $error; }
        #edit { background: $warning; }
        """

        BINDINGS = [
            Binding("a", "decide('approve')", "Approve"),
            Binding("e", "decide('edit')", "Edit"),
            Binding("r,escape", "decide('reject')", "Reject"),
        ]

        def __init__(self, plan: ExecutionPlan) -> None:
            super().__init__()
            self.plan = plan
            self.decision: Decision = Decision.REJECT  # safe default

        def compose(self) -> "ComposeResult":
            s = self.plan.get_risk_summary()
            yield Label(f"🛡️  {self.plan.title}", id="title")
            yield Static(
                f"🟢 {s['low']}  🟡 {s['medium']}  🔴 {s['high']}  ⛔ {s['critical']}    "
                f"max risk: {self.plan.max_risk.label.upper()}    "
                f"⏱ {ExecutionPlan._format_duration(self.plan.total_estimated_duration)}",
                id="summary",
            )
            with VerticalScroll():
                yield DataTable(id="steps", zebra_stripes=True, cursor_type="row")
            with Horizontal(id="buttons"):
                yield Button("✅ Approve (a)", id="approve", variant="success")
                yield Button("✏️ Edit (e)", id="edit", variant="warning")
                yield Button("❌ Reject (r)", id="reject", variant="error")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#steps", DataTable)
            table.add_columns("#", "Risk", "Action", "Tool / params")
            for step in self.plan.steps:
                from rich.text import Text  # textual always ships rich

                risk = Text(step.risk_level.label.upper(),
                            style=_RISK_COLOR[step.risk_level])
                action = step.description
                if step.warnings:
                    action += "\n" + "\n".join(f"⚠ {w}" for w in step.warnings)
                table.add_row(
                    str(step.step_id), risk, action,
                    f"{step.tool_name}\n{step.format_params()}",
                )

        def action_decide(self, decision: str) -> None:
            self.decision = Decision(decision)
            self.exit(self.decision)

        def on_button_pressed(self, event: "Button.Pressed") -> None:
            self.action_decide(event.button.id)


class TextualApprovalUI:
    """Guard-compatible UI backed by the Textual app."""

    def __init__(self, *, non_interactive_default: Optional[Decision] = None) -> None:
        self.non_interactive_default = non_interactive_default

    def render_and_prompt(self, plan: ExecutionPlan) -> Decision:
        if not _HAS_TEXTUAL:
            raise ImportError(
                "Textual is required for the TUI. Install it with:\n"
                '    pip install "precheck-guardian[tui]"'
            )
        app = ApprovalApp(plan)
        result = app.run()
        return result if isinstance(result, Decision) else Decision.REJECT

    # Fallback so the UI still satisfies the simple protocol if needed.
    def prompt_approval(self) -> Decision:  # pragma: no cover - not the primary path
        return self.non_interactive_default or Decision.REJECT

    def prompt_confirm(self, message: str = "Confirm?") -> bool:  # pragma: no cover
        return bool(self.non_interactive_default and self.non_interactive_default.proceed)
