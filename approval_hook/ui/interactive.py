"""Interactive approval prompt. Uses `questionary` if present, else input()."""

from __future__ import annotations

from typing import Optional

from ..models.approval_record import Decision

try:  # optional dependency
    import questionary

    _HAS_QUESTIONARY = True
except ImportError:  # pragma: no cover
    _HAS_QUESTIONARY = False


class ApprovalUI:
    """Prompt the operator to approve, reject or edit a plan."""

    def __init__(self, *, non_interactive_default: Optional[Decision] = None) -> None:
        # When stdin is not a TTY (CI, pipelines) fall back to this decision.
        self.non_interactive_default = non_interactive_default

    def prompt_approval(self) -> Decision:
        if not self._stdin_is_tty():
            if self.non_interactive_default is not None:
                return self.non_interactive_default
            # Safe default: refuse rather than auto-run unattended.
            return Decision.REJECT

        if _HAS_QUESTIONARY:
            choice = questionary.select(
                "How do you want to proceed?",
                choices=[
                    questionary.Choice("✅ Approve — run the plan", "approve"),
                    questionary.Choice("✏️  Edit & replan", "edit"),
                    questionary.Choice("❌ Reject — abort", "reject"),
                ],
            ).ask()
            return Decision(choice) if choice else Decision.REJECT

        return self._text_prompt()

    def prompt_confirm(self, message: str = "Confirm?") -> bool:
        if not self._stdin_is_tty():
            return bool(self.non_interactive_default and self.non_interactive_default.proceed)
        if _HAS_QUESTIONARY:
            return bool(questionary.confirm(message, default=False).ask())
        return input(f"{message} [y/N] ").strip().lower() in {"y", "yes"}

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _stdin_is_tty() -> bool:
        import sys

        try:
            return sys.stdin.isatty()
        except (AttributeError, ValueError):
            return False

    def _text_prompt(self) -> Decision:
        mapping = {
            "a": Decision.APPROVE,
            "approve": Decision.APPROVE,
            "e": Decision.EDIT,
            "edit": Decision.EDIT,
            "r": Decision.REJECT,
            "reject": Decision.REJECT,
            "": Decision.REJECT,
        }
        while True:
            raw = input("[a]pprove / [e]dit / [r]eject (default reject): ").strip().lower()
            if raw in mapping:
                return mapping[raw]
            print("Please enter a, e, or r.")
