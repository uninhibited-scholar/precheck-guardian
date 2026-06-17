"""Framework integration helpers.

These are thin, dependency-free wrappers around :class:`ApprovalGuard` that let
you bolt an approval checkpoint onto existing code with a single decorator or
wrapper call. They work with any agent framework — LangChain, a custom ReAct
loop, or your own tool runner.
"""

from .decorator import (
    PlanRejected,
    gate_plan,
    guard_callable,
    review_result,
)

__all__ = [
    "gate_plan",
    "review_result",
    "guard_callable",
    "PlanRejected",
]
