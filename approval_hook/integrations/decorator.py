"""Drop-in decorators to gate any plan-producing or plan-executing function.

Two ergonomic ways to add an approval checkpoint without restructuring code:

``@gate_plan``
    Wrap a function that *executes* a plan. Its plan argument is reviewed first;
    if the operator rejects, the wrapped function is never called.

``@review_result``
    Wrap a function that *returns* a plan (e.g. an agent's ``.plan()``). The
    return value is reviewed; on rejection a :class:`PlanRejected` is raised.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional

from ..guard import ApprovalGuard
from ..models.approval_record import Decision


class PlanRejected(Exception):
    """Raised when an operator rejects (or declines to approve) a plan."""

    def __init__(self, decision: Decision, message: str = "") -> None:
        self.decision = decision
        super().__init__(message or f"plan not approved (decision={decision.value})")


def _resolve_guard(guard: Optional[ApprovalGuard]) -> ApprovalGuard:
    return guard if guard is not None else ApprovalGuard()


def gate_plan(
    plan_arg: str = "plan",
    *,
    guard: Optional[ApprovalGuard] = None,
    on_reject: Optional[Callable[[Decision], Any]] = None,
) -> Callable:
    """Gate a function whose *input* is a plan.

    The argument named ``plan_arg`` is reviewed before the function runs.
    On non-approval the function is skipped and ``on_reject(decision)`` is
    returned (default: ``None``).

    Example::

        @gate_plan("steps")
        def execute(steps): ...
    """

    def decorator(func: Callable) -> Callable:
        sig = inspect.signature(func)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            bound = sig.bind_partial(*args, **kwargs)
            if plan_arg not in bound.arguments:
                raise TypeError(f"{func.__name__}() missing plan argument {plan_arg!r}")
            decision = _resolve_guard(guard).review(bound.arguments[plan_arg])
            if not decision.proceed:
                return on_reject(decision) if on_reject else None
            return func(*args, **kwargs)

        return wrapper

    return decorator


def guard_callable(
    func: Callable,
    *,
    tool_name: Optional[str] = None,
    guard: Optional[ApprovalGuard] = None,
) -> Callable:
    """Wrap a single tool function so every invocation is reviewed first.

    Framework-agnostic: pass any plain callable (e.g. the ``func`` behind a
    LangChain ``Tool``). The call's name and arguments are shown for approval
    before the tool runs; on rejection :class:`PlanRejected` is raised.

    Example::

        safe_delete = guard_callable(delete_file, tool_name="delete_file")
    """
    name = tool_name or getattr(func, "__name__", "tool")

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        call = {
            "tool": name,
            "args": {**{f"arg{i}": a for i, a in enumerate(args)}, **kwargs},
            "description": f"call {name}",
        }
        decision = _resolve_guard(guard).review([call], title=f"Tool call: {name}")
        if not decision.proceed:
            raise PlanRejected(decision)
        return func(*args, **kwargs)

    return wrapper


def review_result(*, guard: Optional[ApprovalGuard] = None) -> Callable:
    """Gate a function whose *output* is a plan.

    Reviews the return value; raises :class:`PlanRejected` if not approved.

    Example::

        @review_result()
        def make_plan() -> str:
            return agent.plan(task)
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = func(*args, **kwargs)
            decision = _resolve_guard(guard).review(result)
            if not decision.proceed:
                raise PlanRejected(decision)
            return result

        return wrapper

    return decorator
