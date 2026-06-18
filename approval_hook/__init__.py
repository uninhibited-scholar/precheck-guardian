"""PreCheck Guardian — a pre-execution approval gate for AI agents.

Quick start::

    from approval_hook import ApprovalGuard

    guard = ApprovalGuard()
    if guard.is_approved(agent_plan_text):
        run(agent_plan_text)
"""

from .config import ApprovalConfig
from .core.plan_parser import PlanParser
from .core.risk_annotator import RiskAnnotator, RiskRule
from .diff.diff_engine import DiffEngine
from .guard import ApprovalGuard
from .integrations import PlanRejected, gate_plan, guard_callable, review_result
from .models.approval_record import ApprovalRecord, Decision
from .models.plan import ActionStep, ExecutionPlan, RiskLevel

__version__ = "0.1.1"

__all__ = [
    "ApprovalGuard",
    "ApprovalConfig",
    "PlanParser",
    "RiskAnnotator",
    "RiskRule",
    "DiffEngine",
    "ActionStep",
    "ExecutionPlan",
    "RiskLevel",
    "Decision",
    "ApprovalRecord",
    # integrations
    "gate_plan",
    "review_result",
    "guard_callable",
    "PlanRejected",
    "__version__",
]
