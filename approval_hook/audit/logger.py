"""Append-only JSON-Lines audit log of approval decisions."""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterator, List

from ..models.approval_record import ApprovalRecord


def summarize_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate audit records into headline stats for reporting.

    Returns counts by decision and by max-risk level, plus the number of
    blocked (rejected) plans and the approval rate.
    """
    total = len(records)
    by_decision = Counter(r.get("decision", "unknown") for r in records)
    by_risk = Counter(r.get("max_risk", "unknown") for r in records)
    approved = by_decision.get("approve", 0)
    return {
        "total": total,
        "by_decision": dict(by_decision),
        "by_risk": dict(by_risk),
        "blocked": by_decision.get("reject", 0),
        "approval_rate": (approved / total) if total else 0.0,
    }


class AuditLogger:
    """Persist :class:`ApprovalRecord` objects as JSON Lines.

    Each decision is one line, so the log is append-only, tail-able and
    trivially parseable for compliance review.
    """

    def __init__(self, path: str | os.PathLike[str] = "approval_audit.jsonl") -> None:
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, record: ApprovalRecord) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")

    def read_all(self) -> List[dict]:
        return list(self.iter_records())

    def iter_records(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
