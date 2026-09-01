"""Finding model shared by the deliverability and copy linters."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Iterable

SEVERITIES = ("error", "warn", "info")
_SEV_RANK = {"error": 2, "warn": 1, "info": 0}


@dataclass(frozen=True)
class Finding:
    """One problem (or one passing observation) produced by a check.

    ``category`` is either ``"deliverability"`` or ``"legal"``. Spam-trigger
    and link/image checks live in ``deliverability`` on purpose: they are not
    legal requirements anywhere.
    """

    id: str
    severity: str
    category: str
    jurisdiction: str
    title: str
    detail: str
    fix: str
    citation: str
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r} on {self.id}")
        if self.category not in ("deliverability", "legal"):
            raise ValueError(f"bad category {self.category!r} on {self.id}")

    @property
    def rank(self) -> int:
        return _SEV_RANK[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def exit_code(findings: Iterable[Finding]) -> int:
    """0 = clean, 1 = warnings only, 2 = at least one error."""
    worst = 0
    for f in findings:
        if f.severity == "error":
            return 2
        if f.severity == "warn":
            worst = 1
    return worst
