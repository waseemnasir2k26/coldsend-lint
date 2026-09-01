"""Load the YAML rulesets in ``rules/`` and route them by jurisdiction."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_PKG = Path(__file__).resolve().parent


def default_rules_dir() -> Path:
    """Where the shipped rulesets live.

    Order: ``COLDSEND_LINT_RULES`` env var, then the repo-root ``rules/`` used
    when running from a checkout, then the copy bundled inside the wheel
    at ``coldsend_lint/_rules`` (underscored so it cannot shadow this module).
    """
    env = os.environ.get("COLDSEND_LINT_RULES")
    if env:
        return Path(env)
    checkout = _PKG.parent / "rules"
    if checkout.is_dir():
        return checkout
    return _PKG / "_rules"


DEFAULT_RULES_DIR = default_rules_dir()

VALID_SEVERITIES = ("error", "warn", "info")
VALID_CATEGORIES = ("legal", "deliverability")


class RulesetError(ValueError):
    """A YAML ruleset is malformed."""


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    what: str
    fix: str
    citation: str
    check: dict[str, Any]
    category: str = "legal"


@dataclass(frozen=True)
class Ruleset:
    jurisdiction: str  # "us", "eu", "uk", "es", "ca", or "global"
    name: str
    regime: str  # "opt-out", "consent", "soft opt-in", "n/a"
    applies_to: tuple[str, ...]  # ISO-3166 alpha-2 recipient countries
    summary: str
    rules: tuple[Rule, ...]
    always: bool = False  # loaded regardless of --jurisdiction
    source: str = ""


def _require(data: dict[str, Any], key: str, where: str) -> Any:
    if key not in data:
        raise RulesetError(f"{where}: missing required key {key!r}")
    return data[key]


def parse_ruleset(data: dict[str, Any], source: str = "") -> Ruleset:
    where = source or "<ruleset>"
    rules: list[Rule] = []
    for raw in _require(data, "rules", where):
        rid = _require(raw, "id", where)
        severity = _require(raw, "severity", where)
        if severity not in VALID_SEVERITIES:
            raise RulesetError(f"{where}: rule {rid} has bad severity {severity!r}")
        category = raw.get("category", "legal")
        if category not in VALID_CATEGORIES:
            raise RulesetError(f"{where}: rule {rid} has bad category {category!r}")
        check = _require(raw, "check", where)
        if "type" not in check:
            raise RulesetError(f"{where}: rule {rid} check has no type")
        rules.append(
            Rule(
                id=rid,
                severity=severity,
                title=_require(raw, "title", where),
                what=_require(raw, "what", where),
                fix=_require(raw, "fix", where),
                citation=_require(raw, "citation", where),
                check=check,
                category=category,
            )
        )
    return Ruleset(
        jurisdiction=_require(data, "jurisdiction", where),
        name=_require(data, "name", where),
        regime=data.get("regime", "n/a"),
        applies_to=tuple(data.get("applies_to", ())),
        summary=data.get("summary", ""),
        rules=tuple(rules),
        always=bool(data.get("always", False)),
        source=source,
    )


def load_rulesets(rules_dir: str | Path | None = None) -> dict[str, Ruleset]:
    directory = Path(rules_dir) if rules_dir else default_rules_dir()
    if not directory.is_dir():
        raise RulesetError(f"rules directory not found: {directory}")
    out: dict[str, Ruleset] = {}
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise RulesetError(f"{path}: top level must be a mapping")
        ruleset = parse_ruleset(data, source=str(path))
        if ruleset.jurisdiction in out:
            raise RulesetError(f"duplicate jurisdiction {ruleset.jurisdiction!r}")
        out[ruleset.jurisdiction] = ruleset
    if not out:
        raise RulesetError(f"no *.yaml rulesets in {directory}")
    return out


def selectable(rulesets: dict[str, Ruleset]) -> list[str]:
    """Jurisdiction codes a user may pass to --jurisdiction."""
    return sorted(k for k, rs in rulesets.items() if not rs.always)


def select(
    rulesets: dict[str, Ruleset], requested: list[str]
) -> tuple[list[Ruleset], list[str]]:
    """Return (selected rulesets, unknown codes). ``all`` selects everything."""
    codes = [c.strip().lower() for c in requested if c.strip()]
    available = selectable(rulesets)
    if "all" in codes:
        codes = available
    unknown = [c for c in codes if c not in rulesets or rulesets[c].always]
    chosen = [rulesets[c] for c in codes if c in rulesets and not rulesets[c].always]
    chosen += [rs for rs in rulesets.values() if rs.always]
    return chosen, unknown


def country_matrix(rulesets: dict[str, Ruleset]) -> dict[str, list[str]]:
    """Recipient country -> the ruleset codes that claim it."""
    matrix: dict[str, list[str]] = {}
    for code, rs in rulesets.items():
        for country in rs.applies_to:
            matrix.setdefault(country.upper(), []).append(code)
    for v in matrix.values():
        v.sort()
    return matrix


def consent_jurisdictions(chosen: list[Ruleset]) -> list[Ruleset]:
    """Selected rulesets whose regime needs consent rather than opt-out."""
    return [rs for rs in chosen if rs.regime in ("consent", "soft opt-in")]
