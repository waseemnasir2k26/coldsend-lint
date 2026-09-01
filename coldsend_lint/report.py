"""Renderers: terminal report, JSON, SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Iterable

from .findings import Finding, exit_code

DISCLAIMER = (
    "NOT LEGAL ADVICE. coldsend-lint is an automated checklist built from public "
    "summaries of the named statutes. It cannot read your contracts, your consent "
    "records or your recipient list, the law changes, and enforcement practice "
    "varies by regulator. A clean run is not a defence. Have a qualified lawyer "
    "in the relevant jurisdiction review your outbound programme."
)

_MARK = {"error": "ERROR", "warn": " WARN", "info": " INFO"}
_ORDER = {"error": 0, "warn": 1, "info": 2}
_RULE = "-" * 78


def _wrap(text: str, width: int = 74, indent: str = "        ") -> list[str]:
    words = " ".join(text.split()).split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(indent + current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(indent + current)
    return lines


def render_terminal(
    findings: list[Finding],
    *,
    target: str,
    jurisdictions: list[str],
    regime_notes: list[str],
    show_info: bool = True,
) -> str:
    out: list[str] = []
    out.append("")
    out.append(f"coldsend-lint  {target}")
    if jurisdictions:
        out.append(f"jurisdictions: {', '.join(j.upper() for j in jurisdictions)}")
    out.append(_RULE)

    if regime_notes:
        out.append("")
        out.append("JURISDICTION ROUTING")
        for note in regime_notes:
            for line in _wrap(note, indent="  "):
                out.append(line)

    shown = [f for f in findings if show_info or f.severity != "info"]
    for category, heading in (
        ("deliverability", "DELIVERABILITY"),
        ("legal", "LEGAL / COPY COMPLIANCE"),
    ):
        block = [f for f in shown if f.category == category]
        if not block:
            continue
        block.sort(key=lambda f: (_ORDER[f.severity], f.id))
        out.append("")
        out.append(heading)
        for f in block:
            jur = f"[{f.jurisdiction}] " if f.jurisdiction not in ("-", "") else ""
            out.append(f"  {_MARK[f.severity]}  {f.id}  {jur}{f.title}")
            out.extend(_wrap(f.detail))
            for ev in f.evidence[:6]:
                out.append(f"        > {ev}")
            out.extend(_wrap(f"fix: {f.fix}"))
            out.append(f"        cite: {f.citation}")
            out.append("")

    errors = sum(1 for f in findings if f.severity == "error")
    warns = sum(1 for f in findings if f.severity == "warn")
    infos = sum(1 for f in findings if f.severity == "info")
    out.append(_RULE)
    out.append(f"{errors} error(s)  {warns} warning(s)  {infos} info")
    out.append(f"exit code: {exit_code(findings)}")
    out.append("")
    out.extend(_wrap(DISCLAIMER, indent="  "))
    out.append("")
    return "\n".join(out)


def render_json(
    findings: list[Finding],
    *,
    target: str,
    jurisdictions: list[str],
    regime_notes: list[str],
) -> str:
    payload = {
        "tool": "coldsend-lint",
        "target": target,
        "jurisdictions": jurisdictions,
        "regime_notes": regime_notes,
        "disclaimer": DISCLAIMER,
        "summary": {
            "error": sum(1 for f in findings if f.severity == "error"),
            "warn": sum(1 for f in findings if f.severity == "warn"),
            "info": sum(1 for f in findings if f.severity == "info"),
            "exit_code": exit_code(findings),
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


_SARIF_LEVEL = {"error": "error", "warn": "warning", "info": "note"}


def render_sarif(findings: list[Finding], *, target: str) -> str:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.id, f)
    rules = [
        {
            "id": f.id,
            "name": f.id.replace("-", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": " ".join(f.detail.split())},
            "help": {"text": f"{' '.join(f.fix.split())}\n\nCitation: {f.citation}"},
            "properties": {"category": f.category, "jurisdiction": f.jurisdiction},
        }
        for f in seen.values()
    ]
    results = [
        {
            "ruleId": f.id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {
                "text": " ".join(f"{f.title}. {f.detail}".split())
                + (f" Evidence: {'; '.join(f.evidence)}" if f.evidence else "")
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": target},
                        "region": {"startLine": 1},
                    }
                }
            ],
        }
        for f in findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "coldsend-lint",
                        "informationUri": "https://github.com/skynetlabs/coldsend-lint",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {"error": 0, "warn": 0, "info": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts
