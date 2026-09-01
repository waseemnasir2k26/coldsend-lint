"""coldsend-lint command line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Sequence

from .copy_checks import run_copy_checks
from .dns_checks import DEFAULT_DKIM_SELECTORS, DEFAULT_DNSBL_ZONES, run_dns_checks
from .findings import Finding, exit_code
from .message import load_message
from .report import DISCLAIMER, render_json, render_sarif, render_terminal
from .resolver import Resolver
from .rules import Ruleset, load_rulesets, select, selectable

ResolverFactory = Callable[[argparse.Namespace], Resolver]

EPILOG = (
    "EXIT CODES\n"
    "  0  clean\n"
    "  1  warnings only\n"
    "  2  at least one error\n"
    "\n"
    "NOT LEGAL ADVICE\n  " + DISCLAIMER + "\n"
)


def _default_resolver_factory(args: argparse.Namespace) -> Resolver:
    from .resolver import DnsPythonResolver

    return DnsPythonResolver(
        timeout=getattr(args, "timeout", 5.0),
        nameservers=getattr(args, "nameserver", None) or None,
    )


def build_parser(available: Sequence[str]) -> argparse.ArgumentParser:
    juris_help = (
        "comma-separated recipient jurisdictions to lint against "
        f"({', '.join(available)}, or 'all'). Default: us"
    )
    parser = argparse.ArgumentParser(
        prog="coldsend-lint",
        description=(
            "Lint a cold-email campaign on both axes before you send: sending-domain "
            "deliverability (SPF, DKIM, DMARC, MX, PTR, blacklists) and legal/copy "
            "compliance (CAN-SPAM, GDPR/ePrivacy, PECR, LSSI-CE, CASL)."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="coldsend-lint 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_output_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", action="store_true", help="emit JSON instead of text")
        p.add_argument("--sarif", action="store_true", help="emit SARIF 2.1.0")
        p.add_argument(
            "--quiet", action="store_true", help="hide info findings in the text report"
        )

    def add_dns_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--ip", help="public IPv4 you send from (enables PTR + DNSBL)")
        p.add_argument(
            "--dkim-selector",
            action="append",
            default=[],
            metavar="NAME",
            help="extra DKIM selector to probe (repeatable)",
        )
        p.add_argument(
            "--no-dnsbl", action="store_true", help="skip DNS blacklist lookups"
        )
        p.add_argument(
            "--nameserver",
            action="append",
            default=[],
            metavar="IP",
            help="resolver to query (repeatable)",
        )
        p.add_argument("--timeout", type=float, default=5.0, help="DNS timeout seconds")

    def add_copy_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--jurisdiction", "-j", default="us", metavar="LIST", help=juris_help
        )
        p.add_argument(
            "--rules-dir", metavar="DIR", help="load YAML rulesets from this directory"
        )

    p_dns = sub.add_parser("dns", help="check a sending domain's DNS posture")
    p_dns.add_argument("domain")
    add_dns_flags(p_dns)
    add_output_flags(p_dns)

    p_copy = sub.add_parser("copy", help="lint a message body for legal compliance")
    p_copy.add_argument("message", help="path to the message file (.txt / .eml / .html)")
    add_copy_flags(p_copy)
    add_output_flags(p_copy)

    p_all = sub.add_parser("all", help="run both checks")
    p_all.add_argument("domain")
    p_all.add_argument("message")
    add_dns_flags(p_all)
    add_copy_flags(p_all)
    add_output_flags(p_all)

    return parser


def regime_notes(chosen: list[Ruleset]) -> list[str]:
    """Explain which regime applies to which recipient country, loudly."""
    notes: list[str] = []
    real = [rs for rs in chosen if not rs.always]
    for rs in sorted(real, key=lambda r: r.jurisdiction):
        countries = ", ".join(rs.applies_to[:8]) or "n/a"
        more = "" if len(rs.applies_to) <= 8 else f" (+{len(rs.applies_to) - 8} more)"
        notes.append(
            f"{rs.jurisdiction.upper()}: {rs.name} - regime: {rs.regime} - "
            f"recipients in: {countries}{more}"
        )
    consent = sorted(
        (rs for rs in real if rs.regime in ("consent", "soft opt-in")),
        key=lambda r: r.jurisdiction,
    )
    if consent:
        codes = ", ".join(rs.jurisdiction.upper() for rs in consent)
        notes.append(
            f"WARNING: {codes} are consent-based regimes. CAN-SPAM's opt-out model is "
            "NOT sufficient for those recipients: under GDPR/ePrivacy, PECR, LSSI-CE "
            "and CASL you generally need a lawful basis or consent BEFORE you send, "
            "and the burden of proving it is on you. A message that passes the US "
            "rules can still be unlawful in the EU, the UK, Spain or Canada."
        )
    if not consent and real:
        notes.append(
            "Only opt-out jurisdictions selected. If any recipient sits in the EEA, "
            "the UK, Spain or Canada, re-run with those jurisdictions: their rules "
            "are stricter and CAN-SPAM compliance does not carry over."
        )
    return notes


def _emit(
    findings: list[Finding],
    args: argparse.Namespace,
    target: str,
    jurisdictions: list[str],
    notes: list[str],
    stream,
) -> int:
    if getattr(args, "sarif", False):
        print(render_sarif(findings, target=target), file=stream)
    elif getattr(args, "json", False):
        print(
            render_json(
                findings, target=target, jurisdictions=jurisdictions, regime_notes=notes
            ),
            file=stream,
        )
    else:
        print(
            render_terminal(
                findings,
                target=target,
                jurisdictions=jurisdictions,
                regime_notes=notes,
                show_info=not getattr(args, "quiet", False),
            ),
            file=stream,
        )
    return exit_code(findings)


def run(
    argv: Sequence[str] | None = None,
    *,
    resolver_factory: ResolverFactory | None = None,
    stream=None,
) -> int:
    stream = stream or sys.stdout
    try:
        available = selectable(load_rulesets())
    except Exception:  # pragma: no cover - only if the package install is broken
        available = ["us", "eu", "uk", "es", "ca"]
    parser = build_parser(available)
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    jurisdictions: list[str] = []
    notes: list[str] = []
    targets: list[str] = []

    if args.command in ("dns", "all"):
        factory = resolver_factory or _default_resolver_factory
        try:
            resolver = factory(args)
        except ImportError:
            print(
                "dnspython is required for live DNS checks: pip install dnspython",
                file=sys.stderr,
            )
            return 2
        selectors = tuple(args.dkim_selector) + DEFAULT_DKIM_SELECTORS
        findings += run_dns_checks(
            resolver,
            args.domain,
            ip=args.ip,
            dkim_selectors=selectors,
            dnsbl_zones=DEFAULT_DNSBL_ZONES,
            skip_dnsbl=args.no_dnsbl,
        )
        targets.append(args.domain)

    if args.command in ("copy", "all"):
        path = Path(args.message)
        if not path.is_file():
            print(f"message file not found: {path}", file=sys.stderr)
            return 2
        rulesets = load_rulesets(args.rules_dir)
        requested = [c for c in args.jurisdiction.split(",") if c.strip()]
        chosen, unknown = select(rulesets, requested)
        if unknown:
            print(
                f"unknown jurisdiction(s): {', '.join(unknown)}. "
                f"Available: {', '.join(selectable(rulesets))}, all",
                file=sys.stderr,
            )
            return 2
        jurisdictions = [rs.jurisdiction for rs in chosen if not rs.always]
        notes = regime_notes(chosen)
        findings += run_copy_checks(load_message(path), chosen)
        targets.append(str(path))

    return _emit(findings, args, " + ".join(targets), jurisdictions, notes, stream)


def main() -> None:  # console-script entry point
    sys.exit(run())


if __name__ == "__main__":  # pragma: no cover
    main()
