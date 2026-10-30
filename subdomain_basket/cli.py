from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .recon import MAX_HOSTS, ReconError, inspect_domain, normalize_domain
from .reports import write_reports


def _print_table(hosts: list[dict[str, Any]]) -> None:
    headers = ("HOST", "SOURCES", "DNS", "HTTP", "HTTPS", "TITLE")
    rows = []
    for host in hosts:
        title = host["https"]["title"] or host["http"]["title"] or "-"
        rows.append(
            (
                host["host"],
                ", ".join(host["discovery_sources"]),
                ", ".join(host["dns_addresses"]) or "unresolved",
                str(host["http"]["status"] or "-"),
                str(host["https"]["status"] or "-"),
                title[:48],
            )
        )
    widths = [
        min(max([len(headers[index]), *(len(row[index]) for row in rows)]), 48)
        for index in range(len(headers))
    ]
    print("  ".join(headers[index].ljust(widths[index]) for index in range(len(headers))))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        cells = [value[:widths[index]].ljust(widths[index]) for index, value in enumerate(row)]
        print("  ".join(cells))
    for host in hosts:
        errors = [
            f"{label}: {error}"
            for label, error in (
                ("DNS", host["dns_error"]),
                ("HTTP", host["http"]["error"]),
                ("HTTPS", host["https"]["error"]),
            )
            if error
        ]
        if errors:
            print(f"  {host['host']}: " + " | ".join(errors))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subdomain-basket",
        description=(
            "Authorization-only domain inventory using passive discovery and a bounded "
            "in-scope web crawl (no brute force or port scans)."
        ),
    )
    parser.add_argument("--domain", help="authorized domain to inspect; prompted if omitted")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"), help="report directory (default: reports)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < (3, 11):
        print("Error: Subdomain Basket requires Python 3.11 or later.", file=sys.stderr)
        return 2
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        raw_domain = args.domain if args.domain is not None else input("Authorized domain: ")
    except EOFError:
        print("Error: an authorized domain is required.", file=sys.stderr)
        return 2
    try:
        domain = normalize_domain(raw_domain)
    except ReconError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        confirmation = input(
            f"Confirm you own {domain} or have explicit written authorization to assess it.\n"
            "Type I HAVE AUTHORIZATION to continue: "
        )
    except EOFError:
        print("Error: authorization confirmation is required.", file=sys.stderr)
        return 2
    if confirmation.strip() != "I HAVE AUTHORIZATION":
        print("Stopped: authorization was not confirmed; no requests were made.")
        return 1

    print(f"Starting authorized, in-scope inventory for {domain} (maximum {MAX_HOSTS} hosts).")
    results = inspect_domain(domain)
    print("Discovery tools:")
    for source in results["discovery_sources"]:
        summary = (
            f"  {source['name']}: {source['status']} "
            f"({source['hosts_found']} in-scope host(s))"
        )
        if source["error"]:
            summary += f" — {source['error']}"
        print(summary)
    print(results["activity_definition"])
    _print_table(results["hosts"])
    if results["discovery_error"]:
        print(f"Discovery warning: {results['discovery_error']}")
    dns_errors = sum(host["dns_error"] is not None for host in results["hosts"])
    endpoint_errors = sum(
        endpoint["error"] is not None
        for host in results["hosts"]
        for endpoint in (host["http"], host["https"])
    )
    print(f"Hosts: {len(results['hosts'])}; DNS errors: {dns_errors}; HTTP(S) errors: {endpoint_errors}")

    try:
        json_path, csv_path, subdomains_path = write_reports(results, args.output_dir)
    except OSError as exc:
        print(f"Error: unable to write reports to {args.output_dir}: {exc}", file=sys.stderr)
        return 1
    print(f"JSON report: {json_path}")
    print(f"CSV report:  {csv_path}")
    print(f"Subdomains:  {subdomains_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
