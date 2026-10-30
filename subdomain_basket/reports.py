from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_reports(results: dict[str, Any], output_dir: Path) -> tuple[Path, Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fields = (
        "host",
        "discovery_source",
        "discovery_error",
        "discovery_statuses",
        "host_discovery_sources",
        "activity",
        "dns_addresses",
        "dns_error",
        "http_status",
        "http_title",
        "http_error",
        "https_status",
        "https_title",
        "https_error",
        "tls_subject",
        "tls_issuer",
        "tls_not_before",
        "tls_not_after",
        "tls_subject_alt_names",
    )

    for suffix in range(10_000):
        stem = f"{results['domain']}_{timestamp}"
        if suffix:
            stem += f"_{suffix}"
        json_path = output_dir / f"{stem}.json"
        csv_path = output_dir / f"{stem}.csv"
        subdomains_path = output_dir / ("subdomains.txt" if suffix == 0 else f"subdomains_{suffix}.txt")
        json_created = False
        try:
            json_file = json_path.open("x", encoding="utf-8")
            json_created = True
            with json_file:
                json.dump(results, json_file, indent=2, ensure_ascii=False)
                json_file.write("\n")
        except FileExistsError:
            continue
        except OSError:
            if json_created:
                json_path.unlink(missing_ok=True)
            raise
        csv_created = False
        try:
            csv_file = csv_path.open("x", newline="", encoding="utf-8")
            csv_created = True
            with csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fields)
                writer.writeheader()
                hosts = results["hosts"] or [{}]
                for host in hosts:
                    certificate = (host.get("https", {}).get("tls_certificate") or {})
                    writer.writerow(
                        {
                            "host": host.get("host", ""),
                            "discovery_source": results["discovery_source"],
                            "discovery_error": results["discovery_error"] or "",
                            "discovery_statuses": json.dumps(results.get("discovery_sources", [])),
                            "host_discovery_sources": ";".join(host.get("discovery_sources", [])),
                            "activity": (
                                f"DNS={'resolved' if host.get('dns_addresses') else 'unresolved'};"
                                f"HTTP={host.get('http', {}).get('status') or 'unreachable'};"
                                f"HTTPS={host.get('https', {}).get('status') or 'unreachable'}"
                            ),
                            "dns_addresses": ";".join(host.get("dns_addresses", [])),
                            "dns_error": host.get("dns_error") or "",
                            "http_status": host.get("http", {}).get("status") or "",
                            "http_title": host.get("http", {}).get("title", ""),
                            "http_error": host.get("http", {}).get("error") or "",
                            "https_status": host.get("https", {}).get("status") or "",
                            "https_title": host.get("https", {}).get("title", ""),
                            "https_error": host.get("https", {}).get("error") or "",
                            "tls_subject": certificate.get("subject", ""),
                            "tls_issuer": certificate.get("issuer", ""),
                            "tls_not_before": certificate.get("not_before", ""),
                            "tls_not_after": certificate.get("not_after", ""),
                            "tls_subject_alt_names": ";".join(
                                certificate.get("subject_alt_names", [])
                            ),
                        }
                    )
        except FileExistsError:
            json_path.unlink(missing_ok=True)
            continue
        except OSError:
            json_path.unlink(missing_ok=True)
            if csv_created:
                csv_path.unlink(missing_ok=True)
            raise

        subdomains = sorted(
            {
                host["host"]
                for host in results["hosts"]
                if host.get("host") != results["domain"]
            }
        )
        subdomains_created = False
        try:
            subdomains_file = subdomains_path.open("x", encoding="utf-8", newline="\n")
            subdomains_created = True
            with subdomains_file:
                for host in subdomains:
                    subdomains_file.write(f"{host}\n")
        except FileExistsError:
            json_path.unlink(missing_ok=True)
            csv_path.unlink(missing_ok=True)
            continue
        except OSError:
            json_path.unlink(missing_ok=True)
            csv_path.unlink(missing_ok=True)
            if subdomains_created:
                subdomains_path.unlink(missing_ok=True)
            raise
        return json_path, csv_path, subdomains_path
    raise FileExistsError("Unable to find an unused timestamped report filename.")
