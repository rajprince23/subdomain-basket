import csv
import json
import tempfile
import unittest
from pathlib import Path

from subdomain_basket.reports import write_reports


class ReportTests(unittest.TestCase):
    def test_writes_timestamped_json_and_csv(self) -> None:
        results = {
            "domain": "example.com",
            "discovery_source": "crt.sh Certificate Transparency logs",
            "discovery_error": None,
            "hosts": [
                {
                    "host": "www.example.com",
                    "dns_addresses": ["192.0.2.10"],
                    "dns_error": None,
                    "http": {
                        "status": 200,
                        "title": "Example",
                        "tls_certificate": None,
                        "error": None,
                    },
                    "https": {
                        "status": 200,
                        "title": "Example",
                        "tls_certificate": {"subject": "CN=www.example.com"},
                        "error": None,
                    },
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            json_path, csv_path, subdomains_path = write_reports(
                results, Path(temporary_directory)
            )
            self.assertRegex(json_path.name, r"^example\.com_\d{8}T\d{6}Z\.json$")
            self.assertRegex(csv_path.name, r"^example\.com_\d{8}T\d{6}Z\.csv$")
            self.assertEqual(subdomains_path.name, "subdomains.txt")
            self.assertEqual(subdomains_path.read_text(encoding="utf-8"), "www.example.com\n")
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), results)
            with csv_path.open(newline="", encoding="utf-8") as csv_file:
                row = next(csv.DictReader(csv_file))
            self.assertEqual(row["host"], "www.example.com")
            self.assertEqual(row["https_status"], "200")
            self.assertEqual(row["host_discovery_sources"], "")
            self.assertEqual(row["activity"], "DNS=resolved;HTTP=200;HTTPS=200")
            self.assertEqual(row["tls_subject"], "CN=www.example.com")
            second_json_path, second_csv_path, second_subdomains_path = write_reports(
                results, Path(temporary_directory)
            )
            self.assertNotEqual(json_path, second_json_path)
            self.assertNotEqual(csv_path, second_csv_path)
            self.assertEqual(second_subdomains_path.name, "subdomains_1.txt")

    def test_csv_retains_discovery_error_without_hosts(self) -> None:
        results = {
            "domain": "example.com",
            "discovery_source": "crt.sh Certificate Transparency logs",
            "discovery_error": "lookup unavailable",
            "hosts": [],
        }
        with tempfile.TemporaryDirectory() as temporary_directory:
            _, csv_path, subdomains_path = write_reports(
                results, Path(temporary_directory)
            )
            with csv_path.open(newline="", encoding="utf-8") as csv_file:
                row = next(csv.DictReader(csv_file))
            self.assertEqual(row["host"], "")
            self.assertEqual(row["discovery_error"], "lookup unavailable")
            self.assertEqual(subdomains_path.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
