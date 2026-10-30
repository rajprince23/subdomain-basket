import unittest
from unittest.mock import Mock, patch

from subdomain_basket.recon import (
    ReconError,
    _certificate_details,
    _discovery_tool_commands,
    _hosts_from_output,
    is_in_scope,
    normalize_domain,
    run_discovery_tool,
)


class DomainValidationTests(unittest.TestCase):
    def test_normalizes_domain(self) -> None:
        self.assertEqual(normalize_domain("WWW.Example.COM."), "www.example.com")

    def test_rejects_url_and_ip_address(self) -> None:
        with self.assertRaises(ReconError):
            normalize_domain("https://example.com/path")
        with self.assertRaises(ReconError):
            normalize_domain("192.0.2.1")

    def test_scope_requires_domain_label_boundary(self) -> None:
        self.assertTrue(is_in_scope("example.com", "example.com"))
        self.assertTrue(is_in_scope("api.example.com", "example.com"))
        self.assertFalse(is_in_scope("example.com.attacker.test", "example.com"))
        self.assertFalse(is_in_scope("attackerexample.com", "example.com"))

    def test_certificate_names_are_limited_to_authorized_scope(self) -> None:
        connection = Mock()
        connection.sock.getpeercert.return_value = {
            "subject": ((("commonName", "www.example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "Jan 01 00:00:00 2026 GMT",
            "notAfter": "Jan 01 00:00:00 2027 GMT",
            "subjectAltName": (
                ("DNS", "www.example.com"),
                ("DNS", "*.example.com"),
                ("DNS", "other.test"),
            ),
        }
        details = _certificate_details(connection, "example.com")
        self.assertEqual(
            details["subject_alt_names"],
            ["www.example.com", "*.example.com"],
        )

    def test_external_output_is_normalized_and_scope_filtered(self) -> None:
        output = "\n".join(
            (
                "WWW.Example.com.",
                "*.api.example.com",
                "https://shop.example.com/products",
                "example.com.attacker.test",
                "not a hostname",
            )
        )
        self.assertEqual(
            _hosts_from_output(output, "example.com"),
            {"www.example.com", "api.example.com", "shop.example.com"},
        )

    def test_discovery_commands_use_only_approved_tools_and_safe_modes(self) -> None:
        commands = _discovery_tool_commands("example.com")
        self.assertEqual(
            [name for name, _ in commands],
            ["subfinder", "amass", "katana", "assetfinder", "sublist3r"],
        )
        command_text = " ".join(" ".join(command) for _, command in commands)
        self.assertIn("-passive", command_text)
        self.assertIn("--subs-only", command_text)
        self.assertNotIn("gobuster", command_text)
        self.assertNotIn("-b ", command_text)

    @patch("subdomain_basket.recon.subprocess.run")
    @patch("subdomain_basket.recon.shutil.which", return_value="C:\\tools\\subfinder.exe")
    def test_discovery_tool_parses_results_and_records_status(
        self, _which: Mock, run: Mock
    ) -> None:
        run.return_value = Mock(
            stdout="api.example.com\nother.test\n",
            stderr="",
            returncode=0,
        )
        hosts, status = run_discovery_tool(
            "subfinder", ["subfinder", "-d", "example.com"], "example.com"
        )
        self.assertEqual(hosts, {"api.example.com"})
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["hosts_found"], 1)

    @patch("subdomain_basket.recon.shutil.which", return_value=None)
    def test_missing_discovery_tool_is_reported_without_failure(self, _which: Mock) -> None:
        hosts, status = run_discovery_tool(
            "subfinder", ["subfinder", "-d", "example.com"], "example.com"
        )
        self.assertEqual(hosts, set())
        self.assertEqual(status["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
