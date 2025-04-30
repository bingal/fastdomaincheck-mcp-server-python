# tests/test_checker.py
import unittest
from unittest.mock import patch, MagicMock
import sys
import os
import logging # Import logging
import socket # Import socket for simulating errors

# Add project root's src directory to sys.path to import the package
# project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# sys.path.insert(0, project_root) # No longer needed with src layout if installed correctly

# Import from the package structure
from fastdomaincheck_mcp_server import checker
from fastdomaincheck_mcp_server.checker import check_domain_availability, check_domains_availability, logger # Import logger

# Need to patch functions within the *package* context now
WHOIS_PATCH_TARGET = 'fastdomaincheck_mcp_server.checker.whois.whois'
SOCKET_PATCH_TARGET = 'fastdomaincheck_mcp_server.checker.socket.getaddrinfo'
SINGLE_CHECK_PATCH_TARGET = 'fastdomaincheck_mcp_server.checker.check_domain_availability'
WHOIS_PARSER_PATCH_TARGET = 'fastdomaincheck_mcp_server.checker.whois.parser.PywhoisError'


# Disable checker module's logging output to keep test output clean
logger.setLevel(logging.CRITICAL) # Use logging.CRITICAL

class MockWhoisInfo:
    """Simulates a valid object returned by whois.whois"""
    def __init__(self, domain_name="registered.com", status=None):
        # Check if domain_name is an empty string, as some libraries might return this
        self.domain_name = domain_name if domain_name else None
        self.status = status # Allow setting status for testing specific WHOIS responses
        # Can add other simulated attributes like expiration_date

class TestDomainChecker(unittest.TestCase):

    # --- WHOIS Only Scenarios --- 

    @patch(SOCKET_PATCH_TARGET) # Mock DNS to avoid it running
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_registered_by_whois_only(self, mock_whois, mock_dns):
        """Test domain confirmed registered by WHOIS (DNS mocked)."""
        mock_whois.return_value = MockWhoisInfo(domain_name="registered.com")
        mock_dns.return_value = [('some_ip_info')] # Simulate successful DNS lookup
        result = check_domain_availability("registered.com")
        self.assertEqual(result, "registered")
        mock_whois.assert_called_once_with("registered.com")
        mock_dns.assert_called_once_with("registered.com", None)

    @patch(SOCKET_PATCH_TARGET) # Mock DNS
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_available_by_whois_no_match_string(self, mock_whois, mock_dns):
        """Test domain available via WHOIS 'no match' status string."""
        mock_whois.return_value = MockWhoisInfo(domain_name=None, status="No match for domain.")
        result = check_domain_availability("available-no-match.com")
        self.assertEqual(result, "available")
        mock_whois.assert_called_once_with("available-no-match.com")
        mock_dns.assert_not_called() # Should return early based on WHOIS status

    # --- DNS Only Scenarios (WHOIS fails or is ambiguous) --- 

    @patch(SOCKET_PATCH_TARGET)
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_registered_by_dns_whois_none(self, mock_whois, mock_dns):
        """Test domain registered by DNS when WHOIS returns None."""
        mock_whois.return_value = None
        mock_dns.return_value = [('some_ip_info')] # Simulate successful DNS
        result = check_domain_availability("registered-by-dns.com")
        self.assertEqual(result, "registered")
        mock_whois.assert_called_once_with("registered-by-dns.com")
        mock_dns.assert_called_once_with("registered-by-dns.com", None)

    @patch(SOCKET_PATCH_TARGET)
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_available_by_dns_whois_none(self, mock_whois, mock_dns):
        """Test domain available by DNS (EAI_NONAME) when WHOIS returns None."""
        mock_whois.return_value = None
        mock_dns.side_effect = socket.gaierror(socket.EAI_NONAME, "DNS Not Found")
        result = check_domain_availability("available-by-dns.com")
        self.assertEqual(result, "available")
        mock_whois.assert_called_once_with("available-by-dns.com")
        mock_dns.assert_called_once_with("available-by-dns.com", None)

    @patch(SOCKET_PATCH_TARGET)
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_available_by_dns_whois_error(self, mock_whois, mock_dns):
        """Test domain available by DNS (EAI_NONAME) when WHOIS fails."""
        mock_whois.side_effect = Exception("WHOIS server down")
        mock_dns.side_effect = socket.gaierror(socket.EAI_NONAME, "DNS Not Found")
        result = check_domain_availability("available-whois-fails.com")
        self.assertEqual(result, "available")
        mock_whois.assert_called_once_with("available-whois-fails.com")
        mock_dns.assert_called_once_with("available-whois-fails.com", None)

    # --- Conflicting Scenarios --- 

    @patch(SOCKET_PATCH_TARGET)
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_registered_conflict_whois_reg_dns_fail(self, mock_whois, mock_dns):
        """Test registered status when WHOIS says registered but DNS fails (EAI_NONAME)."""
        mock_whois.return_value = MockWhoisInfo(domain_name="conflict-reg-dns-fail.com")
        mock_dns.side_effect = socket.gaierror(socket.EAI_NONAME, "DNS Not Found")
        result = check_domain_availability("conflict-reg-dns-fail.com")
        self.assertEqual(result, "registered")
        mock_whois.assert_called_once_with("conflict-reg-dns-fail.com")
        mock_dns.assert_called_once_with("conflict-reg-dns-fail.com", None)

    # --- Error Scenarios --- 

    @patch(SOCKET_PATCH_TARGET)
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_error_both_fail(self, mock_whois, mock_dns):
        """Test error status when both WHOIS and DNS queries fail."""
        mock_whois.side_effect = Exception("WHOIS server down")
        mock_dns.side_effect = socket.gaierror(-2, "Temporary failure in name resolution") # Example other GAI error
        result = check_domain_availability("error-both-fail.com")
        self.assertTrue(result.startswith("error:"))
        self.assertIn("Both WHOIS and DNS lookups failed", result)
        mock_whois.assert_called_once_with("error-both-fail.com")
        mock_dns.assert_called_once_with("error-both-fail.com", None)

    @patch(SOCKET_PATCH_TARGET)
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_error_dns_timeout(self, mock_whois, mock_dns):
        """Test error status when DNS query times out (WHOIS ambiguous)."""
        mock_whois.return_value = MockWhoisInfo(domain_name=None) # Ambiguous WHOIS
        mock_dns.side_effect = socket.timeout("DNS timeout")
        result = check_domain_availability("error-dns-timeout.com")
        self.assertTrue(result.startswith("error:"))
        self.assertIn("DNS lookup timed out", result)
        mock_whois.assert_called_once_with("error-dns-timeout.com")
        mock_dns.assert_called_once_with("error-dns-timeout.com", None)
        
    @patch(SOCKET_PATCH_TARGET)
    @patch(WHOIS_PATCH_TARGET)
    def test_domain_registered_dns_timeout_whois_reg(self, mock_whois, mock_dns):
        """Test registered status when DNS times out but WHOIS indicated registered."""
        mock_whois.return_value = MockWhoisInfo(domain_name="reg-dns-timeout.com") # WHOIS says registered
        mock_dns.side_effect = socket.timeout("DNS timeout")
        result = check_domain_availability("reg-dns-timeout.com")
        self.assertEqual(result, "registered") # Prioritize WHOIS registered status
        mock_whois.assert_called_once_with("reg-dns-timeout.com")
        mock_dns.assert_called_once_with("reg-dns-timeout.com", None)

    # --- Batch Check Test (remains largely the same) ---

    @patch(SINGLE_CHECK_PATCH_TARGET)
    def test_check_multiple_domains(self, mock_check_single):
        """Test batch checking multiple domains."""
        # Let single check return predefined values
        def side_effect(domain):
            if domain == "available.com":
                return "available"
            elif domain == "registered.com":
                return "registered"
            elif domain == "error.com":
                return "error: some issue"
            return "unknown" # Fallback

        mock_check_single.side_effect = side_effect

        domains_to_check = ["available.com", "registered.com", "error.com"]
        expected_results = {
            "available.com": "available",
            "registered.com": "registered",
            "error.com": "error: some issue"
        }
        results = check_domains_availability(domains_to_check)
        self.assertEqual(results, expected_results)
        # Verify check_domain_availability was called three times
        self.assertEqual(mock_check_single.call_count, len(domains_to_check))
        mock_check_single.assert_any_call("available.com")
        mock_check_single.assert_any_call("registered.com")
        mock_check_single.assert_any_call("error.com")


if __name__ == '__main__':
    # Run tests when script is executed
    unittest.main() 