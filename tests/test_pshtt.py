"""Test the core functionality of the library."""

# Standard Python Libraries
import datetime
import ipaddress
import unittest
from unittest.mock import MagicMock, patch

# Third-Party Libraries
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sslyze import ScanCommandAttemptStatusEnum, ServerConnectivityStatusEnum
from unittest_parametrize import ParametrizedTestCase, param, parametrize

# cisagov Libraries
from pshtt.models import Domain, Endpoint
from pshtt.pshtt import (
    certificate_is_expired,
    certificate_matches_hostname,
    https_check,
    is_live,
    is_strictly_forces_https,
)


class TestLiveliness(unittest.TestCase):
    """Test the liveliness of a domain."""

    def setUp(self):
        """Perform initial setup."""
        base_domain = "example.com"
        self.domain = Domain(base_domain)

        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_none(self):
        """Test in an unchecked state."""
        self.assertFalse(is_live(self.domain))

    def test_http_only(self):
        """Test when only HTTP access is live on the base domain name."""
        self.domain.http.live = True

        self.assertTrue(is_live(self.domain))

    def test_https_only(self):
        """Test when only HTTPS access is live on the base domain name."""
        self.domain.https.live = True

        self.assertTrue(is_live(self.domain))

    def test_httpwww_only(self):
        """Test when only HTTP access is live on the www prefixed domain name."""
        self.domain.httpwww.live = True

        self.assertTrue(is_live(self.domain))

    def test_httpswww_only(self):
        """Test when only HTTPS access is live on the www prefixed domain name."""
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_http_both(self):
        """Test when only HTTP access is live on both domain names."""
        self.domain.http.live = True
        self.domain.httpwww.live = True

        self.assertTrue(is_live(self.domain))

    def test_https_both(self):
        """Test when only HTTPS access is live on both domain names."""
        self.domain.https.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_www_neither(self):
        """Test when both HTTP and HTTPS are live on only the base domain."""
        self.domain.http.live = True
        self.domain.https.live = True

        self.assertTrue(is_live(self.domain))

    def test_www_both(self):
        """Test when both HTTP and HTTPS are live on the www prefixed domain name."""
        self.domain.httpwww.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))

    def test_all(self):
        """Test when both HTTP and HTTPS are live on both domain names."""
        self.domain.http.live = True
        self.domain.https.live = True
        self.domain.httpwww.live = True
        self.domain.httpswww.live = True

        self.assertTrue(is_live(self.domain))


class TestHttpsCheckServerLocation(ParametrizedTestCase):
    """Test HTTPS check parses endpoint host/port correctly for sslyze."""

    @patch("pshtt.pshtt.ServerNetworkLocation")
    def test_https_check_uses_explicit_port(self, mock_server_network_location):
        """Use the endpoint's explicit port when building sslyze target."""
        endpoint = Endpoint("https", "root", "example.com:9443")

        # We stop the check early by raising when the location is built;
        # https_check catches that and logs it via logging.exception, which
        # would otherwise dump a traceback into the test output and look like
        # a failure. Capture the expected error log so the output stays clean.
        mock_server_network_location.side_effect = RuntimeError(
            "stop after checking location args"
        )
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)

        mock_server_network_location.assert_called_once_with(
            hostname="example.com", port=9443
        )

    @parametrize(
        ("port", "protocol"),
        [
            param(80, "http", id="http"),
            param(443, "https", id="https"),
        ],
    )
    @patch("pshtt.pshtt.ServerNetworkLocation")
    def test_check_default_web_ports(
        self, mock_server_network_location, port, protocol
    ):
        """Default to expected default port when endpoint URL has no explicit port."""
        endpoint = Endpoint(protocol, "root", "example.com")

        mock_server_network_location.side_effect = RuntimeError(
            "stop after checking location args"
        )
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)

        mock_server_network_location.assert_called_once_with(
            hostname="example.com", port=port
        )


def make_certificate(dns_names=(), ip_names=(), with_san=True):
    """Build a self-signed certificate with the given subjectAltName entries."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if with_san:
        names = [x509.DNSName(n) for n in dns_names]
        names += [x509.IPAddress(ipaddress.ip_address(i)) for i in ip_names]
        builder = builder.add_extension(x509.SubjectAlternativeName(names), False)
    return builder.sign(key, hashes.SHA256())


class TestCertificateMatchesHostname(ParametrizedTestCase):
    """Test the subjectAltName hostname matching used in place of sslyze's."""

    @parametrize(
        ("dns_names", "hostname", "expected"),
        [
            param(["example.com"], "example.com", True, id="exact"),
            param(["Example.COM"], "example.com", True, id="case_insensitive"),
            param(["example.com"], "example.com.", True, id="trailing_dot"),
            param(["example.com"], "www.example.com", False, id="subdomain"),
            param(["*.example.com"], "www.example.com", True, id="wildcard"),
            param(["*.example.com"], "example.com", False, id="wildcard_apex"),
            param(["*.example.com"], "a.b.example.com", False, id="wildcard_depth"),
            param(["*.com"], "example.com", False, id="wildcard_tld"),
            param(["a.example.com", "b.example.com"], "b.example.com", True, id="any"),
            param([], "example.com", False, id="no_names"),
        ],
    )
    def test_dns_names(self, dns_names, hostname, expected):
        """Match DNS names, including single-label wildcards."""
        cert = make_certificate(dns_names=dns_names)
        self.assertEqual(certificate_matches_hostname(cert, hostname), expected)

    def test_ip_address(self):
        """Match an IP address only against IP entries."""
        cert = make_certificate(dns_names=["example.com"], ip_names=["192.0.2.1"])
        self.assertTrue(certificate_matches_hostname(cert, "192.0.2.1"))
        self.assertFalse(certificate_matches_hostname(cert, "192.0.2.2"))

    def test_no_san(self):
        """Never match when there is no subjectAltName extension."""
        cert = make_certificate(with_san=False)
        self.assertFalse(certificate_matches_hostname(cert, "test"))


class TestHttpsCheckScanResults(ParametrizedTestCase):
    """Test how https_check interprets sslyze scan results."""

    @staticmethod
    def server_scan_result(connectivity_ok=True, certificate=None, chains=None):
        """Build a fake sslyze ServerScanResult."""
        result = MagicMock()
        result.server_location.ip_address = "192.0.2.10"
        if not connectivity_ok:
            result.connectivity_status = ServerConnectivityStatusEnum.ERROR
            result.connectivity_error_trace.format.return_value = ["boom"]
            return result
        result.connectivity_status = ServerConnectivityStatusEnum.COMPLETED
        result.connectivity_result.client_auth_requirement.name = "DISABLED"
        attempt = result.scan_result.certificate_info
        attempt.status = ScanCommandAttemptStatusEnum.COMPLETED
        deployment = MagicMock()
        deployment.received_certificate_chain = chains or [certificate]
        deployment.verified_certificate_chain = None
        store = MagicMock()
        store.trust_store.name = "Mozilla"
        store.was_validation_successful = False
        store.verified_certificate_chain = None
        deployment.path_validation_results = [store]
        attempt.result.hostname_used_for_server_name_indication = "example.com"
        attempt.result.certificate_deployments = [deployment]
        return result

    @patch("pshtt.pshtt.ServerNetworkLocation")
    @patch("pshtt.pshtt.scan_certificates")
    def test_no_connectivity(self, mock_scan, mock_location):
        """Mark the endpoint not live when sslyze cannot connect."""
        mock_scan.return_value = self.server_scan_result(connectivity_ok=False)
        endpoint = Endpoint("https", "root", "example.com")
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)
        self.assertFalse(endpoint.live)
        self.assertFalse(endpoint.https_valid)

    @patch("pshtt.pshtt.ServerNetworkLocation")
    @patch("pshtt.pshtt.scan_certificates")
    def test_unresolvable_hostname(self, mock_scan, mock_location):
        """Flag an unknown error when the location cannot be built."""
        mock_location.side_effect = RuntimeError("Could not resolve example.com")
        endpoint = Endpoint("https", "root", "example.com")
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)
        self.assertTrue(endpoint.unknown_error)
        mock_scan.assert_not_called()

    @patch("pshtt.pshtt.ServerNetworkLocation")
    @patch("pshtt.pshtt.scan_certificates")
    def test_scan_error_is_unknown(self, mock_scan, mock_location):
        """Flag an unknown error when the certificate scan failed."""
        result = self.server_scan_result(certificate=make_certificate(["example.com"]))
        result.scan_result.certificate_info.status = (
            ScanCommandAttemptStatusEnum.ERROR
        )
        result.scan_result.certificate_info.error_trace.format.return_value = ["x"]
        mock_scan.return_value = result
        endpoint = Endpoint("https", "root", "example.com")
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)
        self.assertTrue(endpoint.unknown_error)
        self.assertIsNone(endpoint.https_valid)
        self.assertTrue(endpoint.live)

    @patch("pshtt.pshtt.ServerNetworkLocation")
    @patch("pshtt.pshtt.scan_certificates")
    def test_timeout_is_retried_once(self, mock_scan, mock_location):
        """Retry the scan when the certificate scan timed out."""
        timed_out = self.server_scan_result(
            certificate=make_certificate(["example.com"])
        )
        timed_out.scan_result.certificate_info.status = (
            ScanCommandAttemptStatusEnum.ERROR
        )
        timed_out.scan_result.certificate_info.error_trace.format.return_value = [
            "ConnectionToServerTimedOut: timed out"
        ]
        good = self.server_scan_result(certificate=make_certificate(["example.com"]))
        mock_scan.side_effect = [timed_out, good]
        endpoint = Endpoint("https", "root", "example.com")
        with self.assertLogs(level="ERROR"):
            https_check(endpoint)
        self.assertEqual(mock_scan.call_count, 2)
        self.assertFalse(endpoint.unknown_error)

    @parametrize(
        ("dns_names", "bad_hostname"),
        [
            param(["example.com"], False, id="matching_name"),
            param(["other.example.org"], True, id="wrong_name"),
        ],
    )
    @patch("pshtt.pshtt.ServerNetworkLocation")
    @patch("pshtt.pshtt.scan_certificates")
    def test_hostname_and_untrusted(
        self, mock_scan, mock_location, dns_names, bad_hostname
    ):
        """Flag a bad hostname from the received chain when validation failed."""
        mock_scan.return_value = self.server_scan_result(
            certificate=make_certificate(dns_names)
        )
        endpoint = Endpoint("https", "root", "example.com")
        https_check(endpoint)
        self.assertEqual(endpoint.https_bad_hostname, bad_hostname)
        # The certificate is self-signed and sslyze found no trusted chain.
        self.assertTrue(endpoint.https_self_signed_cert)
        self.assertFalse(endpoint.https_public_trusted)
        self.assertFalse(endpoint.https_valid)


class TestCertificateExpiry(ParametrizedTestCase):
    """Test certificate expiration logic uses UTC-aware comparisons."""

    @parametrize(
        "not_valid_after",
        [
            param(
                datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
                id="timezone_aware",
            ),
            param(
                datetime.datetime(
                    2026,
                    1,
                    1,
                    12,
                    0,
                    0,
                ),
                id="naive",
            ),
        ],
    )
    def test_not_valid_after_utc_unavailable(self, not_valid_after):
        """Use not_valid_after if not_valid_after_utc is not available."""
        cert = MagicMock()
        cert.not_valid_after_utc = None
        cert.not_valid_after = not_valid_after

        now_utc = datetime.datetime(2026, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc)

        self.assertFalse(certificate_is_expired(cert, now_utc))

    @parametrize(
        "not_valid_after_utc",
        [
            param(
                datetime.datetime(2026, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc),
                id="timezone_aware",
            ),
            param(
                datetime.datetime(
                    2026,
                    1,
                    1,
                    10,
                    0,
                    0,
                ),
                id="naive",
            ),
        ],
    )
    def test_not_valid_after_utc_available(self, not_valid_after_utc):
        """Use not_valid_after_utc when cryptography exposes it."""
        cert = MagicMock()
        cert.not_valid_after_utc = not_valid_after_utc

        now_utc = datetime.datetime(2026, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc)

        self.assertTrue(certificate_is_expired(cert, now_utc))


class TestStrictlyForcesHttps(unittest.TestCase):
    """Test is_strictly_forces_https always returns a bool, never None.

    When an endpoint is live but redirect_immediately_to_https has not been
    determined yet (its default is None), the inner down_or_redirects helper
    formerly evaluated ``False or None`` which Python propagates as None.
    That None then bubbled up through the ``and`` chain so the public field
    "Strictly Forces HTTPS" was reported as null in JSON output.  See #176.
    """

    def setUp(self):
        """Set up a domain with fresh endpoints."""
        base_domain = "example.com"
        self.domain = Domain(base_domain)
        self.domain.http = Endpoint("http", "root", base_domain)
        self.domain.httpwww = Endpoint("http", "www", base_domain)
        self.domain.https = Endpoint("https", "root", base_domain)
        self.domain.httpswww = Endpoint("https", "www", base_domain)

    def test_result_is_bool_when_http_live_and_redirect_unset(self):
        """Return False (not None) when HTTP is live with no redirect configured."""
        self.domain.https.live = True
        self.domain.http.live = True
        # redirect_immediately_to_https stays at its default value of None

        result = is_strictly_forces_https(self.domain)

        self.assertIsInstance(result, bool, "is_strictly_forces_https must return bool")
        self.assertFalse(result)

    def test_result_is_bool_when_all_endpoints_none(self):
        """Return False (not None) when all endpoint attributes are still None."""
        result = is_strictly_forces_https(self.domain)

        self.assertIsInstance(result, bool, "is_strictly_forces_https must return bool")
        self.assertFalse(result)

    def test_strictly_forces_when_http_endpoints_redirect_to_https(self):
        """Return True when HTTPS is live and HTTP endpoints redirect to HTTPS."""
        self.domain.https.live = True
        self.domain.http.live = True
        self.domain.http.redirect_immediately_to_https = True
        self.domain.httpwww.live = True
        self.domain.httpwww.redirect_immediately_to_https = True

        result = is_strictly_forces_https(self.domain)

        self.assertIsInstance(result, bool)
        self.assertTrue(result)
