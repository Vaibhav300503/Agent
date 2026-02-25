#!/usr/bin/env python3
"""
Unit tests for IPResolver — IP validation, normalization, classification,
NAT detection, proxy header precedence, and direction inference.
"""

import sys
import os
import unittest

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ip_resolver import IPResolver


class TestValidateIP(unittest.TestCase):
    """Tests for IPResolver.validate_ip()"""

    def test_valid_ipv4(self):
        addr = IPResolver.validate_ip("192.168.1.1")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "192.168.1.1")

    def test_valid_ipv6(self):
        addr = IPResolver.validate_ip("2001:db8::1")
        self.assertIsNotNone(addr)

    def test_bracketed_ipv6(self):
        addr = IPResolver.validate_ip("[::1]")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "::1")

    def test_invalid_string(self):
        self.assertIsNone(IPResolver.validate_ip("not.an.ip"))

    def test_empty_string(self):
        self.assertIsNone(IPResolver.validate_ip(""))

    def test_none_input(self):
        self.assertIsNone(IPResolver.validate_ip(None))

    def test_wildcard(self):
        self.assertIsNone(IPResolver.validate_ip("*"))

    def test_dash(self):
        self.assertIsNone(IPResolver.validate_ip("-"))

    def test_all_zeros_ipv4(self):
        self.assertIsNone(IPResolver.validate_ip("0.0.0.0"))

    def test_ipv4_with_port(self):
        """Should strip port and validate IP"""
        addr = IPResolver.validate_ip("1.2.3.4:80")
        self.assertIsNotNone(addr)
        self.assertEqual(str(addr), "1.2.3.4")

    def test_mapped_ipv6(self):
        addr = IPResolver.validate_ip("::ffff:192.168.1.1")
        self.assertIsNotNone(addr)


class TestNormalizeIP(unittest.TestCase):
    """Tests for IPResolver.normalize_ip()"""

    def test_normal_ipv4(self):
        self.assertEqual(IPResolver.normalize_ip("10.0.0.1"), "10.0.0.1")

    def test_mapped_ipv6_to_ipv4(self):
        """IPv4-mapped IPv6 should normalize to plain IPv4"""
        self.assertEqual(IPResolver.normalize_ip("::ffff:192.168.1.1"), "192.168.1.1")

    def test_ipv6_canonical(self):
        result = IPResolver.normalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(result, "2001:db8::1")

    def test_whitespace(self):
        self.assertEqual(IPResolver.normalize_ip("  8.8.8.8  "), "8.8.8.8")

    def test_invalid_returns_none(self):
        self.assertIsNone(IPResolver.normalize_ip("garbage"))


class TestClassifyIP(unittest.TestCase):
    """Tests for IPResolver.classify_ip()"""

    def test_private_rfc1918_class_a(self):
        cls = IPResolver.classify_ip("10.0.0.1")
        self.assertTrue(cls['is_valid'])
        self.assertTrue(cls['is_private'])
        self.assertFalse(cls['is_global'])

    def test_private_rfc1918_class_b(self):
        cls = IPResolver.classify_ip("172.16.0.1")
        self.assertTrue(cls['is_private'])

    def test_private_rfc1918_class_c(self):
        cls = IPResolver.classify_ip("192.168.1.1")
        self.assertTrue(cls['is_private'])

    def test_public_ip(self):
        cls = IPResolver.classify_ip("8.8.8.8")
        self.assertTrue(cls['is_valid'])
        self.assertTrue(cls['is_global'])
        self.assertFalse(cls['is_private'])

    def test_loopback(self):
        cls = IPResolver.classify_ip("127.0.0.1")
        self.assertTrue(cls['is_loopback'])

    def test_loopback_ipv6(self):
        cls = IPResolver.classify_ip("::1")
        self.assertTrue(cls['is_loopback'])

    def test_link_local(self):
        cls = IPResolver.classify_ip("169.254.1.1")
        self.assertTrue(cls['is_link_local'])

    def test_multicast(self):
        cls = IPResolver.classify_ip("224.0.0.1")
        self.assertTrue(cls['is_multicast'])

    def test_invalid_ip(self):
        cls = IPResolver.classify_ip("invalid")
        self.assertFalse(cls['is_valid'])

    def test_ip_version_4(self):
        cls = IPResolver.classify_ip("1.1.1.1")
        self.assertEqual(cls['ip_version'], 4)

    def test_ip_version_6(self):
        cls = IPResolver.classify_ip("2001:db8::1")
        self.assertEqual(cls['ip_version'], 6)


class TestNATDetection(unittest.TestCase):
    """Tests for IPResolver.is_nat_ip()"""

    def test_rfc1918_10(self):
        self.assertTrue(IPResolver.is_nat_ip("10.255.255.255"))

    def test_rfc1918_172(self):
        self.assertTrue(IPResolver.is_nat_ip("172.16.0.1"))
        self.assertTrue(IPResolver.is_nat_ip("172.31.255.255"))

    def test_rfc1918_192(self):
        self.assertTrue(IPResolver.is_nat_ip("192.168.0.1"))

    def test_cgnat_rfc6598(self):
        self.assertTrue(IPResolver.is_nat_ip("100.64.0.1"))
        self.assertTrue(IPResolver.is_nat_ip("100.127.255.255"))

    def test_public_ip_not_nat(self):
        self.assertFalse(IPResolver.is_nat_ip("8.8.8.8"))

    def test_ipv6_ula(self):
        self.assertTrue(IPResolver.is_nat_ip("fd00::1"))

    def test_invalid_ip(self):
        self.assertFalse(IPResolver.is_nat_ip("invalid"))

    def test_172_15_not_nat(self):
        """172.15.x.x is NOT RFC1918"""
        self.assertFalse(IPResolver.is_nat_ip("172.15.0.1"))


class TestResolveRealIP(unittest.TestCase):
    """Tests for IPResolver.resolve_real_ip() — field precedence"""

    def test_real_ip_highest_priority(self):
        log = {'real_ip': '1.2.3.4', 'source_ip': '5.6.7.8'}
        self.assertEqual(IPResolver.resolve_real_ip(log), '1.2.3.4')

    def test_x_forwarded_for_public_ip(self):
        log = {'x_forwarded_for': '10.0.0.1, 203.0.113.50, 198.51.100.1'}
        # Should pick first public (non-private) IP
        self.assertEqual(IPResolver.resolve_real_ip(log), '203.0.113.50')

    def test_x_forwarded_for_all_private(self):
        log = {'x_forwarded_for': '10.0.0.1, 192.168.1.1'}
        # Falls back to first valid when all are private
        self.assertEqual(IPResolver.resolve_real_ip(log), '10.0.0.1')

    def test_source_ip_fallback(self):
        log = {'source_ip': '9.9.9.9'}
        self.assertEqual(IPResolver.resolve_real_ip(log), '9.9.9.9')

    def test_src_ip_field(self):
        log = {'src_ip': '1.1.1.1'}
        self.assertEqual(IPResolver.resolve_real_ip(log), '1.1.1.1')

    def test_no_ip_fields(self):
        log = {'hostname': 'server-01'}
        self.assertIsNone(IPResolver.resolve_real_ip(log))

    def test_empty_log(self):
        self.assertIsNone(IPResolver.resolve_real_ip({}))


class TestDirectionDetection(unittest.TestCase):
    """Tests for IPResolver.detect_direction()"""

    def test_inbound(self):
        log = {'source_ip': '8.8.8.8', 'destination_ip': '10.0.0.5'}
        self.assertEqual(IPResolver.detect_direction(log), 'inbound')

    def test_outbound(self):
        log = {'source_ip': '10.0.0.5', 'destination_ip': '8.8.8.8'}
        self.assertEqual(IPResolver.detect_direction(log), 'outbound')

    def test_internal(self):
        log = {'source_ip': '10.0.0.1', 'destination_ip': '192.168.1.1'}
        self.assertEqual(IPResolver.detect_direction(log), 'internal')

    def test_external(self):
        log = {'source_ip': '8.8.8.8', 'destination_ip': '1.1.1.1'}
        self.assertEqual(IPResolver.detect_direction(log), 'external')

    def test_unknown_no_ips(self):
        log = {'hostname': 'server'}
        self.assertEqual(IPResolver.detect_direction(log), 'unknown')

    def test_with_agent_ip(self):
        log = {'source_ip': '8.8.8.8', 'destination_ip': '10.0.0.5'}
        self.assertEqual(IPResolver.detect_direction(log, agent_ip='10.0.0.5'), 'inbound')


class TestBuildSourceDestination(unittest.TestCase):
    """Tests for IPResolver.build_source_destination()"""

    def test_full_structure(self):
        log = {
            'source_ip': '8.8.8.8', 'source_port': 443,
            'destination_ip': '10.0.0.5', 'destination_port': 51514,
            'protocol': 'TCP'
        }
        result = IPResolver.build_source_destination(log)

        self.assertIn('source', result)
        self.assertEqual(result['source']['ip'], '8.8.8.8')
        self.assertEqual(result['source']['port'], 443)
        self.assertFalse(result['source']['is_private'])

        self.assertIn('destination', result)
        self.assertEqual(result['destination']['ip'], '10.0.0.5')
        self.assertTrue(result['destination']['is_private'])

        self.assertIn('network', result)
        self.assertEqual(result['network']['protocol'], 'TCP')
        self.assertEqual(result['network']['direction'], 'inbound')

    def test_no_ips(self):
        log = {'hostname': 'server'}
        result = IPResolver.build_source_destination(log)
        self.assertNotIn('source', result)
        self.assertNotIn('destination', result)

    def test_port_missing(self):
        log = {'source_ip': '1.1.1.1'}
        result = IPResolver.build_source_destination(log)
        self.assertNotIn('port', result.get('source', {}))


class TestLoopbackDetection(unittest.TestCase):
    """Tests for IPResolver.is_loopback()"""

    def test_127_0_0_1(self):
        self.assertTrue(IPResolver.is_loopback("127.0.0.1"))

    def test_127_other(self):
        self.assertTrue(IPResolver.is_loopback("127.0.0.2"))

    def test_ipv6_loopback(self):
        self.assertTrue(IPResolver.is_loopback("::1"))

    def test_not_loopback(self):
        self.assertFalse(IPResolver.is_loopback("10.0.0.1"))


if __name__ == '__main__':
    unittest.main()
