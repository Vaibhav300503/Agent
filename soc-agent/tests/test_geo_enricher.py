#!/usr/bin/env python3
"""
Unit tests for GeoEnricher — GeoIP/ASN lookups, reverse DNS,
TTL-LRU cache, and the enrich_log_ips() integration function.

Uses mocking to avoid requiring actual MaxMind databases.
"""

import sys
import os
import time
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from geo_enricher import TTLLRUCache, GeoEnricher, enrich_log_ips


# --------------------------------------------------------------------------- #
#  TTLLRUCache tests                                                          #
# --------------------------------------------------------------------------- #
class TestTTLLRUCache(unittest.TestCase):
    """Tests for the thread-safe TTL-LRU cache."""

    def test_put_and_get(self):
        cache = TTLLRUCache(max_size=100, ttl_seconds=60)
        cache.put("key1", "value1")
        self.assertEqual(cache.get("key1"), "value1")

    def test_miss(self):
        cache = TTLLRUCache(max_size=100, ttl_seconds=60)
        self.assertIsNone(cache.get("nonexistent"))

    def test_expiration(self):
        cache = TTLLRUCache(max_size=100, ttl_seconds=0)  # 0 second TTL
        cache.put("key1", "value1")
        time.sleep(0.05)
        self.assertIsNone(cache.get("key1"))

    def test_eviction(self):
        cache = TTLLRUCache(max_size=3, ttl_seconds=60)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        cache.put("d", 4)  # Should evict "a" (oldest)
        self.assertIsNone(cache.get("a"))
        self.assertEqual(cache.get("d"), 4)

    def test_lru_ordering(self):
        cache = TTLLRUCache(max_size=3, ttl_seconds=60)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.put("c", 3)
        cache.get("a")       # Access "a" to make it recently used
        cache.put("d", 4)    # Should evict "b" (least recently used)
        self.assertEqual(cache.get("a"), 1)
        self.assertIsNone(cache.get("b"))

    def test_stats(self):
        cache = TTLLRUCache(max_size=100, ttl_seconds=60)
        cache.put("k", "v")
        cache.get("k")       # hit
        cache.get("miss")    # miss
        stats = cache.stats
        self.assertEqual(stats['hits'], 1)
        self.assertEqual(stats['misses'], 1)
        self.assertEqual(stats['size'], 1)


# --------------------------------------------------------------------------- #
#  GeoEnricher tests (with mocked geoip2)                                     #
# --------------------------------------------------------------------------- #
class TestGeoEnricherLookups(unittest.TestCase):
    """Tests for GeoEnricher with mocked MaxMind readers."""

    def _make_enricher(self):
        """Create a GeoEnricher with mocked readers."""
        enricher = GeoEnricher.__new__(GeoEnricher)
        enricher._enabled = True
        enricher._reverse_dns_enabled = True
        enricher._reverse_dns_timeout = 0.5
        enricher._geo_cache = TTLLRUCache(max_size=1000, ttl_seconds=3600)
        enricher._dns_cache = TTLLRUCache(max_size=1000, ttl_seconds=3600)

        # Mock city reader
        mock_city = MagicMock()
        mock_response = MagicMock()
        mock_response.country.name = "United States"
        mock_response.country.iso_code = "US"
        mock_response.city.name = "Mountain View"
        mock_response.location.latitude = 37.4056
        mock_response.location.longitude = -122.0775
        mock_response.location.time_zone = "America/Los_Angeles"
        mock_city.city.return_value = mock_response
        enricher._city_reader = mock_city

        # Mock ASN reader
        mock_asn = MagicMock()
        mock_asn_response = MagicMock()
        mock_asn_response.autonomous_system_number = 15169
        mock_asn_response.autonomous_system_organization = "Google LLC"
        mock_asn.asn.return_value = mock_asn_response
        enricher._asn_reader = mock_asn

        return enricher

    def test_lookup_geo_public_ip(self):
        enricher = self._make_enricher()
        geo = enricher.lookup_geo("8.8.8.8")
        self.assertIsNotNone(geo)
        self.assertEqual(geo['country'], "United States")
        self.assertEqual(geo['country_code'], "US")
        self.assertEqual(geo['city'], "Mountain View")
        self.assertAlmostEqual(geo['latitude'], 37.4056)

    def test_lookup_geo_private_ip_skipped(self):
        enricher = self._make_enricher()
        geo = enricher.lookup_geo("192.168.1.1")
        self.assertIsNone(geo)

    def test_lookup_geo_loopback_skipped(self):
        enricher = self._make_enricher()
        geo = enricher.lookup_geo("127.0.0.1")
        self.assertIsNone(geo)

    def test_lookup_asn(self):
        enricher = self._make_enricher()
        asn = enricher.lookup_asn("8.8.8.8")
        self.assertIsNotNone(asn)
        self.assertEqual(asn['asn'], "AS15169")
        self.assertEqual(asn['isp'], "Google LLC")

    def test_lookup_asn_private_skipped(self):
        enricher = self._make_enricher()
        asn = enricher.lookup_asn("10.0.0.1")
        self.assertIsNone(asn)

    def test_enrich_ip_combined(self):
        enricher = self._make_enricher()
        result = enricher.enrich_ip("8.8.8.8")
        self.assertIn('country', result)
        self.assertIn('asn', result)
        self.assertIn('isp', result)

    def test_enrich_ip_caching(self):
        enricher = self._make_enricher()
        result1 = enricher.enrich_ip("8.8.8.8")
        result2 = enricher.enrich_ip("8.8.8.8")
        self.assertEqual(result1, result2)
        # City reader should only be called once (cached second time)
        self.assertEqual(enricher._city_reader.city.call_count, 1)

    def test_enrich_ip_disabled(self):
        enricher = self._make_enricher()
        enricher._enabled = False
        result = enricher.enrich_ip("8.8.8.8")
        self.assertIsNone(result)


# --------------------------------------------------------------------------- #
#  Reverse DNS tests                                                          #
# --------------------------------------------------------------------------- #
class TestReverseDNS(unittest.TestCase):
    """Tests for reverse DNS with mocked socket."""

    def _make_enricher(self):
        enricher = GeoEnricher.__new__(GeoEnricher)
        enricher._enabled = True
        enricher._reverse_dns_enabled = True
        enricher._reverse_dns_timeout = 0.5
        enricher._geo_cache = TTLLRUCache(max_size=100, ttl_seconds=60)
        enricher._dns_cache = TTLLRUCache(max_size=100, ttl_seconds=60)
        enricher._city_reader = None
        enricher._asn_reader = None
        return enricher

    @patch('geo_enricher.socket.gethostbyaddr')
    def test_successful_lookup(self, mock_dns):
        mock_dns.return_value = ("dns.google", [], ["8.8.8.8"])
        enricher = self._make_enricher()
        hostname = enricher.reverse_dns("8.8.8.8")
        self.assertEqual(hostname, "dns.google")

    def test_loopback_returns_localhost(self):
        enricher = self._make_enricher()
        hostname = enricher.reverse_dns("127.0.0.1")
        self.assertEqual(hostname, "localhost")

    @patch('geo_enricher.socket.gethostbyaddr')
    def test_dns_caching(self, mock_dns):
        mock_dns.return_value = ("example.com", [], ["1.1.1.1"])
        enricher = self._make_enricher()
        h1 = enricher.reverse_dns("1.1.1.1")
        h2 = enricher.reverse_dns("1.1.1.1")
        self.assertEqual(h1, h2)
        # Socket should only be called once (cached second time)
        self.assertEqual(mock_dns.call_count, 1)

    def test_disabled(self):
        enricher = self._make_enricher()
        enricher._reverse_dns_enabled = False
        self.assertIsNone(enricher.reverse_dns("8.8.8.8"))


# --------------------------------------------------------------------------- #
#  Integration: enrich_log_ips()                                              #
# --------------------------------------------------------------------------- #
class TestEnrichLogIPs(unittest.TestCase):
    """Integration tests for the full enrich_log_ips() function."""

    def test_basic_ip_structuring(self):
        """Test that IPs are properly structured even without geo data."""
        log = {
            'source_ip': '8.8.8.8',
            'source_port': 443,
            'destination_ip': '10.0.0.5',
            'destination_port': 51514,
            'protocol': 'TCP',
        }
        result = enrich_log_ips(log, agent_ip='10.0.0.5')

        self.assertIn('source', result)
        self.assertEqual(result['source']['ip'], '8.8.8.8')
        self.assertFalse(result['source']['is_private'])

        self.assertIn('destination', result)
        self.assertEqual(result['destination']['ip'], '10.0.0.5')
        self.assertTrue(result['destination']['is_private'])

        self.assertIn('network', result)
        self.assertEqual(result['network']['direction'], 'inbound')
        self.assertEqual(result['network']['protocol'], 'TCP')

        self.assertIn('enrichment', result)
        self.assertTrue(result['enrichment']['ip_resolved'])

    def test_no_ips_in_log(self):
        """Test graceful handling of logs without IP fields."""
        log = {'hostname': 'server-01', 'message': 'test event'}
        result = enrich_log_ips(log)
        self.assertIn('enrichment', result)
        self.assertFalse(result['enrichment']['ip_resolved'])

    def test_private_ips_no_geo(self):
        """Private IPs should not get geo enrichment."""
        log = {
            'source_ip': '192.168.1.1',
            'destination_ip': '10.0.0.5',
        }
        result = enrich_log_ips(log)
        # Source should be structured but without geo
        if 'source' in result and isinstance(result['source'], dict):
            self.assertNotIn('geo', result['source'])

    def test_agent_metadata(self):
        """Test that agent metadata is attached when agent_ip provided."""
        log = {'source_ip': '8.8.8.8'}
        with patch('utils.get_hostname', return_value='test-host'), \
             patch('utils.get_agent_id', return_value='agent-test-01'):
            result = enrich_log_ips(log, agent_ip='10.0.0.5')
        self.assertIn('agent', result)
        self.assertEqual(result['agent']['hostname'], 'test-host')
        self.assertEqual(result['agent']['ip_address'], '10.0.0.5')

    def test_with_enricher_and_geo(self):
        """Test full enrichment with a mocked GeoEnricher."""
        mock_enricher = MagicMock(spec=GeoEnricher)
        mock_enricher._enabled = True
        mock_enricher.enrich_ip.return_value = {
            'country': 'United States',
            'country_code': 'US',
            'city': 'Mountain View',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'asn': 'AS15169',
            'isp': 'Google LLC',
        }
        mock_enricher.reverse_dns.return_value = 'dns.google'

        log = {
            'source_ip': '8.8.8.8',
            'source_port': 443,
            'destination_ip': '10.0.0.5',
            'destination_port': 51514,
        }
        result = enrich_log_ips(log, agent_ip='10.0.0.5', enricher=mock_enricher)

        self.assertIn('geo', result['source'])
        self.assertEqual(result['source']['geo']['country'], 'United States')
        self.assertEqual(result['source']['hostname'], 'dns.google')
        self.assertTrue(result['enrichment']['geo_enriched'])
        self.assertTrue(result['enrichment']['reverse_dns_resolved'])


# --------------------------------------------------------------------------- #
#  GeoEnricher graceful fallback                                              #
# --------------------------------------------------------------------------- #
class TestGeoEnricherFallback(unittest.TestCase):
    """Test that GeoEnricher degrades gracefully when DBs are missing."""

    def test_no_db_files(self):
        """Should initialize without error when .mmdb files don't exist."""
        enricher = GeoEnricher()  # No config, no DBs
        # Should not crash
        self.assertIsNotNone(enricher)

    def test_cache_stats(self):
        """Cache stats should be available even without DBs."""
        enricher = GeoEnricher()
        stats = enricher.cache_stats
        self.assertIn('geo_cache', stats)
        self.assertIn('dns_cache', stats)


if __name__ == '__main__':
    unittest.main()
