"""
GeoIP Enrichment Engine for SOC Agent

Provides agent-side IP geolocation, ASN lookup, and reverse DNS resolution
with thread-safe LRU caching for high-throughput environments.

Requires MaxMind GeoLite2 .mmdb databases (City + ASN) at configured paths.
Gracefully degrades when databases are unavailable.

Dependencies: geoip2 (pip install geoip2)
"""

import socket
import time
import logging
import threading
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, Optional

from ip_resolver import IPResolver

logger = logging.getLogger(__name__)

# Attempt to import geoip2; gracefully degrade if not installed
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("geoip2 not installed — GeoIP enrichment disabled. Install with: pip install geoip2")


# --------------------------------------------------------------------------- #
#  Thread-safe TTL-LRU Cache                                                  #
# --------------------------------------------------------------------------- #
class TTLLRUCache:
    """
    Thread-safe LRU cache with per-entry TTL expiration.
    Designed for high-throughput IP lookups.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: int = 3600):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """Get value if present and not expired. Returns None on miss."""
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if time.time() < entry['expires_at']:
                    # Move to end (most recently used)
                    self._cache.move_to_end(key)
                    self._hits += 1
                    return entry['value']
                else:
                    # Expired — remove
                    del self._cache[key]
            self._misses += 1
            return None

    def put(self, key: str, value: Any):
        """Insert or update a cache entry."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = {
                'value': value,
                'expires_at': time.time() + self._ttl,
            }
            # Evict oldest if over capacity
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    @property
    def stats(self) -> Dict[str, int]:
        return {
            'size': len(self._cache),
            'max_size': self._max_size,
            'hits': self._hits,
            'misses': self._misses,
        }


# --------------------------------------------------------------------------- #
#  GeoIP Enricher                                                             #
# --------------------------------------------------------------------------- #
class GeoEnricher:
    """
    Agent-side GeoIP and ASN enrichment with offline MaxMind databases.

    Features:
    - City-level geolocation (country, city, lat/long, timezone)
    - ASN / ISP enrichment
    - Reverse DNS with configurable timeout
    - Thread-safe LRU cache for all lookups
    - Graceful fallback when databases are missing
    """

    def __init__(self, config=None):
        """
        Initialize the GeoEnricher.

        Args:
            config: Config object with geo_enrichment properties, or None for defaults.
        """
        self._city_reader = None
        self._asn_reader = None
        self._enabled = False
        self._reverse_dns_enabled = True
        self._reverse_dns_timeout = 1.0

        # Read config
        if config:
            city_db = getattr(config, 'geoip_city_db_path', None) or 'data/GeoLite2-City.mmdb'
            asn_db = getattr(config, 'geoip_asn_db_path', None) or 'data/GeoLite2-ASN.mmdb'
            self._enabled = getattr(config, 'enable_geo_enrichment', True)
            self._reverse_dns_enabled = getattr(config, 'reverse_dns_enabled', True)
            self._reverse_dns_timeout = getattr(config, 'reverse_dns_timeout', 1.0)
            cache_size = getattr(config, 'geo_cache_max_size', 10000)
            cache_ttl = getattr(config, 'geo_cache_ttl', 3600)
        else:
            city_db = 'data/GeoLite2-City.mmdb'
            asn_db = 'data/GeoLite2-ASN.mmdb'
            cache_size = 10000
            cache_ttl = 3600

        # Initialize caches
        self._geo_cache = TTLLRUCache(max_size=cache_size, ttl_seconds=cache_ttl)
        self._dns_cache = TTLLRUCache(max_size=cache_size, ttl_seconds=cache_ttl)

        # Load MaxMind databases
        if not GEOIP2_AVAILABLE:
            logger.warning("geoip2 library not available — GeoIP enrichment disabled")
            self._enabled = False
            return

        if not self._enabled:
            logger.info("GeoIP enrichment disabled in configuration")
            return

        # Load City database
        try:
            self._city_reader = geoip2.database.Reader(city_db)
            logger.info(f"Loaded GeoIP City database: {city_db}")
        except Exception as e:
            logger.warning(f"Could not load GeoIP City database ({city_db}): {e}")
            logger.warning("City/country geolocation will be unavailable")

        # Load ASN database
        try:
            self._asn_reader = geoip2.database.Reader(asn_db)
            logger.info(f"Loaded GeoIP ASN database: {asn_db}")
        except Exception as e:
            logger.warning(f"Could not load GeoIP ASN database ({asn_db}): {e}")
            logger.warning("ASN/ISP enrichment will be unavailable")

    # ------------------------------------------------------------------ #
    #  GeoIP Lookup (City)                                                #
    # ------------------------------------------------------------------ #
    def lookup_geo(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Look up geolocation data for an IP address.

        Returns dict with: country, country_code, city, latitude, longitude, timezone
        Returns None for private/loopback IPs or if lookup fails.
        """
        if not self._city_reader:
            return None

        # Skip non-global IPs
        classification = IPResolver.classify_ip(ip)
        if not classification.get('is_global', False):
            return None

        # Check cache
        cache_key = f"geo:{ip}"
        cached = self._geo_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            response = self._city_reader.city(ip)
            data = {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
            }
            self._geo_cache.put(cache_key, data)
            return data

        except geoip2.errors.AddressNotFoundError:
            logger.debug(f"GeoIP: Address not found for {ip}")
            # Cache the miss to avoid repeated lookups
            self._geo_cache.put(cache_key, {})
            return {}
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
            return None

    # ------------------------------------------------------------------ #
    #  ASN Lookup                                                         #
    # ------------------------------------------------------------------ #
    def lookup_asn(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Look up ASN/ISP data for an IP address.

        Returns dict with: asn, isp (organization name)
        Returns None for private IPs or if lookup fails.
        """
        if not self._asn_reader:
            return None

        classification = IPResolver.classify_ip(ip)
        if not classification.get('is_global', False):
            return None

        cache_key = f"asn:{ip}"
        cached = self._geo_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            response = self._asn_reader.asn(ip)
            data = {
                'asn': f"AS{response.autonomous_system_number}" if response.autonomous_system_number else None,
                'isp': response.autonomous_system_organization,
            }
            self._geo_cache.put(cache_key, data)
            return data

        except geoip2.errors.AddressNotFoundError:
            self._geo_cache.put(cache_key, {})
            return {}
        except Exception as e:
            logger.warning(f"ASN lookup failed for {ip}: {e}")
            return None

    # ------------------------------------------------------------------ #
    #  Combined Geo + ASN enrichment                                      #
    # ------------------------------------------------------------------ #
    def enrich_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Full enrichment for a single IP: geo + ASN combined.

        Returns dict with: country, country_code, city, latitude, longitude,
                          timezone, asn, isp
        Returns None for private/invalid IPs.
        """
        if not self._enabled:
            return None

        normalized = IPResolver.normalize_ip(ip)
        if not normalized:
            return None

        geo = self.lookup_geo(normalized)
        asn = self.lookup_asn(normalized)

        if not geo and not asn:
            return None

        result = {}
        if geo:
            result.update(geo)
        if asn:
            result.update(asn)

        return result if result else None

    # ------------------------------------------------------------------ #
    #  Reverse DNS                                                        #
    # ------------------------------------------------------------------ #
    def reverse_dns(self, ip: str, timeout: float = None) -> Optional[str]:
        """
        Perform a reverse DNS lookup with timeout protection.

        Returns the hostname string, or None if lookup fails/times out.
        """
        if not self._reverse_dns_enabled:
            return None

        if timeout is None:
            timeout = self._reverse_dns_timeout

        normalized = IPResolver.normalize_ip(ip)
        if not normalized:
            return None

        # Skip loopback
        if IPResolver.is_loopback(normalized):
            return "localhost"

        # Check cache
        cache_key = f"dns:{normalized}"
        cached = self._dns_cache.get(cache_key)
        if cached is not None:
            return cached if cached != '' else None

        # Perform lookup with timeout
        result = [None]
        error = [None]

        def _do_lookup():
            try:
                hostname, _, _ = socket.gethostbyaddr(normalized)
                result[0] = hostname
            except (socket.herror, socket.gaierror, OSError):
                result[0] = None
            except Exception as e:
                error[0] = e

        thread = threading.Thread(target=_do_lookup, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        hostname = result[0]

        # Cache the result (empty string for negative cache)
        self._dns_cache.put(cache_key, hostname if hostname else '')

        if error[0]:
            logger.debug(f"Reverse DNS error for {normalized}: {error[0]}")

        return hostname

    # ------------------------------------------------------------------ #
    #  Cache stats (for diagnostics/heartbeat)                            #
    # ------------------------------------------------------------------ #
    @property
    def cache_stats(self) -> Dict[str, Any]:
        return {
            'geo_cache': self._geo_cache.stats,
            'dns_cache': self._dns_cache.stats,
        }


# --------------------------------------------------------------------------- #
#  Top-level enrichment function — integrates into the log pipeline           #
# --------------------------------------------------------------------------- #
def enrich_log_ips(log_entry: Dict[str, Any], agent_ip: str = None,
                   config=None, enricher: GeoEnricher = None) -> Dict[str, Any]:
    """
    Full IP enrichment pipeline for a single log entry.

    Steps:
    1. Resolve the real source IP using field precedence
    2. Build structured source/destination dicts
    3. Enrich public IPs with GeoIP + ASN data
    4. Resolve reverse DNS hostnames
    5. Attach network direction metadata
    6. Add enrichment status metadata

    Args:
        log_entry: Raw log entry dict
        agent_ip: The agent's own IP (for direction detection)
        config: Config object (optional, used to create enricher if not provided)
        enricher: Pre-initialized GeoEnricher instance (for reuse across calls)

    Returns:
        Enriched log entry with structured source/destination and geo data
    """
    # Build the structured source/destination using IPResolver
    structured = IPResolver.build_source_destination(log_entry, agent_ip)

    enrichment_meta = {
        'ip_resolved': False,
        'geo_enriched': False,
        'reverse_dns_resolved': False,
        'enriched_at': datetime.utcnow().isoformat() + 'Z',
    }

    # Merge structured fields
    if 'source' in structured:
        log_entry['source'] = structured['source']
        enrichment_meta['ip_resolved'] = True
    if 'destination' in structured:
        log_entry['destination'] = structured['destination']
        enrichment_meta['ip_resolved'] = True
    if 'network' in structured:
        # Merge with existing network data
        existing_network = log_entry.get('network', {})
        if isinstance(existing_network, dict):
            existing_network.update(structured['network'])
            log_entry['network'] = existing_network
        else:
            log_entry['network'] = structured['network']

    # Initialize enricher if needed
    if enricher is None and config is not None:
        enricher = GeoEnricher(config)

    # GeoIP + ASN + Reverse DNS enrichment
    if enricher and enricher._enabled:
        # Enrich source IP
        if 'source' in log_entry and isinstance(log_entry['source'], dict):
            src_ip = log_entry['source'].get('ip')
            if src_ip and not log_entry['source'].get('is_private', True):
                geo_data = enricher.enrich_ip(src_ip)
                if geo_data:
                    log_entry['source']['geo'] = geo_data
                    enrichment_meta['geo_enriched'] = True

                hostname = enricher.reverse_dns(src_ip)
                if hostname:
                    log_entry['source']['hostname'] = hostname
                    enrichment_meta['reverse_dns_resolved'] = True

        # Enrich destination IP
        if 'destination' in log_entry and isinstance(log_entry['destination'], dict):
            dst_ip = log_entry['destination'].get('ip')
            if dst_ip and not log_entry['destination'].get('is_private', True):
                geo_data = enricher.enrich_ip(dst_ip)
                if geo_data:
                    log_entry['destination']['geo'] = geo_data
                    enrichment_meta['geo_enriched'] = True

                hostname = enricher.reverse_dns(dst_ip)
                if hostname:
                    log_entry['destination']['hostname'] = hostname
                    enrichment_meta['reverse_dns_resolved'] = True

            # For private destination IPs, try reverse DNS for hostname
            elif dst_ip and log_entry['destination'].get('is_private', False):
                hostname = enricher.reverse_dns(dst_ip)
                if hostname:
                    log_entry['destination']['hostname'] = hostname

    # Add agent metadata
    if agent_ip:
        from utils import get_hostname, get_agent_id
        log_entry['agent'] = {
            'id': get_agent_id(),
            'hostname': get_hostname(),
            'ip_address': agent_ip,
        }

    # Attach enrichment metadata
    log_entry['enrichment'] = enrichment_meta

    return log_entry
