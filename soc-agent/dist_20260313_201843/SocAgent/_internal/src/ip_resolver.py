"""
IP Resolution, Validation, and Classification Module for SOC Agent

Provides:
- IPv4/IPv6 validation and normalization
- RFC1918/RFC6598 private IP classification
- Loopback, link-local, multicast detection
- NAT detection logic
- Proxy header field precedence resolution
- Network direction inference (inbound/outbound/internal)
- Structured source/destination builder

Uses only Python stdlib (ipaddress, socket) — zero external dependencies.
"""

import ipaddress
import socket
import re
import logging
from typing import Any, Dict, Optional, Tuple, Union

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
#  Field precedence for resolving the "real" client IP                        #
# --------------------------------------------------------------------------- #
# Ordered from most trustworthy to least trustworthy.
IP_FIELD_PRECEDENCE = [
    'real_ip',
    'x_forwarded_for',
    'x_real_ip',
    'remote_addr',
    'source_ip',
    'client_ip',
    'src_ip',
]

# Fields that may contain the destination IP
DST_IP_FIELDS = [
    'destination_ip',
    'dest_ip',
    'dst_ip',
    'remote_ip',
    'server_ip',
]

# Port field mappings
SRC_PORT_FIELDS = ['source_port', 'src_port', 'local_port', 'client_port']
DST_PORT_FIELDS = ['destination_port', 'dest_port', 'dst_port', 'remote_port', 'server_port']


class IPResolver:
    """
    Stateless IP resolution and classification engine.
    All methods are static/class-level — no instance state needed.
    """

    # ------------------------------------------------------------------ #
    #  Validation                                                         #
    # ------------------------------------------------------------------ #
    @staticmethod
    def validate_ip(ip_string: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """
        Parse and validate an IP address string.

        Handles:
        - Standard IPv4 ("192.168.1.1")
        - Standard IPv6 ("2001:db8::1")
        - Bracketed IPv6 ("[::1]")
        - IPv4-mapped IPv6 ("::ffff:192.168.1.1")

        Returns:
            ipaddress object on success, None on failure.
        """
        if not ip_string or not isinstance(ip_string, str):
            return None

        ip_string = ip_string.strip()

        # Strip brackets from IPv6 (e.g., "[::1]")
        if ip_string.startswith('[') and ip_string.endswith(']'):
            ip_string = ip_string[1:-1]

        # Reject wildcard/placeholder values
        if ip_string in ('*', '-', '', '0.0.0.0', '::'):
            return None

        try:
            addr = ipaddress.ip_address(ip_string)
            return addr
        except ValueError:
            pass

        # Try stripping a port suffix for IPv4 ("1.2.3.4:80")
        if ':' in ip_string and '::' not in ip_string:
            candidate = ip_string.rsplit(':', 1)[0]
            try:
                return ipaddress.ip_address(candidate)
            except ValueError:
                pass

        logger.debug(f"Invalid IP address: {ip_string}")
        return None

    # ------------------------------------------------------------------ #
    #  Normalization                                                      #
    # ------------------------------------------------------------------ #
    @staticmethod
    def normalize_ip(ip_string: str) -> Optional[str]:
        """
        Return a canonical string representation of an IP.

        - IPv4-mapped IPv6 (::ffff:1.2.3.4) → "1.2.3.4"
        - IPv6 compressed → expanded canonical form
        - Strips brackets, whitespace
        - Returns None for invalid input
        """
        addr = IPResolver.validate_ip(ip_string)
        if addr is None:
            return None

        # Convert IPv4-mapped IPv6 to plain IPv4
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)

        return str(addr)

    # ------------------------------------------------------------------ #
    #  Classification                                                     #
    # ------------------------------------------------------------------ #
    @staticmethod
    def classify_ip(ip_string: str) -> Dict[str, Any]:
        """
        Classify an IP address and return a metadata dict.

        Returns dict with keys:
            ip, is_valid, is_private, is_loopback, is_link_local,
            is_multicast, is_reserved, is_global, ip_version
        """
        result = {
            'ip': ip_string,
            'is_valid': False,
            'is_private': False,
            'is_loopback': False,
            'is_link_local': False,
            'is_multicast': False,
            'is_reserved': False,
            'is_global': False,
            'ip_version': None,
        }

        addr = IPResolver.validate_ip(ip_string)
        if addr is None:
            return result

        # Normalize mapped IPv6
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped

        result['ip'] = str(addr)
        result['is_valid'] = True
        result['ip_version'] = addr.version
        result['is_private'] = addr.is_private
        result['is_loopback'] = addr.is_loopback
        result['is_link_local'] = addr.is_link_local
        result['is_multicast'] = addr.is_multicast
        result['is_reserved'] = addr.is_reserved
        result['is_global'] = addr.is_global

        return result

    # ------------------------------------------------------------------ #
    #  NAT / RFC1918 detection                                            #
    # ------------------------------------------------------------------ #
    @staticmethod
    def is_nat_ip(ip_string: str) -> bool:
        """
        Check if IP falls within NAT ranges:
        - RFC1918:  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        - RFC6598:  100.64.0.0/10 (Carrier-Grade NAT)
        """
        addr = IPResolver.validate_ip(ip_string)
        if addr is None:
            return False

        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped

        if isinstance(addr, ipaddress.IPv4Address):
            nat_ranges = [
                ipaddress.IPv4Network('10.0.0.0/8'),
                ipaddress.IPv4Network('172.16.0.0/12'),
                ipaddress.IPv4Network('192.168.0.0/16'),
                ipaddress.IPv4Network('100.64.0.0/10'),  # CGNAT
            ]
            return any(addr in net for net in nat_ranges)

        # IPv6 ULA (Unique Local Addresses) — equivalent of RFC1918
        if isinstance(addr, ipaddress.IPv6Address):
            ula = ipaddress.IPv6Network('fc00::/7')
            return addr in ula

        return False

    # ------------------------------------------------------------------ #
    #  Loopback detection                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def is_loopback(ip_string: str) -> bool:
        """Detect loopback addresses: 127.0.0.0/8, ::1"""
        addr = IPResolver.validate_ip(ip_string)
        if addr is None:
            return False
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return addr.is_loopback

    # ------------------------------------------------------------------ #
    #  Resolve the "real" source IP from log fields                       #
    # ------------------------------------------------------------------ #
    @staticmethod
    def resolve_real_ip(log_entry: Dict[str, Any]) -> Optional[str]:
        """
        Walk down the field precedence chain to find the most trustworthy
        source IP from a log entry.

        Precedence:
            real_ip > x_forwarded_for (first public) > x_real_ip >
            remote_addr > source_ip > client_ip > src_ip

        For x_forwarded_for, the first non-private IP is selected
        (leftmost = original client in most proxy chains).

        Returns:
            Normalized IP string, or None if no valid IP found.
        """
        for field in IP_FIELD_PRECEDENCE:
            value = log_entry.get(field)
            if not value:
                continue

            # x_forwarded_for may be a comma-separated list
            if field == 'x_forwarded_for':
                ips = [ip.strip() for ip in str(value).split(',')]
                # Prefer the first public (non-private) IP
                for candidate in ips:
                    normalized = IPResolver.normalize_ip(candidate)
                    if normalized and not IPResolver.is_nat_ip(normalized) and not IPResolver.is_loopback(normalized):
                        return normalized
                # Fallback: return the first valid IP even if private
                for candidate in ips:
                    normalized = IPResolver.normalize_ip(candidate)
                    if normalized:
                        return normalized
            else:
                normalized = IPResolver.normalize_ip(str(value))
                if normalized:
                    return normalized

        return None

    # ------------------------------------------------------------------ #
    #  Resolve destination IP                                             #
    # ------------------------------------------------------------------ #
    @staticmethod
    def resolve_dest_ip(log_entry: Dict[str, Any]) -> Optional[str]:
        """
        Resolve the destination IP from standard log fields.
        """
        for field in DST_IP_FIELDS:
            value = log_entry.get(field)
            if value:
                normalized = IPResolver.normalize_ip(str(value))
                if normalized:
                    return normalized
        return None

    # ------------------------------------------------------------------ #
    #  Direction detection                                                #
    # ------------------------------------------------------------------ #
    @staticmethod
    def detect_direction(log_entry: Dict[str, Any], agent_ip: str = None) -> str:
        """
        Infer network flow direction based on source/destination IPs
        and the agent's own IP.

        Returns one of: "inbound", "outbound", "internal", "external", "unknown"
        """
        src = IPResolver.resolve_real_ip(log_entry)
        dst = IPResolver.resolve_dest_ip(log_entry)

        if not src and not dst:
            return "unknown"

        src_private = IPResolver.is_nat_ip(src) if src else None
        dst_private = IPResolver.is_nat_ip(dst) if dst else None

        # If we know the agent IP, use it for precise direction
        if agent_ip and src and dst:
            agent_norm = IPResolver.normalize_ip(agent_ip)
            if agent_norm == dst or (dst_private is True and src_private is False):
                return "inbound"
            if agent_norm == src or (src_private is True and dst_private is False):
                return "outbound"

        # Heuristic-based
        if src_private is True and dst_private is True:
            return "internal"
        if src_private is False and dst_private is False:
            return "external"
        if src_private is False and dst_private is True:
            return "inbound"
        if src_private is True and dst_private is False:
            return "outbound"

        return "unknown"

    # ------------------------------------------------------------------ #
    #  Resolve ports                                                      #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _resolve_port(log_entry: Dict[str, Any], field_list: list) -> Optional[int]:
        """Extract port number from the first matching field."""
        for field in field_list:
            value = log_entry.get(field)
            if value is not None:
                try:
                    port = int(value)
                    if 0 <= port <= 65535:
                        return port
                except (ValueError, TypeError):
                    continue
        return None

    # ------------------------------------------------------------------ #
    #  Build structured source/destination                                #
    # ------------------------------------------------------------------ #
    @staticmethod
    def build_source_destination(log_entry: Dict[str, Any], agent_ip: str = None) -> Dict[str, Any]:
        """
        Build structured 'source' and 'destination' dicts from raw log fields.

        Returns a dict with keys: 'source', 'destination', 'network'
        that should be merged into the log entry.
        """
        result = {}

        # --- Source ---
        src_ip = IPResolver.resolve_real_ip(log_entry)
        if src_ip:
            src_cls = IPResolver.classify_ip(src_ip)
            source = {
                'ip': src_ip,
                'port': IPResolver._resolve_port(log_entry, SRC_PORT_FIELDS),
                'is_private': src_cls.get('is_private', False),
            }
            # Don't include None port
            if source['port'] is None:
                del source['port']
            result['source'] = source

        # --- Destination ---
        dst_ip = IPResolver.resolve_dest_ip(log_entry)
        if dst_ip:
            dst_cls = IPResolver.classify_ip(dst_ip)
            destination = {
                'ip': dst_ip,
                'port': IPResolver._resolve_port(log_entry, DST_PORT_FIELDS),
                'is_private': dst_cls.get('is_private', False),
            }
            if destination['port'] is None:
                del destination['port']
            result['destination'] = destination

        # --- Network metadata ---
        protocol = log_entry.get('protocol', log_entry.get('proto'))
        direction = IPResolver.detect_direction(log_entry, agent_ip)

        network = {}
        if protocol:
            network['protocol'] = str(protocol).upper()
        if direction != "unknown":
            network['direction'] = direction
        if network:
            result['network'] = network

        return result
