import re
import ipaddress
import logging
from datetime import datetime

class LogProcessor:
    """
    Unified Log Processor for specific SOC Agent.
    Handles normalization, classification, and enrichment of logs.
    """

    def __init__(self, geoip_db_path=None):
        self.logger = logging.getLogger(__name__)
        self.geoip_db_path = geoip_db_path
        # Compile common regex patterns once
        # Basic IPv4 pattern
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    def process(self, raw_data: dict) -> dict:
        """
        Main entry point to process a single log entry.
        EXPECTS raw_data to have at least: 'message' and optionally 'log_source'/'level'.
        """
        message = raw_data.get('message', '')
        raw_source = raw_data.get('log_source', 'unknown')
        raw_level = raw_data.get('level', raw_data.get('severity', 'info'))

        # 1. Normalize Severity
        severity_label, severity_score = self._normalize_severity(raw_level, raw_source)

        # 2. Classify Log Type
        log_type = self._classify_type(raw_data)

        # 3. IP Extraction & Enrichment
        src_ip, dst_ip = self._extract_ips(message)
        
        geo_info = {}
        if src_ip:
            geo_info['source_geo'] = self._enrich_ip(src_ip)
        if dst_ip:
            geo_info['dest_geo'] = self._enrich_ip(dst_ip)

        # 4. Construct Standardized Output
        normalized_log = {
            "timestamp": raw_data.get('timestamp', datetime.utcnow().isoformat()),
            "log_type": log_type,
            "severity_level": severity_label,
            "severity_score": severity_score,
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "geo_info": geo_info,
            "message": message,
            "raw_log": raw_data.get('raw_log', message),
            "host": {
                "hostname": raw_data.get('hostname'),
                "os": raw_data.get('os_type'),
                "ip": raw_data.get('ip_address')
            },
            "metadata": {
                "source": raw_source,
                "original_level": raw_level
            }
        }

        return normalized_log

    def _normalize_severity(self, raw_level, source):
        """
        Maps raw severity to Standard (Critical, High, Medium, Low, Info)
        and Score (1-5).
        """
        # Lowercase and stringify for comparison
        level_str = str(raw_level).lower()
        
        # Default Info
        label = "Info"
        score = 1

        # Direct string matching
        if any(x in level_str for x in ['emerg', 'alert', 'crit', 'fatal']):
            label = "Critical"
            score = 5
        elif any(x in level_str for x in ['err', 'high', 'fail']):
            label = "High"
            score = 4
        elif any(x in level_str for x in ['warn', 'medium']):
            label = "Medium"
            score = 3
        elif any(x in level_str for x in ['notice', 'low', 'audit']):
            label = "Low"
            score = 2
        # Windows Event ID specific mapping could go here if raw_level was an ID
        
        return label, score

    def _classify_type(self, raw_data):
        """
        Classifies log into categories: Authentication, Network, Endpoint, Security, Application, System.
        """
        message = raw_data.get('message', '').lower()
        source = raw_data.get('log_source', '').lower()

        if any(x in message for x in ['ssh', 'login', 'auth', 'password', 'user', 'sudo', 'su ']):
            return "Authentication"
        
        if any(x in source for x in ['firewall', 'ufw', 'iptables', 'network']) or \
           any(x in message for x in ['connection', 'accept', 'block', 'deny', 'allow']):
            return "Network"

        if any(x in message for x in ['start', 'stop', 'process', 'service']):
            return "Endpoint"

        if 'malware' in message or 'attack' in message or 'ids' in source:
            return "Security"

        if 'app' in source:
             return "Application"

        return "System"

    def _extract_ips(self, message):
        """
        Extracts source and dest IPs. 
        Simple heuristic: First IP is Src, Second is Dst.
        Validates they are not loopback/private if possible, but for extraction we take what we find.
        """
        ips = self.ip_pattern.findall(message)
        src = None
        dst = None

        unique_ips = []
        for ip in ips:
            if ip not in unique_ips:
                unique_ips.append(ip)

        if len(unique_ips) >= 1:
            src = unique_ips[0]
        if len(unique_ips) >= 2:
            dst = unique_ips[1]
        
        return src, dst

    def _enrich_ip(self, ip):
        """
        Enriches Public IPs with Geo Data.
        STUB IMPLEMENTATION for now.
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return None
            
            # TODO: Integrate real GeoIP lookup here
            # Return placeholder for public IPs to verify structure
            return {
                "country": "Unknown",
                "city": "Unknown",
                "asn": "Unknown"
            }
        except ValueError:
            return None
