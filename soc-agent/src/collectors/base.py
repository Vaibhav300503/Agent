from abc import ABC, abstractmethod
import logging

class BaseCollector(ABC):
    def __init__(self, config, transport):
        self.config = config
        self.transport = transport
        self.running = False
        self.logger = logging.getLogger(self.__class__.__name__)

    @abstractmethod
    def start(self):
        """Start the collector thread or process"""
        pass

    @abstractmethod
    def stop(self):
        """Stop the collector"""
        pass

    def send_log(self, raw_data, normalized_data):
        """
        Standardize, sanitize, enrich, and send log to transport
        
        This method:
        1. Injects mandatory identification fields (ip_address, hostname)
        2. Normalizes timestamps to ISO 8601
        3. Sanitizes data to prevent SQL injection in backend
        4. Enriches with standardized metadata (source, destination, severity_level, log_category)
        5. Buffers log for transmission
        """
        try:
            # Ensure mandatory fields are present for backend identification
            if 'ip_address' not in normalized_data or not normalized_data['ip_address']:
                normalized_data['ip_address'] = getattr(self, 'ip_address', '0.0.0.0')
            
            if 'hostname' not in normalized_data or not normalized_data['hostname']:
                normalized_data['hostname'] = getattr(self, 'hostname', 'unknown')

            # Import enrichment function (lazy import to avoid circular dependencies)
            from sanitizer import enrich_log
            
            # Apply complete enrichment pipeline:
            # - Sanitize and normalize (timestamps, data validation)
            # - Add severity_level (standardized severity)
            # - Add log_category (Security, Application, Network, System)
            # - Add source and destination metadata
            safe_data = enrich_log(normalized_data, self.config)
            
            # Send to transport
            self.transport.buffer_log(safe_data)
            
        except Exception as e:
            self.logger.error(f"Error enriching log: {e}")
            # Fallback: send original data if enrichment fails
            self.transport.buffer_log(normalized_data)



