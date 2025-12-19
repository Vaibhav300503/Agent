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
        """Standardize and send log to transport"""
        # We can add global enrichment here if needed, 
        # but normalize() in child classes should do most work
        self.transport.buffer_log(normalized_data)
