import yaml
import os
import logging

class Config:
    def __init__(self, config_path="config/agent_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            logging.error(f"Config file not found: {self.config_path}")
            return {}
        
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return {}

    @property
    def server_url(self):
        return self.config.get('server', {}).get('url')

    @property
    def api_token(self):
        return self.config.get('server', {}).get('api_token')
    
    @property
    def verify_ssl(self):
        return self.config.get('server', {}).get('verify_ssl', True)

    @property
    def polling_interval(self):
        return self.config.get('agent', {}).get('polling_interval_sec', 5)

    @property
    def buffer_path(self):
        return self.config.get('agent', {}).get('buffer_path', 'agent_buffer.db')

    def get_windows_channels(self):
        return self.config.get('logs', {}).get('windows_events', [])

    def get_linux_files(self):
        return self.config.get('logs', {}).get('linux_files', [])
