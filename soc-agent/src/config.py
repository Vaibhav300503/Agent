import yaml
import os
import logging

class Config:
    def __init__(self, config_path="config/agent_config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            logging.warning(f"Config file not found: {self.config_path}")
            logging.info("Creating default configuration...")
            
            # Create config directory if needed
            config_dir = os.path.dirname(self.config_path)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            
            # Generate safe defaults
            default_config = self._generate_default_config()
            
            # Save to file
            try:
                with open(self.config_path, 'w') as f:
                    yaml.dump(default_config, f, default_flow_style=False)
                logging.info(f"Created default config at: {self.config_path}")
            except Exception as e:
                logging.error(f"Could not write default config: {e}")
            
            return default_config
        
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            logging.warning("Using default configuration")
            return self._generate_default_config()
    
    def _generate_default_config(self):
        """Generate safe default configuration"""
        default = {
            'server': {
                'url': 'http://localhost:5000/api/v1/logs',
                'api_token': 'CHANGE_ME',
                'verify_ssl': True,
                'timeout_sec': 10
            },
            'agent': {
                'polling_interval_sec': 120,
                'buffer_path': 'agent_buffer.db',
                'max_buffer_size_mb': 100,
                'log_level': 'INFO'
            },
            'logs': {
                'windows_events': [
                    'Security',
                    'System',
                    'Application',
                    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
                    'Microsoft-Windows-Windows Defender/Operational'
                ],
                'linux_files': [
                    '/var/log/syslog',
                    '/var/log/auth.log',
                    '/var/log/secure',
                    '/var/log/messages'
                ],
                'web_server_logs': [
                    '/var/log/nginx/access.log',
                    '/var/log/apache2/access.log'
                ],
                'database_logs': [
                    '/var/log/mysql/error.log',
                    '/var/log/postgresql/postgresql-*.log'
                ],
                'dns_logs': [
                    '/var/log/named/security.log'
                ]
            },
            'network': {
                'enabled': True,
                'interval_sec': 60,
                'snapshot': True,
                'bandwidth_threshold_mb': 500,
                'enable_process_attribution': True
            },
            'features': {
                'enable_fim': True,
                'enable_network_monitoring': True,
                'enable_advanced_windows_events': True,
                'enable_linux_application_logs': True
            },
            'fim': {
                'canary_file_name': '.soc_canary',
                'monitor_directories': {
                    'windows': [
                        'C:\\\\Users\\\\*\\\\Documents',
                        'C:\\\\Users\\\\*\\\\Desktop'
                    ],
                    'linux': [
                        '/home/*/Documents',
                        '/root'
                    ]
                }
            },
            'timing': {
                'heartbeat_interval_sec': 420,  # 7 minutes
                'batch_interval_sec': 200       # 200 seconds
            },
            'tls_monitoring': {
                'enabled': False
            }
        }
        return default

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
        return self.config.get('agent', {}).get('polling_interval_sec', 120)

    @property
    def buffer_path(self):
        return self.config.get('agent', {}).get('buffer_path', 'agent_buffer.db')

    def get_windows_channels(self):
        return self.config.get('logs', {}).get('windows_events', [])

    def get_linux_files(self):
        return self.config.get('logs', {}).get('linux_files', [])
    
    # Feature toggles
    @property
    def enable_fim(self):
        return self.config.get('features', {}).get('enable_fim', False)
    
    @property
    def enable_network_monitoring(self):
        return self.config.get('features', {}).get('enable_network_monitoring', True)
    
    @property
    def enable_advanced_windows_events(self):
        return self.config.get('features', {}).get('enable_advanced_windows_events', True)
    
    @property
    def enable_linux_application_logs(self):
        return self.config.get('features', {}).get('enable_linux_application_logs', True)
    
    # FIM Configuration
    def get_fim_directories(self):
        """Get FIM monitored directories for the current OS"""
        fim_config = self.config.get('fim', {})
        monitor_dirs = fim_config.get('monitor_directories', {})
        
        if os.name == 'nt':  # Windows
            return monitor_dirs.get('windows', [])
        else:  # Linux/Unix
            return monitor_dirs.get('linux', [])
    
    def get_canary_filename(self):
        return self.config.get('fim', {}).get('canary_file_name', '.soc_canary')
    
    # Network Configuration
    def get_network_bandwidth_threshold(self):
        """Get bandwidth threshold in MB for anomaly detection"""
        return self.config.get('network', {}).get('bandwidth_threshold_mb', 500)
    
    def get_enable_process_attribution(self):
        return self.config.get('network', {}).get('enable_process_attribution', True)
    
    # Web server logs
    def get_web_server_logs(self):
        return self.config.get('logs', {}).get('web_server_logs', [])
    
    # Database logs
    def get_database_logs(self):
        return self.config.get('logs', {}).get('database_logs', [])
    
    # DNS logs
    def get_dns_logs(self):
        return self.config.get('logs', {}).get('dns_logs', [])
    
    # Timing Configuration
    @property
    def heartbeat_interval(self):
        """Get heartbeat interval in seconds (default: 420s / 7 min)"""
        return self.config.get('timing', {}).get('heartbeat_interval_sec', 420)
    
    @property
    def batch_interval(self):
        """Get log batch transmission interval in seconds (default: 200s)"""
        return self.config.get('timing', {}).get('batch_interval_sec', 200)
    
    # TLS Monitoring
    @property
    def enable_tls_monitoring(self):
        """Check if TLS monitoring is enabled"""
        return self.config.get('tls_monitoring', {}).get('enabled', False)

