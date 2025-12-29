import sqlite3
import time
import json
import logging
import threading
import requests
import os
from datetime import datetime

class Transport:
    def __init__(self, config):
        self.config = config
        self.db_path = config.buffer_path
        self._init_db()
        self.running = False
        self.lock = threading.Lock()
        
        # Enhanced tracking for enterprise telemetry
        self._event_count = 0
        self._last_log_sent_timestamp = None
        self._last_send_attempt_time = time.time()
        self._log_gap_seconds = 0
        self._batch_interval = getattr(config, 'batch_interval', 200)  # 200 seconds default

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS logs_buffer (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                conn.commit()
        except Exception as e:
            logging.error(f"Failed to init DB: {e}")

    def buffer_log(self, log_dict):
        """Add a log entry to the local buffer"""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('INSERT INTO logs_buffer (data) VALUES (?)', (json.dumps(log_dict),))
                    conn.commit()
                self._event_count += 1
        except Exception as e:
            logging.error(f"Failed to buffer log: {e}")

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._sender_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=2)

    # --- Enhanced tracking methods for heartbeat ---
    def get_event_count(self):
        """Get total events buffered since agent start"""
        return self._event_count
    
    def get_last_sent_timestamp(self):
        """Get ISO timestamp of last successful log transmission"""
        return self._last_log_sent_timestamp
    
    def get_log_gap_seconds(self):
        """Get seconds since last successful transmission (for offline detection)"""
        return self._log_gap_seconds

    def send_heartbeat(self, heartbeat_data):
        """Send a heartbeat signal to the server"""
        url = self.config.server_url.replace("/api/v1/logs", "/api/v1/heartbeat")
        headers = {
            'Authorization': f"Bearer {self.config.api_token}",
            'Content-Type': 'application/json'
        }
        
        try:
            # Add agent_id if not present
            if 'agent_id' not in heartbeat_data:
                from utils import get_agent_id
                heartbeat_data['agent_id'] = get_agent_id()
                
            response = requests.post(
                url, 
                json=heartbeat_data, 
                headers=headers, 
                verify=self.config.verify_ssl,
                timeout=5
            )
            
            if response.status_code in [200, 201]:
                logging.debug("Heartbeat sent successfully")
                return True
            else:
                logging.warning(f"Heartbeat failed with status {response.status_code}")
                return False
                
        except Exception as e:
            logging.error(f"Error sending heartbeat: {e}")
            return False

    def _sender_loop(self):
        """Main sender loop with batch interval timing"""
        url = self.config.server_url
        headers = {
            'Authorization': f"Bearer {self.config.api_token}",
            'Content-Type': 'application/json'
        }
        
        last_batch_time = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Check if batch interval has elapsed OR buffer has significant logs
                logs = self._get_batch(batch_size=100)
                time_since_last_batch = current_time - last_batch_time
                
                # Send batch if: interval elapsed AND logs exist, OR buffer is large (>50 logs)
                should_send = (time_since_last_batch >= self._batch_interval and logs) or len(logs) >= 50
                
                if not logs:
                    time.sleep(5)  # Wait if no logs
                    continue
                
                if not should_send:
                    time.sleep(5)  # Wait for batch interval
                    continue

                payload = [json.loads(row[1]) for row in logs]
                
                try:
                    response = requests.post(
                        url, 
                        json=payload, 
                        headers=headers, 
                        verify=self.config.verify_ssl,
                        timeout=10
                    )
                    
                    if response.status_code in [200, 201, 202]:
                        self._delete_batch([row[0] for row in logs])
                        self._last_log_sent_timestamp = datetime.now().isoformat()
                        self._log_gap_seconds = 0
                        last_batch_time = time.time()
                        logging.info(f"Sent {len(logs)} logs successfully (batch interval: {self._batch_interval}s)")
                    elif response.status_code == 422:
                        logging.error(f"Server rejected logs with 422 (Validation Error). Skipping batch. Detail: {response.text}")
                        self._delete_batch([row[0] for row in logs])
                    else:
                        logging.warning(f"Server returned {response.status_code}: {response.text}")
                        self._log_gap_seconds = int(time.time() - self._last_send_attempt_time)
                        time.sleep(10)  # Backoff

                        
                except requests.exceptions.RequestException as e:
                    logging.error(f"Connection error: {e}")
                    self._log_gap_seconds = int(time.time() - (self._last_send_attempt_time or time.time()))
                    time.sleep(10)  # Backoff

            except Exception as e:
                logging.error(f"Sender loop error: {e}")
                time.sleep(10)

    def _get_batch(self, batch_size=100):
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT id, data FROM logs_buffer ORDER BY id ASC LIMIT ?', (batch_size,))
                    return cursor.fetchall()
        except Exception as e:
            logging.error(f"DB Read Error: {e}")
            return []

    def _delete_batch(self, ids):
        if not ids: return
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    placeholders = ','.join(['?'] * len(ids))
                    conn.execute(f'DELETE FROM logs_buffer WHERE id IN ({placeholders})', ids)
                    conn.commit()
        except Exception as e:
            logging.error(f"DB Delete Error: {e}")

