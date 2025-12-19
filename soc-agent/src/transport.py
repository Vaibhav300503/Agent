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

    def _sender_loop(self):
        url = self.config.server_url
        headers = {
            'Authorization': f"Bearer {self.config.api_token}",
            'Content-Type': 'application/json'
        }
        
        while self.running:
            try:
                logs = self._get_batch(batch_size=50)
                if not logs:
                    time.sleep(1) # Wait if no logs
                    continue

                payload = [json.loads(row[1]) for row in logs]
                
                try:
                    response = requests.post(
                        url, 
                        json=payload, 
                        headers=headers, 
                        verify=self.config.verify_ssl,
                        timeout=5
                    )
                    
                    if response.status_code in [200, 201, 202]:
                        self._delete_batch([row[0] for row in logs])
                        logging.info(f"Sent {len(logs)} logs successfully")
                    else:
                        logging.warning(f"Server returned {response.status_code}: {response.text}")
                        time.sleep(5) # Backoff
                        
                except requests.exceptions.RequestException as e:
                    logging.error(f"Connection error: {e}")
                    time.sleep(5) # Backoff

            except Exception as e:
                logging.error(f"Sender loop error: {e}")
                time.sleep(5)

    def _get_batch(self, batch_size=50):
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
