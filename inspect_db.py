import sqlite3
import json
import os

db_path = "agent_buffer.db"
if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
    exit(1)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute("SELECT count(*) FROM logs_buffer")
    count = cursor.fetchone()[0]
    print(f"Total logs in buffer: {count}")
    
    if count > 0:
        cursor.execute("SELECT data FROM logs_buffer LIMIT 20")
        rows = cursor.fetchall()
        for i, row in enumerate(rows):
            try:
                data = json.loads(row[0])
                print(f"Entry {i}: timestamp={data.get('timestamp')} (type={type(data.get('timestamp')).__name__}) log_source={data.get('log_source')}")
            except Exception as je:
                print(f"Entry {i}: Error parsing JSON: {je}")
    
    conn.close()
except Exception as e:
    print(f"Error: {e}")
