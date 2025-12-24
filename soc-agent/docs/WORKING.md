# Internal Architecture & Working

This document explains the data flow and internal logic of the SOC Agent and Server.

## 🔄 High-Level Data Flow

1.  **Collection**: Collectors (Windows, Linux, Network, FIM) gather raw data from the OS.
2.  **Sanitization**: Data passes through `sanitizer.py` to normalize timestamps and escape dangerous characters.
3.  **Buffering**: Sanitized logs are stored in a local SQLite database (`agent_buffer.db`) via `transport.py`.
4.  **Transmission**: A background thread in `transport.py` batches logs from the buffer and sends them to the Server via HTTPS.
5.  **Ingestion**: Server receives logs via the `/api/v1/logs` endpoint and pushes them into a **Redis Queue**.
6.  **Processing**: Workers pull from Redis:
    - **Parser Worker**: Normalizes raw strings into JSON objects.
    - **Enricher Worker**: Adds GeoIP data and hostname metadata.
    - **Detector Worker**: Matches logs against the Rule Engine (MongoDB `rules` collection).
7.  **Alerting**: If a rule threshold is met, an alert is generated and stored. High-severity alerts are pushed to **TheHive**.

---

## 🕵️‍♂️ Collector Implementation Details

### Windows Collector (`windows.py`)
Uses the `win32evtlog` Python library to read Windows Event Channels.
- It maintains "checkpoints" using the `RecordId` and `TimeGenerated` to avoid reading the same log twice.
- Specialized parsers look for specific Event IDs (e.g., 4624 for Login) and extract key fields like Source IP and Account Name.

### Linux Collector (`linux.py`)
Tails log files by tracking file offsets.
- It detects file rotations (when a file is truncated).
- Uses regex patterns for standard formats like Syslog, Nginx access logs, and Auth logs.

### Network Collector (`network.py`)
Uses the `psutil` library.
- Periodically scans all socket connections.
- Compares the current snapshot with the previous one to detect new connections.

### FIM Collector (`fim.py`)
Uses the `watchdog` library.
- Subscribes to OS-level file system events.
- Provides real-time notifications on file modifications without polling.

---

## 🛡 Security & Sanitization

The `sanitizer.py` module is a critical security component. It:
- **Prevents SQL Injection**: Scans all incoming log fields for patterns like `UNION SELECT`, `' OR '1'='1`, etc.
- **HTML Escaping**: Escapes `<` and `>` to prevent XSS if logs are viewed in a web dashboard.
- **Length Enforcement**: Truncates extremely long logs to prevent memory exhaustion or DoS attacks on the server.
- **Normalization**: Ensures every log has a valid ISO 8601 timestamp, making it easy to query in MongoDB.

---

## 📊 Database Schema (MongoDB)

- `raw_logs`: Incoming logs before processing.
- `processed_events`: Normalized and enriched logs.
- `rules`: Detection logic (Condition, Threshold, Severity).
- `alerts`: Generated security alerts.
- `agents`: Metadata for all registered agents and their heartbeat status.
