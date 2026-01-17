# Log Schema Reference

Complete reference of all log fields emitted by the SOC Agent, organized by log source.

## Common Fields (All Logs)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `timestamp` | ISO 8601 | Event timestamp | `"2024-12-29T20:00:00.000Z"` |
| `hostname` | string | Agent hostname | `"WORKSTATION-01"` |
| `ip_address` | string | Agent IP address | `"192.168.1.100"` |
| `os_type` | string | Operating system | `"Windows"`, `"Linux"` |
| `log_source` | string | Log collection source | `"network_snapshot"`, `"web_server"` |
| `message` | string | Human-readable event summary | `"Connection: 192.168.1.100:54321 -> 203.0.113.50:443"` |

---

## Network Snapshot Logs

**Log Source**: `network_snapshot`

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `protocol` | string | Network protocol | ✅ |
| `src_ip` | string | Source IP address | ✅ |
| `src_port` | int | Source port | ✅ |
| `dst_ip` | string | Destination IP address | ✅ |
| `dst_port` | int | Destination port | ✅ |
| `status` | string | Connection state | ✅ |
| `duration` | float | Connection duration in seconds | ✅ (enterprise) |
| `bytes_sent` | int | Bytes sent (null if unavailable) | ✅ (enterprise) |
| `bytes_received` | int | Bytes received (null if unavailable) | ✅ (enterprise) |
| `packets_sent` | int | Packets sent (null if unavailable) | ✅ (enterprise) |
| `packets_received` | int | Packets received (null if unavailable) | ✅ (enterprise) |

**Sample JSON:**
```json
{
  "timestamp": "2024-12-29T20:00:00.000Z",
  "hostname": "WORKSTATION-01",
  "ip_address": "192.168.1.100",
  "os_type": "Windows",
  "log_source": "network_snapshot",
  "protocol": "TCP",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dst_ip": "203.0.113.50",
  "dst_port": 443,
  "status": "ESTABLISHED",
  "duration": 45.2,
  "bytes_sent": null,
  "bytes_received": null,
  "packets_sent": null,
  "packets_received": null,
  "message": "Connection: TCP 192.168.1.100:54321 -> 203.0.113.50:443 [ESTABLISHED]"
}
```

---

## HTTP/Web Server Logs

**Log Source**: `web_server`

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `event_type` | string | Always `"http_request"` | ✅ |
| `client_ip` | string | Requesting client IP | ✅ |
| `http_method` | string | HTTP method | ✅ |
| `uri` | string | Request URI (path only) | ✅ |
| `query_string` | string | Query parameters (after ?) | ✅ (enterprise) |
| `http_protocol` | string | HTTP protocol version | ✅ |
| `status_code` | int | HTTP response status | ✅ |
| `response_size` | string | Response size in bytes | ✅ |
| `referer` | string | HTTP Referer header | ✅ |
| `user_agent` | string | HTTP User-Agent header | ✅ |
| `attack_type` | string | Detected attack type (if any) | ❌ |
| `alert_severity` | string | Alert level for attacks | ❌ |

**Sample JSON:**
```json
{
  "timestamp": "2024-12-29T20:00:00.000Z",
  "hostname": "WEBSERVER-01",
  "ip_address": "10.0.0.5",
  "os_type": "Linux",
  "log_source": "web_server",
  "event_type": "http_request",
  "client_ip": "203.0.113.50",
  "http_method": "GET",
  "uri": "/api/users",
  "query_string": "id=1&page=1",
  "http_protocol": "HTTP/1.1",
  "status_code": 200,
  "response_size": "1024",
  "referer": "-",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "message": "GET /api/users?id=1&page=1 HTTP/1.1 200"
}
```

---

## Authentication Logs

**Log Source**: `authentication`, `windows_authentication`

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `event_type` | string | `authentication`, `ssh_login_success`, etc. | ✅ |
| `auth_status` | string | **Normalized**: `"success"` or `"failure"` | ✅ (enterprise) |
| `auth_method` | string | **Normalized**: `"password"`, `"publickey"`, `"network"`, etc. | ✅ (enterprise) |
| `login_type` | string | **Normalized**: `"ssh"`, `"Interactive"`, `"RemoteInteractive"`, etc. | ✅ (enterprise) |
| `auth_result` | string | Legacy: `"success"` or `"failure"` | ✅ |
| `failure_reason` | string | Reason for auth failure | ❌ |
| `username` / `account_name` | string | Authenticating user | ✅ |
| `source_ip` | string | Source IP of auth attempt | ✅ |
| `workstation` | string | Source workstation name | ❌ |

**Sample JSON (Windows):**
```json
{
  "timestamp": "2024-12-29T20:00:00.000Z",
  "hostname": "DC-01",
  "ip_address": "10.0.0.1",
  "os_type": "Windows",
  "log_source": "windows_authentication",
  "event_type": "authentication",
  "event_id": 4624,
  "auth_status": "success",
  "auth_method": "network",
  "login_type": "Network",
  "auth_result": "success",
  "account_name": "jsmith",
  "account_domain": "CORP",
  "logon_type": "Network",
  "logon_type_code": "3",
  "source_ip": "192.168.1.50"
}
```

**Sample JSON (Linux SSH):**
```json
{
  "timestamp": "2024-12-29T20:00:00.000Z",
  "hostname": "LINUX-01",
  "ip_address": "10.0.0.10",
  "os_type": "Linux",
  "log_source": "authentication",
  "event_type": "ssh_login_success",
  "auth_status": "success",
  "auth_method": "publickey",
  "login_type": "ssh",
  "username": "admin",
  "source_ip": "192.168.1.50"
}
```

---

## Heartbeat Payload

**Interval**: 420 seconds (7 minutes)

| Field | Type | Description | Required |
|-------|------|-------------|----------|
| `agent_id` | string | Unique agent identifier | ✅ |
| `hostname` | string | Agent hostname | ✅ |
| `endpoint_name` | string | Endpoint display name | ✅ |
| `ip_address` | string | Agent IP | ✅ |
| `os_type` | string | Operating system | ✅ |
| `agent_version` | string | Agent version | ✅ |
| `buffer_size_bytes` | int | Local buffer size | ✅ |
| `uptime` | int | Agent uptime in seconds | ✅ (enterprise) |
| `event_count` | int | Total events since start | ✅ (enterprise) |
| `last_log_sent_timestamp` | ISO 8601 | Last successful transmission | ✅ (enterprise) |
| `log_gap_seconds` | int | Seconds since last success | ✅ (enterprise) |
| `status` | string | `"healthy"`, `"degraded"`, `"stopping"` | ✅ (enterprise) |

**Sample JSON:**
```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "WORKSTATION-01",
  "endpoint_name": "WORKSTATION-01",
  "ip_address": "192.168.1.100",
  "os_type": "Windows",
  "agent_version": "2.1.0",
  "buffer_size_bytes": 12048,
  "uptime": 3600,
  "event_count": 1542,
  "last_log_sent_timestamp": "2024-12-29T19:58:00.000Z",
  "log_gap_seconds": 0,
  "status": "healthy",
  "timestamp": "2024-12-29T20:00:00.000Z"
}
```

---

## Timing Configuration

| Timer | Value | Purpose |
|-------|-------|---------|
| Heartbeat Interval | **420 seconds** (7 min) | Agent status reporting |
| Batch Transmission | **200 seconds** | Log batch sending |
| Polling Interval | 120 seconds (configurable) | Collector polling frequency |

---

## Field Normalization Notes

- **Timestamps**: All timestamps normalized to ISO 8601 format
- **auth_status**: Normalized to `"success"` or `"failure"` across all sources
- **auth_method**: Normalized across Windows/Linux (`"password"`, `"publickey"`, `"network"`, `"interactive"`, etc.)
- **login_type**: Maps Windows `logon_type` and Linux SSH to consistent values
