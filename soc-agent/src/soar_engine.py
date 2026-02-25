"""
SOAR Engine — Security Orchestration, Automation and Response

Agent-side risk scoring and server-side playbook execution engine.

Agent-side component:
- Risk scoring based on geo, severity, direction, port, ASN
- Enriches logs with risk metadata before sending to server

Server-side component:  
- Playbook trigger evaluation
- Idempotency guards (Redis)
- Rate limiting
- Response connectors (Firewall, TheHive, Slack, Email)

Zero external dependencies for agent-side risk scoring.
Server-side requires: redis (optional for idempotency/rate-limiting)
"""

import json
import time
import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


# =========================================================================== #
#  PART A — AGENT-SIDE: Risk Scoring (runs inside agent pipeline)             #
# =========================================================================== #

# Country risk scores — ISO 3166-1 alpha-2 → points (0-30)
COUNTRY_RISK_SCORES = {
    'KP': 30,                          # North Korea
    'RU': 25, 'CN': 25, 'IR': 25,     # High-risk
    'NG': 20, 'PK': 20, 'VN': 20,     # Elevated
    'RO': 15, 'UA': 15, 'BY': 15,     # Moderate
    'BR': 10, 'IN': 10, 'TR': 10,     # Baseline elevated
}

# Severity → risk points (0-40)
SEVERITY_SCORES = {
    'critical': 40,
    'high': 25,
    'medium': 10,
    'low': 5,
    'info': 0,
}

# Sensitive destination ports → risk points (0-15)
SENSITIVE_PORTS = {
    3389: 15,   # RDP
    22: 10,     # SSH
    445: 15,    # SMB
    1433: 12,   # MSSQL
    3306: 12,   # MySQL
    5432: 12,   # PostgreSQL
    5900: 10,   # VNC
    23: 10,     # Telnet
    21: 8,      # FTP
    8080: 5,    # Alt HTTP
    8443: 5,    # Alt HTTPS
}

# Known hosting / VPN / proxy ASNs (flag as suspicious)
SUSPICIOUS_ASNS = {
    'AS14061',  # DigitalOcean
    'AS16276',  # OVH
    'AS24940',  # Hetzner
    'AS63949',  # Linode
    'AS13335',  # Cloudflare (when used as proxy origin)
    'AS14618',  # Amazon AWS
    'AS15169',  # Google Cloud
    'AS8075',   # Microsoft Azure
    'AS396982', # Google Cloud
    'AS20473',  # Vultr
}

# Event types with inherent risk
HIGH_RISK_EVENTS = {
    'authentication_failure': 10,
    'privilege_escalation': 15,
    'malware_detected': 20,
    'policy_violation': 10,
    'data_exfiltration': 20,
    'unauthorized_access': 15,
    'brute_force': 15,
    'port_scan': 10,
}

# Minimum risk score threshold for SOAR eligibility
SOAR_THRESHOLD = 70


def compute_risk_score(enriched_log: Dict[str, Any],
                       threat_intel_lookup: Callable = None) -> Dict[str, Any]:
    """
    Compute a composite risk score for an enriched log entry.

    Scoring dimensions:
    1. Geo risk — country-based risk score (0-30 pts)
    2. Severity — log severity multiplier (0-40 pts)
    3. Direction — inbound traffic bonus (0-10 pts)
    4. Port sensitivity — target port risk (0-15 pts)
    5. ASN risk — suspicious hosting/VPN provider (0-20 pts)
    6. Event type — inherent event risk (0-20 pts)
    7. Threat intel — external reputation (0-30 pts)

    Total: capped at 100

    Args:
        enriched_log: Log entry already enriched with source/destination/geo
        threat_intel_lookup: Optional callable(ip) -> dict with 'malicious', 'confidence', 'category'

    Returns:
        Risk dict: {score, level, factors, soar_eligible}
    """
    score = 0
    factors = []

    source = enriched_log.get('source', {})
    destination = enriched_log.get('destination', {})
    geo = source.get('geo', {}) if isinstance(source, dict) else {}
    network = enriched_log.get('network', {})
    severity = enriched_log.get('severity_level',
                enriched_log.get('severity', 'info'))
    if severity:
        severity = severity.lower()

    # ----- Factor 1: Geo Risk (0-30 pts) ----- #
    country_code = geo.get('country_code', '') if isinstance(geo, dict) else ''
    geo_points = COUNTRY_RISK_SCORES.get(country_code, 0)
    if geo_points:
        score += geo_points
        factors.append({
            'factor': 'country_risk',
            'value': country_code,
            'points': geo_points,
        })

    # ----- Factor 2: Severity (0-40 pts) ----- #
    sev_points = SEVERITY_SCORES.get(severity, 0)
    if sev_points:
        score += sev_points
        factors.append({
            'factor': 'severity',
            'value': severity,
            'points': sev_points,
        })

    # ----- Factor 3: Direction (0-10 pts) ----- #
    direction = network.get('direction', 'unknown')
    if direction == 'inbound':
        score += 10
        factors.append({
            'factor': 'direction',
            'value': 'inbound',
            'points': 10,
        })
    elif direction == 'external':
        score += 5
        factors.append({
            'factor': 'direction',
            'value': 'external',
            'points': 5,
        })

    # ----- Factor 4: Sensitive Port (0-15 pts) ----- #
    dst_port = destination.get('port') if isinstance(destination, dict) else None
    port_points = SENSITIVE_PORTS.get(dst_port, 0)
    if port_points:
        score += port_points
        factors.append({
            'factor': 'port_sensitive',
            'value': dst_port,
            'points': port_points,
        })

    # ----- Factor 5: ASN Risk (0-20 pts) ----- #
    asn = geo.get('asn', '') if isinstance(geo, dict) else ''
    if asn and asn in SUSPICIOUS_ASNS:
        score += 20
        factors.append({
            'factor': 'suspicious_asn',
            'value': asn,
            'points': 20,
        })

    # ----- Factor 6: Event Type Risk (0-20 pts) ----- #
    event_type = enriched_log.get('event_type', '')
    event_points = HIGH_RISK_EVENTS.get(event_type, 0)
    if event_points:
        score += event_points
        factors.append({
            'factor': 'event_type',
            'value': event_type,
            'points': event_points,
        })

    # ----- Factor 7: Threat Intel (0-30 pts) ----- #
    if threat_intel_lookup and isinstance(source, dict):
        src_ip = source.get('ip')
        if src_ip and not source.get('is_private', True):
            try:
                intel = threat_intel_lookup(src_ip)
                if intel and intel.get('malicious'):
                    confidence = intel.get('confidence', 50)
                    ti_points = int(min(confidence * 0.3, 30))
                    score += ti_points
                    factors.append({
                        'factor': 'threat_intel',
                        'value': intel.get('category', 'malicious'),
                        'points': ti_points,
                    })
            except Exception as e:
                logger.debug(f"Threat intel lookup failed for {src_ip}: {e}")

    # ----- Compute Final Score ----- #
    score = min(score, 100)

    if score >= 80:
        level = 'critical'
    elif score >= 60:
        level = 'high'
    elif score >= 40:
        level = 'medium'
    elif score >= 20:
        level = 'low'
    else:
        level = 'info'

    return {
        'score': score,
        'level': level,
        'factors': factors,
        'soar_eligible': score >= SOAR_THRESHOLD,
    }


def enrich_log_risk(log_entry: Dict[str, Any],
                    threat_intel_lookup: Callable = None) -> Dict[str, Any]:
    """
    Add risk scoring to an enriched log entry.
    Call AFTER ip_resolver and geo_enricher have run.

    Args:
        log_entry: Enriched log entry with source/destination/geo
        threat_intel_lookup: Optional threat intel callable

    Returns:
        Log entry with 'risk' field added
    """
    if log_entry is None:
        log_entry = {}
    try:
        risk = compute_risk_score(log_entry, threat_intel_lookup)
        log_entry['risk'] = risk
    except Exception as e:
        logger.debug(f"Risk scoring skipped: {e}")
        log_entry['risk'] = {
            'score': 0, 'level': 'info',
            'factors': [], 'soar_eligible': False,
        }
    return log_entry


# =========================================================================== #
#  PART B — SERVER-SIDE: Playbook Engine (runs on central server)             #
# =========================================================================== #

class PlaybookAction:
    """Base class for a SOAR playbook action."""

    ACTION_TYPE = "base"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError


class BlockIPAction(PlaybookAction):
    """Block an IP address via firewall API."""

    ACTION_TYPE = "block_ip"

    def __init__(self, firewall_api_url: str = None, api_key: str = None):
        self.api_url = firewall_api_url
        self.api_key = api_key

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        source_ip = context.get('source_ip')
        alert_id = context.get('alert_id')
        duration = context.get('duration_hours', 24)

        if not source_ip:
            return {'status': 'error', 'reason': 'no_source_ip'}

        logger.info(f"SOAR: Blocking IP {source_ip} for {duration}h (alert: {alert_id})")

        # If firewall API is configured, call it
        if self.api_url:
            try:
                import requests
                response = requests.post(
                    f"{self.api_url}/block",
                    json={
                        'ip': source_ip,
                        'duration_hours': duration,
                        'reason': f"SOAR automated block — alert {alert_id}",
                    },
                    headers={'Authorization': f'Bearer {self.api_key}'},
                    timeout=10,
                )
                return {
                    'status': 'executed',
                    'http_status': response.status_code,
                    'response': response.text[:200],
                }
            except Exception as e:
                logger.error(f"Firewall API call failed: {e}")
                return {'status': 'error', 'reason': str(e)}

        # Dry-run mode (no API configured)
        return {'status': 'dry_run', 'ip': source_ip, 'duration_hours': duration}


class CreateTicketAction(PlaybookAction):
    """Create an incident ticket in TheHive or similar ITSM."""

    ACTION_TYPE = "create_ticket"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        alert = context.get('alert', {})
        logger.info(f"SOAR: Creating ticket for alert {alert.get('alert_id')}")

        return {
            'status': 'delegated',
            'handler': 'thehive_worker',
            'alert_id': alert.get('alert_id'),
        }


class NotifySlackAction(PlaybookAction):
    """Send notification to Slack channel."""

    ACTION_TYPE = "notify_slack"

    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        channel = context.get('channel', '#soc-alerts')
        message = context.get('message', 'SOAR Alert')

        logger.info(f"SOAR: Notifying Slack {channel}: {message}")

        if self.webhook_url:
            try:
                import requests
                response = requests.post(
                    self.webhook_url,
                    json={'channel': channel, 'text': message},
                    timeout=5,
                )
                return {'status': 'sent', 'http_status': response.status_code}
            except Exception as e:
                return {'status': 'error', 'reason': str(e)}

        return {'status': 'dry_run', 'message': message}


class NotifyEmailAction(PlaybookAction):
    """Send email notification."""

    ACTION_TYPE = "notify_email"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        recipients = context.get('recipients', [])
        subject = context.get('subject', 'SOC Alert')
        body = context.get('body', '')

        logger.info(f"SOAR: Sending email to {recipients}: {subject}")

        # Email sending would go through SMTP or an API
        return {
            'status': 'queued',
            'recipients': recipients,
            'subject': subject,
        }


# --------------------------------------------------------------------------- #
#  Playbook Definition                                                        #
# --------------------------------------------------------------------------- #
class Playbook:
    """
    A SOAR playbook defines trigger conditions and a sequence of actions.
    """

    def __init__(self, playbook_id: str, name: str,
                 trigger_conditions: Dict[str, Any],
                 actions: List[PlaybookAction]):
        self.playbook_id = playbook_id
        self.name = name
        self.trigger_conditions = trigger_conditions
        self.actions = actions

    def should_trigger(self, enriched_log: Dict[str, Any],
                       alert: Dict[str, Any] = None) -> bool:
        """Evaluate whether this playbook should fire for the given log/alert."""
        conds = self.trigger_conditions
        risk = enriched_log.get('risk', {})
        source = enriched_log.get('source', {})
        network = enriched_log.get('network', {})
        geo = source.get('geo', {}) if isinstance(source, dict) else {}

        # Minimum risk score
        min_score = conds.get('min_risk_score', 0)
        if risk.get('score', 0) < min_score:
            return False

        # Direction filter
        required_direction = conds.get('direction')
        if required_direction and network.get('direction') != required_direction:
            return False

        # Source must be public
        if conds.get('source_is_public') and source.get('is_private', True):
            return False

        # Country filter
        country_list = conds.get('country_codes')
        if country_list and geo.get('country_code', '') not in country_list:
            return False

        # Severity filter
        severity_list = conds.get('severity')
        if severity_list:
            log_severity = enriched_log.get('severity_level',
                            enriched_log.get('severity', 'info'))
            if log_severity and log_severity.lower() not in severity_list:
                return False

        # Event type filter
        event_types = conds.get('event_types')
        if event_types:
            if enriched_log.get('event_type', '') not in event_types:
                return False

        return True


# --------------------------------------------------------------------------- #
#  Idempotency Guard (Redis-backed)                                           #
# --------------------------------------------------------------------------- #
class IdempotencyGuard:
    """
    Prevents duplicate SOAR actions using Redis with TTL.
    Falls back to in-memory dict if Redis is unavailable.
    """

    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._memory_store: Dict[str, float] = {}  # fallback

    def was_action_taken(self, action_type: str, target: str,
                         window_hours: int = 24) -> bool:
        """Check if this action+target was already executed within the window."""
        key = f"soar:idem:{action_type}:{target}"

        if self._redis:
            return bool(self._redis.exists(key))

        # In-memory fallback
        expires = self._memory_store.get(key, 0)
        return time.time() < expires

    def record_action(self, action_type: str, target: str,
                      result: Dict[str, Any], ttl_hours: int = 24):
        """Record that an action was taken (auto-expires after TTL)."""
        key = f"soar:idem:{action_type}:{target}"
        ttl = ttl_hours * 3600
        payload = json.dumps({
            'action': action_type,
            'target': target,
            'result': result,
            'timestamp': datetime.utcnow().isoformat(),
        })

        if self._redis:
            self._redis.setex(key, ttl, payload)
        else:
            self._memory_store[key] = time.time() + ttl

    def actions_in_window(self, action_type: str,
                          window_minutes: int = 5) -> int:
        """Count total actions of this type in the sliding window."""
        key = f"soar:rate:{action_type}"

        if self._redis:
            count = self._redis.get(key)
            return int(count) if count else 0

        count = self._memory_store.get(key, 0)
        return int(count) if isinstance(count, (int, float)) else 0

    def increment_rate(self, action_type: str, window_minutes: int = 5):
        """Increment rate counter with auto-expiring window."""
        key = f"soar:rate:{action_type}"

        if self._redis:
            pipe = self._redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_minutes * 60)
            pipe.execute()
        else:
            current = self._memory_store.get(key, 0)
            self._memory_store[key] = current + 1


# --------------------------------------------------------------------------- #
#  Rate Limiter                                                               #
# --------------------------------------------------------------------------- #

# Default rate limits
RATE_LIMITS = {
    'block_ip':       {'max_actions': 10, 'window_minutes': 5},
    'create_ticket':  {'max_actions': 20, 'window_minutes': 60},
    'notify_slack':   {'max_actions': 30, 'window_minutes': 15},
    'notify_email':   {'max_actions': 10, 'window_minutes': 15},
    'isolate':        {'max_actions': 5,  'window_minutes': 10},
    '_global':        {'max_actions': 50, 'window_minutes': 15},
}


# --------------------------------------------------------------------------- #
#  SOAR Orchestrator                                                          #
# --------------------------------------------------------------------------- #
class SOAROrchestrator:
    """
    Central SOAR orchestrator that evaluates playbooks against alerts,
    enforces idempotency and rate limits, and executes response actions.
    """

    def __init__(self, redis_client=None):
        self.playbooks: List[Playbook] = []
        self.guard = IdempotencyGuard(redis_client)
        self._execution_log: List[Dict] = []

    def register_playbook(self, playbook: Playbook):
        """Register a playbook for evaluation."""
        self.playbooks.append(playbook)
        logger.info(f"SOAR: Registered playbook '{playbook.name}' ({playbook.playbook_id})")

    def evaluate_and_execute(self, enriched_log: Dict[str, Any],
                             alert: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Evaluate all registered playbooks and execute matching ones.

        Returns list of execution results.
        """
        results = []

        for playbook in self.playbooks:
            if not playbook.should_trigger(enriched_log, alert):
                continue

            logger.info(f"SOAR: Playbook '{playbook.name}' triggered")

            # Check global rate limit
            global_limit = RATE_LIMITS.get('_global', {})
            if self.guard.actions_in_window('_global',
                    global_limit.get('window_minutes', 15)) >= global_limit.get('max_actions', 50):
                logger.warning("SOAR: Global rate limit reached — skipping all actions")
                results.append({
                    'playbook': playbook.playbook_id,
                    'status': 'rate_limited',
                    'reason': 'global_limit',
                })
                break

            for action in playbook.actions:
                action_result = self._execute_action(
                    action, enriched_log, alert, playbook
                )
                results.append({
                    'playbook': playbook.playbook_id,
                    'action': action.ACTION_TYPE,
                    **action_result,
                })

        return results

    def _execute_action(self, action: PlaybookAction,
                        enriched_log: Dict[str, Any],
                        alert: Dict[str, Any],
                        playbook: Playbook) -> Dict[str, Any]:
        """Execute a single action with idempotency and rate limit checks."""
        action_type = action.ACTION_TYPE
        source = enriched_log.get('source', {})
        target = source.get('ip', 'unknown') if isinstance(source, dict) else 'unknown'

        # 1. Idempotency check
        if self.guard.was_action_taken(action_type, target):
            logger.info(f"SOAR: Skipping {action_type} on {target} — already executed")
            return {'status': 'skipped', 'reason': 'idempotent'}

        # 2. Rate limit check
        limit = RATE_LIMITS.get(action_type, {})
        max_actions = limit.get('max_actions', 100)
        window = limit.get('window_minutes', 5)
        if self.guard.actions_in_window(action_type, window) >= max_actions:
            logger.warning(f"SOAR: Rate limit for {action_type} reached ({max_actions}/{window}m)")
            return {'status': 'rate_limited', 'reason': f'{action_type}_limit'}

        # 3. Build context
        context = {
            'source_ip': target,
            'alert_id': alert.get('alert_id') if alert else None,
            'alert': alert or {},
            'enriched_log': enriched_log,
            'playbook_id': playbook.playbook_id,
            'channel': '#soc-alerts',
            'message': self._build_notification_message(enriched_log, alert, playbook),
            'duration_hours': 24,
        }

        # 4. Execute
        try:
            result = action.execute(context)
        except Exception as e:
            logger.error(f"SOAR action {action_type} failed: {e}")
            result = {'status': 'error', 'reason': str(e)}

        # 5. Record for idempotency + rate tracking
        self.guard.record_action(action_type, target, result)
        self.guard.increment_rate(action_type)
        self.guard.increment_rate('_global')

        # 6. Log execution
        execution_record = {
            'timestamp': datetime.utcnow().isoformat(),
            'playbook': playbook.playbook_id,
            'action': action_type,
            'target': target,
            'result': result,
        }
        self._execution_log.append(execution_record)

        return result

    @staticmethod
    def _build_notification_message(enriched_log: Dict, alert: Dict,
                                     playbook: Playbook) -> str:
        """Build a human-readable notification message."""
        source = enriched_log.get('source', {})
        geo = source.get('geo', {}) if isinstance(source, dict) else {}
        risk = enriched_log.get('risk', {})

        parts = [
            f"SOAR Alert: {playbook.name}",
            f"Source: {source.get('ip', 'unknown')}",
        ]
        if geo.get('country'):
            parts.append(f"Country: {geo['country']} ({geo.get('country_code', '')})")
        if geo.get('isp'):
            parts.append(f"ISP: {geo['isp']}")
        if risk.get('score'):
            parts.append(f"Risk: {risk['score']}/100 ({risk.get('level', 'unknown')})")
        if alert and alert.get('rule_name'):
            parts.append(f"Rule: {alert['rule_name']}")

        return " | ".join(parts)

    @property
    def execution_history(self) -> List[Dict]:
        return list(self._execution_log)


# --------------------------------------------------------------------------- #
#  Pre-built Playbook Definitions                                             #
# --------------------------------------------------------------------------- #

def create_default_playbooks(firewall_api_url: str = None,
                              firewall_api_key: str = None,
                              slack_webhook: str = None) -> List[Playbook]:
    """
    Create a set of production-ready default SOAR playbooks.

    Returns list of Playbook instances ready to register.
    """
    playbooks = []

    # --- Playbook 1: Geo Anomaly (High-Risk Country + High Severity) --- #
    playbooks.append(Playbook(
        playbook_id='pb-geo-anomaly',
        name='Geo Anomaly — High-Risk Country Attack',
        trigger_conditions={
            'min_risk_score': 70,
            'direction': 'inbound',
            'source_is_public': True,
            'country_codes': list(COUNTRY_RISK_SCORES.keys()),
            'severity': ['high', 'critical'],
        },
        actions=[
            BlockIPAction(firewall_api_url, firewall_api_key),
            CreateTicketAction(),
            NotifySlackAction(slack_webhook),
        ],
    ))

    # --- Playbook 2: Brute Force Attack --- #
    playbooks.append(Playbook(
        playbook_id='pb-brute-force',
        name='Brute Force Attack Response',
        trigger_conditions={
            'min_risk_score': 60,
            'source_is_public': True,
            'event_types': ['authentication_failure', 'brute_force'],
            'severity': ['high', 'critical'],
        },
        actions=[
            BlockIPAction(firewall_api_url, firewall_api_key),
            CreateTicketAction(),
            NotifySlackAction(slack_webhook),
            NotifyEmailAction(),
        ],
    ))

    # --- Playbook 3: Suspicious ASN / VPN Source --- #
    playbooks.append(Playbook(
        playbook_id='pb-suspicious-asn',
        name='Suspicious ASN / VPN Detection',
        trigger_conditions={
            'min_risk_score': 50,
            'direction': 'inbound',
            'source_is_public': True,
        },
        actions=[
            NotifySlackAction(slack_webhook),
            CreateTicketAction(),
        ],
    ))

    # --- Playbook 4: Critical Severity Immediate Response --- #
    playbooks.append(Playbook(
        playbook_id='pb-critical-response',
        name='Critical Severity — Immediate Response',
        trigger_conditions={
            'min_risk_score': 80,
            'severity': ['critical'],
        },
        actions=[
            BlockIPAction(firewall_api_url, firewall_api_key),
            CreateTicketAction(),
            NotifySlackAction(slack_webhook),
            NotifyEmailAction(),
        ],
    ))

    return playbooks
