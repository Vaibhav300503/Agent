#!/usr/bin/env python3
"""
Unit tests for SOAR Engine — Risk scoring, playbook evaluation,
idempotency guards, rate limiting, and orchestrator.
"""

import sys
import os
import unittest
import json
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from soar_engine import (
    compute_risk_score,
    enrich_log_risk,
    COUNTRY_RISK_SCORES,
    SEVERITY_SCORES,
    SENSITIVE_PORTS,
    SUSPICIOUS_ASNS,
    HIGH_RISK_EVENTS,
    SOAR_THRESHOLD,
    Playbook,
    BlockIPAction,
    CreateTicketAction,
    NotifySlackAction,
    NotifyEmailAction,
    IdempotencyGuard,
    SOAROrchestrator,
    create_default_playbooks,
)


# =========================================================================== #
#  Test Risk Scoring (Agent-Side)                                             #
# =========================================================================== #

class TestRiskScoring(unittest.TestCase):
    """Test the compute_risk_score function."""

    def test_empty_log_scores_zero(self):
        """An empty log should produce a zero risk score."""
        result = compute_risk_score({})
        self.assertEqual(result['score'], 0)
        self.assertEqual(result['level'], 'info')
        self.assertFalse(result['soar_eligible'])

    def test_high_risk_country(self):
        """Known high-risk country should contribute geo points."""
        log = {
            'source': {'ip': '203.0.113.1', 'is_private': False, 'geo': {
                'country_code': 'RU', 'country': 'Russia'
            }},
        }
        result = compute_risk_score(log)
        geo_factor = next(f for f in result['factors'] if f['factor'] == 'country_risk')
        self.assertEqual(geo_factor['points'], 25)
        self.assertGreater(result['score'], 0)

    def test_critical_severity(self):
        """Critical severity should add 40 points."""
        log = {'severity_level': 'critical'}
        result = compute_risk_score(log)
        sev_factor = next(f for f in result['factors'] if f['factor'] == 'severity')
        self.assertEqual(sev_factor['points'], 40)

    def test_inbound_direction(self):
        """Inbound direction adds 10 points."""
        log = {'network': {'direction': 'inbound'}}
        result = compute_risk_score(log)
        dir_factor = next(f for f in result['factors'] if f['factor'] == 'direction')
        self.assertEqual(dir_factor['points'], 10)

    def test_sensitive_port_rdp(self):
        """RDP port 3389 should add 15 points."""
        log = {'destination': {'port': 3389}}
        result = compute_risk_score(log)
        port_factor = next(f for f in result['factors'] if f['factor'] == 'port_sensitive')
        self.assertEqual(port_factor['points'], 15)

    def test_sensitive_port_ssh(self):
        """SSH port 22 should add 10 points."""
        log = {'destination': {'port': 22}}
        result = compute_risk_score(log)
        port_factor = next(f for f in result['factors'] if f['factor'] == 'port_sensitive')
        self.assertEqual(port_factor['points'], 10)

    def test_non_sensitive_port(self):
        """Non-sensitive port (e.g., 443) should add 0 points."""
        log = {'destination': {'port': 443}}
        result = compute_risk_score(log)
        port_factors = [f for f in result['factors'] if f['factor'] == 'port_sensitive']
        self.assertEqual(len(port_factors), 0)

    def test_suspicious_asn(self):
        """Known hosting/VPN ASN adds 20 points."""
        log = {
            'source': {'ip': '1.2.3.4', 'geo': {'asn': 'AS14061'}},
        }
        result = compute_risk_score(log)
        asn_factor = next(f for f in result['factors'] if f['factor'] == 'suspicious_asn')
        self.assertEqual(asn_factor['points'], 20)

    def test_high_risk_event_type(self):
        """High risk event types add event points."""
        log = {'event_type': 'malware_detected'}
        result = compute_risk_score(log)
        event_factor = next(f for f in result['factors'] if f['factor'] == 'event_type')
        self.assertEqual(event_factor['points'], 20)

    def test_score_capped_at_100(self):
        """Score should never exceed 100 even with all factors maxed."""
        log = {
            'source': {'ip': '1.2.3.4', 'is_private': False, 'geo': {
                'country_code': 'KP', 'asn': 'AS14061'
            }},
            'destination': {'port': 3389},
            'network': {'direction': 'inbound'},
            'severity_level': 'critical',
            'event_type': 'malware_detected',
        }
        result = compute_risk_score(log)
        self.assertLessEqual(result['score'], 100)

    def test_soar_eligible_threshold(self):
        """Score >= 70 should be SOAR eligible."""
        # Build a log that scores exactly at threshold
        log = {
            'source': {'ip': '1.2.3.4', 'geo': {'country_code': 'RU'}},
            'severity_level': 'high',  # 25 pts
            'network': {'direction': 'inbound'},  # 10 pts
            'destination': {'port': 3389},  # 15 pts
            # RU: 25 + high: 25 + inbound: 10 + RDP: 15 = 75
        }
        result = compute_risk_score(log)
        self.assertTrue(result['soar_eligible'])
        self.assertGreaterEqual(result['score'], SOAR_THRESHOLD)

    def test_risk_levels(self):
        """Test all risk level thresholds."""
        # Info (0-19)
        self.assertEqual(compute_risk_score({})['level'], 'info')
        # Low (20-39)
        self.assertEqual(compute_risk_score({'severity_level': 'high'})['level'], 'low')
        # Medium (40-59)
        log = {
            'severity_level': 'critical',  # 40
        }
        self.assertEqual(compute_risk_score(log)['level'], 'medium')
        # High (60-79)
        log = {
            'severity_level': 'critical',  # 40
            'source': {'geo': {'asn': 'AS14061'}},  # 20
        }
        self.assertEqual(compute_risk_score(log)['level'], 'high')

    def test_threat_intel_lookup(self):
        """Threat intel callback should contribute points."""
        def mock_threat_intel(ip):
            return {'malicious': True, 'confidence': 100, 'category': 'botnet'}

        log = {
            'source': {'ip': '1.2.3.4', 'is_private': False},
        }
        result = compute_risk_score(log, threat_intel_lookup=mock_threat_intel)
        ti_factor = next(f for f in result['factors'] if f['factor'] == 'threat_intel')
        self.assertEqual(ti_factor['points'], 30)  # 100 * 0.3 = 30

    def test_threat_intel_skips_private(self):
        """Threat intel should NOT be looked up for private IPs."""
        call_count = [0]
        def mock_threat_intel(ip):
            call_count[0] += 1
            return {'malicious': True, 'confidence': 100}

        log = {
            'source': {'ip': '192.168.1.1', 'is_private': True},
        }
        compute_risk_score(log, threat_intel_lookup=mock_threat_intel)
        self.assertEqual(call_count[0], 0)

    def test_severity_fallback_to_severity_field(self):
        """Should fall back to 'severity' if 'severity_level' is missing."""
        log = {'severity': 'high'}
        result = compute_risk_score(log)
        sev_factor = next(f for f in result['factors'] if f['factor'] == 'severity')
        self.assertEqual(sev_factor['points'], 25)


class TestEnrichLogRisk(unittest.TestCase):
    """Test the enrich_log_risk helper function."""

    def test_adds_risk_field(self):
        """Should add 'risk' key to the log entry."""
        log = {'message': 'test'}
        result = enrich_log_risk(log)
        self.assertIn('risk', result)
        self.assertIn('score', result['risk'])
        self.assertIn('level', result['risk'])
        self.assertIn('factors', result['risk'])
        self.assertIn('soar_eligible', result['risk'])

    def test_graceful_on_bad_input(self):
        """Should not crash on bad input, just return zero risk."""
        result = enrich_log_risk(None)
        self.assertIn('risk', result)
        # We accept either 0-score or graceful fallback


# =========================================================================== #
#  Test Playbook Trigger Evaluation                                          #
# =========================================================================== #

class TestPlaybookTrigger(unittest.TestCase):
    """Test Playbook.should_trigger() evaluation logic."""

    def _make_playbook(self, **conditions):
        return Playbook(
            playbook_id='test-pb',
            name='Test Playbook',
            trigger_conditions=conditions,
            actions=[],
        )

    def test_min_risk_score_passes(self):
        """Should trigger when risk score meets minimum."""
        pb = self._make_playbook(min_risk_score=70)
        log = {'risk': {'score': 75}}
        self.assertTrue(pb.should_trigger(log))

    def test_min_risk_score_fails(self):
        """Should NOT trigger when risk score below minimum."""
        pb = self._make_playbook(min_risk_score=70)
        log = {'risk': {'score': 50}}
        self.assertFalse(pb.should_trigger(log))

    def test_direction_filter(self):
        """Should only trigger for matching direction."""
        pb = self._make_playbook(direction='inbound')
        self.assertTrue(pb.should_trigger({'risk': {'score': 0}, 'network': {'direction': 'inbound'}}))
        self.assertFalse(pb.should_trigger({'risk': {'score': 0}, 'network': {'direction': 'outbound'}}))

    def test_source_must_be_public(self):
        """source_is_public should reject private source IPs."""
        pb = self._make_playbook(source_is_public=True)
        self.assertFalse(pb.should_trigger({'risk': {'score': 0}, 'source': {'is_private': True}}))
        self.assertTrue(pb.should_trigger({'risk': {'score': 0}, 'source': {'is_private': False}}))

    def test_country_code_filter(self):
        """Should only trigger for listed country codes."""
        pb = self._make_playbook(country_codes=['RU', 'CN'])
        self.assertTrue(pb.should_trigger({
            'risk': {'score': 0},
            'source': {'geo': {'country_code': 'RU'}},
        }))
        self.assertFalse(pb.should_trigger({
            'risk': {'score': 0},
            'source': {'geo': {'country_code': 'US'}},
        }))

    def test_severity_filter(self):
        """Should only trigger for matching severities."""
        pb = self._make_playbook(severity=['high', 'critical'])
        self.assertTrue(pb.should_trigger({'risk': {'score': 0}, 'severity_level': 'critical'}))
        self.assertFalse(pb.should_trigger({'risk': {'score': 0}, 'severity_level': 'low'}))

    def test_event_type_filter(self):
        """Should only trigger for matching event types."""
        pb = self._make_playbook(event_types=['brute_force', 'authentication_failure'])
        self.assertTrue(pb.should_trigger({'risk': {'score': 0}, 'event_type': 'brute_force'}))
        self.assertFalse(pb.should_trigger({'risk': {'score': 0}, 'event_type': 'login_success'}))

    def test_all_conditions_must_pass(self):
        """All conditions are AND — all must pass for trigger."""
        pb = self._make_playbook(
            min_risk_score=50,
            direction='inbound',
            source_is_public=True,
        )
        # Missing direction
        self.assertFalse(pb.should_trigger({
            'risk': {'score': 60},
            'source': {'is_private': False},
            'network': {'direction': 'outbound'},
        }))


# =========================================================================== #
#  Test Idempotency Guard                                                     #
# =========================================================================== #

class TestIdempotencyGuard(unittest.TestCase):
    """Test IdempotencyGuard with in-memory fallback (no Redis)."""

    def setUp(self):
        self.guard = IdempotencyGuard(redis_client=None)

    def test_no_action_initially(self):
        """Should report no action taken initially."""
        self.assertFalse(self.guard.was_action_taken('block_ip', '1.2.3.4'))

    def test_record_and_check(self):
        """After recording, should report action was taken."""
        self.guard.record_action('block_ip', '1.2.3.4', {'status': 'ok'})
        self.assertTrue(self.guard.was_action_taken('block_ip', '1.2.3.4'))

    def test_different_target_not_affected(self):
        """Recording for one target should not affect another."""
        self.guard.record_action('block_ip', '1.2.3.4', {'status': 'ok'})
        self.assertFalse(self.guard.was_action_taken('block_ip', '5.6.7.8'))

    def test_different_action_type_not_affected(self):
        """Recording one action type should not affect another."""
        self.guard.record_action('block_ip', '1.2.3.4', {'status': 'ok'})
        self.assertFalse(self.guard.was_action_taken('create_ticket', '1.2.3.4'))

    def test_rate_counter(self):
        """Rate counter should increment."""
        self.guard.increment_rate('block_ip')
        self.guard.increment_rate('block_ip')
        self.guard.increment_rate('block_ip')
        self.assertEqual(self.guard.actions_in_window('block_ip'), 3)

    def test_rate_counter_separate_types(self):
        """Rate counters for different action types are independent."""
        self.guard.increment_rate('block_ip')
        self.guard.increment_rate('create_ticket')
        self.assertEqual(self.guard.actions_in_window('block_ip'), 1)
        self.assertEqual(self.guard.actions_in_window('create_ticket'), 1)


# =========================================================================== #
#  Test Action Execution (Dry Run)                                            #
# =========================================================================== #

class TestActions(unittest.TestCase):
    """Test playbook actions in dry-run mode (no API configured)."""

    def test_block_ip_dry_run(self):
        """BlockIPAction without API config should return dry_run."""
        action = BlockIPAction()
        result = action.execute({'source_ip': '1.2.3.4', 'alert_id': 'test-123'})
        self.assertEqual(result['status'], 'dry_run')
        self.assertEqual(result['ip'], '1.2.3.4')

    def test_block_ip_no_source(self):
        """BlockIPAction without source_ip should return error."""
        action = BlockIPAction()
        result = action.execute({})
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['reason'], 'no_source_ip')

    def test_create_ticket(self):
        """CreateTicketAction should delegate to thehive_worker."""
        action = CreateTicketAction()
        result = action.execute({'alert': {'alert_id': 'test-456'}})
        self.assertEqual(result['status'], 'delegated')
        self.assertEqual(result['handler'], 'thehive_worker')

    def test_notify_slack_dry_run(self):
        """NotifySlackAction without webhook should return dry_run."""
        action = NotifySlackAction()
        result = action.execute({'message': 'Test alert'})
        self.assertEqual(result['status'], 'dry_run')

    def test_notify_email(self):
        """NotifyEmailAction should return queued."""
        action = NotifyEmailAction()
        result = action.execute({
            'recipients': ['soc@example.com'],
            'subject': 'Test',
            'body': 'Test body',
        })
        self.assertEqual(result['status'], 'queued')


# =========================================================================== #
#  Test SOAR Orchestrator                                                     #
# =========================================================================== #

class TestSOAROrchestrator(unittest.TestCase):
    """Test the SOAROrchestrator end-to-end flow."""

    def setUp(self):
        self.orch = SOAROrchestrator(redis_client=None)

    def test_no_playbooks_no_results(self):
        """With no registered playbooks, should return empty list."""
        results = self.orch.evaluate_and_execute({})
        self.assertEqual(results, [])

    def test_playbook_triggers_and_executes(self):
        """Matching playbook should trigger and execute actions."""
        pb = Playbook(
            playbook_id='test-pb',
            name='Test',
            trigger_conditions={'min_risk_score': 50},
            actions=[BlockIPAction(), NotifySlackAction()],
        )
        self.orch.register_playbook(pb)

        log = {
            'risk': {'score': 80},
            'source': {'ip': '1.2.3.4', 'is_private': False},
        }
        alert = {'alert_id': 'a-001'}

        results = self.orch.evaluate_and_execute(log, alert)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['action'], 'block_ip')
        self.assertEqual(results[0]['status'], 'dry_run')
        self.assertEqual(results[1]['action'], 'notify_slack')

    def test_idempotency_prevents_duplicate(self):
        """Second execution for same target should be skipped."""
        pb = Playbook(
            playbook_id='test-pb',
            name='Test',
            trigger_conditions={'min_risk_score': 50},
            actions=[BlockIPAction()],
        )
        self.orch.register_playbook(pb)

        log = {
            'risk': {'score': 80},
            'source': {'ip': '1.2.3.4'},
        }

        # First execution
        results1 = self.orch.evaluate_and_execute(log)
        self.assertEqual(results1[0]['status'], 'dry_run')

        # Second execution — should be idempotent
        results2 = self.orch.evaluate_and_execute(log)
        self.assertEqual(results2[0]['status'], 'skipped')
        self.assertEqual(results2[0].get('reason'), 'idempotent')

    def test_non_matching_playbook_skipped(self):
        """Playbook that doesn't match should not execute."""
        pb = Playbook(
            playbook_id='test-pb',
            name='Test',
            trigger_conditions={'min_risk_score': 90},
            actions=[BlockIPAction()],
        )
        self.orch.register_playbook(pb)

        log = {'risk': {'score': 50}, 'source': {'ip': '1.2.3.4'}}
        results = self.orch.evaluate_and_execute(log)
        self.assertEqual(len(results), 0)

    def test_execution_history(self):
        """Orchestrator should track execution history."""
        pb = Playbook(
            playbook_id='test-pb',
            name='Test',
            trigger_conditions={'min_risk_score': 0},
            actions=[NotifySlackAction()],
        )
        self.orch.register_playbook(pb)

        log = {'risk': {'score': 10}, 'source': {'ip': '9.9.9.9'}}
        self.orch.evaluate_and_execute(log)

        history = self.orch.execution_history
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['playbook'], 'test-pb')
        self.assertEqual(history[0]['action'], 'notify_slack')

    def test_notification_message_building(self):
        """Notification message should include relevant details."""
        msg = SOAROrchestrator._build_notification_message(
            enriched_log={
                'source': {'ip': '1.2.3.4', 'geo': {
                    'country': 'Russia', 'country_code': 'RU', 'isp': 'ISP'
                }},
                'risk': {'score': 85, 'level': 'critical'},
            },
            alert={'rule_name': 'Brute Force Detected'},
            playbook=Playbook('pb-1', 'Test PB', {}, []),
        )
        self.assertIn('1.2.3.4', msg)
        self.assertIn('Russia', msg)
        self.assertIn('85', msg)
        self.assertIn('Brute Force', msg)


# =========================================================================== #
#  Test Default Playbook Creation                                             #
# =========================================================================== #

class TestDefaultPlaybooks(unittest.TestCase):
    """Test that default playbooks are correctly created."""

    def test_creates_four_playbooks(self):
        """Should create 4 default playbooks."""
        pbs = create_default_playbooks()
        self.assertEqual(len(pbs), 4)

    def test_playbook_ids_unique(self):
        """All playbook IDs should be unique."""
        pbs = create_default_playbooks()
        ids = [pb.playbook_id for pb in pbs]
        self.assertEqual(len(ids), len(set(ids)))

    def test_geo_anomaly_playbook_conditions(self):
        """Geo anomaly playbook should target high-risk countries."""
        pbs = create_default_playbooks()
        geo_pb = next(pb for pb in pbs if pb.playbook_id == 'pb-geo-anomaly')
        self.assertIn('country_codes', geo_pb.trigger_conditions)
        self.assertIn('RU', geo_pb.trigger_conditions['country_codes'])
        self.assertEqual(geo_pb.trigger_conditions['direction'], 'inbound')

    def test_brute_force_playbook_has_email(self):
        """Brute force playbook should include email notification."""
        pbs = create_default_playbooks()
        bf_pb = next(pb for pb in pbs if pb.playbook_id == 'pb-brute-force')
        action_types = [a.ACTION_TYPE for a in bf_pb.actions]
        self.assertIn('notify_email', action_types)

    def test_critical_response_high_threshold(self):
        """Critical response playbook should have risk >= 80."""
        pbs = create_default_playbooks()
        crit_pb = next(pb for pb in pbs if pb.playbook_id == 'pb-critical-response')
        self.assertEqual(crit_pb.trigger_conditions['min_risk_score'], 80)


if __name__ == '__main__':
    unittest.main()
