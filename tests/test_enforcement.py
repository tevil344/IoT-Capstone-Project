"""Unit tests for Closed-Loop Zero-Trust Policy Engine and Enforcement Controller."""

import os
import tempfile
import unittest

from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.enforcement.controller import ClosedLoopEnforcementController
from gateway.enforcement.policy import (
    DeviceTrustState,
    PolicyDecision,
    ZeroTrustPolicyEngine,
)
from gateway.models.anomaly import BehavioralAnomalyDetector
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.quarantine.manager import QuarantineManager
from gateway.sensing.storage import SensorStorage


class TestEnforcementSubsystem(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_enforce.db")
        self.storage = SensorStorage(db_path=self.db_path)
        self.quarantine = QuarantineManager(db_path=self.db_path, dry_run=True)

        # Generate lightweight classifier
        generator = BenchmarkDatasetGenerator(seed=42)
        df = generator.generate_dataframe(samples_per_device=15, devices_per_class=3)
        self.classifier = ZeroTrustDeviceClassifier(random_state=42)
        known_df = df[df["device_class"] != "rogue_unknown"]
        feature_cols = [c for c in self.classifier.primary_model.feature_names_in_] if hasattr(self.classifier.primary_model, "feature_names_in_") else None
        from gateway.datasets.preprocessor import preprocess_feature_dataframe
        X, y, cols = preprocess_feature_dataframe(known_df, feature_cols=feature_cols)
        self.classifier.fit(X, y)

        self.policy_engine = ZeroTrustPolicyEngine(
            min_confidence=0.70,
            min_consistency=0.70,
            auto_promote=True,
        )

        self.anomaly_detector = BehavioralAnomalyDetector()
        self.anomaly_detector.fit(known_df)

        self.controller = ClosedLoopEnforcementController(
            classifier=self.classifier,
            quarantine_manager=self.quarantine,
            storage=self.storage,
            policy_engine=self.policy_engine,
            anomaly_detector=self.anomaly_detector,
            db_path=self.db_path,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_deny_onboarding(self):
        mac = "11:22:33:44:55:66"
        res = self.controller.register_new_device(mac=mac, ip="192.168.20.10", vendor="Test Device")
        self.assertTrue(res)
        self.assertTrue(self.quarantine.is_quarantined(mac))
        overview = self.controller.get_device_overview(mac)
        self.assertEqual(overview["status"], DeviceTrustState.QUARANTINED.value)

    def test_closed_loop_promotion(self):
        mac = "b8:27:eb:11:22:33"
        self.controller.register_new_device(mac=mac, ip="192.168.20.15", vendor="Camera")

        # Create valid camera snapshot
        camera_features = {
            "has_dhcp": 1.0, "dhcp_options_count": 5.0, "dhcp_param_req_count": 5.0,
            "has_vendor_class": 1.0, "has_hostname": 1.0,
            "has_discovery": 1.0, "discovery_service_count": 3.0, "discovery_txt_keys_count": 3.0, "discovery_ports_count": 3.0,
            "has_tcptls": 1.0, "estimated_initial_ttl": 64.0, "tcp_mss": 1460.0, "initial_window_size": 29200.0, "tcp_options_count": 5.0, "has_tls": 1.0, "sni_count": 1.0,
            "total_packets": 120.0, "packet_rate": 1.5, "byte_rate": 1400.0, "size_min": 60.0, "size_max": 1400.0, "size_mean": 950.0, "size_std": 200.0, "size_median": 950.0,
            "unique_dest_ips": 3.0, "dest_ip_entropy": 1.2, "unique_dest_ports": 3.0, "dest_port_entropy": 1.5,
            "iat_mean": 0.6, "iat_std": 0.2, "iat_cv": 0.33, "periodicity_score": 0.67, "burstiness_ratio": 2.8,
        }
        self.storage.store_feature_snapshot(
            mac=mac,
            structured_data={"duration_seconds": 60.0, "ip": "192.168.20.15", "signals": {}, "features": camera_features},
        )

        decision = self.controller.evaluate_device(mac)
        self.assertEqual(decision.action, "PROMOTE")
        self.assertEqual(decision.new_state, DeviceTrustState.PROMOTED)
        self.assertFalse(self.quarantine.is_quarantined(mac))

    def test_closed_loop_demotion_on_anomaly(self):
        mac = "b8:27:eb:11:22:33"
        # First promote
        self.controller.manual_promote(mac)
        self.assertFalse(self.quarantine.is_quarantined(mac))

        # Store anomalous traffic snapshot (scanning behavior)
        anomaly_features = {
            "total_packets": 500.0, "packet_rate": 50.0, "byte_rate": 5000.0,
            "size_min": 40.0, "size_max": 60.0, "size_mean": 45.0, "size_std": 5.0, "size_median": 45.0,
            "unique_dest_ips": 80.0, "dest_ip_entropy": 5.2, "unique_dest_ports": 90.0, "dest_port_entropy": 5.5,
            "iat_mean": 0.02, "iat_std": 0.005, "iat_cv": 0.25, "periodicity_score": 0.1, "burstiness_ratio": 8.0,
        }
        self.storage.store_feature_snapshot(
            mac=mac,
            structured_data={"duration_seconds": 60.0, "ip": "192.168.10.15", "signals": {}, "features": anomaly_features},
        )

        decision = self.controller.evaluate_device(mac)
        self.assertEqual(decision.action, "DEMOTE")
        self.assertEqual(decision.new_state, DeviceTrustState.DEMOTED_ANOMALOUS)
        self.assertTrue(self.quarantine.is_quarantined(mac))

    def test_manual_overrides(self):
        mac = "aa:bb:cc:dd:ee:01"
        self.controller.manual_quarantine(mac, reason="operator_lockdown")
        self.assertTrue(self.quarantine.is_quarantined(mac))

        self.controller.manual_promote(mac)
        self.assertFalse(self.quarantine.is_quarantined(mac))


if __name__ == "__main__":
    unittest.main()

