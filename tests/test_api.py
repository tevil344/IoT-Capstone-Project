"""Unit tests for Gateway REST API and Dashboard Server."""

import json
import os
import tempfile
import unittest
import urllib.request

from gateway.api.server import GatewayAPIServer
from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.enforcement.controller import ClosedLoopEnforcementController
from gateway.enforcement.policy import ZeroTrustPolicyEngine
from gateway.models.anomaly import BehavioralAnomalyDetector
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.quarantine.manager import QuarantineManager
from gateway.sensing.capture import PacketCaptureEngine
from gateway.sensing.storage import SensorStorage


class TestAPIServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls.temp_dir.name, "api_test.db")
        cls.storage = SensorStorage(db_path=cls.db_path)
        cls.quarantine = QuarantineManager(db_path=cls.db_path, dry_run=True)

        generator = BenchmarkDatasetGenerator(seed=42)
        df = generator.generate_dataframe(samples_per_device=15, devices_per_class=3)
        known_df = df[df["device_class"] != "rogue_unknown"]
        from gateway.datasets.preprocessor import preprocess_feature_dataframe
        X, y, _ = preprocess_feature_dataframe(known_df)
        cls.classifier = ZeroTrustDeviceClassifier(random_state=42)
        cls.classifier.fit(X, y)

        cls.anomaly_detector = BehavioralAnomalyDetector()
        cls.anomaly_detector.fit(known_df)

        cls.controller = ClosedLoopEnforcementController(
            classifier=cls.classifier,
            quarantine_manager=cls.quarantine,
            storage=cls.storage,
            policy_engine=ZeroTrustPolicyEngine(),
            anomaly_detector=cls.anomaly_detector,
            db_path=cls.db_path,
        )
        cls.capture_engine = PacketCaptureEngine(storage=cls.storage)

        # Start API server on a high port
        cls.port = 18989
        cls.server = GatewayAPIServer(
            controller=cls.controller,
            capture_engine=cls.capture_engine,
            host="127.0.0.1",
            port=cls.port,
        )
        cls.server.start(block=False)
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.temp_dir.cleanup()

    def test_get_dashboard_html(self):
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode("utf-8")
            self.assertIn("Zero-Trust IoT Gateway Control Center", body)

    def test_get_status_json(self):
        req = urllib.request.Request(f"{self.base_url}/api/status")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["status"], "OPERATIONAL")
            self.assertIn("total_devices", data)

    def test_simulate_and_device_endpoints(self):
        # 1. Simulate camera connection
        payload = json.dumps({"scenario": "smart_camera"}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/simulate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["scenario"], "smart_camera")

        # 2. Query /api/devices
        req2 = urllib.request.Request(f"{self.base_url}/api/devices")
        with urllib.request.urlopen(req2) as resp2:
            self.assertEqual(resp2.status, 200)
            devices = json.loads(resp2.read().decode("utf-8"))
            self.assertGreater(len(devices), 0)
            mac = devices[0]["mac"]

        # 3. Query /api/devices/{mac}
        req3 = urllib.request.Request(f"{self.base_url}/api/devices/{mac}")
        with urllib.request.urlopen(req3) as resp3:
            self.assertEqual(resp3.status, 200)
            details = json.loads(resp3.read().decode("utf-8"))
            self.assertEqual(details["mac"], mac)

        # 4. Manual Quarantine & Promotion overrides
        req_lock = urllib.request.Request(f"{self.base_url}/api/devices/{mac}/quarantine", method="POST")
        with urllib.request.urlopen(req_lock) as resp4:
            self.assertEqual(resp4.status, 200)

        req_promote = urllib.request.Request(f"{self.base_url}/api/devices/{mac}/promote", method="POST")
        with urllib.request.urlopen(req_promote) as resp5:
            self.assertEqual(resp5.status, 200)


if __name__ == "__main__":
    unittest.main()

