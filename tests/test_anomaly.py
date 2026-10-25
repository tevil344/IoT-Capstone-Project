"""Unit tests for Behavioral Anomaly Detector."""

import os
import tempfile
import unittest

from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.models.anomaly import BehavioralAnomalyDetector


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.model_path = os.path.join(self.temp_dir.name, "anomaly.joblib")
        generator = BenchmarkDatasetGenerator(seed=42)
        self.df = generator.generate_dataframe(samples_per_device=20, devices_per_class=3)
        self.detector = BehavioralAnomalyDetector()
        self.detector.fit(self.df)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_normal_sample_scoring(self):
        # A normal benign sample from camera
        normal_sample = {
            "total_packets": 100.0,
            "packet_rate": 1.2,
            "byte_rate": 900.0,
            "size_min": 60.0,
            "size_max": 1400.0,
            "size_mean": 950.0,
            "size_std": 200.0,
            "unique_dest_ips": 3.0,
            "dest_ip_entropy": 1.2,
            "unique_dest_ports": 3.0,
            "dest_port_entropy": 1.5,
            "iat_mean": 0.6,
            "iat_std": 0.2,
            "iat_cv": 0.33,
            "periodicity_score": 0.67,
            "burstiness_ratio": 2.5,
        }
        res = self.detector.score_sample(normal_sample)
        self.assertFalse(res["is_anomaly"])
        self.assertLess(res["anomaly_score"], 0.65)

    def test_compromised_sample_detection(self):
        # An anomalous DDoS/Scanner sample with 100 unique IPs, extreme packet rate & entropy
        anomalous_sample = {
            "total_packets": 2000.0,
            "packet_rate": 200.0,
            "byte_rate": 20000.0,
            "size_min": 40.0,
            "size_max": 60.0,
            "size_mean": 45.0,
            "size_std": 5.0,
            "unique_dest_ips": 150.0,
            "dest_ip_entropy": 6.8,
            "unique_dest_ports": 120.0,
            "dest_port_entropy": 6.5,
            "iat_mean": 0.005,
            "iat_std": 0.001,
            "iat_cv": 0.2,
            "periodicity_score": 0.1,
            "burstiness_ratio": 12.0,
        }
        res = self.detector.score_sample(anomalous_sample)
        self.assertTrue(res["is_anomaly"])
        self.assertGreaterEqual(res["anomaly_score"], 0.65)
        self.assertGreater(len(res["drift_indicators"]), 0)

    def test_serialization(self):
        self.detector.save(self.model_path)
        loaded = BehavioralAnomalyDetector.load(self.model_path)
        self.assertTrue(loaded.is_fitted)


if __name__ == "__main__":
    unittest.main()

