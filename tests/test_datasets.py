"""Unit tests for Dataset Ingestion, Splitting, and Synthetic Generator."""

import os
import tempfile
import unittest
import pandas as pd

from gateway.datasets.local_loader import LocalTraceLoader
from gateway.datasets.preprocessor import (
    DEFAULT_FEATURE_COLS,
    DeviceDisjointSplitter,
    SessionDisjointSplitter,
    preprocess_feature_dataframe,
    split_open_set,
)
from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.sensing.capture import PacketCaptureEngine
from gateway.sensing.storage import SensorStorage


class TestDatasets(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.generator = BenchmarkDatasetGenerator(seed=123)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_benchmark_generator(self):
        df = self.generator.generate_dataframe(
            samples_per_device=9,
            devices_per_class=2,
            sessions_per_device=3,
        )
        self.assertGreater(len(df), 50)
        self.assertIn("device_class", df.columns)
        self.assertIn("device_id", df.columns)
        self.assertIn("session_id", df.columns)

        # Check that all default feature columns are present
        for col in DEFAULT_FEATURE_COLS:
            self.assertIn(col, df.columns)

    def test_device_disjoint_split(self):
        df = self.generator.generate_dataframe(
            samples_per_device=9,
            devices_per_class=3,
            sessions_per_device=3,
        )
        splitter = DeviceDisjointSplitter(test_size=0.33, random_state=42)
        train_df, test_df = splitter.split(df, device_col="device_id")

        train_devs = set(train_df["device_id"])
        test_devs = set(test_df["device_id"])

        self.assertTrue(train_devs.isdisjoint(test_devs))
        self.assertGreater(len(train_devs), 0)
        self.assertGreater(len(test_devs), 0)

    def test_session_disjoint_split(self):
        df = self.generator.generate_dataframe(
            samples_per_device=9,
            devices_per_class=2,
            sessions_per_device=3,
        )
        splitter = SessionDisjointSplitter(test_size=0.33, random_state=42)
        train_df, test_df = splitter.split(df, session_col="session_id")

        train_sessions = set(train_df["session_id"])
        test_sessions = set(test_df["session_id"])

        self.assertTrue(train_sessions.isdisjoint(test_sessions))

    def test_open_set_split(self):
        df = self.generator.generate_dataframe(
            samples_per_device=9,
            devices_per_class=2,
            sessions_per_device=3,
        )
        train_df, open_set_df = split_open_set(df, holdout_classes=["rogue_unknown"])
        self.assertNotIn("rogue_unknown", train_df["device_class"].unique())
        self.assertEqual(set(open_set_df["device_class"].unique()), {"rogue_unknown"})

    def test_local_loader_from_sqlite(self):
        db_path = os.path.join(self.temp_dir.name, "test_local.db")
        storage = SensorStorage(db_path=db_path)
        engine = PacketCaptureEngine(storage=storage)

        # Generate a test PCAP and process it
        pcap_path = os.path.join(self.temp_dir.name, "test.pcap")
        self.generator.generate_sample_pcap(pcap_path, device_class="smart_plug", packet_count=20)
        engine.process_pcap(pcap_path)

        loader = LocalTraceLoader(db_path=db_path)
        loaded_df = loader.load_from_sqlite()

        self.assertEqual(len(loaded_df), 1)
        self.assertIn("has_dhcp", loaded_df.columns)
        self.assertIn("total_packets", loaded_df.columns)
        self.assertEqual(loaded_df["total_packets"].iloc[0], 20.0)


if __name__ == "__main__":
    unittest.main()
