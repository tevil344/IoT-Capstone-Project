"""Unit tests for Baseline Models, Open-Set Rejection, and Signal Consistency."""

import os
import tempfile
import unittest
import numpy as np

from gateway.datasets.preprocessor import (
    DeviceDisjointSplitter,
    preprocess_feature_dataframe,
    split_open_set,
)
from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.models.evaluate import ModelEvaluator
from gateway.models.train import train_and_export_model


class TestModels(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.model_path = os.path.join(self.temp_dir.name, "test_model.joblib")
        self.generator = BenchmarkDatasetGenerator(seed=42)
        self.df = self.generator.generate_dataframe(
            samples_per_device=20,
            devices_per_class=3,
            sessions_per_device=2,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_train_and_evaluate(self):
        classifier, metrics = train_and_export_model(
            df=self.df,
            output_model_path=self.model_path,
            holdout_unknown_class="rogue_unknown",
            test_size=0.33,
            confidence_threshold=0.65,
            random_state=42,
        )
        self.assertTrue(os.path.exists(self.model_path))
        self.assertGreaterEqual(metrics["macro_f1"], 0.80)
        self.assertGreaterEqual(metrics["accuracy"], 0.80)
        self.assertIsNotNone(metrics["unknown_recall"])
        self.assertGreaterEqual(metrics["unknown_recall"], 0.80)
        self.assertGreater(metrics["mean_known_consistency"], 0.70)

    def test_open_set_novelty_rejection(self):
        train_pool_df, unknown_df = split_open_set(self.df, holdout_classes=["rogue_unknown"])
        X_train, y_train, cols = preprocess_feature_dataframe(train_pool_df)
        X_unknown, _, _ = preprocess_feature_dataframe(unknown_df, feature_cols=cols)

        classifier = ZeroTrustDeviceClassifier(confidence_threshold=0.65, random_state=42)
        classifier.fit(X_train, y_train)

        # Predict on unknown/rogue device
        unknown_sample = X_unknown.iloc[0].to_dict()
        res = classifier.predict_single(unknown_sample)

        self.assertTrue(res["is_rejected"])
        self.assertEqual(res["predicted_class"], "UNKNOWN")

    def test_signal_consistency_score(self):
        train_pool_df, _ = split_open_set(self.df, holdout_classes=["rogue_unknown"])
        X_train, y_train, cols = preprocess_feature_dataframe(train_pool_df)

        classifier = ZeroTrustDeviceClassifier(random_state=42)
        classifier.fit(X_train, y_train)

        # 1. Consistent sample (authentic smart_camera)
        cam_sample = X_train[y_train == "smart_camera"].iloc[0].to_dict()
        cam_res = classifier.predict_single(cam_sample)
        self.assertEqual(cam_res["predicted_class"], "smart_camera")
        self.assertGreaterEqual(cam_res["consistency_score"], 0.75)

        # 2. Inconsistent / Spoofed sample: Camera MAC/DHCP but with Thermostat traffic & ports
        spoofed_sample = dict(cam_sample)
        spoofed_sample["size_mean"] = 180.0  # Thermostat packet size
        spoofed_sample["packet_rate"] = 0.5   # Low rate
        spoofed_sample["discovery_service_count"] = 0.0
        spoofed_sample["discovery_txt_keys_count"] = 0.0

        spoofed_res = classifier.predict_single(spoofed_sample)
        # Consistency should drop due to conflicting signals between DHCP and Traffic
        self.assertLessEqual(spoofed_res["consistency_score"], 0.75)

    def test_model_serialization(self):
        train_pool_df, _ = split_open_set(self.df, holdout_classes=["rogue_unknown"])
        X_train, y_train, _ = preprocess_feature_dataframe(train_pool_df)

        clf = ZeroTrustDeviceClassifier(random_state=42)
        clf.fit(X_train, y_train)
        clf.save(self.model_path)

        loaded_clf = ZeroTrustDeviceClassifier.load(self.model_path)
        self.assertEqual(list(clf.classes_), list(loaded_clf.classes_))
        sample = X_train.iloc[0].to_dict()
        self.assertEqual(clf.predict_single(sample)["predicted_class"], loaded_clf.predict_single(sample)["predicted_class"])


if __name__ == "__main__":
    unittest.main()
