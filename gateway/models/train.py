"""Training and Validation Pipeline for Baseline Zero-Trust Classifier."""

from __future__ import annotations

import argparse
import logging
import os
from typing import Optional, Tuple
import pandas as pd

from gateway.datasets.preprocessor import (
    DeviceDisjointSplitter,
    preprocess_feature_dataframe,
    split_open_set,
)
from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.models.evaluate import ModelEvaluator

logger = logging.getLogger("gateway.models.train")


def train_and_export_model(
    df: Optional[pd.DataFrame] = None,
    output_model_path: str = "models/baseline_rf.joblib",
    holdout_unknown_class: str = "rogue_unknown",
    test_size: float = 0.30,
    confidence_threshold: float = 0.65,
    random_state: int = 42,
) -> Tuple[ZeroTrustDeviceClassifier, dict]:
    """Train classifier with device-disjoint splitting and open-set holdout evaluation."""
    os.makedirs(os.path.dirname(os.path.abspath(output_model_path)), exist_ok=True)

    # 1. Acquire dataset (synthetic benchmark or provided DataFrame)
    if df is None:
        logger.info("Generating standard IoT multi-device benchmark dataset...")
        generator = BenchmarkDatasetGenerator(seed=random_state)
        df = generator.generate_dataframe(
            samples_per_device=40,
            devices_per_class=4,
            sessions_per_device=4,
        )

    # 2. Hold out novel/unknown classes for open-set evaluation
    train_pool_df, unknown_df = split_open_set(df, holdout_classes=[holdout_unknown_class])

    # 3. Device-Disjoint Split (0% device leakage between train and test)
    splitter = DeviceDisjointSplitter(test_size=test_size, random_state=random_state)
    train_df, known_test_df = splitter.split(train_pool_df, device_col="device_id")

    # 4. Preprocess features
    X_train, y_train, feature_cols = preprocess_feature_dataframe(train_df)
    X_known_test, y_known_test, _ = preprocess_feature_dataframe(known_test_df, feature_cols=feature_cols)
    X_unknown_test, _, _ = preprocess_feature_dataframe(unknown_df, feature_cols=feature_cols)

    # 5. Fit model
    classifier = ZeroTrustDeviceClassifier(
        confidence_threshold=confidence_threshold,
        random_state=random_state,
    )
    classifier.fit(X_train, y_train)

    # 6. Evaluate
    evaluator = ModelEvaluator(classifier)
    metrics = evaluator.evaluate(
        X_known_test=X_known_test,
        y_known_test=y_known_test,
        X_unknown_test=X_unknown_test,
    )
    evaluator.print_summary(metrics)

    # 7. Persist artifact
    classifier.save(output_model_path)
    return classifier, metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Zero-Trust IoT Device Classifier")
    parser.add_argument(
        "--output",
        default="models/baseline_rf.joblib",
        help="Path to save trained model artifact",
    )
    parser.add_argument(
        "--confidence-thresh",
        type=float,
        default=0.65,
        help="Open-set confidence threshold",
    )
    parser.add_argument(
        "--unknown-class",
        default="rogue_unknown",
        help="Class held out to evaluate unknown-recall",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    train_and_export_model(
        output_model_path=args.output,
        confidence_threshold=args.confidence_thresh,
        holdout_unknown_class=args.unknown_class,
    )


if __name__ == "__main__":
    main()
