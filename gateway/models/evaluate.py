"""Evaluation Suite for Zero-Trust Device Classification.

Calculates:
- Macro-F1 Score
- Class-level Precision, Recall, and Accuracy
- Unknown-Recall (Open-Set Rejection TPR)
- Multi-Signal Consistency Score distribution
- Confusion Matrix
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from gateway.models.classifier import ZeroTrustDeviceClassifier

logger = logging.getLogger("gateway.models.evaluate")


class ModelEvaluator:
    """Evaluates classifier performance on closed-world and open-set test partitions."""

    def __init__(self, classifier: ZeroTrustDeviceClassifier) -> None:
        self.classifier = classifier

    def evaluate(
        self,
        X_known_test: pd.DataFrame,
        y_known_test: pd.Series,
        X_unknown_test: Optional[pd.DataFrame] = None,
    ) -> Dict[str, Any]:
        """Run complete evaluation and return metrics dictionary."""
        # 1. Closed-world predictions on known test set
        detailed_known: List[Dict[str, Any]] = [
            self.classifier.predict_single(row.to_dict())
            for _, row in X_known_test.iterrows()
        ]
        y_pred_known = [d["predicted_class"] for d in detailed_known]
        known_consistencies = [d["consistency_score"] for d in detailed_known]

        # Calculate Macro-F1 (for known classes)
        # Note: If any known sample was rejected as 'UNKNOWN', it counts as a false negative against its true class
        known_classes = list(self.classifier.classes_)
        all_eval_classes = sorted(list(set(known_classes).union(set(y_pred_known))))
        macro_f1 = float(f1_score(y_known_test, y_pred_known, labels=known_classes, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_known_test, y_pred_known, labels=known_classes, average="weighted", zero_division=0))
        accuracy = float(np.mean(np.array(y_pred_known) == np.array(y_known_test)))

        report_dict = classification_report(
            y_known_test,
            y_pred_known,
            labels=known_classes,
            output_dict=True,
            zero_division=0,
        )

        conf_matrix = confusion_matrix(
            y_known_test,
            y_pred_known,
            labels=all_eval_classes,
        ).tolist()

        # 2. Open-set / Unknown Rejection Evaluation
        unknown_recall: Optional[float] = None
        unknown_rejection_count = 0
        unknown_total = 0
        unknown_consistencies: List[float] = []

        if X_unknown_test is not None and len(X_unknown_test) > 0:
            detailed_unknown: List[Dict[str, Any]] = [
                self.classifier.predict_single(row.to_dict())
                for _, row in X_unknown_test.iterrows()
            ]
            unknown_preds = [d["predicted_class"] for d in detailed_unknown]
            unknown_consistencies = [d["consistency_score"] for d in detailed_unknown]
            unknown_rejection_count = sum(1 for p in unknown_preds if p == "UNKNOWN")
            unknown_total = len(unknown_preds)
            unknown_recall = float(unknown_rejection_count / unknown_total)

        metrics = {
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "accuracy": round(accuracy, 4),
            "unknown_recall": round(unknown_recall, 4) if unknown_recall is not None else None,
            "unknown_samples_tested": unknown_total,
            "unknown_samples_rejected": unknown_rejection_count,
            "mean_known_consistency": round(float(np.mean(known_consistencies)), 3) if known_consistencies else 0.0,
            "mean_unknown_consistency": round(float(np.mean(unknown_consistencies)), 3) if unknown_consistencies else 0.0,
            "classes": all_eval_classes,
            "confusion_matrix": conf_matrix,
            "classification_report": report_dict,
        }

        logger.info(
            "Evaluation: Macro-F1=%.4f, Accuracy=%.4f, Unknown-Recall=%s",
            metrics["macro_f1"],
            metrics["accuracy"],
            metrics["unknown_recall"],
        )
        return metrics

    def print_summary(self, metrics: Dict[str, Any]) -> None:
        """Print human-readable performance summary."""
        print("=" * 60)
        print(" IoT Zero-Trust Classifier Evaluation Report")
        print("=" * 60)
        print(f" Macro-F1 Score    : {metrics['macro_f1']:.4f}")
        print(f" Weighted-F1 Score : {metrics['weighted_f1']:.4f}")
        print(f" Accuracy          : {metrics['accuracy'] * 100:.2f}%")
        if metrics["unknown_recall"] is not None:
            print(f" Unknown-Recall    : {metrics['unknown_recall'] * 100:.2f}% "
                  f"({metrics['unknown_samples_rejected']}/{metrics['unknown_samples_tested']} novelty rejected)")
        print(f" Mean Consistency (Known)   : {metrics['mean_known_consistency']:.3f}")
        if metrics["mean_unknown_consistency"] > 0:
            print(f" Mean Consistency (Unknown) : {metrics['mean_unknown_consistency']:.3f}")
        print("=" * 60)
