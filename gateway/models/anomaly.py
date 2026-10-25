"""Unsupervised Post-Admission Behavioral Anomaly Detector.

Monitors devices after promotion to the trusted VLAN. Detects compromised
endpoints, botnet enrollment (Mirai/BASHLITE), port scanning, and C2 beacons
by analyzing statistical traffic drift without inspecting payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("gateway.models.anomaly")

DRIFT_FEATURE_COLS = [
    "total_packets",
    "packet_rate",
    "byte_rate",
    "size_min",
    "size_max",
    "size_mean",
    "size_std",
    "unique_dest_ips",
    "dest_ip_entropy",
    "unique_dest_ports",
    "dest_port_entropy",
    "iat_mean",
    "iat_std",
    "iat_cv",
    "periodicity_score",
    "burstiness_ratio",
]


class BehavioralAnomalyDetector:
    """Detects statistical behavioral drift in continuous IoT telemetry using Isolation Forest."""

    def __init__(
        self,
        contamination: float = 0.05,
        anomaly_threshold: float = 0.65,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.contamination = contamination
        self.anomaly_threshold = anomaly_threshold
        self.random_state = random_state

        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.feature_names: List[str] = list(DRIFT_FEATURE_COLS)
        self.is_fitted: bool = False
        self.baseline_stats: Dict[str, Dict[str, float]] = {}

    def fit(self, X: pd.DataFrame) -> BehavioralAnomalyDetector:
        """Fit Isolation Forest on benign baseline traffic profiles."""
        cols = [c for c in self.feature_names if c in X.columns]
        self.feature_names = cols
        X_clean = X[cols].fillna(0.0)

        X_scaled = self.scaler.fit_transform(X_clean)
        self.model.fit(X_scaled)

        # Record mean and std for each feature for interpretable drift reporting
        for c in cols:
            self.baseline_stats[c] = {
                "mean": float(np.mean(X_clean[c])),
                "std": float(np.std(X_clean[c])) + 1e-6,
            }

        self.is_fitted = True
        logger.info(
            "BehavioralAnomalyDetector fitted on %d samples across %d features.",
            len(X),
            len(self.feature_names),
        )
        return self

    def score_sample(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """Evaluate a single feature snapshot for anomalous drift.

        Returns an anomaly score in [0.0, 1.0], alert flag, and specific drift indicators.
        """
        if not self.is_fitted:
            raise RuntimeError("Anomaly detector must be fitted before scoring samples.")

        # Construct single-row DataFrame aligned to feature names
        row = pd.DataFrame(index=[0])
        for c in self.feature_names:
            row[c] = float(feature_dict.get(c, 0.0))

        X_scaled = self.scaler.transform(row)

        # In scikit-learn IsolationForest, decision_function returns:
        # positive values for inliers (normal), negative values for outliers (anomalies)
        dec_func = float(self.model.decision_function(X_scaled)[0])

        if dec_func >= 0.0:
            normalized_anomaly_score = float(np.clip(0.5 - (dec_func * 2.5), 0.0, 0.49))
        else:
            normalized_anomaly_score = float(np.clip(0.5 + (abs(dec_func) * 3.5), 0.51, 1.0))

        is_anomaly = (dec_func < 0.0) or (normalized_anomaly_score >= self.anomaly_threshold)

        # Identify features with highest standard deviations from baseline mean
        drift_indicators: List[Dict[str, Any]] = []
        for c in self.feature_names:
            val = float(row[c].iloc[0])
            stats = self.baseline_stats.get(c, {"mean": 0.0, "std": 1.0})
            z_score = abs(val - stats["mean"]) / stats["std"]
            if z_score >= 3.0:  # Beyond 3 standard deviations
                drift_indicators.append({
                    "feature": c,
                    "observed": round(val, 2),
                    "baseline_mean": round(stats["mean"], 2),
                    "z_score": round(z_score, 2),
                })

        # Sort by z-score descending
        drift_indicators.sort(key=lambda x: x["z_score"], reverse=True)

        reason = "NORMAL"
        if is_anomaly:
            top_causes = [d["feature"] for d in drift_indicators[:3]]
            reason = f"SURGE_IN_{'_AND_'.join(top_causes).upper()}" if top_causes else "STATISTICAL_OUTLIER"

        return {
            "anomaly_score": round(normalized_anomaly_score, 4),
            "is_anomaly": is_anomaly,
            "raw_score": round(dec_func, 4),
            "reason": reason,
            "drift_indicators": drift_indicators,
        }

    def save(self, filepath: str) -> None:
        """Serialize detector to disk."""
        joblib.dump(self, filepath)
        logger.info("Saved BehavioralAnomalyDetector to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> BehavioralAnomalyDetector:
        """Load detector from disk."""
        obj = joblib.load(filepath)
        logger.info("Loaded BehavioralAnomalyDetector from %s", filepath)
        return obj

