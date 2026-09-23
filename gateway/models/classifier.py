"""Zero-Trust Multi-Class Device Classifier with Open-Set Rejection and Multi-Signal Consistency.

Architecture:
1. Primary Ensemble Classifier (Random Forest / Gradient Boosting) emitting P(c|x).
2. Open-Set Novelty Rejection:
   - Max-Softmax Probability (MSP) threshold
   - Class centroid Mahalanobis/standardized distance threshold
   - Devices violating either threshold are classified as 'UNKNOWN'.
3. Multi-Signal Consistency Score:
   - Independent sub-predictors for DHCP, Discovery, TCP/IP+TLS, and Traffic.
   - Computes agreement fraction across active signal groups to detect spoofing or inconsistency.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger("gateway.models.classifier")

SIGNAL_GROUPS = {
    "dhcp": [
        "has_dhcp",
        "dhcp_options_count",
        "dhcp_param_req_count",
        "has_vendor_class",
        "has_hostname",
    ],
    "discovery": [
        "has_discovery",
        "discovery_service_count",
        "discovery_txt_keys_count",
        "discovery_ports_count",
    ],
    "tcptls": [
        "has_tcptls",
        "estimated_initial_ttl",
        "tcp_mss",
        "initial_window_size",
        "tcp_options_count",
        "has_tls",
        "sni_count",
    ],
    "traffic": [
        "total_packets",
        "packet_rate",
        "byte_rate",
        "size_min",
        "size_max",
        "size_mean",
        "size_std",
        "size_median",
        "unique_dest_ips",
        "dest_ip_entropy",
        "unique_dest_ports",
        "dest_port_entropy",
        "iat_mean",
        "iat_std",
        "iat_cv",
        "periodicity_score",
        "burstiness_ratio",
    ],
}


class ZeroTrustDeviceClassifier:
    """Multi-class classifier with open-set rejection and signal consistency scoring."""

    def __init__(
        self,
        confidence_threshold: float = 0.65,
        distance_threshold_percentile: float = 98.0,
        n_estimators: int = 80,
        max_depth: int = 12,
        random_state: int = 42,
    ) -> None:
        self.confidence_threshold = confidence_threshold
        self.distance_threshold_percentile = distance_threshold_percentile
        self.random_state = random_state

        # Primary full-feature classifier
        self.primary_model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            n_jobs=-1,
        )

        # Feature scaler for distance-to-centroid calculation
        self.scaler = StandardScaler()
        self.class_centroids: Dict[str, np.ndarray] = {}
        self.distance_threshold: float = 10.0

        # Sub-classifiers for each signal group to compute consistency
        self.group_models: Dict[str, RandomForestClassifier] = {
            group: RandomForestClassifier(
                n_estimators=40,
                max_depth=8,
                random_state=random_state + i,
                n_jobs=-1,
            )
            for i, group in enumerate(SIGNAL_GROUPS.keys())
        }

        self.feature_names: List[str] = []
        self.classes_: np.ndarray = np.array([])
        self.is_fitted: bool = False

    def fit(self, X: pd.DataFrame, y: pd.Series) -> ZeroTrustDeviceClassifier:
        """Fit the primary ensemble, group sub-models, and compute open-set centroid baselines."""
        self.feature_names = list(X.columns)
        self.classes_ = np.unique(y)

        # 1. Fit primary model
        self.primary_model.fit(X, y)

        # 2. Fit sub-models for each signal group
        for group_name, cols in SIGNAL_GROUPS.items():
            valid_cols = [c for c in cols if c in X.columns]
            if valid_cols:
                self.group_models[group_name].fit(X[valid_cols], y)

        # 3. Fit scaler and compute class centroids in normalized feature space
        X_scaled = self.scaler.fit_transform(X)
        intra_class_distances: List[float] = []

        for cls in self.classes_:
            cls_mask = (y == cls).values
            cls_points = X_scaled[cls_mask]
            if len(cls_points) > 0:
                centroid = np.mean(cls_points, axis=0)
                self.class_centroids[str(cls)] = centroid
                # Distances of training samples to their own centroid
                dists = np.linalg.norm(cls_points - centroid, axis=1)
                intra_class_distances.extend(dists.tolist())

        # Set open-set distance threshold based on training distribution
        if intra_class_distances:
            self.distance_threshold = float(
                np.percentile(intra_class_distances, self.distance_threshold_percentile)
            )
        else:
            self.distance_threshold = 10.0

        self.is_fitted = True
        logger.info(
            "ZeroTrustDeviceClassifier fitted on %d samples across %d classes. Distance threshold=%.3f",
            len(X),
            len(self.classes_),
            self.distance_threshold,
        )
        return self

    def _min_centroid_distance(self, x_scaled_row: np.ndarray) -> float:
        """Compute minimum Euclidean distance from a normalized sample to known centroids."""
        distances = [
            np.linalg.norm(x_scaled_row - centroid)
            for centroid in self.class_centroids.values()
        ]
        return min(distances) if distances else 0.0

    def predict_single(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """Predict for a single device feature dictionary.

        Returns structured verdict including predicted class, confidence,
        open-set rejection status, and multi-signal consistency score.
        """
        if not self.is_fitted:
            raise RuntimeError("Classifier must be fitted before calling predict.")

        df_row = pd.DataFrame([feature_dict])
        # Align features
        aligned = pd.DataFrame(index=[0])
        for col in self.feature_names:
            aligned[col] = float(df_row[col].iloc[0]) if col in df_row.columns else 0.0

        # Class probabilities P(c|x)
        probs = self.primary_model.predict_proba(aligned)[0]
        max_prob_idx = int(np.argmax(probs))
        raw_class = str(self.classes_[max_prob_idx])
        confidence = float(probs[max_prob_idx])
        prob_dict = {str(c): round(float(p), 4) for c, p in zip(self.classes_, probs)}

        # Distance-to-centroid novelty check
        row_scaled = self.scaler.transform(aligned)[0]
        min_dist = self._min_centroid_distance(row_scaled)

        # Open-set rejection check
        is_unknown_prob = confidence < self.confidence_threshold
        is_unknown_dist = min_dist > self.distance_threshold
        is_rejected = is_unknown_prob or is_unknown_dist

        final_verdict_class = "UNKNOWN" if is_rejected else raw_class

        # Multi-signal consistency score
        group_verdicts: Dict[str, str] = {}
        active_groups_count = 0
        matching_groups_count = 0

        for group_name, cols in SIGNAL_GROUPS.items():
            valid_cols = [c for c in cols if c in aligned.columns]
            if not valid_cols:
                continue

            # Determine if signal group is active for this device
            has_activity = False
            if group_name == "dhcp" and aligned.get("has_dhcp", pd.Series([0]))[0] > 0:
                has_activity = True
            elif group_name == "discovery" and aligned.get("has_discovery", pd.Series([0]))[0] > 0:
                has_activity = True
            elif group_name == "tcptls" and aligned.get("has_tcptls", pd.Series([0]))[0] > 0:
                has_activity = True
            elif group_name == "traffic" and aligned.get("total_packets", pd.Series([0]))[0] > 0:
                has_activity = True

            if has_activity and group_name in self.group_models:
                sub_pred = str(self.group_models[group_name].predict(aligned[valid_cols])[0])
                group_verdicts[group_name] = sub_pred
                active_groups_count += 1
                if sub_pred == raw_class:
                    matching_groups_count += 1

        consistency_score = (
            round(matching_groups_count / active_groups_count, 3)
            if active_groups_count > 0
            else 1.0
        )

        return {
            "predicted_class": final_verdict_class,
            "raw_class": raw_class,
            "confidence": round(confidence, 4),
            "consistency_score": consistency_score,
            "is_rejected": is_rejected,
            "rejection_reason": (
                "LOW_CONFIDENCE"
                if is_unknown_prob
                else ("OUTLIER_DISTANCE" if is_unknown_dist else "NONE")
            ),
            "centroid_distance": round(min_dist, 3),
            "class_probabilities": prob_dict,
            "active_signal_groups": list(group_verdicts.keys()),
            "group_predictions": group_verdicts,
        }

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Batch prediction returning array of predicted labels ('UNKNOWN' for rejected)."""
        verdicts = []
        for _, row in X.iterrows():
            res = self.predict_single(row.to_dict())
            verdicts.append(res["predicted_class"])
        return np.array(verdicts)

    def save(self, filepath: str) -> None:
        """Serialize fitted model to disk."""
        joblib.dump(self, filepath)
        logger.info("Saved ZeroTrustDeviceClassifier model to %s", filepath)

    @classmethod
    def load(cls, filepath: str) -> ZeroTrustDeviceClassifier:
        """Load serialized model from disk."""
        model = joblib.load(filepath)
        logger.info("Loaded ZeroTrustDeviceClassifier model from %s", filepath)
        return model
