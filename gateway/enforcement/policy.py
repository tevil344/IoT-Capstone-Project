"""Zero-Trust Policy Decision Point (PDP).

Defines formal zero-trust policy rules, state transitions, and evaluation
logic for device containment, promotion, and automated demotion.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class DeviceTrustState(str, Enum):
    """Lifecycle states of an IoT endpoint on the Zero-Trust Gateway."""

    UNSEEN = "UNSEEN"
    QUARANTINED = "QUARANTINED"
    PROMOTED = "PROMOTED"
    REJECTED_UNKNOWN = "REJECTED_UNKNOWN"
    FLAGGED_INCONSISTENT = "FLAGGED_INCONSISTENT"
    DEMOTED_ANOMALOUS = "DEMOTED_ANOMALOUS"
    MANUAL_HOLD = "MANUAL_HOLD"


@dataclass
class PolicyDecision:
    """Formal decision emitted by the Zero-Trust Policy Decision Point."""

    mac: str
    action: str  # 'PROMOTE', 'MAINTAIN_QUARANTINE', 'DEMOTE', 'MANUAL_REVIEW'
    new_state: DeviceTrustState
    reason: str
    confidence: float
    consistency_score: float
    anomaly_score: float = 0.0
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mac": self.mac,
            "action": self.action,
            "new_state": self.new_state.value,
            "reason": self.reason,
            "confidence": round(self.confidence, 4),
            "consistency_score": round(self.consistency_score, 4),
            "anomaly_score": round(self.anomaly_score, 4),
            "details": self.details or {},
        }


class ZeroTrustPolicyEngine:
    """Evaluates passive fingerprinting verdicts against zero-trust admission policies."""

    def __init__(
        self,
        min_confidence: float = 0.70,
        min_consistency: float = 0.70,
        anomaly_threshold: float = 0.65,
        auto_promote: bool = True,
        allowed_classes: Optional[List[str]] = None,
    ) -> None:
        self.min_confidence = min_confidence
        self.min_consistency = min_consistency
        self.anomaly_threshold = anomaly_threshold
        self.auto_promote = auto_promote
        self.allowed_classes = allowed_classes  # None means all valid known classes are eligible

    def evaluate_admission(self, mac: str, ml_verdict: Dict[str, Any]) -> PolicyDecision:
        """Evaluate an initial fingerprint to decide promotion or sustained quarantine."""
        confidence = float(ml_verdict.get("confidence", 0.0))
        consistency = float(ml_verdict.get("consistency_score", 0.0))
        is_rejected = bool(ml_verdict.get("is_rejected", False))
        predicted_class = str(ml_verdict.get("predicted_class", "UNKNOWN"))

        # 1. Open-Set Rejection (Outlier or Unknown Device)
        if is_rejected or predicted_class == "UNKNOWN":
            rejection_reason = ml_verdict.get("rejection_reason", "OUTLIER_NOVELTY")
            return PolicyDecision(
                mac=mac,
                action="MAINTAIN_QUARANTINE",
                new_state=DeviceTrustState.REJECTED_UNKNOWN,
                reason=f"Open-set novelty rejection ({rejection_reason}). Centroid distance exceeded threshold.",
                confidence=confidence,
                consistency_score=consistency,
                details=ml_verdict,
            )

        # 2. Multi-Signal Inconsistency (Potential MAC/DHCP Spoofing)
        if consistency < self.min_consistency:
            return PolicyDecision(
                mac=mac,
                action="MAINTAIN_QUARANTINE",
                new_state=DeviceTrustState.FLAGGED_INCONSISTENT,
                reason=f"Signal disagreement across groups ({consistency*100:.1f}% < {self.min_consistency*100:.1f}%). Possible profile spoofing.",
                confidence=confidence,
                consistency_score=consistency,
                details=ml_verdict,
            )

        # 3. Low Model Confidence
        if confidence < self.min_confidence:
            return PolicyDecision(
                mac=mac,
                action="MAINTAIN_QUARANTINE",
                new_state=DeviceTrustState.REJECTED_UNKNOWN,
                reason=f"Insufficient model confidence ({confidence*100:.1f}% < {self.min_confidence*100:.1f}%).",
                confidence=confidence,
                consistency_score=consistency,
                details=ml_verdict,
            )

        # 4. Class Whitelist Filter
        if self.allowed_classes is not None and predicted_class not in self.allowed_classes:
            return PolicyDecision(
                mac=mac,
                action="MAINTAIN_QUARANTINE",
                new_state=DeviceTrustState.MANUAL_HOLD,
                reason=f"Identified class '{predicted_class}' is not in policy whitelist {self.allowed_classes}.",
                confidence=confidence,
                consistency_score=consistency,
                details=ml_verdict,
            )

        # 5. Policy Admission Approved
        if self.auto_promote:
            return PolicyDecision(
                mac=mac,
                action="PROMOTE",
                new_state=DeviceTrustState.PROMOTED,
                reason=f"Verified fingerprint profile '{predicted_class}' with {confidence*100:.1f}% confidence and {consistency*100:.1f}% signal agreement.",
                confidence=confidence,
                consistency_score=consistency,
                details=ml_verdict,
            )
        else:
            return PolicyDecision(
                mac=mac,
                action="MANUAL_REVIEW",
                new_state=DeviceTrustState.QUARANTINED,
                reason=f"Verified fingerprint profile '{predicted_class}' awaiting manual operator promotion.",
                confidence=confidence,
                consistency_score=consistency,
                details=ml_verdict,
            )

    def evaluate_behavioral_drift(
        self, mac: str, current_state: DeviceTrustState, anomaly_verdict: Dict[str, Any]
    ) -> PolicyDecision:
        """Evaluate continuous post-admission telemetry for behavioral drift."""
        is_anomaly = bool(anomaly_verdict.get("is_anomaly", False))
        anomaly_score = float(anomaly_verdict.get("anomaly_score", 0.0))
        drift_reason = anomaly_verdict.get("reason", "BEHAVIORAL_ANOMALY")

        if current_state == DeviceTrustState.PROMOTED and is_anomaly:
            return PolicyDecision(
                mac=mac,
                action="DEMOTE",
                new_state=DeviceTrustState.DEMOTED_ANOMALOUS,
                reason=f"Post-promotion behavioral drift detected ({drift_reason}, score={anomaly_score:.2f} >= {self.anomaly_threshold:.2f}).",
                confidence=0.0,
                consistency_score=0.0,
                anomaly_score=anomaly_score,
                details=anomaly_verdict,
            )

        return PolicyDecision(
            mac=mac,
            action="NONE",
            new_state=current_state,
            reason="Telemetry conforms to benign baseline.",
            confidence=0.0,
            consistency_score=0.0,
            anomaly_score=anomaly_score,
            details=anomaly_verdict,
        )

