"""Closed-Loop Policy Enforcement Controller.

Orchestrates passive sensing telemetry, machine learning inference, zero-trust
policy decisions, and Linux nftables quarantine enforcement.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from gateway.enforcement.policy import (
    DeviceTrustState,
    PolicyDecision,
    ZeroTrustPolicyEngine,
)
from gateway.models.anomaly import BehavioralAnomalyDetector
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.quarantine.manager import QuarantineManager, normalize_mac
from gateway.sensing.storage import SensorStorage

logger = logging.getLogger("gateway.enforcement.controller")


class ClosedLoopEnforcementController:
    """Central orchestrator for zero-trust admission and continuous behavioral enforcement."""

    def __init__(
        self,
        classifier: ZeroTrustDeviceClassifier,
        quarantine_manager: Optional[QuarantineManager] = None,
        storage: Optional[SensorStorage] = None,
        policy_engine: Optional[ZeroTrustPolicyEngine] = None,
        anomaly_detector: Optional[BehavioralAnomalyDetector] = None,
        db_path: str = "data/gateway.db",
    ) -> None:
        self.db_path = db_path
        self.classifier = classifier
        self.quarantine_manager = quarantine_manager or QuarantineManager(db_path=db_path)
        self.storage = storage or SensorStorage(db_path=db_path)
        self.policy_engine = policy_engine or ZeroTrustPolicyEngine()
        self.anomaly_detector = anomaly_detector

        logger.info("ClosedLoopEnforcementController initialized (db=%s).", self.db_path)

    def register_new_device(
        self, mac: str, ip: Optional[str] = None, hostname: Optional[str] = None, vendor: Optional[str] = None
    ) -> bool:
        """Default-Deny entrypoint: Quarantine device immediately upon network connection."""
        mac_norm = normalize_mac(mac)
        logger.info("Zero-Trust onboarding: Quarantining newly connected endpoint %s", mac_norm)

        # 1. Add to nftables quarantine set
        success = self.quarantine_manager.quarantine_mac(
            mac_norm, reason="zero_trust_default_deny_on_connect"
        )

        # 2. Upsert in device database with QUARANTINED status
        self.storage.upsert_device(
            mac=mac_norm,
            ip=ip,
            hostname=hostname,
            vendor=vendor,
            status=DeviceTrustState.QUARANTINED.value,
        )

        # 3. Audit trail
        self.storage.log_audit_event(
            event_type="DEVICE_ONBOARDED_QUARANTINED",
            message=f"Endpoint {mac_norm} placed in quarantine by default-deny policy.",
            mac=mac_norm,
            metadata={"ip": ip, "hostname": hostname, "vendor": vendor},
        )
        return success

    def evaluate_device(self, mac: str) -> PolicyDecision:
        """Evaluate latest telemetry snapshot and execute closed-loop policy enforcement."""
        mac_norm = normalize_mac(mac)
        snapshot = self.storage.get_latest_snapshot(mac_norm)

        if not snapshot:
            logger.warning("No telemetry snapshot available to evaluate for device %s", mac_norm)
            return PolicyDecision(
                mac=mac_norm,
                action="MAINTAIN_QUARANTINE",
                new_state=DeviceTrustState.QUARANTINED,
                reason="No packet telemetry captured yet.",
                confidence=0.0,
                consistency_score=0.0,
            )

        features = snapshot.get("features", {})
        current_status_str = self._get_device_current_status(mac_norm)
        try:
            current_state = DeviceTrustState(current_status_str)
        except ValueError:
            current_state = DeviceTrustState.QUARANTINED

        # SCENARIO A: Device is currently QUARANTINED -> Evaluate admission via Classifier
        if current_state in (
            DeviceTrustState.QUARANTINED,
            DeviceTrustState.UNSEEN,
            DeviceTrustState.REJECTED_UNKNOWN,
            DeviceTrustState.FLAGGED_INCONSISTENT,
            DeviceTrustState.MANUAL_HOLD,
        ):
            ml_verdict = self.classifier.predict_single(features)
            decision = self.policy_engine.evaluate_admission(mac_norm, ml_verdict)

            if decision.action == "PROMOTE":
                # Execute Promotion in firewall
                self.quarantine_manager.release_mac(mac_norm, reason=decision.reason)
                self.storage.upsert_device(mac=mac_norm, status=DeviceTrustState.PROMOTED.value)
                self.storage.log_audit_event(
                    event_type="ENFORCEMENT_PROMOTED",
                    message=f"Endpoint {mac_norm} promoted to trusted VLAN: {decision.reason}",
                    mac=mac_norm,
                    metadata=decision.to_dict(),
                )
                logger.info("[POLICY PEP] Promoted %s to trusted zone: %s", mac_norm, decision.reason)

            elif decision.action == "MAINTAIN_QUARANTINE":
                # Enforce containment
                self.quarantine_manager.quarantine_mac(mac_norm, reason=decision.reason)
                self.storage.upsert_device(mac=mac_norm, status=decision.new_state.value)
                self.storage.log_audit_event(
                    event_type="ENFORCEMENT_ADMISSION_DENIED",
                    message=f"Endpoint {mac_norm} kept in quarantine: {decision.reason}",
                    mac=mac_norm,
                    metadata=decision.to_dict(),
                )
                logger.warning("[POLICY PEP] Admission denied for %s: %s", mac_norm, decision.reason)

            return decision

        # SCENARIO B: Device is currently PROMOTED -> Evaluate continuous behavioral drift
        elif current_state == DeviceTrustState.PROMOTED:
            if self.anomaly_detector and self.anomaly_detector.is_fitted:
                anomaly_verdict = self.anomaly_detector.score_sample(features)
                decision = self.policy_engine.evaluate_behavioral_drift(
                    mac_norm, current_state, anomaly_verdict
                )

                if decision.action == "DEMOTE":
                    # Execute Demotion in firewall: Kick back to quarantine!
                    self.quarantine_manager.quarantine_mac(mac_norm, reason=decision.reason)
                    self.storage.upsert_device(mac=mac_norm, status=DeviceTrustState.DEMOTED_ANOMALOUS.value)
                    self.storage.log_audit_event(
                        event_type="ENFORCEMENT_DEMOTED_ANOMALY",
                        message=f"Endpoint {mac_norm} demoted to quarantine: {decision.reason}",
                        mac=mac_norm,
                        metadata=decision.to_dict(),
                    )
                    logger.error("[POLICY PEP] Alert! Demoted %s back to quarantine: %s", mac_norm, decision.reason)

                return decision
            else:
                return PolicyDecision(
                    mac=mac_norm,
                    action="NONE",
                    new_state=DeviceTrustState.PROMOTED,
                    reason="Device verified and trusted. Anomaly detector inactive.",
                    confidence=1.0,
                    consistency_score=1.0,
                )

        # Fallback
        return PolicyDecision(
            mac=mac_norm,
            action="NONE",
            new_state=current_state,
            reason="No state transition required.",
            confidence=0.0,
            consistency_score=0.0,
        )

    def manual_promote(self, mac: str, operator: str = "admin") -> bool:
        """Operator manual promotion override."""
        mac_norm = normalize_mac(mac)
        success = self.quarantine_manager.release_mac(mac_norm, reason=f"manual_operator_override_by_{operator}")
        if success:
            self.storage.upsert_device(mac=mac_norm, status=DeviceTrustState.PROMOTED.value)
            self.storage.log_audit_event(
                event_type="MANUAL_PROMOTION_OVERRIDE",
                message=f"Operator {operator} manually promoted device {mac_norm} to trusted zone.",
                mac=mac_norm,
            )
            logger.info("Operator %s manually promoted %s to trusted zone.", operator, mac_norm)
        return success

    def manual_quarantine(self, mac: str, reason: str = "operator_lockdown", operator: str = "admin") -> bool:
        """Operator manual quarantine override / emergency lockdown."""
        mac_norm = normalize_mac(mac)
        success = self.quarantine_manager.quarantine_mac(mac_norm, reason=f"{reason}_by_{operator}")
        if success:
            self.storage.upsert_device(mac=mac_norm, status=DeviceTrustState.QUARANTINED.value)
            self.storage.log_audit_event(
                event_type="MANUAL_QUARANTINE_OVERRIDE",
                message=f"Operator {operator} locked down device {mac_norm} into quarantine ({reason}).",
                mac=mac_norm,
            )
            logger.info("Operator %s quarantined %s (%s).", operator, mac_norm, reason)
        return success

    def _get_device_current_status(self, mac: str) -> str:
        """Fetch current status from SQLite devices table."""
        with self.storage._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT status FROM devices WHERE mac = ?", (mac,))
            row = cursor.fetchone()
            return str(row[0]) if row and row[0] else DeviceTrustState.QUARANTINED.value

    def get_device_overview(self, mac: str) -> Optional[Dict[str, Any]]:
        """Get consolidated 360-degree telemetry, policy, and audit state for a device."""
        mac_norm = normalize_mac(mac)
        with self.storage._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT mac, ip, hostname, vendor, first_seen, last_seen, status FROM devices WHERE mac = ?",
                (mac_norm,),
            )
            dev_row = cursor.fetchone()
            if not dev_row:
                return None

        snapshot = self.storage.get_latest_snapshot(mac_norm)
        audit_history = self.quarantine_manager.get_audit_history(mac_norm)

        # Calculate live inference verdict if snapshot exists
        verdict = self.classifier.predict_single(snapshot["features"]) if snapshot else {}
        anomaly_verdict = (
            self.anomaly_detector.score_sample(snapshot["features"])
            if (self.anomaly_detector and self.anomaly_detector.is_fitted and snapshot)
            else {}
        )

        return {
            "mac": dev_row[0],
            "ip": dev_row[1] or "",
            "hostname": dev_row[2] or "",
            "vendor": dev_row[3] or "",
            "first_seen": dev_row[4],
            "last_seen": dev_row[5],
            "status": dev_row[6],
            "is_in_firewall_quarantine": self.quarantine_manager.is_quarantined(mac_norm),
            "ml_verdict": verdict,
            "anomaly_verdict": anomaly_verdict,
            "latest_snapshot": snapshot,
            "audit_trail": audit_history,
        }

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """List all tracked devices with current trust states."""
        with self.storage._connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mac, ip, hostname, vendor, first_seen, last_seen, status FROM devices ORDER BY last_seen DESC")
            rows = cursor.fetchall()

        results = []
        for r in rows:
            mac = r[0]
            results.append({
                "mac": mac,
                "ip": r[1] or "",
                "hostname": r[2] or "",
                "vendor": r[3] or "",
                "first_seen": r[4],
                "last_seen": r[5],
                "status": r[6],
                "is_in_firewall_quarantine": self.quarantine_manager.is_quarantined(mac),
            })
        return results
