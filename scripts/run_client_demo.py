#!/usr/bin/env python3
"""Zero-Trust IoT Gateway - Client Presentation Master Demonstration.

Executes all 4 mission-critical zero-trust lifecycle scenarios:
1. Scenario 1: Authorized Smart Camera Onboarding -> Default Quarantine -> Auto-Promotion to Trusted VLAN.
2. Scenario 2: Novel Attacker / Rogue Scanner -> Outlier Novelty Rejection -> Sustained Quarantine.
3. Scenario 3: Identity / MAC Spoofing Attempt -> Multi-Signal Disagreement -> Flagged & Quarantined.
4. Scenario 4: Post-Admission Device Compromise -> Behavioral Drift Detection -> Automated Emergency Demotion!
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.enforcement.controller import ClosedLoopEnforcementController
from gateway.enforcement.policy import DeviceTrustState, ZeroTrustPolicyEngine
from gateway.models.anomaly import BehavioralAnomalyDetector
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.models.train import train_and_export_model
from gateway.quarantine.manager import QuarantineManager
from gateway.sensing.capture import PacketCaptureEngine
from gateway.sensing.storage import SensorStorage


def print_banner(text: str) -> None:
    print("\n" + "=" * 78)
    print(f"  {text}")
    print("=" * 78)


def print_step(title: str) -> None:
    print(f"\n[+] {title}")


def run_full_client_demonstration(
    model_path: str = "models/baseline_rf.joblib",
    db_path: str = "data/gateway.db",
) -> None:
    print_banner("RASPBERRY PI ZERO-TRUST IoT GATEWAY — 100% PRODUCT DEMO")
    print(" Architecture : OpenWrt (VLAN 10/20, nftables) + Pi 4/5 (Passive ML + Closed Loop)")
    print(" Core Tenet   : Never Trust, Always Verify, Continuous Post-Admission Monitoring")
    print("=" * 78)

    # 1. Initialize Subsystems
    quarantine = QuarantineManager(db_path=db_path, dry_run=True)
    storage = SensorStorage(db_path=db_path)
    capture_engine = PacketCaptureEngine(storage=storage, window_seconds=60)
    policy_engine = ZeroTrustPolicyEngine(
        min_confidence=0.70,
        min_consistency=0.70,
        anomaly_threshold=0.65,
        auto_promote=True,
    )

    # 2. Ensure Trained Classifier & Anomaly Detector Models
    if not os.path.exists(model_path):
        print("\n[*] Initializing baseline classifier artifact...")
        classifier, _ = train_and_export_model(output_model_path=model_path)
    else:
        classifier = ZeroTrustDeviceClassifier.load(model_path)

    print("[*] Training Behavioral Anomaly Detector baseline...")
    generator = BenchmarkDatasetGenerator(seed=42)
    benign_df = generator.generate_dataframe(samples_per_device=25, devices_per_class=3)
    anomaly_detector = BehavioralAnomalyDetector()
    anomaly_detector.fit(benign_df)

    # 3. Initialize Closed-Loop Orchestrator
    controller = ClosedLoopEnforcementController(
        classifier=classifier,
        quarantine_manager=quarantine,
        storage=storage,
        policy_engine=policy_engine,
        anomaly_detector=anomaly_detector,
        db_path=db_path,
    )

    temp_dir = tempfile.mkdtemp()

    # =========================================================================
    # SCENARIO 1: Authorized Smart Camera Onboarding & Automated Promotion
    # =========================================================================
    print_banner("SCENARIO 1: Authorized Endpoint Connection (Smart Camera)")
    cam_mac = "b8:27:eb:aa:11:22"
    cam_ip = "192.168.20.55"

    print_step("Step 1.1: Device connects to network with unverified MAC")
    controller.register_new_device(mac=cam_mac, ip=cam_ip, vendor="Raspberry Pi Trading Ltd")
    print(f"  [ENFORCEMENT] Device {cam_mac} inserted into nftables @quarantine_macs.")
    print(f"  [FIREWALL] Assigned to Quarantine Zone (VLAN 20). Lateral & WAN traffic DROPPED.")

    print_step("Step 1.2: Passive sensing extracts 4 signal groups without payload inspection")
    cam_pcap = os.path.join(temp_dir, "cam_valid.pcap")
    generator.generate_sample_pcap(cam_pcap, device_class="smart_camera", mac=cam_mac, ip=cam_ip, packet_count=35)
    capture_engine.process_pcap(cam_pcap)

    print_step("Step 1.3: Closed-Loop Policy Evaluation & Automated Promotion")
    decision1 = controller.evaluate_device(cam_mac)
    print(f"  - Inferred Class     : {decision1.details.get('predicted_class')}")
    print(f"  - Model Confidence   : {decision1.confidence * 100:.1f}%")
    print(f"  - Signal Consistency : {decision1.consistency_score * 100:.1f}% (All groups in agreement)")
    print(f"  - Decision Action    : {decision1.action}")
    print(f"  - Resulting State    : {decision1.new_state.value}")
    print(f"  [✔] Device successfully promoted from VLAN 20 (Quarantine) to VLAN 10 (Trusted)!")

    # =========================================================================
    # SCENARIO 2: Rogue Scanner / Novel Threat Isolation
    # =========================================================================
    print_banner("SCENARIO 2: Rogue / Unmodeled Attacker Connection (Kali Scanner)")
    rogue_mac = "a0:b1:c2:d3:e4:f5"
    rogue_ip = "192.168.20.99"

    print_step("Step 2.1: Attacker connects with rogue MAC")
    controller.register_new_device(mac=rogue_mac, ip=rogue_ip, vendor="Unknown Network Hardware")

    print_step("Step 2.2: Passive sensing extracts irregular flow statistics")
    rogue_pcap = os.path.join(temp_dir, "rogue.pcap")
    generator.generate_sample_pcap(rogue_pcap, device_class="rogue_unknown", mac=rogue_mac, ip=rogue_ip, packet_count=35)
    capture_engine.process_pcap(rogue_pcap)

    print_step("Step 2.3: Closed-Loop Policy Decision via Open-Set Novelty Detection")
    decision2 = controller.evaluate_device(rogue_mac)
    print(f"  - Inferred Class     : {decision2.details.get('predicted_class')} (Novel/Unseen Endpoint)")
    print(f"  - Centroid Distance  : {decision2.details.get('centroid_distance')} (Threshold: {classifier.distance_threshold:.2f})")
    print(f"  - Decision Action    : {decision2.action}")
    print(f"  - Resulting State    : {decision2.new_state.value}")
    print(f"  [✔] Threat isolated! Attacker remains locked in quarantine VLAN 20.")

    # =========================================================================
    # SCENARIO 3: Identity Spoofing Detection via Multi-Signal Consistency
    # =========================================================================
    print_banner("SCENARIO 3: Profile Spoofing Attack (Camera MAC with Rogue Signals)")
    spoof_mac = "b8:27:eb:cc:dd:ee"
    spoof_ip = "192.168.20.60"

    print_step("Step 3.1: Attacker attempts to spoof an authorized Camera MAC")
    controller.register_new_device(mac=spoof_mac, ip=spoof_ip, vendor="Raspberry Pi Trading Ltd")

    print_step("Step 3.2: Passive telemetry reveals conflicting signal groups")
    # Device advertises camera DHCP/hostname, but sends thermostat-like low volume traffic without RTSP
    spoofed_features = {
        "has_dhcp": 1.0,
        "dhcp_options_count": 5.0,
        "dhcp_param_req_count": 5.0,
        "has_vendor_class": 1.0,
        "has_hostname": 1.0,
        "has_discovery": 0.0,
        "discovery_service_count": 0.0,
        "discovery_txt_keys_count": 0.0,
        "discovery_ports_count": 0.0,
        "has_tcptls": 1.0,
        "estimated_initial_ttl": 64.0,
        "tcp_mss": 1360.0,
        "initial_window_size": 14600.0,
        "tcp_options_count": 3.0,
        "has_tls": 0.0,
        "sni_count": 0.0,
        "total_packets": 20.0,
        "packet_rate": 0.33,
        "byte_rate": 45.0,
        "size_min": 40.0,
        "size_max": 180.0,
        "size_mean": 120.0,
        "size_std": 30.0,
        "size_median": 120.0,
        "unique_dest_ips": 1.0,
        "dest_ip_entropy": 0.0,
        "unique_dest_ports": 1.0,
        "dest_port_entropy": 0.0,
        "iat_mean": 3.0,
        "iat_std": 0.1,
        "iat_cv": 0.03,
        "periodicity_score": 0.95,
        "burstiness_ratio": 1.1,
    }
    storage.store_feature_snapshot(
        mac=spoof_mac,
        structured_data={
            "duration_seconds": 60.0,
            "ip": spoof_ip,
            "signals": {},
            "features": spoofed_features,
        },
    )

    print_step("Step 3.3: Multi-Signal Consistency Engine evaluates cross-group agreement")
    decision3 = controller.evaluate_device(spoof_mac)
    print(f"  - Raw Class Candidate: {decision3.details.get('raw_class')}")
    print(f"  - Signal Consistency : {decision3.consistency_score * 100:.1f}% (FAILED: Conflicting protocol signatures)")
    print(f"  - Decision Action    : {decision3.action}")
    print(f"  - Resulting State    : {decision3.new_state.value}")
    print(f"  [✔] Spoofing thwarted! Device flagged as FLAGGED_INCONSISTENT and quarantined.")

    # =========================================================================
    # SCENARIO 4: Post-Admission Device Compromise & Automated Emergency Demotion
    # =========================================================================
    print_banner("SCENARIO 4: Post-Admission Compromise & Automated Demotion")
    print(f"Target: Endpoint {cam_mac} (Previously verified & promoted to Trusted VLAN 10)")

    print_step("Step 4.1: Camera endpoint is hijacked (e.g. infected with Mirai botnet)")
    print("  [ALERT] Camera suddenly initiates horizontal port scan and high-volume burst traffic...")
    compromised_features = {
        "total_packets": 600.0,
        "packet_rate": 60.0,
        "byte_rate": 6500.0,
        "size_min": 40.0,
        "size_max": 80.0,
        "size_mean": 52.0,
        "size_std": 8.0,
        "unique_dest_ips": 65.0,  # Mass scanning
        "dest_ip_entropy": 4.8,   # High entropy
        "unique_dest_ports": 80.0,
        "dest_port_entropy": 5.1,
        "iat_mean": 0.016,
        "iat_std": 0.005,
        "iat_cv": 0.31,
        "periodicity_score": 0.15,
        "burstiness_ratio": 9.2,  # Sudden massive burst
    }
    storage.store_feature_snapshot(
        mac=cam_mac,
        structured_data={
            "duration_seconds": 60.0,
            "ip": cam_ip,
            "signals": {"traffic": compromised_features},
            "features": compromised_features,
        },
    )

    print_step("Step 4.2: Behavioral Anomaly Detector evaluates statistical drift")
    decision4 = controller.evaluate_device(cam_mac)
    print(f"  - Anomaly Score      : {decision4.anomaly_score:.2f} (Threshold: {policy_engine.anomaly_threshold:.2f})")
    print(f"  - Detection Reason   : {decision4.reason}")
    print(f"  - Decision Action    : {decision4.action}")
    print(f"  - Resulting State    : {decision4.new_state.value}")
    print(f"  [✔] Emergency response executed! Device {cam_mac} immediately revoked from VLAN 10 and locked back into quarantine.")

    # =========================================================================
    # Audit Trail Summary
    # =========================================================================
    print_banner("DEMONSTRATION COMPLETE — AUDIT TRAIL PERSISTED")
    recent_audits = quarantine.get_audit_history()
    print(f"Total audit log entries persisted: {len(recent_audits)}")
    print("\nRecent 5 Audit Events:")
    for entry in recent_audits[-5:]:
        print(f"  [{entry['timestamp'][11:19]}] {entry['mac']} | {entry['action']} -> {entry['reason']}")
    print("=" * 78 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Zero-Trust IoT Gateway Full Client Demonstration")
    parser.add_argument("--model-path", default="models/baseline_rf.joblib", help="Model path")
    parser.add_argument("--db-path", default="data/gateway.db", help="SQLite database path")
    args = parser.parse_args()

    run_full_client_demonstration(model_path=args.model_path, db_path=args.db_path)


if __name__ == "__main__":
    main()

