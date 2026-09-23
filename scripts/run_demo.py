#!/usr/bin/env python3
"""Raspberry Pi Zero-Trust IoT Gateway - End-to-End Demonstration Script.

Simulates or processes a device connection:
1. Device connects with unverified MAC -> Placed in Quarantine zone (DHCP/DNS/NTP only).
2. Passive sensing captures network metadata across 4 signal groups:
   - DHCP (Option order, vendor class, hostname, client-id)
   - Discovery (mDNS/SSDP service types, TXT keys, ports)
   - TCP/IP + TLS (TTL, TCP options, MSS, JA3/SNI)
   - Traffic (Diversity, size stats, periodicity, burstiness)
3. Structured snapshot persisted to SQLite with full audit log.
4. Baseline ML inference:
   - Evaluates P(c|x)
   - Performs open-set novelty rejection
   - Computes multi-signal consistency score
5. Prints comprehensive verdict and zero-trust policy decision.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import time

# Ensure project root is in python module path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.models.train import train_and_export_model
from gateway.quarantine.manager import QuarantineManager
from gateway.sensing.capture import PacketCaptureEngine
from gateway.sensing.storage import SensorStorage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("gateway.demo")


def run_pipeline(
    device_class: str = "smart_camera",
    custom_pcap: str = None,
    model_path: str = "models/baseline_rf.joblib",
    db_path: str = "data/gateway.db",
) -> dict:
    """Run end-to-end device onboarding and detection pipeline."""
    print("\n" + "=" * 75)
    print("  RASPBERRY PI ZERO-TRUST IoT GATEWAY — PASSIVE DETECTION MVP")
    print("=" * 75)

    # 1. Initialize Subsystems (Quarantine, Storage, Sensing Engine)
    quarantine = QuarantineManager(db_path=db_path, dry_run=True)
    storage = SensorStorage(db_path=db_path)
    capture_engine = PacketCaptureEngine(storage=storage, window_seconds=60)

    # 2. Ensure Trained Model Artifact Exists
    if not os.path.exists(model_path):
        print(f"\n[*] Training baseline classifier artifact at {model_path} ...")
        classifier, _ = train_and_export_model(output_model_path=model_path)
    else:
        classifier = ZeroTrustDeviceClassifier.load(model_path)

    # 3. Simulate or Ingest Device Connection
    if custom_pcap and os.path.exists(custom_pcap):
        pcap_file = custom_pcap
        mac = "b8:27:eb:aa:11:22"
        ip = "192.168.20.55"
        print(f"\n[STEP 1] Ingesting network trace from PCAP: {custom_pcap}")
    else:
        generator = BenchmarkDatasetGenerator(seed=int(time.time()))
        temp_dir = tempfile.mkdtemp()
        pcap_file = os.path.join(temp_dir, f"{device_class}_trace.pcap")
        mac = f"b8:27:eb:{device_class[:2].encode().hex()[:4]}:55"
        if device_class == "rogue_unknown":
            mac = "a0:b1:c2:d3:e4:f5"
        elif device_class == "smart_speaker":
            mac = "44:65:0d:88:99:aa"
        elif device_class == "smart_plug":
            mac = "50:c7:bf:12:34:56"
        elif device_class == "thermostat":
            mac = "00:17:88:fe:dc:ba"

        ip = "192.168.20.77"
        print(f"\n[STEP 1] Device Connected: MAC={mac} (Class={device_class})")
        generator.generate_sample_pcap(
            output_pcap_path=pcap_file,
            device_class=device_class,
            mac=mac,
            ip=ip,
            packet_count=35,
        )

    # 4. Quarantine Zone Enforcement (Default Deny)
    print(f"\n[STEP 2] Enforcing Zero-Trust Policy:")
    quarantine.quarantine_mac(mac, reason="unverified_new_device", timeout_seconds=300)
    is_contained = quarantine.is_quarantined(mac)
    print(f"  [+] Device {mac} added to nftables @quarantine_macs set")
    print(f"  [+] Zone: QUARANTINE (VLAN 20) | Active: {is_contained}")
    print(f"  [+] Allow: DHCP (UDP 67/68), DNS (UDP 53 to gateway), NTP (UDP 123)")
    print(f"  [+] Deny: Lateral east-west probing, WAN forward egress")

    # 5. Passive Sensing (Metadata Extraction across 4 Signal Groups)
    print(f"\n[STEP 3] Passive Sensing & Metadata Extraction (60s window)...")
    pkt_count = capture_engine.process_pcap(pcap_file)
    print(f"  [✔] Ingested {pkt_count} packets without payload inspection")

    # Retrieve structured snapshot and flat feature vector
    snapshot = storage.get_latest_snapshot(mac)
    if not snapshot:
        raise RuntimeError(f"No snapshot recorded for MAC {mac}")

    signals = snapshot["signals"]
    features = snapshot["features"]

    print("  [✔] Signal Group 1 (DHCP):")
    print(f"      - Option Order : {signals['dhcp'].get('option_order')}")
    print(f"      - Hostname     : {signals['dhcp'].get('hostname') or '(none)'}")
    print(f"      - Vendor Class : {signals['dhcp'].get('vendor_class_id') or '(none)'}")

    print("  [✔] Signal Group 2 (Service Discovery):")
    print(f"      - Services     : {signals['discovery'].get('services') or '(none)'}")
    print(f"      - TXT Keys     : {signals['discovery'].get('txt_keys') or '(none)'}")
    print(f"      - Open Ports   : {signals['discovery'].get('discovered_ports') or '(none)'}")

    print("  [✔] Signal Group 3 (TCP/IP + TLS):")
    print(f"      - Initial TTL  : {signals['tcptls'].get('estimated_initial_ttl')}")
    print(f"      - TCP Options  : {signals['tcptls'].get('tcp_options_str') or '(none)'}")
    print(f"      - TCP MSS      : {signals['tcptls'].get('tcp_mss')}")
    print(f"      - JA3 / SNI    : {signals['tcptls'].get('ja3_hash') or '(none)'} / {signals['tcptls'].get('sni_hostnames') or '[]'}")

    print("  [✔] Signal Group 4 (Traffic Dynamics):")
    print(f"      - Packets / Bytes : {signals['traffic'].get('total_packets')} pkts / {signals['traffic'].get('total_bytes')} bytes")
    print(f"      - Mean Size ± Std : {signals['traffic'].get('size_mean')} ± {signals['traffic'].get('size_std')} bytes")
    print(f"      - Periodicity     : {signals['traffic'].get('periodicity_score')} (Burstiness: {signals['traffic'].get('burstiness_ratio')}x)")

    # 6. Baseline Classifier Inference & Open-Set Rejection
    print(f"\n[STEP 4] ML Classification & Open-Set Consistency Scoring...")
    verdict = classifier.predict_single(features)

    # 7. Zero-Trust Policy Decision (Separate from Sensing/Inference)
    if verdict["is_rejected"]:
        policy_verdict = "MAINTAIN_QUARANTINE (NOVEL/UNKNOWN THREAT)"
        recommendation = "Reject promotion. Device exhibits unmodeled behavior or anomalous feature distance."
    elif verdict["consistency_score"] < 0.60:
        policy_verdict = "MAINTAIN_QUARANTINE (SIGNAL INCONSISTENCY)"
        recommendation = "Flag for security review. Potential MAC/DHCP spoofing detected across signal groups."
    else:
        policy_verdict = "READY_FOR_PROMOTION_REVIEW"
        recommendation = f"Fingerprint matches authorized profile '{verdict['predicted_class']}'. Operator may promote to VLAN 10."

    # Record inference decision to audit log
    storage.log_audit_event(
        event_type="INFERENCE_COMPLETED",
        message=f"Inference verdict: {verdict['predicted_class']} (conf={verdict['confidence']}, cons={verdict['consistency_score']})",
        mac=mac,
        metadata={
            "verdict": verdict,
            "policy_action": policy_verdict,
        },
    )

    # Print Final Report
    print("\n" + "=" * 75)
    print("  ZERO-TRUST GATEWAY VERDICT & AUDIT TRAIL")
    print("=" * 75)
    print(f" Target MAC Address     : {mac}")
    print(f" Current State          : QUARANTINED (nftables @quarantine_macs)")
    print(f" Predicted Class        : {verdict['predicted_class']}")
    print(f" Raw Model Candidate    : {verdict['raw_class']}")
    print(f" Confidence P(c|x)      : {verdict['confidence'] * 100:.2f}%")
    print(f" Consistency Score      : {verdict['consistency_score'] * 100:.1f}% (Agreement across signal groups)")
    print(f" Open-Set Rejected      : {verdict['is_rejected']} (Reason: {verdict['rejection_reason']})")
    print(f" Centroid Distance      : {verdict['centroid_distance']:.3f} (Max threshold: {classifier.distance_threshold:.3f})")
    print(f" Signal Group Breakdown : {json.dumps(verdict['group_predictions'])}")
    print(f" Policy Status          : {policy_verdict}")
    print(f" Recommendation         : {recommendation}")
    print("=" * 75 + "\n")

    return {
        "mac": mac,
        "verdict": verdict,
        "policy_status": policy_verdict,
        "snapshot_id": snapshot["id"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Zero-Trust IoT Gateway Passive Detection MVP Demo"
    )
    parser.add_argument(
        "--device",
        choices=["smart_camera", "smart_speaker", "smart_plug", "thermostat", "rogue_unknown"],
        default="smart_camera",
        help="Device category to simulate and fingerprint",
    )
    parser.add_argument(
        "--pcap",
        default=None,
        help="Path to custom PCAP trace file to process",
    )
    parser.add_argument(
        "--model-path",
        default="models/baseline_rf.joblib",
        help="Path to trained classifier model artifact",
    )
    parser.add_argument(
        "--db-path",
        default="data/gateway.db",
        help="Path to SQLite persistence database",
    )
    args = parser.parse_args()

    run_pipeline(
        device_class=args.device,
        custom_pcap=args.pcap,
        model_path=args.model_path,
        db_path=args.db_path,
    )


if __name__ == "__main__":
    main()
