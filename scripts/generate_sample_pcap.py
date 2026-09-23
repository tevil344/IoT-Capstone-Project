#!/usr/bin/env python3
"""CLI utility to generate synthetic IoT PCAP traces for testing."""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway.datasets.synthetic import DEVICE_PROFILES_CONFIG, BenchmarkDatasetGenerator


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic IoT network capture traces")
    parser.add_argument(
        "--output",
        default="sample_trace.pcap",
        help="Destination PCAP file path",
    )
    parser.add_argument(
        "--device",
        choices=list(DEVICE_PROFILES_CONFIG.keys()),
        default="smart_camera",
        help="Device class profile to synthesize",
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=50,
        help="Number of packets to synthesize",
    )
    args = parser.parse_args()

    generator = BenchmarkDatasetGenerator()
    out = generator.generate_sample_pcap(
        output_pcap_path=args.output,
        device_class=args.device,
        packet_count=args.packets,
    )
    print(f"[✔] Successfully generated {args.device} trace ({args.packets} pkts) at {out}")


if __name__ == "__main__":
    main()
