"""Synthetic IoT Benchmark Dataset and PCAP Generator.

Generates reproducible, authentic IoT traffic traces matching our 4-signal
passive extraction schema across multiple device categories:
- smart_camera (High bandwidth, RTSP/HTTP, mDNS/ONVIF, Linux TTL=64, periodic keepalive + video bursts)
- smart_speaker (Medium bandwidth, mDNS/SSDP Spotify/GoogleCast, TLS ClientHello, bursty streaming)
- smart_plug (Low bandwidth, UDP 9999 / MQTT, small packets, high periodicity heartbeats, TTL=64/128)
- thermostat (Very low bandwidth, NTP + HTTPS periodic telemetry, highly periodic, TTL=64)
- rogue_unknown (Novel/unseen class: port scanner, SSH brute-forcer, irregular packet sizes, unknown services)
"""

from __future__ import annotations

import os
import random
import time
from typing import Any, Dict, List, Tuple
import pandas as pd
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap


DEVICE_PROFILES_CONFIG = {
    "smart_camera": {
        "oui": "b8:27:eb",
        "hostname_prefix": "cam-ipc",
        "vendor_class": "Linux-IPC-Cam",
        "dhcp_options": [53, 61, 50, 12, 55],
        "mdns_services": ["_rtsp._tcp.local", "_http._tcp.local", "_onvif._tcp.local"],
        "txt_keys": ["mac", "model", "ver"],
        "tcp_mss": 1460,
        "ttl": 64,
        "window_size": 29200,
        "pkt_size_mean": 950.0,
        "pkt_size_std": 350.0,
        "periodicity_score": 0.65,
        "burstiness_ratio": 2.8,
        "unique_dest_ips": 3,
        "ports": [554, 80, 8080],
    },
    "smart_speaker": {
        "oui": "44:65:0d",
        "hostname_prefix": "smart-speaker",
        "vendor_class": "android-dhcp-audio",
        "dhcp_options": [53, 55, 57, 61, 50, 12],
        "mdns_services": ["_googlecast._tcp.local", "_spotify-connect._tcp.local"],
        "txt_keys": ["md", "fn", "id", "ve"],
        "tcp_mss": 1400,
        "ttl": 64,
        "window_size": 65535,
        "pkt_size_mean": 420.0,
        "pkt_size_std": 220.0,
        "periodicity_score": 0.50,
        "burstiness_ratio": 3.5,
        "unique_dest_ips": 5,
        "ports": [443, 8008, 8443],
    },
    "smart_plug": {
        "oui": "50:c7:bf",
        "hostname_prefix": "kasa-plug",
        "vendor_class": "TP-LINK-Smart-Plug",
        "dhcp_options": [53, 50, 12, 55],
        "mdns_services": ["_iot-device._udp.local"],
        "txt_keys": ["type", "dev_name"],
        "tcp_mss": 1460,
        "ttl": 128,
        "window_size": 8192,
        "pkt_size_mean": 110.0,
        "pkt_size_std": 35.0,
        "periodicity_score": 0.90,
        "burstiness_ratio": 1.2,
        "unique_dest_ips": 2,
        "ports": [9999, 8883],
    },
    "thermostat": {
        "oui": "00:17:88",
        "hostname_prefix": "ecobee-stat",
        "vendor_class": "ecobee-firmware-4.2",
        "dhcp_options": [53, 55, 12],
        "mdns_services": ["_ecobee._tcp.local"],
        "txt_keys": ["id", "fw"],
        "tcp_mss": 1360,
        "ttl": 64,
        "window_size": 14600,
        "pkt_size_mean": 180.0,
        "pkt_size_std": 45.0,
        "periodicity_score": 0.95,
        "burstiness_ratio": 1.1,
        "unique_dest_ips": 2,
        "ports": [443, 123],
    },
    "rogue_unknown": {
        "oui": "a0:b1:c2",
        "hostname_prefix": "kali-recon",
        "vendor_class": "nmap-scan-engine",
        "dhcp_options": [53, 55],
        "mdns_services": [],
        "txt_keys": [],
        "tcp_mss": 1024,
        "ttl": 255,
        "window_size": 1024,
        "pkt_size_mean": 60.0,
        "pkt_size_std": 10.0,
        "periodicity_score": 0.15,
        "burstiness_ratio": 6.0,
        "unique_dest_ips": 25,
        "ports": [22, 23, 80, 445, 3389],
    },
}


class BenchmarkDatasetGenerator:
    """Generates synthetic dataset and PCAP traces for reproducible testing."""

    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        random.seed(seed)

    def generate_dataframe(
        self,
        samples_per_device: int = 30,
        devices_per_class: int = 3,
        sessions_per_device: int = 3,
    ) -> pd.DataFrame:
        """Generate structured DataFrame with device_id, session_id, and exact feature columns."""
        rows: List[Dict[str, Any]] = []

        for label, config in DEVICE_PROFILES_CONFIG.items():
            for dev_idx in range(devices_per_class):
                device_id = f"{label}_dev{dev_idx + 1}"
                mac = f"{config['oui']}:{dev_idx:02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}"

                for sess_idx in range(sessions_per_device):
                    session_id = f"{device_id}_sess{sess_idx + 1}"

                    for sample_idx in range(samples_per_device // sessions_per_device):
                        row = self._generate_feature_row(
                            label=label,
                            config=config,
                            device_id=device_id,
                            session_id=session_id,
                            mac=mac,
                        )
                        rows.append(row)

        df = pd.DataFrame(rows)
        return df

    def _generate_feature_row(
        self,
        label: str,
        config: Dict[str, Any],
        device_id: str,
        session_id: str,
        mac: str,
    ) -> Dict[str, Any]:
        """Synthesize a single feature vector row."""
        # Jitter numerical features with realistic Gaussian noise
        size_mean = max(40.0, random.gauss(config["pkt_size_mean"], config["pkt_size_std"] * 0.15))
        size_std = max(5.0, random.gauss(config["pkt_size_std"], 10.0))
        periodicity = max(0.05, min(0.99, random.gauss(config["periodicity_score"], 0.05)))
        burstiness = max(1.0, random.gauss(config["burstiness_ratio"], 0.2))
        unique_dest_ips = max(1, int(random.gauss(config["unique_dest_ips"], 0.5)))
        unique_dest_ports = max(1, len(config["ports"]) + random.choice([0, 1]))

        total_pkts = random.randint(30, 250)
        duration = random.uniform(60.0, 120.0)

        return {
            # Metadata columns (used for leakage-safe splitting, excluded from model training)
            "device_id": device_id,
            "session_id": session_id,
            "mac": mac,
            "device_class": label,

            # Signal 1: DHCP Features
            "has_dhcp": 1.0 if config["dhcp_options"] else 0.0,
            "dhcp_options_count": float(len(config["dhcp_options"])),
            "dhcp_param_req_count": float(random.choice([4, 5, 6])),
            "has_vendor_class": 1.0 if config["vendor_class"] else 0.0,
            "has_hostname": 1.0,

            # Signal 2: Service Discovery Features
            "has_discovery": 1.0 if config["mdns_services"] else 0.0,
            "discovery_service_count": float(len(config["mdns_services"])),
            "discovery_txt_keys_count": float(len(config["txt_keys"])),
            "discovery_ports_count": float(len(config["ports"])),

            # Signal 3: TCP/IP + TLS Features
            "has_tcptls": 1.0,
            "estimated_initial_ttl": float(config["ttl"]),
            "tcp_mss": float(config["tcp_mss"]),
            "initial_window_size": float(config["window_size"]),
            "tcp_options_count": float(random.choice([4, 5])),
            "has_tls": 1.0 if label in ("smart_speaker", "thermostat", "smart_camera") else 0.0,
            "sni_count": 1.0 if label in ("smart_speaker", "thermostat", "smart_camera") else 0.0,

            # Signal 4: Traffic Dynamics
            "total_packets": float(total_pkts),
            "packet_rate": round(total_pkts / duration, 4),
            "byte_rate": round((total_pkts * size_mean) / duration, 4),
            "size_min": round(max(30.0, size_mean - (2 * size_std)), 1),
            "size_max": round(size_mean + (2.5 * size_std), 1),
            "size_mean": round(size_mean, 2),
            "size_std": round(size_std, 2),
            "size_median": round(size_mean, 2),
            "unique_dest_ips": float(unique_dest_ips),
            "dest_ip_entropy": round(random.uniform(0.5, 2.0), 4),
            "unique_dest_ports": float(unique_dest_ports),
            "dest_port_entropy": round(random.uniform(0.5, 2.5), 4),
            "iat_mean": round(duration / total_pkts, 5),
            "iat_std": round((duration / total_pkts) * (1.0 - periodicity), 5),
            "iat_cv": round(1.0 - periodicity, 4),
            "periodicity_score": round(periodicity, 4),
            "burstiness_ratio": round(burstiness, 2),
        }

    def generate_sample_pcap(
        self,
        output_pcap_path: str,
        device_class: str = "smart_camera",
        mac: str = "b8:27:eb:11:22:33",
        ip: str = "192.168.20.55",
        gateway_ip: str = "192.168.20.1",
        packet_count: int = 40,
    ) -> str:
        """Generate a realistic PCAP file containing DHCP, Discovery, TCP/TLS, and traffic."""
        if device_class not in DEVICE_PROFILES_CONFIG:
            raise ValueError(f"Unknown device class: {device_class}")

        config = DEVICE_PROFILES_CONFIG[device_class]
        os.makedirs(os.path.dirname(os.path.abspath(output_pcap_path)), exist_ok=True)
        packets: List[Packet] = []
        base_time = time.time() - 60.0

        # 1. DHCP Discover & Request
        dhcp_pkt = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")))
            / DHCP(
                options=[
                    ("message-type", 1),
                    ("hostname", f"{config['hostname_prefix']}-01"),
                    ("vendor_class_id", config["vendor_class"]),
                    ("param_req_list", [1, 3, 6, 15, 28, 51]),
                    "end",
                ]
            )
        )
        dhcp_pkt.time = base_time
        packets.append(dhcp_pkt)

        # 2. mDNS Service Advertisement
        if config["mdns_services"]:
            mdns_pkt = (
                Ether(src=mac, dst="01:00:5e:00:00:fb")
                / IP(src=ip, dst="224.0.0.251")
                / UDP(sport=5353, dport=5353)
                / DNS(
                    qr=1,
                    an=DNSRR(
                        rrname=f"{config['mdns_services'][0]}.",
                        type="PTR",
                        rdata=f"Device.{config['mdns_services'][0]}.",
                    )
                    / DNSRR(
                        rrname=f"Device.{config['mdns_services'][0]}.",
                        type="TXT",
                        rdata=[f"{k}=val".encode() for k in config["txt_keys"]],
                    ),
                )
            )
            mdns_pkt.time = base_time + 1.2
            packets.append(mdns_pkt)

        # 3. TCP SYN Connection
        syn_pkt = (
            Ether(src=mac, dst="00:11:22:33:44:01")
            / IP(src=ip, dst=gateway_ip, ttl=config["ttl"])
            / TCP(
                sport=45120,
                dport=config["ports"][0],
                flags="S",
                window=config["window_size"],
                options=[("MSS", config["tcp_mss"]), ("SAckOK", b""), ("WScale", 7)],
            )
        )
        syn_pkt.time = base_time + 2.0
        packets.append(syn_pkt)

        # 4. Data Traffic stream
        cur_time = base_time + 2.5
        payload_size = int(config["pkt_size_mean"])
        for i in range(packet_count - len(packets)):
            cur_time += max(0.01, random.gauss(0.5, 0.1))
            pkt = (
                Ether(src=mac, dst="00:11:22:33:44:01")
                / IP(src=ip, dst=f"198.51.100.{10 + (i % config['unique_dest_ips'])}", ttl=config["ttl"])
                / TCP(sport=45120, dport=config["ports"][0], flags="PA")
                / Raw(b"\x00" * payload_size)
            )
            pkt.time = cur_time
            packets.append(pkt)

        wrpcap(output_pcap_path, packets)
        return output_pcap_path
