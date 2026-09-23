"""Device Signal Aggregator and Feature Vector Generator.

Aggregates 4 signal groups (DHCP, Discovery, TCP/TLS, Traffic)
over a configurable sliding window (60-180 seconds) per device MAC.
Outputs structured JSON and flat numerical feature vectors for ML inference.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from gateway.quarantine.manager import normalize_mac
from gateway.sensing.extractors.dhcp import DHCPExtractor
from gateway.sensing.extractors.discovery import DiscoveryExtractor
from gateway.sensing.extractors.tcptls import TCPTLSExtractor
from gateway.sensing.extractors.traffic import TrafficExtractor

logger = logging.getLogger("gateway.sensing.aggregator")


class DeviceProfile:
    """Holds active signal extractors for a single device MAC within a time window."""

    def __init__(self, mac: str, start_time: Optional[float] = None) -> None:
        self.mac: str = normalize_mac(mac)
        self.start_time: float = start_time or time.time()
        self.last_seen: float = self.start_time
        self.ip_address: Optional[str] = None

        # 4 Signal Groups
        self.dhcp = DHCPExtractor()
        self.discovery = DiscoveryExtractor()
        self.tcptls = TCPTLSExtractor()
        self.traffic = TrafficExtractor()

    def update(self, packet: Packet, is_outbound: bool = True) -> None:
        """Feed packet into the 4 extractors."""
        now = float(getattr(packet, "time", time.time()))
        self.last_seen = max(self.last_seen, now)

        if is_outbound:
            if packet.haslayer(IP):
                self.ip_address = packet.getlayer(IP).src
            elif packet.haslayer(IPv6):
                self.ip_address = packet.getlayer(IPv6).src

            self.dhcp.process_packet(packet)
            self.discovery.process_packet(packet)
            self.tcptls.process_packet(packet)
            self.traffic.process_packet(packet, is_outbound=True)
        else:
            # Inbound packet destined for this device
            self.traffic.process_packet(packet, is_outbound=False)


class DeviceSignalAggregator:
    """Aggregates multi-source packet signals per device MAC over a sliding window."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds: int = window_seconds
        self.devices: Dict[str, DeviceProfile] = {}

    def process_packet(self, packet: Packet) -> None:
        """Dispatch packet to source and destination device profiles."""
        if not packet.haslayer(Ether):
            return

        eth = packet.getlayer(Ether)
        src_mac = eth.src
        dst_mac = eth.dst
        pkt_time = float(getattr(packet, "time", time.time()))

        # Update source device (outbound)
        if src_mac and src_mac != "ff:ff:ff:ff:ff:ff":
            profile = self._get_or_create(src_mac, pkt_time)
            profile.update(packet, is_outbound=True)

        # Update destination device (inbound traffic stats)
        if dst_mac and dst_mac != "ff:ff:ff:ff:ff:ff" and dst_mac in self.devices:
            self.devices[dst_mac].update(packet, is_outbound=False)

    def _get_or_create(self, mac: str, timestamp: float) -> DeviceProfile:
        """Retrieve existing profile or create a fresh one."""
        mac_norm = normalize_mac(mac)
        if mac_norm not in self.devices:
            self.devices[mac_norm] = DeviceProfile(mac_norm, start_time=timestamp)
        return self.devices[mac_norm]

    def get_profile(self, mac: str) -> Optional[DeviceProfile]:
        """Get profile for a given MAC."""
        mac_norm = normalize_mac(mac)
        return self.devices.get(mac_norm)

    def export_structured_json(self, mac: str) -> Optional[Dict[str, Any]]:
        """Export comprehensive nested JSON structure for a device."""
        mac_norm = normalize_mac(mac)
        profile = self.devices.get(mac_norm)
        if not profile:
            return None

        window_duration = max(1.0, profile.last_seen - profile.start_time)
        return {
            "mac": profile.mac,
            "ip": profile.ip_address or "",
            "window_start": profile.start_time,
            "window_end": profile.last_seen,
            "duration_seconds": round(window_duration, 2),
            "signals": {
                "dhcp": profile.dhcp.to_dict(),
                "discovery": profile.discovery.to_dict(),
                "tcptls": profile.tcptls.to_dict(),
                "traffic": profile.traffic.to_dict(),
            },
            "features": self.get_flattened_features(mac_norm),
        }

    def get_flattened_features(self, mac: str) -> Dict[str, float]:
        """Convert multi-signal metadata into a flat numeric feature vector for scikit-learn models."""
        mac_norm = normalize_mac(mac)
        profile = self.devices.get(mac_norm)
        if not profile:
            return {}

        dhcp_dict = profile.dhcp.to_dict()
        disc_dict = profile.discovery.to_dict()
        tt_dict = profile.tcptls.to_dict()
        traf_dict = profile.traffic.to_dict()

        duration = max(1.0, profile.last_seen - profile.start_time)
        total_pkts = traf_dict.get("total_packets", 0)
        total_bytes = traf_dict.get("total_bytes", 0)

        # Standardized schema of numeric features
        return {
            # Signal 1: DHCP Features
            "has_dhcp": 1.0 if dhcp_dict.get("has_dhcp") else 0.0,
            "dhcp_options_count": float(len(dhcp_dict.get("option_order", []))),
            "dhcp_param_req_count": float(len(dhcp_dict.get("param_req_list", []))),
            "has_vendor_class": 1.0 if dhcp_dict.get("vendor_class_id") else 0.0,
            "has_hostname": 1.0 if dhcp_dict.get("hostname") else 0.0,

            # Signal 2: Service Discovery Features
            "has_discovery": 1.0 if disc_dict.get("has_discovery") else 0.0,
            "discovery_service_count": float(disc_dict.get("service_count", 0)),
            "discovery_txt_keys_count": float(disc_dict.get("txt_keys_count", 0)),
            "discovery_ports_count": float(disc_dict.get("discovered_ports_count", 0)),

            # Signal 3: TCP/IP + TLS Features
            "has_tcptls": 1.0 if tt_dict.get("has_tcptls") else 0.0,
            "estimated_initial_ttl": float(tt_dict.get("estimated_initial_ttl", 0)),
            "tcp_mss": float(tt_dict.get("tcp_mss", 0)),
            "initial_window_size": float(tt_dict.get("initial_window_size", 0)),
            "tcp_options_count": float(len(tt_dict.get("tcp_options_sequence", []))),
            "has_tls": 1.0 if tt_dict.get("ja3_hash") else 0.0,
            "sni_count": float(tt_dict.get("sni_count", 0)),

            # Signal 4: Traffic Dynamics
            "total_packets": float(total_pkts),
            "packet_rate": round(total_pkts / duration, 4),
            "byte_rate": round(total_bytes / duration, 4),
            "size_min": float(traf_dict.get("size_min", 0.0)),
            "size_max": float(traf_dict.get("size_max", 0.0)),
            "size_mean": float(traf_dict.get("size_mean", 0.0)),
            "size_std": float(traf_dict.get("size_std", 0.0)),
            "size_median": float(traf_dict.get("size_median", 0.0)),
            "unique_dest_ips": float(traf_dict.get("unique_dest_ips", 0)),
            "dest_ip_entropy": float(traf_dict.get("dest_ip_entropy", 0.0)),
            "unique_dest_ports": float(traf_dict.get("unique_dest_ports", 0)),
            "dest_port_entropy": float(traf_dict.get("dest_port_entropy", 0.0)),
            "iat_mean": float(traf_dict.get("iat_mean", 0.0)),
            "iat_std": float(traf_dict.get("iat_std", 0.0)),
            "iat_cv": float(traf_dict.get("iat_cv", 0.0)),
            "periodicity_score": float(traf_dict.get("periodicity_score", 0.0)),
            "burstiness_ratio": float(traf_dict.get("burstiness_ratio", 1.0)),
        }
