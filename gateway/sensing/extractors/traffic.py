"""Traffic Dynamics Signal Group Extractor.

Extracts statistical behavioral metadata:
- Destination IP & Port Diversity (counts and Shannon entropy)
- Packet Size Statistics (min, max, mean, std, median)
- Inter-Arrival Time (IAT) Statistics & Periodicity metric
- Traffic Burstiness Ratio
Metadata and header statistics only; no payload inspection.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet


class TrafficExtractor:
    """Extracts statistical flow dynamics over a sampling window."""

    def __init__(self) -> None:
        self.packet_timestamps: List[float] = []
        self.packet_sizes: List[int] = []
        self.dest_ips: List[str] = []
        self.dest_ports: List[int] = []
        self.protocols: Counter[str] = Counter()
        self.total_bytes: int = 0
        self.total_packets: int = 0

    def process_packet(self, packet: Packet, is_outbound: bool = True) -> bool:
        """Process packet to record size, timestamp, and destination info."""
        pkt_len = len(packet)
        self.packet_sizes.append(pkt_len)
        self.total_bytes += pkt_len
        self.total_packets += 1

        ts = float(getattr(packet, "time", 0.0))
        if ts > 0:
            self.packet_timestamps.append(ts)

        if is_outbound:
            # Destination IP
            if packet.haslayer(IP):
                self.dest_ips.append(packet.getlayer(IP).dst)
            elif packet.haslayer(IPv6):
                self.dest_ips.append(packet.getlayer(IPv6).dst)

            # Destination Port
            if packet.haslayer(TCP):
                self.dest_ports.append(int(packet.getlayer(TCP).dport))
                self.protocols["TCP"] += 1
            elif packet.haslayer(UDP):
                self.dest_ports.append(int(packet.getlayer(UDP).dport))
                self.protocols["UDP"] += 1
            else:
                self.protocols["OTHER"] += 1

        return True

    @staticmethod
    def _shannon_entropy(items: List[Any]) -> float:
        """Calculate Shannon entropy in bits for a sequence of values."""
        if not items:
            return 0.0
        n = len(items)
        counts = Counter(items)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def _calc_size_stats(self) -> Dict[str, float]:
        """Compute packet size min, max, mean, std, median."""
        if not self.packet_sizes:
            return {"min": 0.0, "max": 0.0, "mean": 0.0, "std": 0.0, "median": 0.0}

        sizes = sorted(self.packet_sizes)
        n = len(sizes)
        mean_val = sum(sizes) / n
        variance = sum((x - mean_val) ** 2 for x in sizes) / n
        std_val = math.sqrt(variance)

        if n % 2 == 1:
            median_val = float(sizes[n // 2])
        else:
            median_val = (sizes[n // 2 - 1] + sizes[n // 2]) / 2.0

        return {
            "min": float(sizes[0]),
            "max": float(sizes[-1]),
            "mean": round(mean_val, 2),
            "std": round(std_val, 2),
            "median": round(median_val, 2),
        }

    def _calc_timing_and_periodicity(self) -> Dict[str, float]:
        """Compute inter-arrival time (IAT) stats, periodicity, and burstiness."""
        if len(self.packet_timestamps) < 2:
            return {
                "iat_min": 0.0,
                "iat_max": 0.0,
                "iat_mean": 0.0,
                "iat_std": 0.0,
                "iat_cv": 0.0,
                "periodicity_score": 0.0,
                "burstiness_ratio": 1.0,
            }

        sorted_ts = sorted(self.packet_timestamps)
        iats = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]
        n_iats = len(iats)

        iat_mean = sum(iats) / n_iats
        iat_var = sum((x - iat_mean) ** 2 for x in iats) / n_iats
        iat_std = math.sqrt(iat_var)

        # Coefficient of variation (CV = std / mean)
        iat_cv = (iat_std / iat_mean) if iat_mean > 1e-6 else 0.0

        # Periodicity score in [0.0, 1.0]: 1.0 indicates perfectly constant IAT
        periodicity_score = max(0.0, 1.0 - min(1.0, iat_cv))

        # Burstiness: bin packets into 1-second slices
        start_t = sorted_ts[0]
        bins: Dict[int, int] = defaultdict(int)
        for t in sorted_ts:
            b = int(t - start_t)
            bins[b] += 1

        bin_counts = list(bins.values())
        peak_rate = max(bin_counts) if bin_counts else 0
        avg_rate = (sum(bin_counts) / len(bin_counts)) if bin_counts else 0.0
        burstiness_ratio = (peak_rate / avg_rate) if avg_rate > 0 else 1.0

        return {
            "iat_min": round(min(iats), 5),
            "iat_max": round(max(iats), 5),
            "iat_mean": round(iat_mean, 5),
            "iat_std": round(iat_std, 5),
            "iat_cv": round(iat_cv, 4),
            "periodicity_score": round(periodicity_score, 4),
            "burstiness_ratio": round(burstiness_ratio, 2),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export statistical traffic metrics."""
        size_stats = self._calc_size_stats()
        timing_stats = self._calc_timing_and_periodicity()

        unique_dest_ips = len(set(self.dest_ips))
        unique_dest_ports = len(set(self.dest_ports))

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "size_min": size_stats["min"],
            "size_max": size_stats["max"],
            "size_mean": size_stats["mean"],
            "size_std": size_stats["std"],
            "size_median": size_stats["median"],
            "unique_dest_ips": unique_dest_ips,
            "dest_ip_entropy": self._shannon_entropy(self.dest_ips),
            "unique_dest_ports": unique_dest_ports,
            "dest_port_entropy": self._shannon_entropy(self.dest_ports),
            "iat_min": timing_stats["iat_min"],
            "iat_max": timing_stats["iat_max"],
            "iat_mean": timing_stats["iat_mean"],
            "iat_std": timing_stats["iat_std"],
            "iat_cv": timing_stats["iat_cv"],
            "periodicity_score": timing_stats["periodicity_score"],
            "burstiness_ratio": timing_stats["burstiness_ratio"],
            "protocol_counts": dict(self.protocols),
        }
