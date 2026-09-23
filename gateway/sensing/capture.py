"""Packet Capture Engine supporting offline PCAPs and live interface sniffing."""

from __future__ import annotations

import logging
import os
from typing import Callable, Optional
from scapy.all import PcapReader, sniff
from scapy.packet import Packet

from gateway.sensing.aggregator import DeviceSignalAggregator
from gateway.sensing.storage import SensorStorage

logger = logging.getLogger("gateway.sensing.capture")


class PacketCaptureEngine:
    """Captures network packets passively, aggregates multi-signal features, and persists to SQLite."""

    def __init__(
        self,
        db_path: str = "data/gateway.db",
        window_seconds: int = 60,
        storage: Optional[SensorStorage] = None,
    ) -> None:
        self.db_path = db_path
        self.window_seconds = window_seconds
        self.storage = storage or SensorStorage(db_path=db_path)
        self.aggregator = DeviceSignalAggregator(window_seconds=window_seconds)

    def process_packet(self, packet: Packet) -> None:
        """Process a single packet and feed into aggregator."""
        self.aggregator.process_packet(packet)

    def process_pcap(self, pcap_path: str) -> int:
        """Read and process an offline PCAP/PCAPNG file."""
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        logger.info("Reading packets from PCAP: %s", pcap_path)
        count = 0
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                self.process_packet(pkt)
                count += 1

        logger.info("Processed %d packets from %s across %d devices", count, pcap_path, len(self.aggregator.devices))

        # Persist snapshots for all detected devices
        self.save_all_device_snapshots()
        return count

    def save_all_device_snapshots(self) -> None:
        """Export and persist structured snapshots for all tracked devices."""
        for mac in self.aggregator.devices:
            structured = self.aggregator.export_structured_json(mac)
            if structured:
                snap_id = self.storage.store_feature_snapshot(mac, structured)
                self.storage.log_audit_event(
                    event_type="SNAPSHOT_RECORDED",
                    message=f"Recorded feature snapshot #{snap_id} for device {mac}",
                    mac=mac,
                    metadata={"snapshot_id": snap_id, "duration": structured["duration_seconds"]},
                )

    def start_live_capture(
        self,
        interface: str,
        packet_count: int = 0,
        timeout: Optional[int] = None,
        packet_callback: Optional[Callable[[Packet], None]] = None,
    ) -> None:
        """Start passive live capture on network interface."""
        logger.info("Starting live capture on interface %s (timeout=%s)", interface, timeout)
        self.storage.log_audit_event(
            event_type="CAPTURE_STARTED",
            message=f"Passive sniffing initiated on interface {interface}",
        )

        def _handler(pkt: Packet) -> None:
            self.process_packet(pkt)
            if packet_callback:
                packet_callback(pkt)

        sniff(
            iface=interface,
            prn=_handler,
            count=packet_count,
            timeout=timeout,
            store=False,
        )

        self.save_all_device_snapshots()
        self.storage.log_audit_event(
            event_type="CAPTURE_STOPPED",
            message=f"Passive sniffing completed on interface {interface}",
        )

