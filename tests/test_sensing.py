"""Unit tests for Passive Sensing Pipeline."""

import os
import tempfile
import time
import unittest

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from gateway.sensing.aggregator import DeviceSignalAggregator
from gateway.sensing.capture import PacketCaptureEngine
from gateway.sensing.extractors.dhcp import DHCPExtractor
from gateway.sensing.extractors.discovery import DiscoveryExtractor
from gateway.sensing.extractors.tcptls import TCPTLSExtractor
from gateway.sensing.extractors.traffic import TrafficExtractor
from gateway.sensing.storage import SensorStorage


class TestPassiveSensing(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_sensing.db")
        self.storage = SensorStorage(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dhcp_extractor(self):
        extractor = DHCPExtractor()
        pkt = (
            Ether(src="11:22:33:44:55:66", dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=b"\x11\x22\x33\x44\x55\x66")
            / DHCP(
                options=[
                    ("message-type", 1),
                    ("client_id", b"\x01\x11\x22\x33\x44\x55\x66"),
                    ("hostname", "test-smart-camera"),
                    ("vendor_class_id", "cam-os-1.0"),
                    ("param_req_list", [1, 3, 6, 15, 28, 51]),
                    "end",
                ]
            )
        )
        processed = extractor.process_packet(pkt)
        self.assertTrue(processed)
        d = extractor.to_dict()
        self.assertTrue(d["has_dhcp"])
        self.assertEqual(d["hostname"], "test-smart-camera")
        self.assertEqual(d["vendor_class_id"], "cam-os-1.0")
        self.assertIn(53, d["option_order"])
        self.assertIn(60, d["option_order"])

    def test_discovery_extractor(self):
        extractor = DiscoveryExtractor()
        # Synthetic mDNS response
        mdns_pkt = (
            Ether(src="11:22:33:44:55:66", dst="01:00:5e:00:00:fb")
            / IP(src="192.168.20.100", dst="224.0.0.251")
            / UDP(sport=5353, dport=5353)
            / DNS(
                qr=1,
                an=DNSRR(
                    rrname="_googlecast._tcp.local.",
                    type="PTR",
                    rdata="LivingRoom._googlecast._tcp.local.",
                )
                / DNSRR(
                    rrname="LivingRoom._googlecast._tcp.local.",
                    type="TXT",
                    rdata=[b"md=Chromecast", b"fn=Living Room Audio", b"ve=05"],
                ),
            )
        )
        processed = extractor.process_packet(mdns_pkt)
        self.assertTrue(processed)
        d = extractor.to_dict()
        self.assertTrue(d["has_discovery"])
        self.assertIn("md", d["txt_keys"])
        self.assertIn("fn", d["txt_keys"])

    def test_tcptls_extractor(self):
        extractor = TCPTLSExtractor()
        # Synthetic TCP SYN packet with options
        syn_pkt = (
            Ether(src="11:22:33:44:55:66", dst="00:11:22:33:44:01")
            / IP(src="192.168.20.100", dst="192.168.20.1", ttl=64)
            / TCP(
                sport=45231,
                dport=443,
                flags="S",
                window=64240,
                options=[("MSS", 1460), ("SAckOK", b""), ("WScale", 7)],
            )
        )
        processed = extractor.process_packet(syn_pkt)
        self.assertTrue(processed)
        d = extractor.to_dict()
        self.assertEqual(d["estimated_initial_ttl"], 64)
        self.assertEqual(d["tcp_mss"], 1460)
        self.assertEqual(d["initial_window_size"], 64240)
        self.assertIn("MSS", d["tcp_options_sequence"])

    def test_traffic_extractor(self):
        extractor = TrafficExtractor()
        base_t = time.time()
        for i in range(10):
            pkt = (
                Ether(src="11:22:33:44:55:66", dst="00:11:22:33:44:01")
                / IP(src="192.168.20.100", dst=f"93.184.216.{34 + (i % 2)}")
                / UDP(sport=5000 + i, dport=8080)
                / Raw(b"X" * (100 + i * 20))
            )
            pkt.time = base_t + (i * 0.5)
            extractor.process_packet(pkt, is_outbound=True)

        d = extractor.to_dict()
        self.assertEqual(d["total_packets"], 10)
        self.assertGreater(d["total_bytes"], 1000)
        self.assertEqual(d["unique_dest_ips"], 2)
        self.assertGreater(d["dest_ip_entropy"], 0.0)
        self.assertGreater(d["periodicity_score"], 0.5)

    def test_aggregator_and_storage(self):
        engine = PacketCaptureEngine(storage=self.storage, window_seconds=60)
        mac = "aa:bb:cc:dd:ee:ff"
        pkt = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="192.168.20.105", dst="255.255.255.255", ttl=64)
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=b"\xaa\xbb\xcc\xdd\xee\xff")
            / DHCP(options=[("message-type", 1), ("hostname", "plug-smart"), "end"])
        )
        engine.process_packet(pkt)
        structured = engine.aggregator.export_structured_json(mac)
        self.assertIsNotNone(structured)
        self.assertEqual(structured["mac"], mac)
        self.assertIn("has_dhcp", structured["features"])
        self.assertEqual(structured["features"]["has_dhcp"], 1.0)

        # Save to SQLite
        engine.save_all_device_snapshots()
        latest = self.storage.get_latest_snapshot(mac)
        self.assertIsNotNone(latest)
        self.assertEqual(latest["mac"], mac)
        self.assertEqual(latest["signals"]["dhcp"]["hostname"], "plug-smart")


if __name__ == "__main__":
    unittest.main()
