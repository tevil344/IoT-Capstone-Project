"""Service Discovery Signal Group Extractor.

Extracts mDNS (Multicast DNS, UDP 5353) and SSDP (Simple Service Discovery
Protocol, UDP 1900) service types, advertised TXT keys, and service ports.
Privacy-preserving: TXT keys only; values/payloads are discarded.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import UDP
from scapy.packet import Packet


class DiscoveryExtractor:
    """Extracts local service discovery fingerprints (mDNS, SSDP, UPnP)."""

    def __init__(self) -> None:
        self.mdns_services: Set[str] = set()
        self.mdns_txt_keys: Set[str] = set()
        self.ssdp_services: Set[str] = set()
        self.ssdp_server_tokens: Set[str] = set()
        self.discovered_ports: Set[int] = set()
        self.seen_count: int = 0

    def process_packet(self, packet: Packet) -> bool:
        """Process packet for mDNS or SSDP discovery signatures."""
        if not packet.haslayer(UDP):
            return False

        udp = packet.getlayer(UDP)
        is_discovery = False

        # mDNS: Port 5353
        if udp.dport == 5353 or udp.sport == 5353:
            if packet.haslayer(DNS):
                self._parse_mdns(packet.getlayer(DNS))
                is_discovery = True

        # SSDP: Port 1900
        if udp.dport == 1900 or udp.sport == 1900:
            if packet.haslayer("Raw"):
                raw_bytes = bytes(packet.getlayer("Raw").load)
                self._parse_ssdp(raw_bytes)
                is_discovery = True

        if is_discovery:
            self.seen_count += 1
            if udp.sport != 5353 and udp.sport != 1900 and udp.sport > 0:
                self.discovered_ports.add(int(udp.sport))

        return is_discovery

    def _parse_mdns(self, dns: DNS) -> None:
        """Parse mDNS queries and answers for service signatures and TXT keys."""
        # Queries (QD)
        qd_field = getattr(dns, "qd", None)
        queries = qd_field if isinstance(qd_field, (list, tuple)) else ([qd_field] if qd_field else [])
        for q in queries:
            curr = q
            while curr:
                if hasattr(curr, "qname") and curr.qname:
                    qname = self._clean_dns_name(curr.qname)
                    if self._is_service_name(qname):
                        self.mdns_services.add(qname)
                curr = getattr(curr, "payload", None) if not isinstance(qd_field, (list, tuple)) else None

        # Answers (AN), Authority (NS), and Additional (AR) records
        for section in ("an", "ns", "ar"):
            sec_val = getattr(dns, section, None)
            records = sec_val if isinstance(sec_val, (list, tuple)) else ([sec_val] if sec_val else [])
            for r in records:
                rr = r
                while rr and hasattr(rr, "name") and rr.name != "NoPayload":
                    if isinstance(rr, DNSRR):
                        rr_name = self._clean_dns_name(rr.rrname)
                        if self._is_service_name(rr_name):
                            self.mdns_services.add(rr_name)

                        # PTR records point to service instances
                        if rr.type == 12 and hasattr(rr, "rdata") and rr.rdata:  # PTR
                            ptr_val = self._clean_dns_name(rr.rdata)
                            if self._is_service_name(ptr_val):
                                self.mdns_services.add(ptr_val)

                        # SRV records contain target port
                        elif rr.type == 33 and hasattr(rr, "port") and rr.port:  # SRV
                            self.discovered_ports.add(int(rr.port))

                        # TXT records: extract keys only (e.g. key=val -> key)
                        elif rr.type == 16 and hasattr(rr, "rdata") and rr.rdata:  # TXT
                            self._extract_txt_keys(rr.rdata)

                    rr = getattr(rr, "payload", None)

    def _extract_txt_keys(self, rdata: Any) -> None:
        """Extract only key names from mDNS TXT records for privacy preservation."""
        entries: List[bytes] = []
        if isinstance(rdata, list):
            entries = [x for x in rdata if isinstance(x, (bytes, str))]
        elif isinstance(rdata, bytes):
            entries = [rdata]
        elif isinstance(rdata, str):
            entries = [rdata.encode()]

        for entry in entries:
            text = entry.decode("utf-8", errors="ignore") if isinstance(entry, bytes) else entry
            # Format: 'key=value' or just 'key'
            if "=" in text:
                key = text.split("=", 1)[0].strip()
                if key:
                    self.mdns_txt_keys.add(key)
            elif text.strip():
                self.mdns_txt_keys.add(text.strip())

    def _parse_ssdp(self, raw: bytes) -> None:
        """Parse HTTPU/SSDP headers for service types and UPnP device URNs."""
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return

        lines = text.splitlines()
        for line in lines:
            if ":" not in line:
                continue
            header, _, value = line.partition(":")
            header = header.strip().upper()
            val = value.strip()

            # Search Target (ST) and Notification Type (NT)
            if header in ("ST", "NT") and val:
                # E.g. urn:schemas-upnp-org:device:MediaRenderer:1 or ssdp:all
                self.ssdp_services.add(val)

            # SERVER header (e.g. Linux/4.14 UPnP/1.0 Sonos/1.0)
            elif header == "SERVER" and val:
                self.ssdp_server_tokens.add(val)

            # LOCATION port extraction
            elif header == "LOCATION" and val:
                port_match = re.search(r":(\d{2,5})/", val)
                if port_match:
                    self.discovered_ports.add(int(port_match.group(1)))

    @staticmethod
    def _clean_dns_name(val: Any) -> str:
        """Convert DNS name bytes/string to clean string."""
        if isinstance(val, bytes):
            s = val.decode("utf-8", errors="ignore")
        else:
            s = str(val)
        return s.rstrip(".")

    @staticmethod
    def _is_service_name(name: str) -> bool:
        """Check if string is a service query or type."""
        return ("_tcp" in name or "_udp" in name or "local" in name or "urn:" in name)

    def to_dict(self) -> Dict[str, Any]:
        """Export discovery features."""
        all_services = sorted(list(self.mdns_services.union(self.ssdp_services)))
        return {
            "has_discovery": self.seen_count > 0,
            "seen_count": self.seen_count,
            "services": all_services,
            "service_count": len(all_services),
            "mdns_services": sorted(list(self.mdns_services)),
            "ssdp_services": sorted(list(self.ssdp_services)),
            "txt_keys": sorted(list(self.mdns_txt_keys)),
            "txt_keys_count": len(self.mdns_txt_keys),
            "ssdp_server_tokens": sorted(list(self.ssdp_server_tokens)),
            "discovered_ports": sorted(list(self.discovered_ports)),
            "discovered_ports_count": len(self.discovered_ports),
        }
