"""TCP/IP Stack and TLS Client Hello Extractor.

Extracts OS/Stack fingerprints:
- Estimated Initial TTL
- TCP Options Sequence
- TCP Maximum Segment Size (MSS)
- Advertised Window Size
- TLS Client Hello JA3 Hash / String
- Server Name Indication (SNI)
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict, List, Optional, Set, Tuple
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

# GREASE ciphers/extensions to filter for JA3 calculation (RFC 8701)
GREASE_TABLE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBAAB, 0xCAAC, 0xDAAD, 0xEAAE, 0xFAAF
}


class TCPTLSExtractor:
    """Extracts transport and TLS session handshake metadata."""

    def __init__(self) -> None:
        self.observed_ttls: List[int] = []
        self.estimated_initial_ttl: Optional[int] = None
        self.tcp_options_sequence: List[str] = []
        self.tcp_options_str: str = ""
        self.tcp_mss: Optional[int] = None
        self.tcp_window_sizes: List[int] = []
        self.initial_window_size: Optional[int] = None

        # TLS attributes
        self.ja3_string: Optional[str] = None
        self.ja3_hash: Optional[str] = None
        self.sni_hostnames: Set[str] = set()
        self.tls_versions: Set[int] = set()
        self.cipher_suites: List[int] = []

    def process_packet(self, packet: Packet) -> bool:
        """Process an IP/TCP/TLS packet."""
        processed = False

        # 1. IP Layer (TTL / Hop Limit)
        if packet.haslayer(IP):
            ip = packet.getlayer(IP)
            ttl = int(ip.ttl)
            self.observed_ttls.append(ttl)
            if self.estimated_initial_ttl is None:
                self.estimated_initial_ttl = self._estimate_initial_ttl(ttl)
            processed = True
        elif packet.haslayer(IPv6):
            ip6 = packet.getlayer(IPv6)
            hlim = int(ip6.hlim)
            self.observed_ttls.append(hlim)
            if self.estimated_initial_ttl is None:
                self.estimated_initial_ttl = self._estimate_initial_ttl(hlim)
            processed = True

        # 2. TCP Layer (SYN Options, MSS, Window)
        if packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            self.tcp_window_sizes.append(int(tcp.window))

            # Prioritize SYN / SYN-ACK packets for options and initial window
            flags = str(tcp.flags)
            if "S" in flags:
                if self.initial_window_size is None:
                    self.initial_window_size = int(tcp.window)

                if hasattr(tcp, "options") and tcp.options:
                    opts, mss = self._parse_tcp_options(tcp.options)
                    if opts and not self.tcp_options_sequence:
                        self.tcp_options_sequence = opts
                        self.tcp_options_str = "-".join(opts)
                    if mss is not None and self.tcp_mss is None:
                        self.tcp_mss = mss

            # 3. TLS Client Hello Layer Inspection (port 443 or payload heuristic)
            if packet.haslayer("Raw"):
                raw_payload = bytes(packet.getlayer("Raw").load)
                if self._is_tls_client_hello(raw_payload):
                    self._parse_tls_client_hello(raw_payload)

            processed = True

        return processed

    @staticmethod
    def _estimate_initial_ttl(observed_ttl: int) -> int:
        """Estimate initial TTL based on common OS defaults (32, 64, 128, 255)."""
        candidates = [32, 64, 128, 255]
        for c in candidates:
            if observed_ttl <= c:
                return c
        return 255

    @staticmethod
    def _parse_tcp_options(options: List[Tuple[Any, ...]]) -> Tuple[List[str], Optional[int]]:
        """Extract option names and MSS value."""
        opt_names: List[str] = []
        mss_val: Optional[int] = None

        for opt in options:
            if isinstance(opt, tuple):
                name = str(opt[0])
                opt_names.append(name)
                if name.upper() == "MSS" and len(opt) > 1 and isinstance(opt[1], int):
                    mss_val = opt[1]
            elif isinstance(opt, str):
                opt_names.append(opt)

        return opt_names, mss_val

    @staticmethod
    def _is_tls_client_hello(payload: bytes) -> bool:
        """Check if payload begins with TLS Handshake Client Hello."""
        # ContentType: Handshake (22 / 0x16)
        # Version: 0x0300 - 0x0304
        # HandshakeType: ClientHello (1)
        if len(payload) < 9:
            return False
        return (
            payload[0] == 0x16
            and payload[1] == 0x03
            and (0x00 <= payload[2] <= 0x04)
            and payload[5] == 0x01
        )

    def _parse_tls_client_hello(self, payload: bytes) -> None:
        """Parse TLS Client Hello to extract JA3 elements and SNI."""
        try:
            # Skip record header (5 bytes) + handshake header (4 bytes) -> offset 9
            offset = 9
            if len(payload) < offset + 34:
                return

            client_version = struct.unpack("!H", payload[offset : offset + 2])[0]
            self.tls_versions.add(client_version)
            offset += 2

            # Skip Random (32 bytes)
            offset += 32

            # Session ID
            session_id_len = payload[offset]
            offset += 1 + session_id_len

            if len(payload) < offset + 2:
                return

            # Cipher Suites
            cipher_suites_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2

            cipher_suites: List[int] = []
            for i in range(0, cipher_suites_len, 2):
                if offset + i + 2 > len(payload):
                    break
                cs = struct.unpack("!H", payload[offset + i : offset + i + 2])[0]
                if cs not in GREASE_TABLE:
                    cipher_suites.append(cs)
            self.cipher_suites = cipher_suites
            offset += cipher_suites_len

            if offset >= len(payload):
                return

            # Compression Methods
            comp_len = payload[offset]
            offset += 1 + comp_len

            if offset + 2 > len(payload):
                return

            # Extensions
            extensions_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            offset += 2

            ext_end = offset + extensions_len
            extensions: List[int] = []
            elliptic_curves: List[int] = []
            ec_point_formats: List[int] = []

            while offset + 4 <= min(ext_end, len(payload)):
                ext_type = struct.unpack("!H", payload[offset : offset + 2])[0]
                ext_data_len = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
                offset += 4
                ext_data = payload[offset : offset + ext_data_len]

                if ext_type not in GREASE_TABLE:
                    extensions.append(ext_type)

                # SNI (Extension Type 0x0000)
                if ext_type == 0 and len(ext_data) >= 5:
                    sni = self._extract_sni(ext_data)
                    if sni:
                        self.sni_hostnames.add(sni)

                # Supported Elliptic Curves / Groups (Extension Type 0x000a / 10)
                elif ext_type == 10 and len(ext_data) >= 2:
                    curves_len = struct.unpack("!H", ext_data[0:2])[0]
                    for j in range(2, min(2 + curves_len, len(ext_data)), 2):
                        curve = struct.unpack("!H", ext_data[j : j + 2])[0]
                        if curve not in GREASE_TABLE:
                            elliptic_curves.append(curve)

                # EC Point Formats (Extension Type 0x000b / 11)
                elif ext_type == 11 and len(ext_data) >= 1:
                    fmt_len = ext_data[0]
                    for j in range(1, min(1 + fmt_len, len(ext_data))):
                        ec_point_formats.append(ext_data[j])

                offset += ext_data_len

            # Formulate JA3 string: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            ja3_str = (
                f"{client_version},"
                f"{'-'.join(str(c) for c in cipher_suites)},"
                f"{'-'.join(str(e) for e in extensions)},"
                f"{'-'.join(str(c) for c in elliptic_curves)},"
                f"{'-'.join(str(p) for p in ec_point_formats)}"
            )
            self.ja3_string = ja3_str
            self.ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

        except Exception:
            pass

    @staticmethod
    def _extract_sni(ext_data: bytes) -> Optional[str]:
        """Extract Server Name Indication string from SNI extension data."""
        try:
            sni_list_len = struct.unpack("!H", ext_data[0:2])[0]
            offset = 2
            if offset < len(ext_data) and ext_data[offset] == 0x00:  # Hostname type
                offset += 1
                name_len = struct.unpack("!H", ext_data[offset : offset + 2])[0]
                offset += 2
                name = ext_data[offset : offset + name_len].decode("utf-8", errors="ignore")
                return name
        except Exception:
            pass
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Export TCP/IP and TLS fingerprint parameters."""
        avg_ttl = (sum(self.observed_ttls) / len(self.observed_ttls)) if self.observed_ttls else 0.0
        return {
            "has_tcptls": len(self.observed_ttls) > 0,
            "estimated_initial_ttl": self.estimated_initial_ttl or 0,
            "avg_observed_ttl": round(avg_ttl, 2),
            "tcp_options_sequence": self.tcp_options_sequence,
            "tcp_options_str": self.tcp_options_str,
            "tcp_mss": self.tcp_mss or 0,
            "initial_window_size": self.initial_window_size or 0,
            "ja3_string": self.ja3_string or "",
            "ja3_hash": self.ja3_hash or "",
            "sni_hostnames": sorted(list(self.sni_hostnames)),
            "sni_count": len(self.sni_hostnames),
        }
