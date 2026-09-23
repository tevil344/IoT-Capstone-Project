"""DHCP Signal Group Extractor.

Extracts Option Order, Vendor Class Identifier (Option 60),
Client Hostname (Option 12), and Client Identifier (Option 61).
No payload inspection; extracts protocol negotiation metadata only.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.packet import Packet


class DHCPExtractor:
    """Extracts DHCP fingerprint signatures from BOOTP/DHCP packets."""

    def __init__(self) -> None:
        self.option_order: List[int] = []
        self.vendor_class_id: Optional[str] = None
        self.hostname: Optional[str] = None
        self.client_id: Optional[str] = None
        self.requested_ip: Optional[str] = None
        self.message_types: List[str] = []
        self.parameter_request_list: List[int] = []
        self.seen_count: int = 0

    def process_packet(self, packet: Packet) -> bool:
        """Process a packet. Return True if it was a DHCP packet."""
        if not (packet.haslayer(DHCP) or packet.haslayer(BOOTP)):
            return False

        dhcp_layer = packet.getlayer(DHCP)
        if not dhcp_layer or not hasattr(dhcp_layer, "options"):
            return False

        self.seen_count += 1
        current_options: List[int] = []

        # Standard Scapy DHCP options format: list of tuples (opt_code_or_name, opt_val)
        # or special string "end" / "pad"
        for opt in dhcp_layer.options:
            if isinstance(opt, tuple):
                opt_name = opt[0]
                opt_val = opt[1] if len(opt) > 1 else None

                # Map common option names to option codes if string
                opt_code = self._get_option_code(opt_name)
                if opt_code is not None:
                    current_options.append(opt_code)

                if opt_name in ("message-type", 53):
                    msg_type_str = str(opt_val)
                    if msg_type_str not in self.message_types:
                        self.message_types.append(msg_type_str)

                elif opt_name in ("vendor_class_id", 60):
                    if opt_val is not None:
                        self.vendor_class_id = self._decode_bytes(opt_val)

                elif opt_name in ("hostname", 12):
                    if opt_val is not None:
                        self.hostname = self._decode_bytes(opt_val)

                elif opt_name in ("client_id", 61):
                    if opt_val is not None:
                        self.client_id = self._format_client_id(opt_val)

                elif opt_name in ("requested_addr", 50):
                    if opt_val is not None:
                        self.requested_ip = str(opt_val)

                elif opt_name in ("param_req_list", 55):
                    if isinstance(opt_val, (bytes, bytearray)):
                        self.parameter_request_list = list(opt_val)
                    elif isinstance(opt_val, (list, tuple)):
                        self.parameter_request_list = [int(x) for x in opt_val if isinstance(x, int)]

            elif isinstance(opt, str):
                if opt == "end":
                    current_options.append(255)
                elif opt == "pad":
                    current_options.append(0)

        if current_options and not self.option_order:
            self.option_order = current_options

        return True

    @staticmethod
    def _decode_bytes(val: Any) -> str:
        """Decode string/bytes safely."""
        if isinstance(val, bytes):
            return val.decode("utf-8", errors="replace").strip("\x00").strip()
        return str(val).strip()

    @staticmethod
    def _format_client_id(val: Any) -> str:
        """Format Client Identifier."""
        if isinstance(val, bytes):
            # Often first byte is hardware type (e.g. 1 for Ethernet), rest is MAC
            if len(val) == 7 and val[0] == 1:
                return ":".join(f"{b:02x}" for b in val[1:])
            return val.hex()
        return str(val)

    @staticmethod
    def _get_option_code(opt_name: Any) -> Optional[int]:
        """Convert Scapy option name to RFC standard code."""
        if isinstance(opt_name, int):
            return opt_name
        name_map = {
            "pad": 0,
            "subnet_mask": 1,
            "router": 3,
            "name_server": 6,
            "hostname": 12,
            "domain": 15,
            "broadcast_address": 28,
            "requested_addr": 50,
            "lease_time": 51,
            "message-type": 53,
            "server_id": 54,
            "param_req_list": 55,
            "max_dhcp_size": 57,
            "vendor_class_id": 60,
            "client_id": 61,
            "end": 255,
        }
        return name_map.get(str(opt_name).lower())

    def to_dict(self) -> Dict[str, Any]:
        """Export extracted DHCP features as structured dictionary."""
        return {
            "has_dhcp": self.seen_count > 0,
            "seen_count": self.seen_count,
            "option_order": self.option_order,
            "option_order_str": ",".join(str(x) for x in self.option_order) if self.option_order else "",
            "vendor_class_id": self.vendor_class_id or "",
            "hostname": self.hostname or "",
            "client_id": self.client_id or "",
            "requested_ip": self.requested_ip or "",
            "message_types": self.message_types,
            "param_req_list": self.parameter_request_list,
            "param_req_list_str": ",".join(str(x) for x in self.parameter_request_list) if self.parameter_request_list else "",
        }

