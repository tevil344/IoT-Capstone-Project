"""Dynamic nftables Quarantine Controller.

Manages device containment by inserting/removing MAC addresses from
the OpenWrt/Linux nftables `@quarantine_macs` and `@trusted_macs` sets.
Logs all enforcement state transitions to SQLite for an immutable audit trail.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("gateway.quarantine")
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def normalize_mac(mac: str) -> str:
    """Normalize and validate a MAC address to lowercase colon-separated format."""
    mac_clean = mac.strip().lower()
    if not MAC_REGEX.match(mac_clean):
        raise ValueError(f"Invalid MAC address format: {mac}")
    return mac_clean.replace("-", ":")


class QuarantineManager:
    """Controls zero-trust device quarantine via Linux nftables."""

    def __init__(
        self,
        db_path: str = "data/gateway.db",
        dry_run: Optional[bool] = None,
        table_family: str = "inet",
        table_name: str = "filter",
        quarantine_set: str = "quarantine_macs",
        trusted_set: str = "trusted_macs",
        nft_binary: str = "nft",
    ) -> None:
        self.db_path = db_path
        self.table_family = table_family
        self.table_name = table_name
        self.quarantine_set = quarantine_set
        self.trusted_set = trusted_set
        self.nft_binary = nft_binary

        # Determine dry run mode: explicit or auto-detected if nft is absent
        nft_available = shutil.which(self.nft_binary) is not None
        if dry_run is None:
            self.dry_run = not nft_available
        else:
            self.dry_run = dry_run

        # In-memory tracking for dry-run / fallback environments
        self._mock_quarantine: set[str] = set()
        self._mock_trusted: set[str] = set()

        self._init_db()
        logger.info(
            "QuarantineManager initialized (dry_run=%s, nft_available=%s, db=%s)",
            self.dry_run,
            nft_available,
            self.db_path,
        )

    def _init_db(self) -> None:
        """Initialize SQLite audit database table."""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS quarantine_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT,
                    details TEXT
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_quarantine_mac ON quarantine_audit (mac)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_quarantine_ts ON quarantine_audit (timestamp)"
            )
            conn.commit()

    def _log_audit(
        self, mac: str, action: str, reason: str, details: str = ""
    ) -> None:
        """Persist an enforcement action into the audit trail."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO quarantine_audit (timestamp, mac, action, reason, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now, mac, action, reason, details),
            )
            conn.commit()

    def _run_nft_cmd(self, args: List[str]) -> subprocess.CompletedProcess[str]:
        """Execute an nft command via subprocess."""
        cmd = [self.nft_binary] + args
        logger.debug("Executing nftables command: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )

    def quarantine_mac(
        self, mac: str, reason: str = "new_unverified_device", timeout_seconds: int = 0
    ) -> bool:
        """Add MAC address to the quarantine set.

        Traffic will be restricted strictly to DHCP, DNS, and NTP.
        """
        mac_norm = normalize_mac(mac)

        if self.dry_run:
            self._mock_trusted.discard(mac_norm)
            self._mock_quarantine.add(mac_norm)
            self._log_audit(mac_norm, "QUARANTINE", reason, f"dry_run=True, timeout={timeout_seconds}s")
            logger.info("[MOCK-NFT] Device %s added to quarantine set (%s)", mac_norm, reason)
            return True

        try:
            # First remove from trusted set if present
            self._run_nft_cmd(
                ["delete", "element", self.table_family, self.table_name, self.trusted_set, f"{{ {mac_norm} }}"]
            )
        except subprocess.CalledProcessError:
            pass  # Was not in trusted set, ignore

        try:
            # Build element command with optional timeout
            elem_spec = mac_norm
            if timeout_seconds > 0:
                elem_spec += f" timeout {timeout_seconds}s"

            self._run_nft_cmd(
                ["add", "element", self.table_family, self.table_name, self.quarantine_set, f"{{ {elem_spec} }}"]
            )
            self._log_audit(mac_norm, "QUARANTINE", reason, f"timeout={timeout_seconds}s")
            logger.info("Device %s added to nftables quarantine set", mac_norm)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to quarantine MAC %s: %s", mac_norm, exc.stderr)
            self._log_audit(mac_norm, "QUARANTINE_FAILED", reason, exc.stderr.strip())
            return False

    def release_mac(
        self, mac: str, reason: str = "fingerprint_verified_and_trusted"
    ) -> bool:
        """Release MAC address from quarantine set and place in trusted set."""
        mac_norm = normalize_mac(mac)

        if self.dry_run:
            self._mock_quarantine.discard(mac_norm)
            self._mock_trusted.add(mac_norm)
            self._log_audit(mac_norm, "RELEASE_TO_TRUSTED", reason, "dry_run=True")
            logger.info("[MOCK-NFT] Device %s released to trusted set (%s)", mac_norm, reason)
            return True

        try:
            # Remove from quarantine set
            self._run_nft_cmd(
                ["delete", "element", self.table_family, self.table_name, self.quarantine_set, f"{{ {mac_norm} }}"]
            )
        except subprocess.CalledProcessError:
            pass  # Might already be absent

        try:
            # Add to trusted set
            self._run_nft_cmd(
                ["add", "element", self.table_family, self.table_name, self.trusted_set, f"{{ {mac_norm} }}"]
            )
            self._log_audit(mac_norm, "RELEASE_TO_TRUSTED", reason, "")
            logger.info("Device %s promoted to trusted set", mac_norm)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to release MAC %s: %s", mac_norm, exc.stderr)
            self._log_audit(mac_norm, "RELEASE_FAILED", reason, exc.stderr.strip())
            return False

    def is_quarantined(self, mac: str) -> bool:
        """Check whether a MAC address is currently in the quarantine set."""
        mac_norm = normalize_mac(mac)

        if self.dry_run:
            return mac_norm in self._mock_quarantine

        try:
            res = self._run_nft_cmd(
                ["get", "element", self.table_family, self.table_name, self.quarantine_set, f"{{ {mac_norm} }}"]
            )
            return mac_norm in res.stdout
        except subprocess.CalledProcessError:
            return False

    def list_quarantined_macs(self) -> List[str]:
        """Return list of all MAC addresses currently under quarantine."""
        if self.dry_run:
            return sorted(list(self._mock_quarantine))

        try:
            res = self._run_nft_cmd(
                ["list", "set", self.table_family, self.table_name, self.quarantine_set]
            )
            # Find MACs in set output
            matches = MAC_REGEX.findall(res.stdout)
            return sorted(list(set(normalize_mac(m) for m in matches)))
        except subprocess.CalledProcessError:
            return []

    def get_audit_history(self, mac: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve audit log history."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if mac:
                mac_norm = normalize_mac(mac)
                cursor.execute(
                    "SELECT timestamp, mac, action, reason, details FROM quarantine_audit WHERE mac = ? ORDER BY id ASC",
                    (mac_norm,),
                )
            else:
                cursor.execute(
                    "SELECT timestamp, mac, action, reason, details FROM quarantine_audit ORDER BY id ASC"
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
