"""SQLite Storage and Audit Persistence Engine for Passive Sensing."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger("gateway.sensing.storage")


class SensorStorage:
    """Manages SQLite tables for devices, feature snapshots, and security audit logs."""

    def __init__(self, db_path: str = "data/gateway.db") -> None:
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager providing auto-commit and clean connection closing."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create database tables and indices if not present."""
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with self._connection() as conn:
            cursor = conn.cursor()

            # Device registry
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT DEFAULT 'quarantined'
                )
                """
            )

            # Feature snapshots
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS feature_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    mac TEXT NOT NULL,
                    window_seconds REAL NOT NULL,
                    dhcp_json TEXT,
                    discovery_json TEXT,
                    tcptls_json TEXT,
                    traffic_json TEXT,
                    feature_vector_json TEXT NOT NULL,
                    FOREIGN KEY (mac) REFERENCES devices(mac)
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_snap_mac ON feature_snapshots (mac)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_snap_ts ON feature_snapshots (timestamp)")

            # Sensing / System audit log
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    mac TEXT,
                    message TEXT NOT NULL,
                    metadata_json TEXT
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log (event_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_mac ON audit_log (mac)")

    def upsert_device(
        self,
        mac: str,
        ip: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        status: Optional[str] = None,
    ) -> None:
        """Insert or update device record."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO devices (mac, ip, hostname, vendor, first_seen, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, 'quarantined'))
                ON CONFLICT(mac) DO UPDATE SET
                    ip = COALESCE(excluded.ip, devices.ip),
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    vendor = COALESCE(excluded.vendor, devices.vendor),
                    last_seen = excluded.last_seen,
                    status = COALESCE(?, devices.status)
                """,
                (mac, ip, hostname, vendor, now, now, status, status),
            )

    def store_feature_snapshot(
        self,
        mac: str,
        structured_data: Dict[str, Any],
    ) -> int:
        """Store structured feature vector snapshot."""
        now = datetime.now(timezone.utc).isoformat()
        signals = structured_data.get("signals", {})
        window_duration = float(structured_data.get("duration_seconds", 60.0))

        dhcp_json = json.dumps(signals.get("dhcp", {}))
        disc_json = json.dumps(signals.get("discovery", {}))
        tt_json = json.dumps(signals.get("tcptls", {}))
        traf_json = json.dumps(signals.get("traffic", {}))
        features_json = json.dumps(structured_data.get("features", {}))

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO feature_snapshots (
                    timestamp, mac, window_seconds,
                    dhcp_json, discovery_json, tcptls_json, traffic_json,
                    feature_vector_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    mac,
                    window_duration,
                    dhcp_json,
                    disc_json,
                    tt_json,
                    traf_json,
                    features_json,
                ),
            )
            snapshot_id = cursor.lastrowid or 0

        # Update last seen in devices
        self.upsert_device(mac=mac, ip=structured_data.get("ip"))
        return snapshot_id

    def log_audit_event(
        self,
        event_type: str,
        message: str,
        mac: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record system audit log event."""
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata) if metadata else None
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_log (timestamp, event_type, mac, message, metadata_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (now, event_type, mac, message, meta_json),
            )

    def get_latest_snapshot(self, mac: str) -> Optional[Dict[str, Any]]:
        """Retrieve the most recent snapshot for a device."""
        with self._connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, mac, window_seconds, dhcp_json, discovery_json,
                       tcptls_json, traffic_json, feature_vector_json
                FROM feature_snapshots
                WHERE mac = ?
                ORDER BY id DESC LIMIT 1
                """,
                (mac,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "mac": row["mac"],
                "window_seconds": row["window_seconds"],
                "signals": {
                    "dhcp": json.loads(row["dhcp_json"]),
                    "discovery": json.loads(row["discovery_json"]),
                    "tcptls": json.loads(row["tcptls_json"]),
                    "traffic": json.loads(row["traffic_json"]),
                },
                "features": json.loads(row["feature_vector_json"]),
            }

