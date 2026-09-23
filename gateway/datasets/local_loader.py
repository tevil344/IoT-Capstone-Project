"""Local Trace and Snapshot Loader.

Loads passive sensing feature vectors directly from:
1. SQLite database (`feature_snapshots` table)
2. Local JSON files / directory of captured trace snapshots
Ensures strict schema alignment with Step 3 feature extractor outputs.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from typing import Any, Dict, List, Optional
import pandas as pd
import yaml

from gateway.datasets.preprocessor import DEFAULT_FEATURE_COLS

logger = logging.getLogger("gateway.datasets.local_loader")


class LocalTraceLoader:
    """Loads and formats locally captured feature vectors."""

    def __init__(self, db_path: str = "data/gateway.db", inventory_path: Optional[str] = None) -> None:
        self.db_path = db_path
        self.inventory_path = inventory_path
        self._inventory_labels: Dict[str, str] = {}
        if self.inventory_path and os.path.exists(self.inventory_path):
            self._load_inventory()

    def _load_inventory(self) -> None:
        """Load known MAC-to-class mappings from device inventory."""
        try:
            with open(self.inventory_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                for dev in data.get("devices", []):
                    mac = dev.get("mac", "").lower()
                    cls_name = dev.get("expected_class")
                    if mac and cls_name:
                        self._inventory_labels[mac] = cls_name
        except Exception as exc:
            logger.warning("Failed to load inventory from %s: %s", self.inventory_path, exc)

    def load_from_sqlite(
        self,
        table_name: str = "feature_snapshots",
        limit: Optional[int] = None,
    ) -> pd.DataFrame:
        """Load feature vectors directly from SQLite persistence database."""
        if not os.path.exists(self.db_path):
            logger.warning("SQLite database not found at %s. Returning empty DataFrame.", self.db_path)
            return pd.DataFrame(columns=DEFAULT_FEATURE_COLS + ["mac", "device_class"])

        rows: List[Dict[str, Any]] = []
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            query = f"SELECT id, timestamp, mac, window_seconds, feature_vector_json FROM {table_name} ORDER BY id ASC"
            if limit:
                query += f" LIMIT {int(limit)}"

            cursor.execute(query)
            for row in cursor.fetchall():
                mac = row["mac"].lower()
                feat_dict = json.loads(row["feature_vector_json"])
                feat_dict["mac"] = mac
                feat_dict["snapshot_id"] = row["id"]
                feat_dict["timestamp"] = row["timestamp"]
                feat_dict["device_id"] = mac
                feat_dict["session_id"] = f"{mac}_{row['timestamp'][:10]}"
                feat_dict["device_class"] = self._inventory_labels.get(mac, "unknown")
                rows.append(feat_dict)
        finally:
            conn.close()

        df = pd.DataFrame(rows)
        logger.info("Loaded %d snapshots from SQLite database (%s)", len(df), self.db_path)
        return df

    def load_from_json(self, json_path: str) -> pd.DataFrame:
        """Load a single JSON trace snapshot or a list of snapshots."""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            items = [data]
        elif isinstance(data, list):
            items = data
        else:
            raise ValueError(f"Unexpected JSON root type in {json_path}: {type(data)}")

        rows: List[Dict[str, Any]] = []
        for item in items:
            mac = item.get("mac", "").lower()
            features = item.get("features", {})
            features["mac"] = mac
            features["device_id"] = mac
            features["session_id"] = f"{mac}_{item.get('window_start', '')}"
            features["device_class"] = self._inventory_labels.get(mac, "unknown")
            rows.append(features)

        df = pd.DataFrame(rows)
        return df

    def load_from_json_dir(self, dir_path: str) -> pd.DataFrame:
        """Recursively load all JSON snapshots in a directory."""
        all_dfs: List[pd.DataFrame] = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".json"):
                    full_path = os.path.join(root, file)
                    try:
                        sub_df = self.load_from_json(full_path)
                        all_dfs.append(sub_df)
                    except Exception as exc:
                        logger.warning("Error loading %s: %s", full_path, exc)

        if not all_dfs:
            return pd.DataFrame(columns=DEFAULT_FEATURE_COLS + ["mac", "device_class"])
        return pd.concat(all_dfs, ignore_index=True)

