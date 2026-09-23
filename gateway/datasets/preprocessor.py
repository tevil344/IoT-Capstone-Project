"""Leakage-Safe Dataset Splitting and Feature Preprocessing.

Guarantees strict separation between train and evaluation sets:
1. Device-Disjoint: No physical device instance present in train appears in test.
2. Session-Disjoint: No temporal capture session present in train appears in test.
3. Open-Set Holdout: Specific device categories held out exclusively for unknown-rejection testing.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Set, Tuple
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

logger = logging.getLogger("gateway.datasets.preprocessor")

DEFAULT_FEATURE_COLS = [
    # Signal 1: DHCP
    "has_dhcp",
    "dhcp_options_count",
    "dhcp_param_req_count",
    "has_vendor_class",
    "has_hostname",
    # Signal 2: Discovery
    "has_discovery",
    "discovery_service_count",
    "discovery_txt_keys_count",
    "discovery_ports_count",
    # Signal 3: TCP/IP + TLS
    "has_tcptls",
    "estimated_initial_ttl",
    "tcp_mss",
    "initial_window_size",
    "tcp_options_count",
    "has_tls",
    "sni_count",
    # Signal 4: Traffic Dynamics
    "total_packets",
    "packet_rate",
    "byte_rate",
    "size_min",
    "size_max",
    "size_mean",
    "size_std",
    "size_median",
    "unique_dest_ips",
    "dest_ip_entropy",
    "unique_dest_ports",
    "dest_port_entropy",
    "iat_mean",
    "iat_std",
    "iat_cv",
    "periodicity_score",
    "burstiness_ratio",
]


class DeviceDisjointSplitter:
    """Splits dataset ensuring physical device instances are disjoint between train and test."""

    def __init__(self, test_size: float = 0.3, random_state: int = 42) -> None:
        self.test_size = test_size
        self.random_state = random_state

    def split(
        self, df: pd.DataFrame, device_col: str = "device_id", label_col: str = "device_class"
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Perform device-disjoint train/test split."""
        if device_col not in df.columns:
            raise KeyError(f"Column '{device_col}' required for device-disjoint splitting.")

        gss = GroupShuffleSplit(n_splits=1, test_size=self.test_size, random_state=self.random_state)
        train_idx, test_idx = next(gss.split(df, groups=df[device_col]))

        train_df = df.iloc[train_idx].copy().reset_index(drop=True)
        test_df = df.iloc[test_idx].copy().reset_index(drop=True)

        # Verification
        train_devs = set(train_df[device_col])
        test_devs = set(test_df[device_col])
        overlap = train_devs.intersection(test_devs)
        if overlap:
            raise RuntimeError(f"Data leakage detected! Devices in both train and test: {overlap}")

        logger.info(
            "Device-disjoint split: Train=%d (%d devices), Test=%d (%d devices)",
            len(train_df),
            len(train_devs),
            len(test_df),
            len(test_devs),
        )
        return train_df, test_df


class SessionDisjointSplitter:
    """Splits dataset ensuring capture sessions are disjoint between train and test."""

    def __init__(self, test_size: float = 0.3, random_state: int = 42) -> None:
        self.test_size = test_size
        self.random_state = random_state

    def split(
        self, df: pd.DataFrame, session_col: str = "session_id"
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Perform session-disjoint train/test split."""
        if session_col not in df.columns:
            raise KeyError(f"Column '{session_col}' required for session-disjoint splitting.")

        gss = GroupShuffleSplit(n_splits=1, test_size=self.test_size, random_state=self.random_state)
        train_idx, test_idx = next(gss.split(df, groups=df[session_col]))

        train_df = df.iloc[train_idx].copy().reset_index(drop=True)
        test_df = df.iloc[test_idx].copy().reset_index(drop=True)

        # Verification
        overlap = set(train_df[session_col]).intersection(set(test_df[session_col]))
        if overlap:
            raise RuntimeError(f"Session leakage detected! Sessions in both sets: {overlap}")

        logger.info(
            "Session-disjoint split: Train=%d, Test=%d",
            len(train_df),
            len(test_df),
        )
        return train_df, test_df


def split_open_set(
    df: pd.DataFrame,
    holdout_classes: List[str],
    label_col: str = "device_class",
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Hold out specific device classes exclusively for testing unknown-rejection."""
    train_df = df[~df[label_col].isin(holdout_classes)].copy().reset_index(drop=True)
    open_set_df = df[df[label_col].isin(holdout_classes)].copy().reset_index(drop=True)

    logger.info(
        "Open-set split: Known samples=%d, Held-out unknown samples=%d (Classes: %s)",
        len(train_df),
        len(open_set_df),
        holdout_classes,
    )
    return train_df, open_set_df


def preprocess_feature_dataframe(
    df: pd.DataFrame,
    feature_cols: Optional[List[str]] = None,
    label_col: str = "device_class",
) -> Tuple[pd.DataFrame, Optional[pd.Series], List[str]]:
    """Clean and align features with the standard schema."""
    cols = feature_cols or DEFAULT_FEATURE_COLS

    # Fill missing features with 0.0
    features_df = pd.DataFrame(index=df.index)
    for c in cols:
        if c in df.columns:
            features_df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
        else:
            features_df[c] = 0.0

    labels = df[label_col].copy() if label_col in df.columns else None
    return features_df, labels, cols
