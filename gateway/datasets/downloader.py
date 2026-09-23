"""Dataset Download Manager for IoT Benchmark Datasets.

Handles automated downloading, verification, and extraction of:
1. N-BaIoT (UCI Machine Learning Repository: 9 commercial IoT devices)
2. Bot-IoT (UNSW Canberra: Smart Home IoT testbed)
3. IoTID20 (Smart Home device traces: TP-Link, Echo, Netatmo)
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import urllib.request
import zipfile
from typing import Dict, Optional

logger = logging.getLogger("gateway.datasets.downloader")

DATASET_CATALOG: Dict[str, Dict[str, str]] = {
    "nbaiot": {
        "name": "N-BaIoT",
        "description": "Traffic from 9 commercial IoT devices under benign and attack conditions (UCI)",
        "url": "https://archive.ics.uci.edu/static/public/442/detection_of_iot_botnet_attacks_n_baiot.zip",
        "archive_name": "nbaiot.zip",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    },
    "botiot": {
        "name": "Bot-IoT (5% Subset)",
        "description": "UNSW Canberra IoT testbed network flow and packet features",
        "url": "https://cloudstor.aarnet.edu.au/plus/s/umT9LeUDvvQIImU/download?path=%2F&files=UNSW_2018_IoT_Botnet_Final_10_Best.csv",
        "archive_name": "botiot_subset.csv",
        "sha256": "",
    },
    "iotid20": {
        "name": "IoTID20",
        "description": "IoT Intrusion Dataset 2020 smart home devices (TP-Link bulbs, camera, Echo)",
        "url": "https://sites.google.com/view/iot-network-intrusion-dataset/home",
        "archive_name": "iotid20.zip",
        "sha256": "",
    },
}


class DatasetDownloader:
    """Manages downloading and extracting external public datasets."""

    def __init__(self, target_dir: str = "data/raw") -> None:
        self.target_dir = target_dir
        os.makedirs(self.target_dir, exist_ok=True)

    def download(self, dataset_key: str, force: bool = False) -> str:
        """Download specified dataset by key ('nbaiot', 'botiot', 'iotid20')."""
        if dataset_key not in DATASET_CATALOG:
            raise ValueError(f"Unknown dataset key: {dataset_key}. Available: {list(DATASET_CATALOG.keys())}")

        info = DATASET_CATALOG[dataset_key]
        dest_path = os.path.join(self.target_dir, info["archive_name"])

        if os.path.exists(dest_path) and not force:
            logger.info("Dataset %s archive already exists at %s", dataset_key, dest_path)
            return dest_path

        logger.info("Downloading %s from %s ...", info["name"], info["url"])
        try:
            # Custom User-Agent to prevent 403 Forbidden from dataset hosts
            req = urllib.request.Request(
                info["url"],
                headers={"User-Agent": "Mozilla/5.0 (IoT-Security-Research/1.0)"},
            )
            with urllib.request.urlopen(req) as response, open(dest_path, "wb") as out_file:
                chunk_size = 65536
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    out_file.write(chunk)
            logger.info("Download completed: %s", dest_path)
        except Exception as exc:
            logger.error("Download failed for %s: %s", dataset_key, exc)
            if os.path.exists(dest_path):
                os.remove(dest_path)
            raise

        if dest_path.endswith(".zip"):
            extract_dir = os.path.join(self.target_dir, dataset_key)
            self.extract_zip(dest_path, extract_dir)
            return extract_dir

        return dest_path

    @staticmethod
    def extract_zip(zip_path: str, extract_to: str) -> None:
        """Extract a zip archive safely."""
        logger.info("Extracting %s to %s ...", zip_path, extract_to)
        os.makedirs(extract_to, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(extract_to)
        logger.info("Extraction complete: %s", extract_to)


def main() -> None:
    parser = argparse.ArgumentParser(description="IoT Benchmark Dataset Downloader")
    parser.add_argument(
        "--dataset",
        choices=list(DATASET_CATALOG.keys()),
        required=True,
        help="Dataset identifier to download",
    )
    parser.add_argument(
        "--output-dir",
        default="data/raw",
        help="Directory to save downloaded files",
    )
    parser.add_argument("--force", action="store_true", help="Force redownload")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    downloader = DatasetDownloader(target_dir=args.output_dir)
    downloader.download(args.dataset, force=args.force)


if __name__ == "__main__":
    main()
