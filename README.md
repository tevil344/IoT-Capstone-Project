# IoT Zero-Trust Gateway

A prototype zero-trust IoT gateway that passively fingerprints devices on the network and quarantines unknown or suspicious devices before they can reach trusted segments. The project is focused on a Raspberry Pi-style gateway workflow: capture metadata from network traffic, build a structured fingerprint, classify devices with a machine learning model, and enforce policy decisions through a quarantine manager.

This repository is organized as a research/engineering prototype and includes synthetic dataset generation, model training, passive sensing, and a demonstration pipeline.

## Why this project exists

Modern IoT networks often rely on MAC addresses, DHCP information, and static inventories, but those can be spoofed or bypassed. This project explores a zero-trust model where:

- devices are not trusted by default,
- traffic is passively observed without payload inspection,
- device fingerprints are compared to known-good profiles,
- unknown or inconsistent devices are isolated in a quarantine VLAN or set,
- a model decides whether a device should be promoted or rejected.

## Core ideas

- Passive sensing: extract features from DHCP, service discovery, TCP/TLS metadata, and traffic characteristics.
- Zero-trust enforcement: quarantine unverified MAC addresses using nftables-style set logic.
- ML-based classification: train a Random Forest-based classifier with open-set novelty rejection.
- Auditability: persist enforcement and inference events to SQLite.

## Project architecture

The repo is divided into a few clear subsystems:

- `gateway/sensing/`: packet capture, feature aggregation, and persistence of extracted telemetry.
- `gateway/models/`: training, evaluation, and classification logic for device profiling.
- `gateway/quarantine/`: MAC quarantine logic and audit trail management.
- `gateway/datasets/`: synthetic data generators and loaders used to simulate representative IoT device behavior.
- `inventory/`: baseline device inventory and trust policy metadata.
- `scripts/`: end-to-end demo and sample PCAP generation utilities.
- `tests/`: verification coverage for datasets, models, quarantine behavior, and sensing logic.

## Repository structure

```text
.
├── README.md
├── requirements.txt
├── .gitignore
├── config/
│   ├── openwrt/
│   └── pi/
├── gateway/
│   ├── __init__.py
│   ├── datasets/
│   │   ├── __init__.py
│   │   ├── downloader.py
│   │   ├── local_loader.py
│   │   ├── preprocessor.py
│   │   └── synthetic.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── classifier.py
│   │   ├── evaluate.py
│   │   └── train.py
│   ├── quarantine/
│   │   ├── __init__.py
│   │   └── manager.py
│   └── sensing/
│       ├── __init__.py
│       ├── aggregator.py
│       ├── capture.py
│       ├── extractors/
│       └── storage.py
├── inventory/
│   └── device_inventory.yaml
├── scripts/
│   ├── generate_sample_pcap.py
│   └── run_demo.py
├── tests/
│   ├── __init__.py
│   ├── test_datasets.py
│   ├── test_models.py
│   ├── test_quarantine.py
│   └── test_sensing.py
└── eval "$(ssh-agent -s)"*
```

## How the system works

The project implements a passive device fingerprinting pipeline similar to the following:

1. Device connects to the network.
2. The gateway places the device into a quarantine state by default.
3. Passive sensing captures metadata from the traffic without inspecting payload contents.
4. Features are extracted across four signal groups:
   - DHCP metadata
   - Service discovery information
   - TCP/IP and TLS metadata
   - Traffic behavior and periodicity
5. A classifier predicts the device class and checks whether the sample is a known or novel device.
6. The quarantine policy either keeps the device isolated or promotes it after verification.

The demonstration script `scripts/run_demo.py` walks through this flow end-to-end and prints a verdict with model confidence, consistency score, and policy action.

## Device profiling and classification

The classifier uses a Random Forest ensemble with signal-specific submodels. It measures:

- overall confidence `P(c|x)`
- distance to class centroids for novelty detection
- agreement across active signal groups for consistency scoring
- open-set rejection when a device is too distant from known classes or has low confidence

This is implemented in `gateway/models/classifier.py` and used during the demo pipeline.

## Quarantine and policy enforcement

The quarantine manager in `gateway/quarantine/manager.py` is designed to:

- validate MAC addresses,
- add or remove them from a quarantine set,
- keep an SQLite audit record,
- support dry-run behavior when nftables is not available,
- emulate the zero-trust policy model in development environments.

This is a useful abstraction for testing and simulation before deploying on a real OpenWrt or Linux firewall environment.

## Inventory and policy metadata

The repo includes a device inventory template in `inventory/device_inventory.yaml`.

It defines:

- baseline profiles for known devices,
- VLAN assignments,
- trust state,
- default policy thresholds,
- quarantine and promotion rules.

This inventory gives the project a policy backbone for known-good devices and a place to track edge cases or suspicious devices.

## Data and model workflow

The project includes synthetic and local dataset utilities:

- `gateway/datasets/synthetic.py`: creates benchmark PCAP-like traffic traces and labels.
- `gateway/datasets/local_loader.py`: loads local dataset artifacts.
- `gateway/datasets/preprocessor.py`: prepares feature tables for model training.
- `gateway/models/train.py`: trains the baseline classifier and exports the model artifact.
- `gateway/models/evaluate.py`: evaluates model performance.

## Getting started

### Prerequisites

- Python 3.10+
- pip
- Linux/macOS environment for local development
- Optional: nftables and a Linux-based networking environment for real enforcement

### Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the demo

```bash
python scripts/run_demo.py --device smart_camera
```

You can also try other device classes:

```bash
python scripts/run_demo.py --device smart_speaker
python scripts/run_demo.py --device smart_plug
python scripts/run_demo.py --device thermostat
python scripts/run_demo.py --device rogue_unknown
```

The script will:

- generate or load a sample PCAP,
- place the device in a quarantine state,
- extract features,
- run inference,
- print a policy decision and audit summary.

## Testing

The repository includes focused tests for the core modules:

```bash
pytest -q
```

The test suite covers:

- synthetic datasets,
- model behavior and performance,
- sensing pipeline output,
- quarantine logic and state transitions.

## Dependencies

The project relies on the following Python libraries:

- scikit-learn
- pandas
- numpy
- scipy
- scapy
- pyyaml
- joblib

See `requirements.txt` for the exact versions and package list.

## Notes and assumptions

This repository is best viewed as a working prototype and a research-oriented capstone project. It is intentionally designed around a simplified model of zero-trust onboarding and passive device identification rather than a full production-ready network security stack.

The codebase assumes:

- network metadata can be extracted without deep packet inspection,
- device behaviors are differentiable enough to cluster by class,
- open-set rejection is useful for unknown or malicious devices,
- Linux-based enforcement is available for deployment in a real network path.

## Potential next steps

Possible extensions for this project include:

- integration with actual PCAP capture from a network tap or monitor interface,
- adding a real-time packet ingestion pipeline,
- expanding the device inventory with production baselines,
- integrating with a web dashboard or alerting system,
- replacing the synthetic dataset approach with real-world IoT traces,
- deploying the quarantine logic on OpenWrt or a gateway appliance.

## Summary

This project demonstrates a practical zero-trust IoT gateway approach: capture metadata, model known device behavior, isolate unknowns, and enforce trust policy with auditability. It is a solid prototype for learning and experimentation around IoT security, passive monitoring, and ML-driven device fingerprinting.

## License

This repository does not currently declare a license file in the root directory. If you plan to reuse or distribute the code, check whether the project has an explicit license requirement before publishing or integrating it elsewhere.
