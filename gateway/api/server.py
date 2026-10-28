"""Lightweight Zero-Trust Gateway Management API and Web Dashboard.

Provides:
1. RESTful JSON API for device status, manual overrides, and audit queries.
2. Production-grade, zero-dependency HTML5/CSS3/JavaScript operator dashboard.
3. Interactive client presentation simulator for live demonstrations.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from gateway.datasets.synthetic import BenchmarkDatasetGenerator
from gateway.enforcement.controller import ClosedLoopEnforcementController
from gateway.enforcement.policy import DeviceTrustState, ZeroTrustPolicyEngine
from gateway.models.anomaly import BehavioralAnomalyDetector
from gateway.models.classifier import ZeroTrustDeviceClassifier
from gateway.models.train import train_and_export_model
from gateway.quarantine.manager import QuarantineManager
from gateway.sensing.capture import PacketCaptureEngine
from gateway.sensing.storage import SensorStorage

logger = logging.getLogger("gateway.api")

HTML_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zero-Trust IoT Gateway | Operations Center</title>
    <style>
        :root {
            --bg: #0b0f19;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: #374151;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --primary-glow: rgba(59, 130, 246, 0.3);
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --badge-bg: rgba(255, 255, 255, 0.05);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background: var(--bg); color: var(--text-main); min-height: 100vh; padding: 24px; }
        header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
        .logo-area { display: flex; align-items: center; gap: 12px; }
        .logo-badge { background: linear-gradient(135deg, var(--primary), #8b5cf6); padding: 8px 14px; border-radius: 8px; font-weight: 700; font-size: 16px; letter-spacing: 0.5px; }
        h1 { font-size: 20px; font-weight: 600; }
        .subtext { font-size: 13px; color: var(--text-muted); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px; position: relative; overflow: hidden; }
        .stat-card::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--primary); }
        .stat-card.danger::before { background: var(--danger); }
        .stat-card.success::before { background: var(--success); }
        .stat-card.warning::before { background: var(--warning); }
        .stat-label { font-size: 12px; font-weight: 500; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
        .stat-value { font-size: 28px; font-weight: 700; }
        .dashboard-main { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
        @media (max-width: 1024px) { .dashboard-main { grid-template-columns: 1fr; } }
        .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; }
        .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .panel-title { font-size: 16px; font-weight: 600; }
        table { width: 100%; border-collapse: collapse; text-align: left; font-size: 13px; }
        th { padding: 10px 12px; color: var(--text-muted); border-bottom: 1px solid var(--border); font-weight: 500; }
        td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        tr:hover { background: var(--surface-hover); }
        .badge { display: inline-flex; align-items: center; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 600; letter-spacing: 0.3px; }
        .badge-quarantined { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-promoted { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-rejected, .badge-demoted { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        .btn { padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: 500; cursor: pointer; border: none; transition: all 0.15s ease; }
        .btn-promote { background: var(--success); color: #fff; }
        .btn-promote:hover { opacity: 0.9; }
        .btn-quarantine { background: var(--danger); color: #fff; margin-left: 6px; }
        .btn-quarantine:hover { opacity: 0.9; }
        .btn-sim { background: var(--primary); color: #fff; width: 100%; padding: 10px; font-size: 13px; font-weight: 600; margin-bottom: 10px; }
        .btn-sim:hover { box-shadow: 0 0 12px var(--primary-glow); }
        .sim-box { display: flex; flex-direction: column; gap: 10px; }
        .audit-item { padding: 10px; border-left: 3px solid var(--primary); background: rgba(255, 255, 255, 0.02); margin-bottom: 8px; border-radius: 0 6px 6px 0; font-size: 12px; }
        .audit-item.danger { border-left-color: var(--danger); }
        .audit-item.success { border-left-color: var(--success); }
        .audit-time { font-size: 10px; color: var(--text-muted); margin-bottom: 2px; }
        .modal { display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.7); align-items: center; justify-content: center; z-index: 100; }
        .modal.active { display: flex; }
        .modal-content { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; width: 90%; max-width: 600px; max-height: 85vh; overflow-y: auto; padding: 24px; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
        .close-btn { background: none; border: none; color: var(--text-muted); font-size: 20px; cursor: pointer; }
        pre { background: #000; padding: 12px; border-radius: 8px; font-size: 11px; overflow-x: auto; color: #a7f3d0; }
    </style>
</head>
<body>
    <header>
        <div class="logo-area">
            <div class="logo-badge">ZT-IOT</div>
            <div>
                <h1>Zero-Trust IoT Gateway Control Center</h1>
                <div class="subtext">Raspberry Pi 4/5 + OpenWrt Passive Detection &amp; Closed-Loop Enforcement</div>
            </div>
        </div>
        <button class="btn" style="background: var(--surface-hover); color: var(--text-main);" onclick="refreshData()">&#x21bb; Refresh Telemetry</button>
    </header>

    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-label">Total Endpoints</div>
            <div class="stat-value" id="stat-total">0</div>
        </div>
        <div class="stat-card warning">
            <div class="stat-label">Quarantined (VLAN 20)</div>
            <div class="stat-value" id="stat-quarantined">0</div>
        </div>
        <div class="stat-card success">
            <div class="stat-label">Trusted Endpoints (VLAN 10)</div>
            <div class="stat-value" id="stat-trusted">0</div>
        </div>
        <div class="stat-card danger">
            <div class="stat-label">Blocked Outliers &amp; Anomalies</div>
            <div class="stat-value" id="stat-blocked">0</div>
        </div>
    </div>

    <div class="dashboard-main">
        <div class="panel">
            <div class="panel-header">
                <div class="panel-title">Active Monitored Endpoints</div>
                <span class="subtext">Auto-evaluated via 4-Signal Fingerprint Engine</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>MAC / Hostname</th>
                        <th>IP Address</th>
                        <th>Inferred Class</th>
                        <th>Confidence</th>
                        <th>Trust Zone</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="device-table-body">
                    <tr><td colspan="6" style="text-align:center; color:var(--text-muted);">Loading live endpoint telemetry...</td></tr>
                </tbody>
            </table>
        </div>

        <div style="display:flex; flex-direction:column; gap:24px;">
            <div class="panel">
                <div class="panel-header">
                    <div class="panel-title">Presentation Simulator</div>
                </div>
                <div class="sim-box">
                    <p style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">
                        Trigger live zero-trust onboarding events to demonstrate automated containment, fingerprinting, promotion, and anomaly demotion to clients:
                    </p>
                    <button class="btn btn-sim" onclick="simulateEvent('smart_camera')">1. Connect Authorized Camera (Promote)</button>
                    <button class="btn btn-sim" style="background:#059669;" onclick="simulateEvent('smart_speaker')">2. Connect Authorized Speaker (Promote)</button>
                    <button class="btn btn-sim" style="background:#dc2626;" onclick="simulateEvent('rogue_unknown')">3. Connect Rogue Scanner (Block Outlier)</button>
                    <button class="btn btn-sim" style="background:#d97706;" onclick="simulateEvent('compromised_drift')">4. Simulate Drift on Camera (Auto-Demote)</button>
                </div>
            </div>

            <div class="panel" style="flex:1;">
                <div class="panel-header">
                    <div class="panel-title">Zero-Trust Audit Log</div>
                </div>
                <div id="audit-log-container" style="max-height: 280px; overflow-y: auto;">
                    <div class="subtext">Fetching audit events...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Telemetry Modal -->
    <div class="modal" id="telemetry-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modal-title">Device Telemetry 360</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <pre id="modal-json">Loading...</pre>
        </div>
    </div>

    <script>
        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                document.getElementById('stat-total').innerText = data.total_devices;
                document.getElementById('stat-quarantined').innerText = data.quarantined_count;
                document.getElementById('stat-trusted').innerText = data.trusted_count;
                document.getElementById('stat-blocked').innerText = data.blocked_count;
            } catch (err) { console.error('Failed to fetch status:', err); }
        }

        async function fetchDevices() {
            try {
                const res = await fetch('/api/devices');
                const devices = await res.json();
                const tbody = document.getElementById('device-table-body');
                tbody.innerHTML = '';
                if (devices.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-muted);">No devices detected yet. Run a simulation scenario.</td></tr>';
                    return;
                }
                devices.forEach(d => {
                    let badgeClass = 'badge-quarantined';
                    if (d.status === 'PROMOTED') badgeClass = 'badge-promoted';
                    else if (d.status === 'REJECTED_UNKNOWN' || d.status === 'DEMOTED_ANOMALOUS') badgeClass = 'badge-rejected';

                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>
                            <div style="font-weight:600;">${d.mac}</div>
                            <div style="font-size:11px; color:var(--text-muted);">${d.hostname || d.vendor || 'Unknown Host'}</div>
                        </td>
                        <td>${d.ip || 'Pending DHCP'}</td>
                        <td><strong>${d.inferred_class || 'Scanning...'}</strong></td>
                        <td>${d.confidence ? (d.confidence * 100).toFixed(1) + '%' : 'N/A'}</td>
                        <td><span class="badge ${badgeClass}">${d.status}</span></td>
                        <td>
                            <button class="btn btn-promote" onclick="promoteDevice('${d.mac}')">&#x2713; Allow</button>
                            <button class="btn btn-quarantine" onclick="quarantineDevice('${d.mac}')">&#x2715; Lock</button>
                            <button class="btn" style="background:#374151; color:#fff; margin-left:4px;" onclick="viewTelemetry('${d.mac}')">&#x1f50d;</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (err) { console.error('Failed to fetch devices:', err); }
        }

        async function fetchAudit() {
            try {
                const res = await fetch('/api/audit');
                const logs = await res.json();
                const container = document.getElementById('audit-log-container');
                container.innerHTML = '';
                logs.slice(0, 15).forEach(log => {
                    const item = document.createElement('div');
                    let colorClass = '';
                    if (log.action.includes('PROMOT') || log.action.includes('ALLOW')) colorClass = 'success';
                    if (log.action.includes('QUARANTINE') || log.action.includes('DEMOT') || log.action.includes('REJECT')) colorClass = 'danger';
                    item.className = `audit-item ${colorClass}`;
                    item.innerHTML = `
                        <div class="audit-time">${log.timestamp.slice(11, 19)} | <strong>${log.mac}</strong></div>
                        <div><strong>${log.action}</strong>: ${log.reason}</div>
                    `;
                    container.appendChild(item);
                });
            } catch (err) { console.error('Failed to fetch audit:', err); }
        }

        async function promoteDevice(mac) {
            await fetch(`/api/devices/${mac}/promote`, { method: 'POST' });
            refreshData();
        }

        async function quarantineDevice(mac) {
            await fetch(`/api/devices/${mac}/quarantine`, { method: 'POST' });
            refreshData();
        }

        async function viewTelemetry(mac) {
            document.getElementById('modal-title').innerText = `Telemetry: ${mac}`;
            document.getElementById('modal-json').innerText = 'Loading...';
            document.getElementById('telemetry-modal').classList.add('active');
            const res = await fetch(`/api/devices/${mac}`);
            const data = await res.json();
            document.getElementById('modal-json').innerText = JSON.stringify(data, null, 2);
        }

        function closeModal() {
            document.getElementById('telemetry-modal').classList.remove('active');
        }

        async function simulateEvent(scenario) {
            const btn = event.target;
            const originalText = btn.innerText;
            btn.innerText = 'Processing event...';
            btn.disabled = true;
            try {
                await fetch('/api/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scenario: scenario })
                });
                await refreshData();
            } finally {
                btn.innerText = originalText;
                btn.disabled = false;
            }
        }

        function refreshData() {
            fetchStatus();
            fetchDevices();
            fetchAudit();
        }

        setInterval(refreshData, 4000);
        refreshData();
    </script>
</body>
</html>
"""


class GatewayAPIHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler providing REST API endpoints and Web Dashboard."""

    controller: ClosedLoopEnforcementController
    capture_engine: PacketCaptureEngine

    def _send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, html: str, status: int = 200) -> None:
        payload = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        url = urlparse(self.path)
        path = url.path.rstrip("/")

        # 1. Dashboard UI
        if path in ("", "/dashboard", "/index.html"):
            self._send_html(HTML_DASHBOARD_TEMPLATE)
            return

        # 2. System Status Endpoint
        if path == "/api/status":
            devices = self.controller.get_all_devices()
            quarantined = sum(1 for d in devices if d["status"] in ("QUARANTINED", "REJECTED_UNKNOWN", "FLAGGED_INCONSISTENT", "DEMOTED_ANOMALOUS"))
            trusted = sum(1 for d in devices if d["status"] == "PROMOTED")
            blocked = sum(1 for d in devices if d["status"] in ("REJECTED_UNKNOWN", "DEMOTED_ANOMALOUS", "FLAGGED_INCONSISTENT"))
            self._send_json({
                "status": "OPERATIONAL",
                "total_devices": len(devices),
                "quarantined_count": quarantined,
                "trusted_count": trusted,
                "blocked_count": blocked,
                "model": "RandomForest_MultiSignal_OpenSet_v1",
                "distance_threshold": self.controller.classifier.distance_threshold,
            })
            return

        # 3. Devices List
        if path == "/api/devices":
            devices = self.controller.get_all_devices()
            # Enrich with inferred class and confidence
            enriched = []
            for d in devices:
                mac = d["mac"]
                snap = self.controller.storage.get_latest_snapshot(mac)
                inferred_class = "Unknown"
                confidence = 0.0
                if snap:
                    v = self.controller.classifier.predict_single(snap["features"])
                    inferred_class = v.get("predicted_class", "Unknown")
                    confidence = v.get("confidence", 0.0)
                item = dict(d)
                item["inferred_class"] = inferred_class
                item["confidence"] = confidence
                enriched.append(item)
            self._send_json(enriched)
            return

        # 4. Single Device Telemetry
        if path.startswith("/api/devices/"):
            mac = path.split("/api/devices/")[1]
            details = self.controller.get_device_overview(mac)
            if details:
                self._send_json(details)
            else:
                self._send_json({"error": "Device not found"}, status=404)
            return

        # 5. Audit Log
        if path == "/api/audit":
            logs = self.controller.quarantine_manager.get_audit_history()
            logs.reverse()
            self._send_json(logs[:50])
            return

        self._send_json({"error": "Endpoint not found"}, status=404)

    def do_POST(self) -> None:
        url = urlparse(self.path)
        path = url.path.rstrip("/")

        # Manual Promote
        if path.startswith("/api/devices/") and path.endswith("/promote"):
            mac = path.split("/api/devices/")[1].split("/promote")[0]
            success = self.controller.manual_promote(mac, operator="web_ui")
            self._send_json({"mac": mac, "action": "PROMOTED", "success": success})
            return

        # Manual Quarantine
        if path.startswith("/api/devices/") and path.endswith("/quarantine"):
            mac = path.split("/api/devices/")[1].split("/quarantine")[0]
            success = self.controller.manual_quarantine(mac, reason="operator_lockdown", operator="web_ui")
            self._send_json({"mac": mac, "action": "QUARANTINED", "success": success})
            return

        # Interactive Simulator Trigger
        if path == "/api/simulate":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
            try:
                payload = json.loads(body) if body else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json({"error": "Request body must be valid JSON."}, status=400)
                return
            if not isinstance(payload, dict):
                self._send_json({"error": "Request body must be a JSON object."}, status=400)
                return
            scenario = payload.get("scenario", "smart_camera")
            if not isinstance(scenario, str):
                self._send_json({"error": "scenario must be a string."}, status=400)
                return

            generator = BenchmarkDatasetGenerator()

            if scenario in ("smart_camera", "smart_speaker", "smart_plug", "thermostat", "rogue_unknown"):
                mac_map = {
                    "smart_camera": "b8:27:eb:aa:11:22",
                    "smart_speaker": "44:65:0d:88:99:aa",
                    "smart_plug": "50:c7:bf:12:34:56",
                    "thermostat": "00:17:88:fe:dc:ba",
                    "rogue_unknown": "a0:b1:c2:d3:e4:f5",
                }
                mac = mac_map[scenario]
                ip = "192.168.20.77"
                # Use a managed temporary directory so repeated dashboard
                # simulations do not leave PCAP files behind on the gateway.
                with tempfile.TemporaryDirectory(prefix="iot-gateway-") as temp_dir:
                    pcap_path = os.path.join(temp_dir, f"{scenario}.pcap")

                    # Step 1: Default-deny quarantine
                    self.controller.register_new_device(mac=mac, ip=ip, vendor=scenario.replace("_", " ").title())

                    # Step 2: Ingest PCAP
                    generator.generate_sample_pcap(output_pcap_path=pcap_path, device_class=scenario, mac=mac, ip=ip, packet_count=35)
                    self.capture_engine.process_pcap(pcap_path)

                # Step 3: Run closed loop policy evaluation
                decision = self.controller.evaluate_device(mac)
                self._send_json({"scenario": scenario, "decision": decision.to_dict()})
                return

            elif scenario == "compromised_drift":
                # Camera MAC that previously got promoted suddenly starts scanning ports with high burstiness
                mac = "b8:27:eb:aa:11:22"
                # First ensure it's promoted
                self.controller.manual_promote(mac, operator="sim_setup")

                # Generate anomalous traffic (port scanner behavior)
                drift_features = {
                    "total_packets": 250.0,
                    "packet_rate": 25.0,
                    "byte_rate": 2500.0,
                    "size_min": 40.0,
                    "size_max": 60.0,
                    "size_mean": 45.0,
                    "size_std": 5.0,
                    "unique_dest_ips": 45.0,
                    "dest_ip_entropy": 3.8,
                    "unique_dest_ports": 50.0,
                    "dest_port_entropy": 4.1,
                    "iat_mean": 0.04,
                    "iat_std": 0.01,
                    "iat_cv": 0.25,
                    "periodicity_score": 0.1,
                    "burstiness_ratio": 7.5,
                }
                # Store snapshot with anomalous telemetry
                self.controller.storage.store_feature_snapshot(
                    mac=mac,
                    structured_data={
                        "duration_seconds": 60.0,
                        "ip": "192.168.10.55",
                        "signals": {"traffic": drift_features},
                        "features": drift_features,
                    },
                )
                # Closed loop evaluation should detect drift and demote!
                decision = self.controller.evaluate_device(mac)
                self._send_json({"scenario": scenario, "decision": decision.to_dict()})
                return

            self._send_json({"error": f"Unknown scenario: {scenario}"}, status=400)
            return

        self._send_json({"error": "Endpoint not found"}, status=404)


class GatewayAPIServer:
    """Manages the lifecycle of the API HTTP daemon."""

    def __init__(
        self,
        controller: ClosedLoopEnforcementController,
        capture_engine: PacketCaptureEngine,
        host: str = "0.0.0.0",
        port: int = 8080,
    ) -> None:
        self.host = host
        self.port = port
        self.controller = controller
        self.capture_engine = capture_engine
        self.server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, block: bool = False) -> None:
        """Start the API server."""
        # Attach controller and capture engine to handler class
        GatewayAPIHandler.controller = self.controller
        GatewayAPIHandler.capture_engine = self.capture_engine

        self.server = ThreadingHTTPServer((self.host, self.port), GatewayAPIHandler)
        logger.info("Gateway API Server & Dashboard started at http://%s:%d", self.host, self.port)

        if block:
            try:
                self.server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
        else:
            self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop the API server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Gateway API Server stopped.")


def run_api_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    model_path: str = "models/baseline_rf.joblib",
    db_path: str = "data/gateway.db",
) -> None:
    """Entry point helper to launch API server from command line."""
    # A new installation has no model artifact yet.  Train the deterministic
    # baseline once so the documented `python -m gateway.api.server` command
    # is immediately usable; subsequent starts reuse the saved artifact.
    if os.path.exists(model_path):
        classifier = ZeroTrustDeviceClassifier.load(model_path)
    else:
        os.makedirs(os.path.dirname(os.path.abspath(model_path)), exist_ok=True)
        logger.info("No classifier artifact at %s; training baseline model.", model_path)
        classifier, _ = train_and_export_model(output_model_path=model_path)
    storage = SensorStorage(db_path=db_path)
    quarantine = QuarantineManager(db_path=db_path)
    policy_engine = ZeroTrustPolicyEngine()

    # Load or fit anomaly detector
    anomaly_detector = BehavioralAnomalyDetector()
    generator = BenchmarkDatasetGenerator()
    train_df = generator.generate_dataframe(samples_per_device=20, devices_per_class=3)
    anomaly_detector.fit(train_df)

    controller = ClosedLoopEnforcementController(
        classifier=classifier,
        quarantine_manager=quarantine,
        storage=storage,
        policy_engine=policy_engine,
        anomaly_detector=anomaly_detector,
        db_path=db_path,
    )
    capture_engine = PacketCaptureEngine(storage=storage)

    server = GatewayAPIServer(controller=controller, capture_engine=capture_engine, host=host, port=port)
    server.start(block=True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    run_api_server()

