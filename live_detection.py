from scapy.all import sniff
from collections import defaultdict
import pandas as pd
import joblib
import time
import requests
import threading

# ===============================
# Configuration
# ===============================

MODEL_PATH = "random_forest_model.pkl"
# CLOUD_API = "https://hybrid-intrusion-detection-system.onrender.com/api/alert/"
CLOUD_API = "http://127.0.0.1:8000/api/alert/"

FLOW_TIMEOUT = 5
DOS_PACKET_THRESHOLD = 100
PORT_SCAN_THRESHOLD = 20
CONFIDENCE_THRESHOLD = 0.80
ALERT_COOLDOWN = 30
FLOW_CLEANUP_INTERVAL = 2

# ===============================
# Load Model
# ===============================

model = joblib.load(MODEL_PATH)

# ===============================
# Flow Storage (Thread-Safe)
# ===============================

flows = defaultdict(lambda: {
    "start_time": None,
    "last_seen": None,
    "packet_count": 0,
    "total_bytes": 0,
    "ports": set(),
})

flows_lock = threading.Lock()
last_alert_time = {}

# ===============================
# Alert Sender (Non-Blocking)
# ===============================

def send_alert(ip, attack_type, severity="High"):
    now = time.time()

    if ip in last_alert_time:
        if now - last_alert_time[ip] < ALERT_COOLDOWN:
            return

    def async_alert():
        try:
            response = requests.post(
                CLOUD_API,
                json={
                    "ip": ip,
                    "attack_type": attack_type,
                    "severity": severity
                },
                timeout=5
            )
            print(f"[ALERT SENT] {ip} → {attack_type} ({response.status_code})")
        except Exception as e:
            print("Failed to send alert:", e)

    threading.Thread(target=async_alert, daemon=True).start()
    last_alert_time[ip] = now

# ===============================
# Flow Analyzer
# ===============================
def analyze_flow(flow_key, flow):

    src, dst, proto = flow_key

    duration = (flow["last_seen"] - flow["start_time"]) if flow["start_time"] else 0
    packet_count = flow["packet_count"]
    byte_count = flow["total_bytes"]

    features = {
        "duration": duration,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "bytes_per_sec": byte_count / duration if duration > 0 else 0
    }

    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]
    prob = model.predict_proba(df)[0][1]

    attack_type = None
    severity = "Medium"

    # ======================
    # ML Detection
    # ======================

    if prediction != "BENIGN":
        attack_type = "ML-Attack"
        severity = "High"

    # ======================
    # Signature Detection
    # ======================

    # ======================
    # Signature Detection
    # ======================

    # Data Exfiltration (Large data transfer)
    if byte_count > 5000:
        attack_type = "Data Exfiltration"
        severity = "High"
    
    # elif packet_count > 20000:
    #     attack_type = "Data Flood"
    #     severity = "High"
# Port Scan (many ports accessed)
    elif len(flow["ports"]) > 5:
        attack_type = "Port Scan"
        severity = "Medium"

# DoS (many packets in short time)
    elif packet_count > 20:
        attack_type = "DoS Attack"
        severity = "High"

    # ======================
    # Hybrid Decision
    # ======================

    if attack_type:
        print(f"[HYBRID ALERT] {src} → {attack_type}")
        send_alert(src, attack_type, severity)

    print(f"{src} → prediction={prediction}, prob={prob:.2f}")
    
# ===============================
# Flow Cleanup Thread
# ===============================

def cleanup_flows():
    while True:

        time.sleep(FLOW_CLEANUP_INTERVAL)
        now = time.time()

        with flows_lock:

            for key, flow in list(flows.items()):

                if not flow["start_time"]:
                    continue

                duration = now - flow["start_time"]

                # analyze flow periodically
                if duration >= 3:
                    analyze_flow(key, flow)

                # remove old flows
                if flow["last_seen"] and (now - flow["last_seen"] >= FLOW_TIMEOUT):
                    del flows[key]
            expired = [
                key for key, flow in flows.items()
                if flow["last_seen"] and (now - flow["last_seen"] >= FLOW_TIMEOUT)
            ]

            for key in expired:
                analyze_flow(key, flows[key])
                del flows[key]

# ===============================
# Packet Processor
# ===============================

def process_packet(packet):

    if not packet.haslayer("IP"):
        return

    src = packet["IP"].src
    dst = packet["IP"].dst
    proto = packet["IP"].proto

    dport = None
    if packet.haslayer("TCP"):
        dport = packet["TCP"].dport
    elif packet.haslayer("UDP"):
        dport = packet["UDP"].dport

    flow_key = (src, dst, proto)

    with flows_lock:
        flow = flows[flow_key]

        now = time.time()

        if flow["start_time"] is None:
            flow["start_time"] = now

        flow["last_seen"] = now
        flow["packet_count"] += 1
        flow["total_bytes"] += len(packet)

        if dport:
            flow["ports"].add(dport)

# ===============================
# Start System
# ===============================

if __name__ == "__main__":
    print("Starting Real Packet Capture...")

    # Start background cleanup thread
    threading.Thread(target=cleanup_flows, daemon=True).start()

    # Start packet capture
    sniff(prn=process_packet, store=False)