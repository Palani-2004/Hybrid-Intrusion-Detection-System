from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
import requests
import time
from collections import defaultdict

# Load trained model
model = joblib.load("random_forest_model.pkl")

# Store simple flow stats
flow_data = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "start_time": time.time()
})

CLOUD_API = "https://hybrid-intrusion-detection-system-2.onrender.com/api/alert/"   # CHANGE THIS

def extract_features(flow):
    duration = time.time() - flow["start_time"]
    packet_count = flow["packet_count"]
    byte_count = flow["byte_count"]

    bytes_per_sec = byte_count / duration if duration > 0 else 0

    # IMPORTANT:
    # These features must match your model training features order
    return np.array([[duration, packet_count, byte_count, bytes_per_sec]])

def send_alert(ip, attack_type):
    try:
        requests.post(CLOUD_API, json={
            "ip": ip,
            "attack_type": attack_type,
            "severity": "HIGH"
        })
        print(f"[ALERT SENT] {ip} → {attack_type}")
    except:
        print("Failed to send alert")

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        key = src_ip

        flow_data[key]["packet_count"] += 1
        flow_data[key]["byte_count"] += len(packet)

        # Every 20 packets → check prediction
        if flow_data[key]["packet_count"] % 20 == 0:
            features = extract_features(flow_data[key])
            prediction = model.predict(features)[0]

            print(f"{src_ip} → {prediction}")

            if prediction != "BENIGN":
                send_alert(src_ip, prediction)

print("Starting Live Detection...")
sniff(prn=process_packet, store=False)