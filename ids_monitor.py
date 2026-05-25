import os
import time
import requests
import joblib
import pandas as pd
import signal
import sys
from scapy.all import sniff, IP, get_if_list

INTERFACE = "wg0"
try:
    interfaces = get_if_list()
    for iface in interfaces:
        if "wireguard" in iface.lower() or "tunnel" in iface.lower():
            INTERFACE = iface
            break
except Exception:
    pass

NODEJS_API_URL = "http://localhost:3000/api/report-attack" 
MODEL_PATH = "random_forest_model.pkl"

if os.path.exists(MODEL_PATH):
    clf = joblib.load(MODEL_PATH)
    print(f"[*] Đã nạp bộ não AI thành công từ {MODEL_PATH}")
else:
    print(f"[!] LỖI: Không tìm thấy file {MODEL_PATH}. Hãy chạy train_model.py trước!")
    sys.exit(1)

last_packet_time = {}
packet_counts = {}

def signal_handler(sig, frame):
    print("\n[*] Đang dừng hệ thống giám sát...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def process_packet(packet):
    global last_packet_time, packet_counts
    
    if packet.haslayer(IP):
        src_ip = str(packet[IP].src).replace('::ffff:', '').strip()
        dst_ip = str(packet[IP].dst).replace('::ffff:', '').strip()
        
        if not src_ip.startswith("10.10."):
            return

        packet_size = len(packet)
        current_time = time.time()

        interval = 0.0
        if src_ip in last_packet_time:
            interval = current_time - last_packet_time[src_ip]
        last_packet_time[src_ip] = current_time

        if src_ip not in packet_counts:
            packet_counts[src_ip] = []
        packet_counts[src_ip].append(current_time)
        packet_counts[src_ip] = [t for t in packet_counts[src_ip] if current_time - t <= 1.0]
        packet_rate = len(packet_counts[src_ip])

        features = pd.DataFrame([[packet_size, interval, packet_rate]], 
                                columns=['packet_size', 'interval', 'packet_rate'])
        
        prediction = clf.predict(features)[0]
        
        if prediction == 1:
            print(f"[⚠️ WARNING] AI phát hiện hành vi Flood dồn dập từ IP: {src_ip} (Rate: {packet_rate} p/s)")
            try:
                payload = {
                    "attacker_ip": src_ip,
                    "target_ip": dst_ip,
                    "attack_type": "DDoS/Flood (Random Forest)",
                    "packet_rate": packet_rate
                }
                requests.post(NODEJS_API_URL, json=payload, timeout=1)
                print(f"[✔] Đã đẩy dữ liệu cách ly tới Web IPS.")
            except Exception:
                pass 

print(f"[*] Hệ thống IDS đã sẵn sàng. Đang giám sát trên interface: {INTERFACE}...")
sniff(iface=INTERFACE, prn=process_packet, store=0)