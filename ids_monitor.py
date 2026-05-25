# ids_monitor.py
import os
import time
import requests
import joblib
import pandas as pd
import signal
import sys
import numpy as np
from scapy.all import sniff, IP, TCP, get_if_list

# Tự động dò tìm và khớp nối Interface của card mạng ảo WireGuard trên hệ thống
INTERFACE = "wg0"
try:
    interfaces = get_if_list()
    for iface in interfaces:
        if "wireguard" in iface.lower() or "tunnel" in iface.lower():
            INTERFACE = iface
            break
except Exception:
    pass

# Tải mô hình AI đã huấn luyện
NODEJS_API_URL = "http://localhost:3000/api/report-attack" 
MODEL_PATH = "random_forest_model.pkl"
if os.path.exists(MODEL_PATH):
    clf = joblib.load(MODEL_PATH)
    print(f"[*] Đã nạp bộ não AI thành công từ {MODEL_PATH}")
else:
    print(f"[!] LỖI: Không tìm thấy file {MODEL_PATH}. Hãy chạy train_model.py trước!")
    sys.exit(1)

# Thiết lập bộ đệm lưu trữ trạng thái lưu lượng và cơ chế xử lý khi tắt script
flow_stats = {}
def signal_handler(sig, frame):
    print("\n[*] Đang dừng hệ thống giám sát...")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# Hàm gác cổng trích xuất đặc trưng và đưa dữ liệu mạng vào AI đối chiếu theo thời gian thực
def process_packet(packet):
    global flow_stats
    
    if packet.haslayer(IP):
        src_ip = str(packet[IP].src).replace('::ffff:', '').strip()
        dst_ip = str(packet[IP].dst).replace('::ffff:', '').strip()
        
        if not src_ip.startswith("10.10."):
            return

        current_time = time.time()
        packet_len = len(packet)
        
        is_syn = 0
        is_ack = 0
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'S' in flags: is_syn = 1  
            if 'A' in flags: is_ack = 1  

        if src_ip not in flow_stats:
            flow_stats[src_ip] = []
            
        flow_stats[src_ip].append({
            'time': current_time,
            'len': packet_len,
            'syn': is_syn,
            'ack': is_ack
        })

        flow_stats[src_ip] = [pkt for pkt in flow_stats[src_ip] if current_time - pkt['time'] <= 1.0]
        window = flow_stats[src_ip]
        flow_packets_s = len(window)
        
        if flow_packets_s > 1:
            fwd_pkt_len_mean = np.mean([pkt['len'] for pkt in window])
            
            timestamps = sorted([pkt['time'] for pkt in window])
            iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            flow_iat_mean = np.mean(iats) * 1000000 
            
            syn_flag_count = sum(pkt['syn'] for pkt in window)
            ack_flag_count = sum(pkt['ack'] for pkt in window)

            features = pd.DataFrame(
                [[fwd_pkt_len_mean, flow_iat_mean, flow_packets_s, syn_flag_count, ack_flag_count]], 
                columns=['Fwd Packet Length Mean', 'Flow IAT Mean', 'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count']
            )
            
            prediction = clf.predict(features)[0]
            
            if prediction == 1:
                print(f"[⚠️ WARNING] AI phát hiện DDoS/Flood từ IP: {src_ip} (Tốc độ: {flow_packets_s} gói/s)")
                try:
                    payload = {
                        "attacker_ip": src_ip,
                        "target_ip": dst_ip,
                        "attack_type": "DDoS/Flood (CICIDS2017 Pattern)",
                        "packet_rate": flow_packets_s
                    }
                    requests.post(NODEJS_API_URL, json=payload, timeout=1)
                    print(f"[✔] Đã đồng bộ lệnh cách ly thiết bị tới Web IPS.")
                except Exception:
                    pass 

# Kích hoạt vòng lặp bắt gói tin liên tục trên card mạng mà không lưu vào bộ nhớ RAM
print(f"[*] Hệ thống IDS chuyên sâu đã sẵn sàng. Đang giám sát trên interface: {INTERFACE}...")
sniff(iface=INTERFACE, prn=process_packet, store=0)