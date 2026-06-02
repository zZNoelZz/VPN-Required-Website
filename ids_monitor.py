import os
import time
import requests
import joblib
import pandas as pd
import signal
import sys
import numpy as np
from scapy.all import sniff, IP, TCP

# Tự động dò tìm và khớp nối Interface của card mạng trên hệ thống
INTERFACE = r"\Device\NPF_{65EC0FEA-5CCC-4C6A-A7B7-1461BCFFE94B}"

NODEJS_API_URL = "http://localhost:3000/api/report-attack" 

# Load 2 model đã train sẵn (Random Forest & Isolation Forest)
rf_model_path = "ids_random_forest.pkl"
if_model_path = "ids_isolation_forest.pkl"

if os.path.exists(rf_model_path) and os.path.exists(if_model_path):
    rf_clf = joblib.load(rf_model_path)
    if_clf = joblib.load(if_model_path)
    print("[*] HỆ THỐNG HYBRID IDS ĐÃ SẴN SÀNG")
else:
    print("[!] LỖI: Thiếu file .pkl. Hãy đảm bảo bạn đã copy đủ 2 file model vào thư mục này!")
    sys.exit(1)

flow_stats = {}
def signal_handler(sig, frame):
    print("\n[*] Đang dừng hệ thống giám sát...")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def process_packet(packet):
    global flow_stats
    
    if packet.haslayer(IP):
        src_ip = str(packet[IP].src).replace('::ffff:', '').strip()
        dst_ip = str(packet[IP].dst).replace('::ffff:', '').strip()

        # Bỏ qua máy chủ tự gửi (Tránh tự block chính mình)
        if src_ip == "192.168.2.143":
            return

        current_time = time.time()
        packet_len = 0
        is_syn = 0
        is_ack = 0

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            if 'S' in flags: is_syn = 1
            if 'A' in flags: is_ack = 1
            if packet.haslayer('Raw'):
                packet_len = len(packet['Raw'].load)
                
        if src_ip not in flow_stats:
            flow_stats[src_ip] = []
            
        flow_stats[src_ip].append({
            'time': current_time,
            'len': packet_len,
            'syn': is_syn,
            'ack': is_ack
        })

        # Cửa sổ trượt 1 giây
        flow_stats[src_ip] = [pkt for pkt in flow_stats[src_ip] if current_time - pkt['time'] <= 1.0]
        window = flow_stats[src_ip]
        flow_packets_s = len(window)
        
        if flow_packets_s > 1:
            fwd_pkt_len_mean = np.mean([pkt['len'] for pkt in window])
            
            timestamps = sorted([pkt['time'] for pkt in window])
            iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            flow_iat_mean = np.mean(iats) * 1000000 
            
            syn_count_raw = sum(pkt['syn'] for pkt in window)
            ack_count_raw = sum(pkt['ack'] for pkt in window)

            syn_flag_binary = 1 if syn_count_raw > 0 else 0
            ack_flag_binary = 1 if ack_count_raw > 0 else 0

            # Gom dữ liệu vào DataFrame theo đúng 5 TÊN CỘT đã train
            features = pd.DataFrame(
                [[fwd_pkt_len_mean, flow_iat_mean, flow_packets_s, syn_flag_binary, ack_flag_binary]], 
                columns=['fwd_pkt_len_mean', 'flow_iat_mean', 'flow_pkts/s', 'syn_flag_cnt', 'ack_flag_cnt']
            )
            
            # 1. Random Forest (1 = Tấn công, 0 = Bình thường)
            rf_pred = rf_clf.predict(features)[0]
            
            # 2. Isolation Forest (-1 = Dị thường/Zero-day, 1 = Bình thường)
            if_pred = if_clf.predict(features)[0]
            
            is_attack = False
            attack_type = ""

            # Chỉ cần 1 trong 2 não phát hiện sự bất thường là khóa chặn
            if rf_pred == 1:
                is_attack = True
                attack_type = "Known Attack Signature (Random Forest)"
            elif if_pred == -1:
                is_attack = True
                attack_type = "Zero-Day Anomaly (Isolation Forest)"

            # In log debug để dễ theo dõi quá trình
            if flow_packets_s > 10:
                print(f"[🔍] IP {src_ip}: {flow_packets_s} pkts/s | Len: {fwd_pkt_len_mean:.1f} | RF: {rf_pred} | IF: {if_pred}")

            if is_attack:
                print(f"\n[⚠️ WARNING] HỆ THỐNG PHÁT HIỆN TẤN CÔNG TỪ IP: {src_ip}")
                print(f"   -> Phân loại: {attack_type}")
                print(f"   -> Tốc độ: {flow_packets_s} gói/giây")
                
                try:
                    payload = {
                        "attacker_ip": src_ip,
                        "target_ip": dst_ip,
                        "attack_type": attack_type,
                        "packet_rate": flow_packets_s
                    }
                    requests.post(NODEJS_API_URL, json=payload, timeout=1)
                    print(f"[✔] Đã đồng bộ lệnh cách ly tầng Ứng dụng/Tường lửa tới Node.js.")
                except Exception:
                    pass 

print(f"[*] Đang giám sát luồng mạng trên interface: {INTERFACE}...")
sniff(iface=INTERFACE, prn=process_packet, store=0, count=0)