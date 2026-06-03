import pandas as pd
import numpy as np
import joblib
import glob
import gc
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.ensemble import RandomForestClassifier, IsolationForest

# ĐỌC VÀ LÀM SẠCH DỮ LIỆU
print("[*] Đang khởi động AI và Hệ thống Đánh giá...")
parquet_files = glob.glob("*.parquet") 

if not parquet_files:
    print("[!] LỖI: Không tìm thấy file .parquet nào!")
    exit()

dataframes = []
TOTAL_SAMPLES = 2500000 
SAMPLES_PER_FILE = TOTAL_SAMPLES // len(parquet_files) 

for file in parquet_files:
    try:
        df_temp = pd.read_parquet(file)
        if len(df_temp) > SAMPLES_PER_FILE:
            df_temp = df_temp.sample(n=SAMPLES_PER_FILE, random_state=42)
        dataframes.append(df_temp)
    except Exception as e:
        print(f"  [!] Bỏ qua file {file}: {e}")

df_tong_hop = pd.concat(dataframes, ignore_index=True)
del dataframes; gc.collect() 

df_tong_hop.columns = df_tong_hop.columns.str.strip().str.replace(' ', '_').str.lower()
features = ['fwd_packet_length_mean', 'flow_iat_mean', 'flow_packets/s', 'syn_flag_count', 'ack_flag_count']

# TỰ ĐỘNG DÒ TÊN CỘT LỆCH
missing_cols = [col for col in features + ['label'] if col not in df_tong_hop.columns]

if missing_cols:
    print(f"\n[!] LỖI BẤT ĐỒNG BỘ: File Parquet không có các cột tên là: {missing_cols}")
    keywords = ['syn', 'ack', 'fwd', 'flow', 'label', 'pkt', 'cnt', 'count', 'len']
    goi_y = [c for c in df_tong_hop.columns if any(kw in c for kw in keywords)]
    for c in goi_y: 
        print(f"  -> {c}")
    exit() 

df_tong_hop = df_tong_hop[features + ['label']]
df_tong_hop.replace([np.inf, -np.inf], np.nan, inplace=True)
df_tong_hop.dropna(inplace=True)
df_tong_hop['label'] = df_tong_hop['label'].astype(str) 
df_tong_hop = df_tong_hop[df_tong_hop['label'] != 'label'] 
df_tong_hop['label'] = df_tong_hop['label'].apply(lambda x: 0 if x.upper() == 'BENIGN' or x == '0' else 1)

for col in features:
    df_tong_hop[col] = pd.to_numeric(df_tong_hop[col], errors='coerce')
df_tong_hop.dropna(inplace=True) 

X = df_tong_hop[features]
y = df_tong_hop['label']

# HUẤN LUYỆN VÀ ĐÁNH GIÁ 
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# RANDOM FOREST
print("\n" + "="*50 + "\n[1] KẾT QUẢ ĐÁNH GIÁ RANDOM FOREST\n" + "="*50)
rf_clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
rf_clf.fit(X_train, y_train) 
rf_preds = rf_clf.predict(X_test) 

print(f"[*] Accuracy  : {accuracy_score(y_test, rf_preds):.4f}")
print(f"[*] Precision : {precision_score(y_test, rf_preds):.4f}")
print(f"[*] Recall    : {recall_score(y_test, rf_preds):.4f}")
print(f"[*] F1-Score  : {f1_score(y_test, rf_preds):.4f}")
joblib.dump(rf_clf, 'ids_random_forest.pkl')

# ISOLATION FOREST
print("\n" + "="*50 + "\n[2] KẾT QUẢ ĐÁNH GIÁ ISOLATION FOREST\n" + "="*50)
X_train_normal = X_train[y_train == 0]
if_clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
if_clf.fit(X_train_normal)

if_raw_preds = if_clf.predict(X_test)
if_preds_mapped = [1 if pred == -1 else 0 for pred in if_raw_preds]

print(f"[*] Accuracy  : {accuracy_score(y_test, if_preds_mapped):.4f}")
print(f"[*] Precision : {precision_score(y_test, if_preds_mapped):.4f}")
print(f"[*] Recall    : {recall_score(y_test, if_preds_mapped):.4f}")
print(f"[*] F1-Score  : {f1_score(y_test, if_preds_mapped):.4f}")
joblib.dump(if_clf, 'ids_isolation_forest.pkl')

print("\n[✔] XUẤT XƯỞNG THÀNH CÔNG!")