import pandas as pd
import numpy as np
import joblib
import glob
import gc
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.ensemble import RandomForestClassifier, IsolationForest

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

# Chuẩn hóa tên cột
df_tong_hop.columns = df_tong_hop.columns.str.strip().str.replace(' ', '_').str.lower()
features = ['fwd_pkt_len_mean', 'flow_iat_mean', 'flow_pkts/s', 'syn_flag_cnt', 'ack_flag_cnt']
df_tong_hop = df_tong_hop[features + ['label']]

# Lọc rác
df_tong_hop.replace([np.inf, -np.inf], np.nan, inplace=True)
df_tong_hop.dropna(inplace=True)
df_tong_hop['label'] = df_tong_hop['label'].astype(str) # Ép kiểu chuỗi để lọc rác
df_tong_hop = df_tong_hop[df_tong_hop['label'] != 'label'] # Xóa dòng lặp tiêu đề

# Đổi Label thành nhị phân: 0 (Bình thường), 1 (Tấn công)
df_tong_hop['label'] = df_tong_hop['label'].apply(lambda x: 0 if x.upper() == 'BENIGN' or x == '0' else 1)

# Ép toàn bộ đặc trưng về dạng số thực (tránh lỗi string của bản thường)
for col in features:
    df_tong_hop[col] = pd.to_numeric(df_tong_hop[col], errors='coerce')
df_tong_hop.dropna(inplace=True) # Xóa nốt những dòng không thể chuyển thành số

X = df_tong_hop[features]
y = df_tong_hop['label']

print("\n[*] Đang chia dữ liệu: 80% để Huấn luyện, 20% để Chấm điểm...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Random Forest
print("\n" + "="*50)
print("[1] KẾT QUẢ ĐÁNH GIÁ RANDOM FOREST")
print("="*50)
rf_clf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
rf_clf.fit(X_train, y_train)
rf_preds = rf_clf.predict(X_test)

# In 4 chỉ số
print(f"[*] Accuracy  : {accuracy_score(y_test, rf_preds):.4f}")
print(f"[*] Precision : {precision_score(y_test, rf_preds):.4f}")
print(f"[*] Recall    : {recall_score(y_test, rf_preds):.4f}")
print(f"[*] F1-Score  : {f1_score(y_test, rf_preds):.4f}")
joblib.dump(rf_clf, 'ids_random_forest.pkl')

# Isolation Forest
print("\n" + "="*50)
print("[2] KẾT QUẢ ĐÁNH GIÁ ISOLATION FOREST")
print("="*50)

# Học dữ liệu sạch trên tập 80% (label=0)
X_train_normal = X_train[y_train == 0]
if_clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42, n_jobs=-1)
if_clf.fit(X_train_normal)

# Test trên tập 20% có cả sạch và tấn công
if_raw_preds = if_clf.predict(X_test)

# ĐỒNG BỘ ĐẦU RA CỦA ISOLATION FOREST:
# IF trả về: 1 (Sạch), -1 (Tấn công)
# Ta đổi lại thành: 0 (Sạch), 1 (Tấn công) để tính điểm cho chuẩn
if_preds_mapped = [1 if pred == -1 else 0 for pred in if_raw_preds]

# In 4 chỉ số
print(f"[*] Accuracy  : {accuracy_score(y_test, if_preds_mapped):.4f}")
print(f"[*] Precision : {precision_score(y_test, if_preds_mapped):.4f}")
print(f"[*] Recall    : {recall_score(y_test, if_preds_mapped):.4f}")
print(f"[*] F1-Score  : {f1_score(y_test, if_preds_mapped):.4f}")
joblib.dump(if_clf, 'ids_isolation_forest.pkl')

print("\n[✔] XUẤT XƯỞNG THÀNH CÔNG!")