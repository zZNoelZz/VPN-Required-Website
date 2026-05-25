import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Nạp và kiểm tra tệp dữ liệu thực tế 
print("[*] Đang nạp Dataset thực tế CICIDS2017 từ Kaggle...")
try:
    df = pd.read_csv('cicids2017_data.csv')
except FileNotFoundError:
    print("[!] LỖI: Không tìm thấy tệp 'cicids2017_data.csv' trong thư mục dự án!")
    exit()

# Sàng lọc ra những đặc trưng cốt lõi mà Card mạng WireGuard có thể bắt Real-time
df.columns = df.columns.str.strip()
features = ['Fwd Packet Length Mean', 'Flow IAT Mean', 'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count']
df = df[features + ['Label']]

# Làm sạch dữ liệu và loại bỏ các hàng chứa giá trị lỗi NaN, Infinity
print("[*] Đang làm sạch dữ liệu...")
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Chuẩn hóa các label (BENIGN thành mạng an toàn 0, các nhãn khác thành tấn công 1)
df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
X = df[features]
y = df['Label']
print(f"[*] Thống kê lưu lượng luồng: Bình thường (0): {sum(y==0)} | Tấn công (1): {sum(y==1)}")

# Chia tập dữ liệu ngẫu nhiên thành 80% để học và 20% để kiểm thử mô hình
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Huấn luyện mô hình Random Forest bằng cách tận dụng 100% tài nguyên đa nhân của CPU
print("[*] Đang tiến hành máy học phân loại Random Forest...")
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# Đánh giá độ chính xác toán học và đóng gói xuất file bộ não AI thực tế
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
joblib.dump(clf, 'random_forest_model.pkl')
print(f"[✔] HUẤN LUYỆN THÀNH CÔNG! Accuracy đạt chuẩn: {acc * 100:.4f}%")