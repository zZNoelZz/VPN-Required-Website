import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import numpy as np

print("[*] Đang khởi tạo tập dữ liệu huấn luyện IDS nâng cao...")

# Nhãn 0 (Bình thường): Kích thước gói đa dạng, khoảng cách lớn, tần suất thấp
normal_data = pd.DataFrame({
    'packet_size': np.random.randint(54, 1500, 1000),
    'interval': np.random.uniform(0.1, 1.0, 1000),
    'packet_rate': np.random.randint(1, 15, 1000),
    'label': 0
})

# Nhãn 1 (Tấn công Flood): Kích thước gói nhỏ/đồng đều, khoảng cách cực nhỏ (~0), tần suất cực cao
attack_data = pd.DataFrame({
    'packet_size': np.random.choice([64, 74, 128], 1000),
    'interval': np.random.uniform(0.0001, 0.005, 1000),
    'packet_rate': np.random.randint(500, 1500, 1000),
    'label': 1
})

# Gộp dữ liệu và XÁO TRỘN NGẪU NHIÊN để tránh AI học vẹt theo thứ tự hàng
df = pd.concat([normal_data, attack_data], ignore_index=True)
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

X = df[['packet_size', 'interval', 'packet_rate']]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)

# Lưu bộ não AI
joblib.dump(clf, 'random_forest_model.pkl')
print(f"[✔] Đã tạo xong file random_forest_model.pkl với Accuracy đạt chuẩn: {acc * 100:.2f}%")