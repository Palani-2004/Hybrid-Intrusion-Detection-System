import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# Load your dataset (change path if needed)
df = pd.read_csv("nids_demo_dataset.csv")

# IMPORTANT:
# Create simple features similar to live detection
df["bytes_per_sec"] = df["byte_count"] / (df["duration"] + 1)

X = df[["duration", "packet_count", "byte_count", "bytes_per_sec"]]
y = df["label"]   # Attack / BENIGN column

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

model = RandomForestClassifier(n_estimators=50)
model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print("Model Accuracy:", accuracy)

joblib.dump(model, "random_forest_model.pkl")

print("Model saved successfully.")