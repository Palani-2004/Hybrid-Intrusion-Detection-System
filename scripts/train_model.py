# scripts/train_model.py
import pandas as pd
from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
import logging

logging.basicConfig(level=logging.INFO, format="[TRAIN] %(message)s")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data" / "processed" / "processed.csv"
MODEL = BASE / "data" / "models" / "rf_clf.joblib"

def main():
    if not DATA.exists():
        raise FileNotFoundError("processed.csv not found. Upload data first.")

    df = pd.read_csv(DATA)
    logging.info(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

    # Determine label column safely
    if "Attack Type" in df.columns:
        label_col = "Attack Type"
    elif "Label" in df.columns:
        label_col = "Label"
    else:
        raise ValueError(
            "No label column found. Expected 'Attack Type' or 'Label'."
    )

    X = df.drop(columns=[label_col])
    y = df[label_col]

    logging.info("Class distribution:")
    logging.info(y.value_counts().to_string())

    from collections import Counter

    class_counts = Counter(y)

# Use stratification only if all classes have >= 2 samples
    if min(class_counts.values()) >= 2:
        stratify_y = y
        print("[TRAIN] Using stratified train-test split")
    else:
        stratify_y = None
        print(
            "[TRAIN] WARNING: Not using stratification "
            "(some classes have < 2 samples)"
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=stratify_y
    )


    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=15,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    report = classification_report(y_test, preds)
    logging.info("Evaluation Metrics:\n" + report)

    MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL)

    logging.info(f"Model saved → {MODEL}")
    print("Training model...")
    print(f"Training data shape: {X.shape}")
    print("Model training completed.")


if __name__ == "__main__":
    main()
