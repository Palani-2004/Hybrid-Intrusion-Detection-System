# scripts/train_model.py

import sys
import pandas as pd
from pathlib import Path
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
import logging
from collections import Counter

logging.basicConfig(level=logging.INFO, format="[TRAIN] %(message)s")

# -------------------------------------------------
# Get Session ID from Django
# -------------------------------------------------
if len(sys.argv) < 2:
    raise Exception("Session ID not provided")

session_id = sys.argv[1]

# -------------------------------------------------
# Resolve project paths safely
# -------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

processed_dir = BASE_DIR / "data" / "processed" / session_id
processed_dir.mkdir(parents=True, exist_ok=True)

DATA = processed_dir / "preprocessed.csv"
MODEL = processed_dir / "model.pkl"

# -------------------------------------------------
# Main Training Logic
# -------------------------------------------------
def main():
    if not DATA.exists():
        raise FileNotFoundError(f"{DATA} not found. Run preprocess first.")

    df = pd.read_csv(DATA)
    logging.info(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")

    # Determine label column safely
    # if "Attack Type" in df.columns:
    #     label_col = "Attack Type"
    # elif "Label" in df.columns:
    #     label_col = "Label"
    # else:
    #     raise ValueError(
    #         "No label column found. Expected 'Attack Type' or 'Label'."
    #     )
    if "Attack Type" in df.columns:
        label_col = "Attack Type"
    elif "Label" in df.columns:
        label_col = "Label"
    else:
        logging.warning("No label column found. Skipping training.")
        print("No label column found. This dataset is for prediction only.")
        return


    X = df.drop(columns=[label_col])
    y = df[label_col]

    logging.info("Class distribution:")
    logging.info(y.value_counts().to_string())

    class_counts = Counter(y)

    # Use stratification only if all classes have >= 2 samples
    if min(class_counts.values()) >= 2:
        stratify_y = y
        logging.info("Using stratified train-test split")
    else:
        stratify_y = None
        logging.warning(
            "Not using stratification (some classes have < 2 samples)"
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

    logging.info("Training model...")
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    report = classification_report(y_test, preds)
    logging.info("Evaluation Metrics:\n" + report)

    joblib.dump(clf, MODEL)
    logging.info(f"Model saved → {MODEL}")

    print("Model training completed successfully.")


if __name__ == "__main__":
    main()
