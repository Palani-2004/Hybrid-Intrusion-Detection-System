# scripts/predict.py

import sys
import pandas as pd
from pathlib import Path
import joblib
import logging

logging.basicConfig(level=logging.INFO, format="[PREDICT] %(message)s")

# -------------------------------------------------
# Get session ID from Django
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
FEATURES = processed_dir / "model_features.pkl"
OUT = processed_dir / "predictions.csv"

THRESHOLD = 0.6  # IDS decision threshold

# -------------------------------------------------
# Main Prediction Logic
# -------------------------------------------------
def main():

    if not DATA.exists():
        raise FileNotFoundError(f"Preprocessed file not found: {DATA}")

    if not MODEL.exists():
        raise FileNotFoundError(f"Model file not found: {MODEL}")

    if not FEATURES.exists():
        raise FileNotFoundError(f"Feature schema file not found: {FEATURES}")

    logging.info("Loading dataset...")
    df = pd.read_csv(DATA)

    logging.info("Loading trained model...")
    clf = joblib.load(MODEL)

    logging.info("Loading feature schema...")
    feature_columns = joblib.load(FEATURES)

    # Remove ground truth if present
    X = df.drop(columns=["Attack Type"], errors="ignore")

    # -------------------------------------------------
    # Enforce training feature order
    # -------------------------------------------------
    missing_cols = [col for col in feature_columns if col not in X.columns]
    if missing_cols:
        raise ValueError(f"Missing required features for prediction: {missing_cols}")

    # Align and reorder columns exactly as training
    X = X[feature_columns]

    logging.info("Running predictions...")
    probs = clf.predict_proba(X)[:, 1]

    df["ml_probability"] = probs
    df["pred_label"] = df["ml_probability"].apply(
        lambda p: "Malicious" if p >= THRESHOLD else "Benign"
    )

    df.to_csv(OUT, index=False)

    logging.info(f"Prediction output written → {OUT}")


if __name__ == "__main__":
    main()