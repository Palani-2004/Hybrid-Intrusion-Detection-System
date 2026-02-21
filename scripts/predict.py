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

    logging.info("Loading dataset...")
    df = pd.read_csv(DATA)

    logging.info("Loading trained model...")
    clf = joblib.load(MODEL)

    # Remove ground truth if present
    X = df.drop(columns=["Attack Type"], errors="ignore")

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
