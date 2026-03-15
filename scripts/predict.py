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

    logging.info("Loading training feature schema...")
    model_features = joblib.load(FEATURES)

    logging.info("Aligning features...")

    # -------------------------------------------------
    # Robust Column Mapping (Schema Normalization)
    # -------------------------------------------------
    COLUMN_MAPPING = {
        "BwdPktLenMean": "BwdPacketLengthMean",
        "FwdPktLenMean": "FwdPacketLengthMean",
        "FlowBytsPerSec": "FlowBytes/s",
        "FlowPktsPerSec": "FlowPackets/s",
        "TotFwdPkts": "Total Fwd Packets",
        "TotBwdPkts": "Total Backward Packets",
    }

    df.rename(columns=COLUMN_MAPPING, inplace=True)

    # -------------------------------------------------
    # Add Missing Features
    # -------------------------------------------------
    missing = set(model_features) - set(df.columns)
    for col in missing:
        df[col] = 0

    if missing:
        logging.warning(f"Missing columns added with 0: {missing}")

    # -------------------------------------------------
    # Drop Extra Columns + Preserve Order
    # -------------------------------------------------
    X = df[model_features]

    # -------------------------------------------------
    # Safe Probability Extraction
    # -------------------------------------------------
    if len(clf.classes_) == 2:
        # Assume binary classification
        positive_class = clf.classes_[1]
        class_index = list(clf.classes_).index(positive_class)
        probs = clf.predict_proba(X)[:, class_index]
    else:
        raise ValueError("Model is not binary classification.")

    df["ml_probability"] = probs
    df["pred_label"] = df["ml_probability"].apply(
    lambda p: "Malicious" if p >= THRESHOLD else "Benign"
    )

    df.to_csv(OUT, index=False)

    logging.info(f"Prediction output written → {OUT}")


if __name__ == "__main__":
    main()