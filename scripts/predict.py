# scripts/predict.py
import pandas as pd
from pathlib import Path
import joblib
import logging

logging.basicConfig(level=logging.INFO, format="[PREDICT] %(message)s")

BASE = Path(__file__).resolve().parents[1]
DATA = BASE / "data" / "processed" / "processed.csv"
MODEL = BASE / "data" / "models" / "rf_clf.joblib"
OUT = BASE / "data" / "processed" / "processed_pred.csv"

THRESHOLD = 0.6  # IDS decision threshold

def main():
    df = pd.read_csv(DATA)
    clf = joblib.load(MODEL)

    # Remove ground truth label before prediction
    X = df.drop(columns=["Attack Type"], errors="ignore")

    probs = clf.predict_proba(X)[:, 1]

    df["pred_proba"] = probs
    df["pred_label"] = df["pred_proba"].apply(
        lambda p: "Malicious" if p >= THRESHOLD else "Benign"
    )

    df.to_csv(OUT, index=False)
    logging.info(f"Prediction output written → {OUT}")

if __name__ == "__main__":
    main()
