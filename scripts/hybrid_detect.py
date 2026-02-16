# scripts/hybrid_detect.py
import pandas as pd
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="[HYBRID] %(message)s")

BASE = Path(__file__).resolve().parents[1]
INP = BASE / "data" / "processed" / "processed_pred.csv"
OUT = BASE / "data" / "processed" / "hybrid_output.csv"

def main():
    df = pd.read_csv(INP)

    rows = []

    for _, r in df.iterrows():

        if r["pred_label"] == "Malicious":
            attack = r.get("Attack Type", "Unknown")
            label = "Malicious"
        else:
            attack = "Benign"
            label = "Benign"

        rows.append({
            "Attack Type": attack,
            "pred_label": label,
            "pred_proba": round(float(r["pred_proba"]), 3)
        })

    out_df = pd.DataFrame(rows)
    out_df.to_csv(OUT, index=False)

    logging.info(f"Hybrid normalized output written → {OUT}")

if __name__ == "__main__":
    main()
