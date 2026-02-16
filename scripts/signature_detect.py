"""
Hybrid Signature + ML Detection Engine

Reads : data/processed/processed_pred.csv
Writes: data/processed/hybrid_output.csv

Decision Logic (Professional IDS):
1) Signature hit → escalate to Malicious
2) Else ML probability >= threshold → Malicious
3) Else keep ML decision
4) Risk score computed for explainability
"""

from pathlib import Path
import logging
import re
from typing import List
import pandas as pd

# --------------------------------------------------
# Logging
# --------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# --------------------------------------------------
# Paths
# --------------------------------------------------
BASE = Path(__file__).resolve().parents[1]
DATA_DIR = BASE / "data"
PROCESSED_DIR = DATA_DIR / "processed"

PRED_PATH = PROCESSED_DIR / "processed_pred.csv"
OUT_PATH = PROCESSED_DIR / "hybrid_output.csv"
SIGNATURES_PATH = DATA_DIR / "signatures.txt"

# --------------------------------------------------
# Thresholds / Weights
# --------------------------------------------------
PROB_THRESHOLD = 0.60
ML_WEIGHT = 0.6
SIG_WEIGHT = 0.4

# --------------------------------------------------
# Severity Mapping (Signature Intelligence)
# --------------------------------------------------
SEVERITY_MAP = {
    "PortScan": 0.3,
    "FTP-BruteForce": 0.6,
    "BruteForce": 0.6,
    "DoS": 1.0,
    "DDoS": 1.0,
}

def severity_score(attack: str) -> float:
    return SEVERITY_MAP.get(str(attack), 0.2)

# --------------------------------------------------
# Signature Loader
# --------------------------------------------------
def load_signatures(sig_file: Path) -> List[str]:
    if not sig_file.exists():
        log.info("No signature file found. Signature-only detection disabled.")
        return []

    sigs = []
    with sig_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sigs.append(line)

    log.info("Loaded %d signatures", len(sigs))
    return sigs


def match_signatures(text: str, sigs: List[str]) -> List[str]:
    hits = []
    if not text:
        return hits

    for s in sigs:
        try:
            if re.search(s, text, flags=re.I):
                hits.append(s)
        except re.error:
            if s.lower() in text.lower():
                hits.append(s)

    return list(dict.fromkeys(hits))

# --------------------------------------------------
# Built-in Heuristic Rules
# --------------------------------------------------
def builtin_rules(row: pd.Series) -> List[str]:
    hits = []

    suspicious_ports = {23, 2323, 4444, 5555, 3389, 8080}
    try:
        if int(row.get("Destination Port", -1)) in suspicious_ports:
            hits.append("suspicious_port")
    except Exception:
        pass

    try:
        if float(row.get("Total Fwd Packets", 0)) > 10000:
            hits.append("high_fwd_packets")
    except Exception:
        pass

    return hits

# --------------------------------------------------
# Probability Column Detection
# --------------------------------------------------
def find_probability_column(df: pd.DataFrame) -> str | None:
    for col in df.columns:
        if "prob" in col.lower():
            return col
    return None

# --------------------------------------------------
# Hybrid Detection Engine
# --------------------------------------------------
def hybrid_detection(df: pd.DataFrame, sigs: List[str]) -> pd.DataFrame:
    df = df.copy()

    # ML probability
    prob_col = find_probability_column(df)
    if prob_col:
        df["ml_probability"] = pd.to_numeric(df[prob_col], errors="coerce")
        log.info("Using ML probability column: %s", prob_col)
    else:
        df["ml_probability"] = pd.NA
        log.info("No ML probability column found.")

    # ML label column
    label_col = next(
        (c for c in ["pred_label", "Predicted Attack Type", "ml_label", "Attack Type"] if c in df.columns),
        None,
    )

    if not label_col:
        raise RuntimeError("No ML label column found in prediction output.")

    signature_hits_all = []
    signature_flags = []
    signature_severity = []
    risk_scores = []
    final_decisions = []
    hybrid_reasons = []

    for _, row in df.iterrows():
        hits = []

        # Built-in rules
        hits.extend(builtin_rules(row))

        # Text signature matching
        text_blob = " ".join(str(v) for v in row.values if pd.notna(v))
        hits.extend(match_signatures(text_blob, sigs))

        hits = list(dict.fromkeys(hits))
        sig_flag = len(hits) > 0

        ml_prob = row.get("ml_probability")
        ml_label = str(row.get(label_col)).strip()

        sev = severity_score(ml_label)

        risk = (
            (ML_WEIGHT * ml_prob if pd.notna(ml_prob) else 0)
            + (SIG_WEIGHT * sev)
        )

        # IDS decision hierarchy
        if sig_flag:
            final = "Malicious"
            reason = "signature_match"
        elif pd.notna(ml_prob) and ml_prob >= PROB_THRESHOLD:
            final = "Malicious"
            reason = "ml_high_confidence"
        else:
            final = "Benign" if ml_label.lower() in ("benign", "normal", "0") else ml_label
            reason = "ml_decision"

        signature_hits_all.append(",".join(hits))
        signature_flags.append(sig_flag)
        signature_severity.append(sev)
        risk_scores.append(round(risk, 3))
        final_decisions.append(final)
        hybrid_reasons.append(reason)

    df["signature_hits"] = signature_hits_all
    df["signature_flag"] = signature_flags
    df["signature_severity"] = signature_severity
    df["final_risk_score"] = risk_scores
    df["hybrid_reason"] = hybrid_reasons
    df["Final Decision"] = final_decisions

    return df

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    if not PRED_PATH.exists():
        log.error("Prediction file missing. Run predict.py first.")
        return

    log.info("Loading prediction file: %s", PRED_PATH)
    df = pd.read_csv(PRED_PATH, low_memory=False)

    sigs = load_signatures(SIGNATURES_PATH)
    hybrid_df = hybrid_detection(df, sigs)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    hybrid_df.to_csv(OUT_PATH, index=False)

    log.info("Hybrid detection completed → %s", OUT_PATH)

if __name__ == "__main__":
    main()
