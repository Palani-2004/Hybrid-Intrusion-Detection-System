# scripts/preprocess.py

import sys
import pandas as pd
from pathlib import Path

# -----------------------------
# Get session ID
# -----------------------------
if len(sys.argv) < 2:
    raise Exception("Session ID not provided")

session_id = sys.argv[1]

# -----------------------------
# Resolve project paths
# -----------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

raw_dir = BASE_DIR / "data" / "raw" / session_id
processed_dir = BASE_DIR / "data" / "processed" / session_id
processed_dir.mkdir(parents=True, exist_ok=True)

raw_path = raw_dir / "input.csv"
proc_path = processed_dir / "preprocessed.csv"

# -----------------------------
# Main Logic
# -----------------------------
def main():
    # Fail fast if input missing
    if not raw_path.exists():
        print(f"ERROR: {raw_path} not found. Upload dataset first.")
        sys.exit(1)

    try:
        print("Loading raw dataset...")
        df = pd.read_csv(raw_path)
        print(f"Loaded dataset with shape: {df.shape}")

        # Minimal preprocessing logic
        if "Label" in df.columns:
            df["Attack Type"] = df["Label"]
            df = df.drop(columns=["Label"])
            print("Normalized Label to Attack Type")

        # Save processed file
        df.to_csv(proc_path, index=False)
        print("Preprocessing complete.")

    except Exception as e:
        print("ERROR during preprocessing:")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
