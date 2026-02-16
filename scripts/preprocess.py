# scripts/preprocess.py
import sys
import pandas as pd
from pathlib import Path

# Resolve project root (parent of /scripts/)
BASE = Path(__file__).resolve().parents[1]

# Input and output paths
raw_path = BASE / "data" / "raw" / "input.csv"
proc_path = BASE / "data" / "processed" / "processed.csv"


def main():
    # Fail fast if input is missing
    if not raw_path.exists():
        print("ERROR: data/raw/input.csv not found. Upload dataset first.")
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

        # Ensure output directory exists
        proc_path.parent.mkdir(parents=True, exist_ok=True)

        # Write processed dataset
        df.to_csv(proc_path, index=False)
        print("Preprocessing complete. processed.csv written.")

    except Exception as e:
        print("ERROR during preprocessing:")
        print(e)
        sys.exit(1)


if __name__ == "__main__":
    main()
