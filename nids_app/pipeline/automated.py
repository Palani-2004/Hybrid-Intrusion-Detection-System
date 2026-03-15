from cmath import log
import os
import sys
import subprocess
from pathlib import Path
from django.conf import settings
from pkg_resources import run_script

# from nids_project.scripts.hybrid_detect import BASE


def run_full_pipeline(session_id, log_callback=None):
    """
    Lightweight automated pipeline for production deployment.
    Uses pretrained model instead of retraining.
    """

    BASE = Path(settings.BASE_DIR)

    SCRIPTS_DIR = BASE / "scripts"

    PREPROCESS_SCRIPT = SCRIPTS_DIR / "preprocess.py"
    TRAIN_SCRIPT = SCRIPTS_DIR / "train_model.py"
    PREDICT_SCRIPT = SCRIPTS_DIR / "predict.py"
    HYBRID_SCRIPT = SCRIPTS_DIR / "signature_detect.py"

    def log(msg):
        if log_callback:
            log_callback(msg + "\n")

    def run_script(script_path, step_name):
        if not script_path.exists():
            raise FileNotFoundError(f"{step_name} script not found: {script_path}")

        process = subprocess.Popen(
            [sys.executable, str(script_path), session_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in process.stdout:
            log(line.strip())

        process.wait()

        if process.returncode != 0:
            raise RuntimeError(f"{step_name} failed with exit code {process.returncode}")
        
    import shutil

    processed_path = BASE / "data" / "processed" / session_id
    processed_path.mkdir(parents=True, exist_ok=True)
    # -------------------------------------------------
    # 1️⃣ Preprocessing
    # -------------------------------------------------
    log("▶ Running Preprocessing...")
    run_script(PREPROCESS_SCRIPT, "Preprocessing")
    log("Preprocessing completed successfully.")

    # -------------------------------------------------
    # 2️⃣ Model Training
    # -------------------------------------------------
    log("▶ Running Model Training...")
    run_script(TRAIN_SCRIPT, "Model Training")
    log("Model training completed successfully.")
    # -------------------------------------------------
    # 3️⃣ Prediction
    # -------------------------------------------------
    log("▶ Running Prediction...")
    run_script(PREDICT_SCRIPT, "Prediction")
    log("Prediction completed successfully.")

    # -------------------------------------------------
    # 4️⃣ Hybrid Detection
    # -------------------------------------------------
    log("▶ Running Hybrid Detection...")
    run_script(HYBRID_SCRIPT, "Hybrid Detection")
    log("Hybrid detection completed successfully.")

    return "Automated pipeline executed successfully"