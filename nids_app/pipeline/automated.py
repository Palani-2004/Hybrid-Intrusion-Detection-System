import os
import subprocess
from pathlib import Path
from django.conf import settings


def run_full_pipeline(log_callback=None):
    """
    Runs the complete Hybrid IDS pipeline in order.
    SINGLE source of truth for automated execution.
    """

    BASE = Path(settings.BASE_DIR)
    PY = os.sys.executable

    def run(script, name):
        if log_callback:
            log_callback(f"\n▶ Running {name}...\n")

        result = subprocess.run(
            [PY, script],
            capture_output=True,
            text=True
        )

        if log_callback:
            if result.stdout:
                log_callback(result.stdout)
            if result.stderr:
                log_callback(result.stderr)

        if result.returncode != 0:
            raise RuntimeError(
                f"{name} failed with exit code {result.returncode}"
            )

    # ---------- SCRIPT PATHS ----------
    preprocess = BASE / "scripts" / "preprocess.py"
    train = BASE / "scripts" / "train_model.py"
    predict = BASE / "scripts" / "predict.py"
    hybrid = BASE / "scripts" / "signature_detect.py"

    model = BASE / "data" / "models" / "rf_clf.joblib"

    # ---------- PIPELINE ----------
    run(preprocess, "Preprocessing")

    if not model.exists():
        run(train, "Training Model")

    run(predict, "Prediction")
    run(hybrid, "Hybrid Detection")
