import os
import subprocess
from pathlib import Path

import pandas as pd
from django.conf import settings
BASE_DATA_DIR = Path(settings.BASE_DIR) / "data" / "raw"
from django.contrib import messages
from django.http import FileResponse, Http404, JsonResponse
from django.shortcuts import redirect, render
from .models import Alert
from django.views.decorators.http import require_POST

from .attack_knowledge import ATTACK_KNOWLEDGE
from nids_app.pipeline.automated import run_full_pipeline
from nids_app.state.pipeline_state import set_state, can_access

import json
import traceback


from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from .models import Alert

def get_session_id(request):
    """
    Ensures every user has a unique pipeline session folder.
    """
    session_id = request.session.get("pipeline_session")

    if not session_id:
        import uuid
        session_id = str(uuid.uuid4())
        request.session["pipeline_session"] = session_id

    return session_id 

@csrf_exempt
def receive_alert(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)

            ip = data.get("ip")
            attack_type = data.get("attack_type")   # ✅ use real attack type
            severity = data.get("severity")

            Alert.objects.create(
                ip=ip,
                attack_type=attack_type,
                severity=severity
            )

            return JsonResponse({"status": "success"})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

    return JsonResponse({"error": "Invalid method"}, status=405)
   
def run_script(request, script_path, success_state, success_msg, redirect_to):
    try:
        session_id = get_session_id(request)

        result = subprocess.run(
            [os.sys.executable, str(script_path), session_id],
            capture_output=True,
            text=True,
            check=True,
        )

        set_state(request, success_state)
        messages.success(request, success_msg)
        return result.stdout, True

    except subprocess.CalledProcessError as e:
        messages.error(request, f"Execution failed:\n{e.stderr}")
        return e.stderr, False
    
def validate_csv(uploaded_file):
    if not uploaded_file.name.endswith(".csv"):
        raise ValueError("Only CSV files are allowed.")
    if uploaded_file.size > 50 * 1024 * 1024:
        raise ValueError("File size exceeds 50MB limit.")


# -------------------------------------------------
# BASIC VIEWS
# -------------------------------------------------

def index(request):
    return render(request, "nids_app/index.html")


def upload_csv(request):

    if request.method == "POST":

        file = request.FILES.get("file")

        if file:

            session_id = get_session_id(request)

            save_path = BASE_DATA_DIR / session_id
            save_path.mkdir(parents=True, exist_ok=True)

            file_path = save_path / file.name

            with open(file_path, "wb+") as destination:
                for chunk in file.chunks():
                    destination.write(chunk)

            # 🔴 THIS LINE IS MISSING IN YOUR PROJECT
            request.session["pipeline_state"] = "UPLOADED"

            messages.success(request, "Dataset uploaded successfully.")

            return redirect("upload_dataset")

    return render(request, "nids_app/upload.html")


def preprocess_page(request):
    if request.method == "POST":
        script = Path(settings.BASE_DIR) / "scripts" / "preprocess.py"
        run_script(
            request,
            script,
            "PREPROCESSED",
            "Preprocessing completed.",
            "train",
        )
        return redirect("train")

    return render(request, "nids_app/preprocess.html")


# -------------------------------------------------
# MANUAL PIPELINE
# -------------------------------------------------

def train_view(request):
    if not can_access(request, "PREPROCESSED"):
        messages.error(request, "Run preprocessing first.")
        return redirect("preprocess")

    output = ""
    success = False

    if request.method == "POST":
        script = Path(settings.BASE_DIR) / "scripts" / "train_model.py"
        output, success = run_script(
            request,
            script,
            "TRAINED",
            "Model training completed.",
            "train",
        )

    return render(
        request,
        "nids_app/train.html",
        {"output": output, "success": success},
    )


def predict_view(request):
    if not can_access(request, "TRAINED"):
        messages.error(request, "Train the model first.")
        return redirect("train")

    output = ""
    predicted = False

    if request.method == "POST":
        script = Path(settings.BASE_DIR) / "scripts" / "predict.py"
        output, predicted = run_script(
            request,
            script,
            "PREDICTED",
            "Prediction completed.",
            "predict",
        )

    return render(
        request,
        "nids_app/predict.html",
        {"output": output, "predicted": predicted},
    )


def signature_view(request):
    if not can_access(request, "PREDICTED"):
        messages.error(request, "Run prediction first.")
        return redirect("predict")

    output = ""
    success = False

    if request.method == "POST":
        script = Path(settings.BASE_DIR) / "scripts" / "signature_detect.py"
        output, success = run_script(
            request,
            script,
            "HYBRID_DONE",
            "Hybrid detection completed.",
            "hybrid",
        )

    return render(
        request,
        "nids_app/hybrid.html",
        {"output": output, "success": success},
    )


def download_hybrid_view(request):
    session_id = get_session_id(request)
    file_path = (
        Path(settings.BASE_DIR)
        / "data"
        / "processed"
        / session_id
        / "hybrid_output.csv"
    )

    if not file_path.exists():
        raise Http404("Hybrid output not found.")

    return FileResponse(open(file_path, "rb"), as_attachment=True)


@require_POST
def run_automated_pipeline(request):
    try:
        session_id = get_session_id(request)

        run_full_pipeline(session_id)

        messages.success(request, "Pipeline executed successfully.")
        return redirect("dashboard")

    except Exception as e:
        messages.error(request, f"Pipeline failed: {e}")
        return redirect("upload_dataset")


# -------------------------------------------------
# DASHBOARD PAGE VIEW
# -------------------------------------------------
def dashboard_view(request):
        return render(request, "nids_app/dashboard.html")


from django.http import JsonResponse
from pathlib import Path
from django.conf import settings
import pandas as pd
from .models import Alert
from .attack_knowledge import ATTACK_KNOWLEDGE

def dashboard_batch_api(request):

    session_id = get_session_id(request)

    file_path = (
        Path(settings.BASE_DIR)
        / "data"
        / "processed"
        / session_id
        / "hybrid_output.csv"
    )

    benign = 0
    malicious = 0
    attacks = []

    if file_path.exists():

        df = pd.read_csv(file_path)

        if "Final Decision" in df.columns:

            benign = int((df["Final Decision"] == "Benign").sum())
            malicious = int((df["Final Decision"] == "Malicious").sum())

            malicious_df = df[df["Final Decision"] == "Malicious"]

            if "Attack Type" in df.columns:

                grouped = malicious_df.groupby("Attack Type")

                for attack, group in grouped:

                    meta = ATTACK_KNOWLEDGE.get(attack, {})

                    attacks.append({
                        "name": attack,
                        "count": int(len(group)),
                        "severity": meta.get("severity", "Medium"),
                        "confidence": round(
                            group.get("ml_probability", pd.Series([0])).mean() * 100,
                            2
                        ),
                        "details": meta
                    })

    return JsonResponse({
        "benign": benign,
        "malicious": malicious,
        "attacks": attacks
    })

def dashboard_live_api(request):

    alerts = Alert.objects.order_by("-timestamp")

    attack_counts = {}

    for alert in alerts:
        attack_counts[alert.attack_type] = (
            attack_counts.get(alert.attack_type, 0) + 1
        )

    attacks = []

    for name, count in attack_counts.items():

        meta = ATTACK_KNOWLEDGE.get(name, {})

        attacks.append({
            "name": name,
            "count": count,
            "severity": meta.get("severity", "High"),
            "confidence": 90,
            "details": meta
        })

    return JsonResponse({
        "benign": 0,
        "malicious": sum(attack_counts.values()),
        "attacks": attacks,
        "alerts": [
            {
                "ip": a.ip,
                "attack_type": a.attack_type,
                "severity": a.severity,
                "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for a in alerts[:50]
        ]
    })