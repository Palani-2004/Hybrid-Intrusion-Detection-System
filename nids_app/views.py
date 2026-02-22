import os
import subprocess
from pathlib import Path

import pandas as pd
from django.conf import settings
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

# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# from .models import Alert

# @csrf_exempt
# def receive_alert(request):
#     try:
#         if request.method != "POST":
#             return JsonResponse({"error": f"Method was {request.method}"}, status=400)

#         data = json.loads(request.body.decode("utf-8"))

#         ip = data.get("ip")
#         attack_type = data.get("attack_type")
#         severity = data.get("severity")

#         Alert.objects.create(
#             ip=ip,
#             attack_type=attack_type,
#             severity=severity
#         )

#         return JsonResponse({"status": "ok"})

        # return JsonResponse({
        #     "error": str(e),
        #     "trace": traceback.format_exc()
        # }, status=500)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def receive_alert(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body.decode("utf-8"))
            print("RECEIVED DATA:", data)
            return JsonResponse({"status": "ok"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)
    
def get_session_id(request):
    if not request.session.session_key:
        request.session.create()
    return request.session.session_key

# def run_script(request, script_path, success_state, success_msg, redirect_to):
#     try:
#         result = subprocess.run(
#             [os.sys.executable, str(script_path)],
#             capture_output=True,
#             text=True,
#             check=True,
#         )
#         set_state(request, success_state)
#         messages.success(request, success_msg)
#         return result.stdout, True
#     except subprocess.CalledProcessError as e:
#         messages.error(request, f"Execution failed:\n{e.stderr}")
#         return e.stderr, False 
    
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
        uploaded = request.FILES.get("file") or request.FILES.get("csv_file")
        if not uploaded:
            messages.error(request, "No file provided.")
            return redirect("upload_dataset")

        try:
            validate_csv(uploaded)
        except ValueError as e:
            messages.error(request, str(e))
            return redirect("upload_dataset")

        session_id = get_session_id(request)
        raw_dir = Path(settings.BASE_DIR) / "data" / "raw" / session_id
        raw_dir.mkdir(parents=True, exist_ok=True)

        with open(raw_dir / "input.csv", "wb") as f:
            for chunk in uploaded.chunks():
                f.write(chunk)

        set_state(request, "UPLOADED")
        messages.success(request, "File uploaded successfully.")
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


# -------------------------------------------------
# AUTOMATED PIPELINE
# -------------------------------------------------

# @require_POST
# def run_automated_pipeline(request):
#     try:
#         run_full_pipeline()
#         messages.success(request, "Pipeline executed successfully.")
#         return redirect("dashboard")
#     except Exception as e:
#         messages.error(request, f"Pipeline failed: {e}")
#         return redirect("upload_dataset")
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
# DASHBOARD
# -------------------------------------------------

def dashboard_view(request):
    return render(request, "nids_app/dashboard.html")

def dashboard_data_api(request):
    alerts = Alert.objects.order_by("-timestamp")[:50]

    data = []
    for alert in alerts:
        data.append({
            "ip": alert.ip,
            "attack_type": alert.attack_type,
            "severity": alert.severity,
            "timestamp": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })

    return JsonResponse({"alerts": data})

    # -------------------------------------------------
    # ✅ DEMO / FALLBACK MODE (CRITICAL FIX)
    # -------------------------------------------------
    if not file_path.exists():
        return JsonResponse(
            {
                "demo": True,
                "total": 5,
                "benign": 3,
                "malicious": 2,
                "attacks": [
                    {
                        "name": "Port-Scanning",
                        "count": 1,
                        "severity": "Medium",
                        "confidence": 72,
                        "details": ATTACK_KNOWLEDGE["Port-Scanning"],
                    },
                    {
                        "name": "SSH-BruteForce",
                        "count": 1,
                        "severity": "High",
                        "confidence": 89,
                        "details": ATTACK_KNOWLEDGE["SSH-BruteForce"],
                    },
                ],
            }
        )

    # -------------------------------------------------
    # REAL DATA PATH
    # -------------------------------------------------
    try:
        df = pd.read_csv(file_path)
    except Exception:
        return JsonResponse({"error": "Invalid CSV file"}, status=400)

    required_cols = {
        "pred_label",
        "Attack Type",
        "ml_probability",
        "signature_flag",
    }

    if not required_cols.issubset(df.columns):
        return JsonResponse({"error": "Missing required columns"}, status=400)

    total = len(df)
    malicious_df = df[df["pred_label"] == "Malicious"]
    benign = total - len(malicious_df)

    attacks = []
    for attack, group in malicious_df.groupby("Attack Type"):
        meta = ATTACK_KNOWLEDGE.get(
            attack,
            {
                "severity": "Medium",
                "description": "Attack detected by Hybrid IDS.",
                "evidence": [],
                "root_cause": "",
                "impact": [],
                "mitigation": [],
                "final_verdict": "Malicious",
            },
        )

        attacks.append(
            {
                "name": attack,
                "count": int(len(group)),
                "severity": meta["severity"],
                "confidence": round(group["ml_probability"].mean() * 100, 2),
                "details": meta,
            }
        )

    return JsonResponse(
        {
            "demo": False,
            "total": total,
            "benign": benign,
            "malicious": len(malicious_df),
            "attacks": attacks,
        }
    )
