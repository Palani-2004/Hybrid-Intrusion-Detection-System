from django.urls import path
from . import views
from .views import receive_alert

urlpatterns = [
    # -------------------------------------------------
    # LIVE ALERT RECEIVER (from IDS sensors)
    # -------------------------------------------------
    path("api/alert/", receive_alert, name="receive_alert"),

    # -------------------------------------------------
    # CORE PAGES
    # -------------------------------------------------
    path("", views.index, name="index"),
    path("dashboard/", views.dashboard_view, name="dashboard"),

    # -------------------------------------------------
    # DATASET & MANUAL PIPELINE
    # -------------------------------------------------
    path("upload/", views.upload_csv, name="upload_dataset"),
    path("preprocess/", views.preprocess_page, name="preprocess"),
    path("train/", views.train_view, name="train"),
    path("predict/", views.predict_view, name="predict"),
    path("hybrid/", views.signature_view, name="hybrid"),

    # -------------------------------------------------
    # AUTOMATED FULL PIPELINE
    # -------------------------------------------------
    path(
        "run-full-pipeline/",
        views.run_automated_pipeline,
        name="run_full_pipeline",
    ),

    # -------------------------------------------------
    # DOWNLOADS
    # -------------------------------------------------
    path(
        "hybrid/download/",
        views.download_hybrid_view,
        name="download_hybrid",
    ),

    # -------------------------------------------------
    # DASHBOARD DATA APIs
    # -------------------------------------------------
    path(
        "api/dashboard-batch/",
        views.dashboard_batch_api,
        name="dashboard_batch_api",
    ),

    path(
        "api/dashboard-live/",
        views.dashboard_live_api,
        name="dashboard_live_api",
    ),
]