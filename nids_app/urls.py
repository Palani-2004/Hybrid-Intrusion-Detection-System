from django.urls import path
from . import views

urlpatterns = [

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
    # DASHBOARD DATA API
    # -------------------------------------------------
    path(
        "api/dashboard-data/",
        views.dashboard_data_api,
        name="dashboard_data_api",
    ),
]
