from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # include the app urls (no namespace needed)
    path('', include('nids_app.urls')),
]
