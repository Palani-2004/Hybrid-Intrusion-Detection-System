from django.contrib import admin
from .models import Prediction

@admin.register(Prediction)
class PredictionAdmin(admin.ModelAdmin):
    list_display = ('id', 'input_file', 'result_file', 'accuracy', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('input_file', 'result_file')
    readonly_fields = ('created_at',)

# If you prefer the simpler registration:
# admin.site.register(Prediction)
