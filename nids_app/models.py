
from django.db import models

class Prediction(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    input_file = models.CharField(max_length=255, blank=True)
    result_file = models.CharField(max_length=255, blank=True)
    accuracy = models.FloatField(null=True, blank=True)

    def __str__(self):
        return f"Prediction {self.id} - {self.created_at}"
class Alert(models.Model):
    ip = models.CharField(max_length=50)
    attack_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip} - {self.attack_type}"