from django.apps import AppConfig
from django.contrib.auth.models import User

class NidsAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'nids_app'

    def ready(self):
        try:
            if not User.objects.filter(username="admin").exists():
                User.objects.create_superuser(
                    username="admin",
                    email="admin@example.com",
                    password="admin123"
                )
        except:
            pass