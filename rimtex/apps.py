from django.apps import AppConfig
from django.conf import settings
import threading

class RimtexConfig(AppConfig):
    name = 'rimtex'

    # def ready(self):
    #     from .mqtt import start_mqtt_loop
    #     threading.Thread(target=start_mqtt_loop, daemon=True).start()