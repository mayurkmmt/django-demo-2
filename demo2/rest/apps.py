from django.apps import AppConfig


class RestConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "demo2.rest"

    def ready(self):
        import demo2_common.signals
