from django.apps import AppConfig
class ApplicationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'consumer'
    verbose_name = "Application"
    verbose_name_plural = 'Applications'


from constance.apps import ConstanceConfig
class ContanceConfig(ConstanceConfig):
    verbose_name = "Configurations"
    
from django.contrib.auth.apps import AuthConfig
class AuthConfig(AuthConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    verbose_name = "Authorization"