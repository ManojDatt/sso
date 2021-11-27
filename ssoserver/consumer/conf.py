from importlib import import_module

from django.test.signals import setting_changed
from django.utils.functional import SimpleLazyObject
from django.utils.translation import gettext_lazy as _

constance_config = None
settings = None

LOGIN_TYPE_MA = "ma"
HOOK_SETTINGS = [
    "MICROSOFT_AUTH_AUTHENTICATE_HOOK",
    "MICROSOFT_AUTH_CALLBACK_HOOK",
]
CACHE_TIMEOUT = 86400
CACHE_KEY_OPENID = "microsoft_auth_openid_config"
CACHE_KEY_JWKS = "microsoft_auth_jwks"

DEFAULT_CONFIG = {}


class SimpleConfig:
    def __init__(self, config=None):
        self._defaults = {}

        if config:
            self.add_default_config(config)

    def add_default_config(self, config):
        tmp_dict = {}

        for key, value in config.items():
            tmp_dict[key] = value[0]

        self._defaults.update(tmp_dict)

    def __getattr__(self, attr):
        val = None

        # Django settings take priority
        try:
            # Check if present in user settings
            val = getattr(settings, attr)
        except AttributeError:
            pass

        # Check Constance first if it is installed

        if val is None and constance_config:
            try:
                val = getattr(constance_config, attr)
            except AttributeError:
                pass

        if val is None:
            # Fall back to defaults
            try:
                val = self._defaults[attr]
            except KeyError:
                raise AttributeError

        return val


def init_config():
    global config, constance_config, settings

    from django.conf import settings as django_settings

    settings = django_settings

    # set constance config global

    if "consumer.apps.ContanceConfig" in settings.INSTALLED_APPS:
        from constance import config as constance_config
    else:
        constance_config = None

    # retrieve and set config class

    if (
        hasattr(settings, "MICROSOFT_AUTH_CONFIG_CLASS")
        and settings.MICROSOFT_AUTH_CONFIG_CLASS is not None
    ):
        module, _, obj = settings.MICROSOFT_AUTH_CONFIG_CLASS.rpartition(".")
        conf = import_module(module)
        config = getattr(conf, obj)

        if hasattr(config, "add_default_config"):
            config.add_default_config(DEFAULT_CONFIG)
    else:
        config = SimpleConfig(DEFAULT_CONFIG)

    return config


""" Override MICROSOFT_AUTH_CONFIG_CLASS to inject your own custom dynamic
    settings class into microsoft_auth. Useful if you want to manage config
    using a dynamic settings manager such as django-constance
    Optionally the class can have an 'add_default_config' method to add the
    above DEFAULT_CONFIG to config manager
"""
config = SimpleLazyObject(init_config)


def reload_settings(*args, **kwargs):
    global config

    setting = kwargs.get("setting", kwargs.get("key"))

    # only reinitialize config if settings changed

    if setting.startswith("MICROSOFT_AUTH_"):
        init_config()


setting_changed.connect(reload_settings)