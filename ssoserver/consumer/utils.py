from random import SystemRandom
from django.conf import settings
import string
import importlib
from .conf import HOOK_SETTINGS
from .conf import config as global_config
random = SystemRandom()

KEY_CHARACTERS = string.ascii_letters + string.digits


def default_gen_secret_key(length=40):
    return ''.join([random.choice(KEY_CHARACTERS) for _ in range(length)])


def gen_secret_key(length=40):
    generator = getattr(settings, 'SSO_KEYGENERATOR', default_gen_secret_key)
    return generator(length)

def get_scheme(request, config=None):
    if config is None:
        config = global_config

    scheme = "https"
    if config.DEBUG and request is not None:
        if "HTTP_X_FORWARDED_PROTO" in request.META:
            scheme = request.META["HTTP_X_FORWARDED_PROTO"]
        else:
            scheme = request.scheme
    return scheme

def get_hook(name):
    if name in HOOK_SETTINGS:
        hook_setting = getattr(global_config, name)
        if hook_setting != "":
            module_path, function_name = hook_setting.rsplit(".", 1)
            module = importlib.import_module(module_path)
            function = getattr(module, function_name)

            return function
    return None