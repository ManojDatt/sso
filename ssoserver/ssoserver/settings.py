"""
Django settings for ssoserver project.

Generated by 'django-admin startproject' using Django 3.2.9.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""

from pathlib import Path
import json
from django.utils.translation import gettext_lazy as _
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-&u^f=$d(*vue20g#r3py9_ij^nm=&sw2_8o#l%es$u!n781_8h'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'consumer.apps.ContanceConfig',
    'constance.backends.database',
    'material',
    'material.admin',
    # 'django.contrib.admin',
    'consumer.apps.AuthConfig',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    
    'consumer.apps.ApplicationConfig'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ssoserver.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'ssoserver.wsgi.application'

AUTHENTICATION_BACKENDS = [
    'consumer.backends.MicrosoftAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend'
]

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

STATICFILES_DIRS = [
    BASE_DIR / "static",
]
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient"
        },
        "KEY_PREFIX": "sso"
    }
}

CONSTANCE_DATABASE_CACHE_BACKEND = 'default'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SITE_ID=1
# CONSTANCE_BACKEND = 'constance.backends.database.DatabaseBackend'
CONSTANCE_BACKEND = 'constance.backends.redisd.RedisBackend'
CONSTANCE_REDIS_CONNECTION = {
    'host': 'localhost',
    'port': 6379,
    'db': 0,
}
CONSTANCE_ADDITIONAL_FIELDS = {
}
CONSTANCE_CONFIG_FIELDSETS = {
    "fieldsets": (
            "MICROSOFT_AUTH_LOGIN_ENABLED",
            "MICROSOFT_AUTH_LOGIN_TYPE",
            "MICROSOFT_AUTH_TENANT_ID",
            "MICROSOFT_AUTH_CLIENT_ID",
            "MICROSOFT_AUTH_CLIENT_SECRET",
            "MICROSOFT_AUTH_EXTRA_SCOPES",
            "MICROSOFT_AUTH_AUTO_CREATE",
            "MICROSOFT_AUTH_REGISTER_INACTIVE_ADMIN",
            "MICROSOFT_AUTH_XBL_SYNC_USERNAME",
            "MICROSOFT_AUTH_AUTO_REPLACE_ACCOUNTS",
            "MICROSOFT_AUTH_AUTHENTICATE_HOOK",
            "MICROSOFT_AUTH_CALLBACK_HOOK",
        )
}
CONSTANCE_CONFIG = {
        "MICROSOFT_AUTH_LOGIN_ENABLED": (
            True,
            _("Whether or not Microsoft OAuth login is enabled."),
            bool,
        ),
        "MICROSOFT_AUTH_LOGIN_TYPE": (
            "ma",
            _(
                """Type of Microsoft login to use.
                Microsoft Accounts is normal Microsoft login.
                Xbox Live Accounts use the old Microsoft Account login screen
                and then also authenticate against Xbox Live to retrieve
                Gamertag."""
            ),
            str,
        ),
        "MICROSOFT_AUTH_TENANT_ID": (
            "65c927f3-ce9a-4b80-acad-531c881762cb",
            _("Microsoft Office 365 Tenant ID"),
            str,
        ),
        "MICROSOFT_AUTH_CLIENT_ID": (
            "90f430ea-6815-423a-9475-c52fc5d33d60",
            _(
                """Microsoft OAuth Client ID, see
                https://apps.dev.microsoft.com/ for more."""
            ),
            str,
        ),
        "MICROSOFT_AUTH_CLIENT_SECRET": (
            "SRL7Q~Rsfl6R33jiVjSMFpADI7l_BhDH9pIBA",
            _(
                """Microsoft OAuth Client Secret, see
                https://apps.dev.microsoft.com/ for more."""
            ),
            str,
        ),
        "MICROSOFT_AUTH_EXTRA_SCOPES": (
            "",
            _(
                """Extra OAuth scopes for authentication. Required
                scopes are always provided ('openid email'
                for Microsoft Auth and 'XboxLive.signin
                XboxLive.offline_access' for Xbox). Scopes are space
                delimited."""
            ),
            str,
        ),
        "MICROSOFT_AUTH_AUTO_CREATE": (
            True,
            _(
                """Autocreate user that attempt to login if they do not
                already exist?"""
            ),
            bool,
        ),
        "MICROSOFT_AUTH_REGISTER_INACTIVE_ADMIN": (
            False,
            _(
                """Automatically register admin class for auth type
                that is not active (Xbox when Microsoft Auth is
                enabled and Microsoft Auth when Xbox is enabled).
                Requires restart of app for setting to take effect."""
            ),
            bool,
        ),
        "MICROSOFT_AUTH_XBL_SYNC_USERNAME": (
            False,
            _(
                """Automatically sync the username from the Xbox Live
                Gamertag?"""
            ),
            bool,
        ),
        "MICROSOFT_AUTH_AUTO_REPLACE_ACCOUNTS": (
            False,
            _(
                """Automatically replace an existing Microsoft Account
                paired to a user when authenticating."""
            ),
            bool,
        ),
        "MICROSOFT_AUTH_AUTHENTICATE_HOOK": (
            "",
            _(
                """Callable hook to call after authenticating a user on the
                `microsoft_auth.backends.MicrosoftAuthenticationBackend`.
                If the login type is Microsoft Auth, the parameters will be
                `(User: user, oauthlib.oauth2.rfc6749.tokens.OAuth2Token:
                token)`"""
            ),
            str,
        ),
        "MICROSOFT_AUTH_CALLBACK_HOOK": (
            "",
            _(
                """Callable hook to call right before completing the `auth_callback` view.
                Really useful for adding custom data to message or chaning the
                expected base URL that gets passed back up to the window that
                initiated the original Authorize request.
                The parameters that will be passed will be `(HttpRequest:
                request, dict: context)`.
                The expected return value is the updated context dictionary.
                You should NOT remove the data that is currently there.
                `base_url` is the expected root URL of the window that
                initiated the authorize request
                `message` is a dictionary that will be serialized as a JSON
                string and passoed back to the initiating window.
                """
            ),
            str,
        )
}

from .admin_ui import *