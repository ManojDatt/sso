"""ssoserver URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from consumer.views import Server, AuthenticateCallbackView, AuthenticateCallbackRedirect
from django.conf import settings

test_server = Server()

urlpatterns = [
    path('admin/', admin.site.urls),
    path('server/', include(test_server.get_urls())),
    path("getAToken", AuthenticateCallbackRedirect.as_view(),name="auth-callback",),
    path("from-auth-redirect", AuthenticateCallbackView.as_view(),name="from-auth-redirect",),
]
