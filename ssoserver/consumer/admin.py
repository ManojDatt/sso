from django.contrib import admin
from .models import Consumer, Token, MicrosoftAccount
admin.site.register(Token)
admin.site.register(MicrosoftAccount)
# Register your models here.
