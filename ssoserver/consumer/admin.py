from django.contrib import admin
from .models import Consumer, Token, MicrosoftAccount, ServerSite
from django.contrib.sites.models import Site
admin.site.unregister(Site)

class AdminServerSite(admin.ModelAdmin):
    list_display = ('domain', 'name', )
    def has_add_permission(self, request) -> bool:
        return not ServerSite.objects.exists()
    
admin.site.register(ServerSite, AdminServerSite)

class AdminToken(admin.ModelAdmin):
    list_display = ('consumer', 'user',  'timestamp',)
    search_fields = ('consumer__name', 'user__email', 'request_token', 'access_token',)
    list_filter = ('timestamp',)
    def has_add_permission(self, request) -> bool:
        return False
    
    
class AdminMicrosoftAccount(admin.ModelAdmin):
    list_display = ('microsoft_id', 'user', 'timestamp',)
    search_fields = ('microsoft_id', 'user__email',)
    list_filter = ('timestamp',)
    def has_add_permission(self, request) -> bool:
        return False

admin.site.register(Token, AdminToken)
admin.site.register(MicrosoftAccount, AdminMicrosoftAccount)
# Register your models here.
