from django.contrib import admin
from .models import GuardStrategy


class GuardStrategyAdmin(admin.ModelAdmin):
    pass

admin.site.register(GuardStrategy, GuardStrategyAdmin)
