from django.contrib import admin

from demo2.rest.models import DomainRule


# Register your models here.
class DomainRuleAdmin(admin.ModelAdmin):
    list_display = ["name", "owner", "created_at"]
    ordering = ["name", "owner", "created_at"]
    list_filter = ("name", "owner")
    search_fields = ["owner", "owner"]


admin.site.register(DomainRule, DomainRuleAdmin)
