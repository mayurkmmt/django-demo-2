"""project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from caesar-subscription import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, re_path
from rest_framework.routers import DefaultRouter
from rest_framework.urlpatterns import format_suffix_patterns

from .rules import RuleRestView
from .views import (
    ConfigureSubscriptionRestView,
    DomainCheckView,
    DomainPauseRestoreView,
    DomainRestView,
    DomainSslConfigRestView,
    DomainTrafficView,
    DomainWidgetView,
    FCMRegisterView,
    RunTasksView,
    SslConfigRestView,
    TrafficStatisticsView,
    UserDomainView,
    notifyView,
)

domainRouter = DefaultRouter()

domain_list = DomainRestView.as_view({"get": "list", "post": "create"})
domain_update = DomainRestView.as_view({"patch": "update", "delete": "destroy"})
domain_stat = DomainWidgetView.as_view({"get": "domain_stat"})
today_stat = DomainTrafficView.as_view({"get": "today_stat"})
monthly_stat = DomainTrafficView.as_view({"get": "monthly_stat"})
total_stat = DomainTrafficView.as_view({"get": "total_stat"})
traffic_stats = TrafficStatisticsView.as_view({"get": "get_overview_data"})
access_logs = TrafficStatisticsView.as_view({"post": "access_logs"})
download_access_logs = TrafficStatisticsView.as_view({"post": "download_access_logs"})
domain_check = DomainCheckView.as_view(
    {
        "post": "check",
    }
)
ssl_config = DomainSslConfigRestView.as_view(
    {"get": "get", "patch": "patch", "post": "post"}
)
ssl_config_update = DomainSslConfigRestView.as_view(
    {"delete": "destroy", "patch": "generate_sshkey"}
)
configure_subscription = ConfigureSubscriptionRestView.as_view(
    {
        "get": "get",
        "post": "post",
    }
)
run_tasks = RunTasksView.as_view({"get": "get", "post": "post"})
user_domain_list = UserDomainView.as_view(
    {
        "get": "list",
    }
)
domain_pause_restore = DomainPauseRestoreView.as_view(
    {
        "post": "post",
    }
)
ssl_rest = SslConfigRestView.as_view({"get": "get"})
ssl_zip = SslConfigRestView.as_view({"post": "zip"})
rule_list = RuleRestView.as_view(
    {
        "get": "list",
        "post": "create",
    }
)
rule_assign = RuleRestView.as_view({"post": "assign"})
rule_detail = RuleRestView.as_view(
    {"get": "get", "patch": "update", "delete": "destroy"}
)
fcm_register_device = FCMRegisterView.as_view(
    {
        "post": "post",
    }
)
notify = notifyView.as_view({"get": "get", "post": "post"})

urlpatterns = format_suffix_patterns(
    [
        path(
            "routes/<route_id>/ssl-config/<certificate_id>/",
            ssl_config_update,
            name="domain-ssl-config-update",
        ),
        path("routes/<route_id>/ssl-config/", ssl_config, name="domain-ssl-config"),
        path("routes/<route_id>/", domain_update, name="domain-update"),
        path("routes/", domain_list, name="domain-list"),
        path(
            "configure/subscription/",
            configure_subscription,
            name="configure-subscription",
        ),
        path("run/tasks/", run_tasks, name="run-tasks"),
        path("traffic/today_stat/", today_stat, name="today-stat"),
        path("traffic/monthly_stat/", monthly_stat, name="monthly-stat"),
        path("traffic/total_stat/", total_stat, name="total-stat"),
        path("traffic_stats/get_overview_data/", traffic_stats, name="traffic-stats"),
        path("traffic_stats/access_logs/", access_logs, name="access-logs"),
        path(
            "traffic_stats/download_access_logs/",
            download_access_logs,
            name="download-access-logs",
        ),
        path("widget/domain_stat/", domain_stat, name="domain-stat"),
        path("user/domains/", user_domain_list, name="user-domain-list"),
        path("pause_restore/", domain_pause_restore, name="user-pause-restore"),
        path("checker/", domain_check, name="domain-checker"),
        path("ssl/", ssl_rest, name="ssl-rest"),
        path("ssl/<id>/zip/", ssl_zip, name="ssl-zip"),
        path("rules/", rule_list, name="rule-list"),
        path("rules/<id>/", rule_detail, name="rule-detail"),
        path("rules/<id>/assign/", rule_assign, name="rule-assign"),
        path("fcm-register/", fcm_register_device, name="fcm-register"),
        path("notify/", notify, name="notify"),
    ]
)
