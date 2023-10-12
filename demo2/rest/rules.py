import logging

from django.core.exceptions import ValidationError
from rest_framework import serializers, status
from rest_framework.generics import get_object_or_404
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from demo2.error_codes import PAYLOAD_INVALID, SUBSCRIPTION_NOT_FOUND
from demo2.rest.models import DomainRule
from demo2.rest.serializers import (
    RECOGNIZED_PLUGINS,
    DomainRuleAssignSerializer,
    DomainRuleSerializer,
    demo2_REDIRECT_PLUGIN_NAME,
)
from demo2.rest.views import full_cname, get_subscription
from kong.gateway import KongServicesAdmin, KongUpstreamsAdmin
from kong.models import KongDataRoute, KongDataService
from strategy.models import Tags

logger = logging.getLogger(__name__)


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 2
    page_size_query_param = "perpage"
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response(
            {
                "page": self.page.number,
                "total_pages": self.page.paginator.num_pages,
                "rules": data,
                "count": self.page.paginator.count,
            }
        )


class RuleRestView(ModelViewSet):
    permission_classes = [IsAuthenticated]
    lookup_field = "name"
    lookup_value_regex = "[0-9a-z\.\-]+"
    serializer_class = DomainRuleSerializer
    model = DomainRule
    search_fields = ["name"]
    filterset_fields = ["name"]
    pagination_class = StandardResultsSetPagination

    def get_queryset(self, with_order=True):
        subscription = get_subscription(self.request.user.username)
        owner = subscription.get("cname")
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        queryset = DomainRule.objects.filter(owner=owner)
        q = self.request.query_params.get("q")
        if q:
            queryset = queryset.filter(name__contains=q)
        return queryset

    def get_object(self) -> DomainRule:
        queryset = self.filter_queryset(self.get_queryset())
        filter_kwargs = {"id": self.kwargs["id"]}
        obj = get_object_or_404(queryset, **filter_kwargs)
        return obj

    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    def get(self, request, id):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        subscription = get_subscription(self.request.user.username)
        owner = subscription.get("cname")
        data = request.data.get("domain")
        data["configs"] = {
            "plugins": data.get("plugins", {}),
            "protocols": data.get("protocols", {}),
            "upstream": data.get("upstream", {}),
        }
        data["owner"] = owner
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        subscription = get_subscription(self.request.user.username)
        owner = subscription.get("cname")
        data = request.data.get("domain")
        data["configs"] = {
            "plugins": data.get("plugins", {}),
            "protocols": data.get("protocols", {}),
            "upstream": data.get("upstream", {}),
        }
        data["owner"] = owner
        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def perform_update(self, serializer):
        try:
            serializer.instance.full_clean()
        except ValidationError as e:
            raise serializers.ValidationError(e.message)

        serializer.save()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

    def assign(self, request, *args, **kwargs):
        subscription = get_subscription(self.request.user.username)
        owner = subscription.get("cname")
        cname = full_cname(subscription)
        if not subscription:
            return Response(
                {"error_code": SUBSCRIPTION_NOT_FOUND},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        logger.info(f"===>>> request.data: {request.data}")
        domain_rule = DomainRule.objects.filter(pk=kwargs.get("id")).first()
        route_id = request.data.get("route_id", "")
        action = request.data.get("action", "")
        if domain_rule:
            logger.info(f"===>>> domain_rule: {domain_rule}")
            configs = domain_rule.configs
            logger.info(f"===>>> domain_rule configs: {domain_rule.configs}")
            if configs:
                ks = KongServicesAdmin(owner, cname=cname)
                tags = Tags.to_list({"cname": cname, "owner": owner})
                ku = KongUpstreamsAdmin(owner, cname=cname)
                if route_id:
                    logger.info(f"===>>> route_id: {route_id}, action: {action}")
                    route = KongDataRoute.objects.filter(id=route_id).first()
                    if route and route.service_id:
                        service_id = str(route.service_id)
                        if (
                            action == "replace"
                        ):  # Replace means overwrite all the settings from predefined rules
                            try:
                                if "plugins" in configs:
                                    self.update_plugins(
                                        configs["plugins"], service_id, ks
                                    )
                            except Exception as e:
                                logger.info(
                                    f"===>>> replace update_plugins Error: {str(e)}"
                                )

                            try:
                                if "upstream" in configs:
                                    self.replace_upstream(
                                        configs["upstream"], service_id, route, ku, tags
                                    )
                            except Exception as e:
                                logger.info(f"===>>> replace_upstream Error: {str(e)}")

                        elif (
                            action == "combine"
                        ):  # Combine means only merge the settings where domain settings is not defined
                            service_update = {"name": "%s.%s" % (service_id[:8], cname)}
                            try:
                                if "plugins" in configs:
                                    plugin_name_to_id = {
                                        p["name"]: p["id"]
                                        for p in ks.get_plugins(service_id)
                                    }
                                    for plugin_data in configs["plugins"]:
                                        plugin = ks.update_or_create_plugin(
                                            service_id,
                                            plugin_data,
                                            plugin_name_to_id.get(plugin_data["name"]),
                                        )
                                        if plugin["name"] == demo2_REDIRECT_PLUGIN_NAME:
                                            service_update.update(
                                                {
                                                    "host": f"demo2-redirect.{plugin['id']}"
                                                }
                                            )
                                    ks.update(service_id, service_update)
                            except Exception as e:
                                logger.info(
                                    f"===>>> combine update_plugins Error: {str(e)}"
                                )

                            try:
                                if "upstream" in configs:
                                    self.combine_upstream(
                                        configs["upstream"], service_id, route, ku, tags
                                    )
                            except Exception as e:
                                logger.info(f"===>>> combine_upstream Error: {str(e)}")
                        else:
                            return Response(
                                {
                                    "field_errors": "service not found",
                                    "error_code": PAYLOAD_INVALID,
                                },
                                status=status.HTTP_400_BAD_REQUEST,
                            )
                    else:
                        return Response(
                            {
                                "field_errors": "provided action is not valid",
                                "error_code": PAYLOAD_INVALID,
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                        )
                else:
                    return Response(
                        {
                            "field_errors": "route_id is required",
                            "error_code": PAYLOAD_INVALID,
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return Response(
                    {
                        "field_errors": "domain rule configs not found",
                        "error_code": PAYLOAD_INVALID,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {
                    "field_errors": "domain rule not found",
                    "error_code": PAYLOAD_INVALID,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response({"success": True}, status.HTTP_200_OK)

    def replace_upstream(self, upstreams, service_id, route, kong_upstream_admin, tags):
        logger.info(
            f"===>>> replace_upstream service_id: {str(service_id)}, upstreams: {upstreams}"
        )
        # service = KongDataService.objects.filter(id=service_id).first()
        if "targets" in upstreams:
            domain_name = route.hosts[0].replace(".", "-")
            logger.info(f"===>>> replace_upstream domain_name: {str(domain_name)}")
            upstream = kong_upstream_admin.get_by_name(domain_name)
            logger.info(f"===>>> replace_upstream upstream: {str(domain_name)}")
            upstream_targets = {
                t.get("target"): t
                for t in kong_upstream_admin.get_targets(upstream.get("id"))
            }
            logger.info(
                f"===>>> replace_upstream upstream_targets: {str(upstream_targets)}"
            )
            for _, target in upstream_targets.items():
                kong_upstream_admin.delete_target(upstream.get("id"), target.get("id"))

            for t in upstreams["targets"]:
                kong_upstream_admin.add_target(upstream.get("id"), t["target"])

            logger.info(f"===>>> replace_upstream update: {str(domain_name)}")
            kong_upstream_admin.update(service_id, {"host": domain_name})

    def combine_upstream(self, upstreams, service_id, route, kong_upstream_admin, tags):
        logger.info(
            f"===>>> combine_upstream service_id: {str(service_id)}, upstreams: {upstreams}"
        )
        # service = KongDataService.objects.filter(id=service_id).first()
        if "targets" in upstreams:
            domain_name = route.hosts[0].replace(".", "-")
            upstream = kong_upstream_admin.get_by_name(domain_name)
            for t in upstreams["targets"]:
                kong_upstream_admin.add_target(upstream.get("id"), t["target"])

            kong_upstream_admin.update(service_id, {"host": domain_name})

    def update_plugins(self, plugins, service_id, kong_services_admin):
        logger.info(
            f"===>>> update_plugins service_id: {str(service_id)}, plugins: {plugins}"
        )
        plugin_name_to_id = {
            p["name"]: p["id"] for p in kong_services_admin.get_plugins(service_id)
        }

        for plugin_data in plugins:
            is_active_plugin = plugin_data["name"] in plugin_name_to_id.keys()
            update_plugin_to_disabled = is_active_plugin and not plugin_data.get(
                "enabled", True
            )
            if update_plugin_to_disabled:
                kong_services_admin.update_or_create_plugin(
                    service_id,
                    {"enabled": False},
                    plugin_name_to_id.get(plugin_data["name"]),
                )
                continue

            if not is_active_plugin and not plugin_data.get("enabled", True):
                logger.info(
                    f"New plugin {plugin_data['name']} is in a disabled state. Skipping."
                )
                continue

            plugin_id = plugin_name_to_id.get(plugin_data["name"])
            plugin = kong_services_admin.update_or_create_plugin(
                service_id, plugin_data, plugin_id
            )
            if plugin["name"] == demo2_REDIRECT_PLUGIN_NAME:
                kong_services_admin.update(
                    service_id, {"host": f"demo2-redirect.{plugin['id']}"}
                )

        # start: delete plugins
        existing_plugins = set(plugin_name_to_id)
        plugins_in_update = {p["name"] for p in plugins}
        plugin_names_to_delete = existing_plugins - plugins_in_update
        for plugin_name_to_delete in plugin_names_to_delete:
            if plugin_name_to_delete not in RECOGNIZED_PLUGINS:
                continue

            plugin_id = plugin_name_to_id.get(plugin_name_to_delete)
            if plugin_id:
                kong_services_admin.delete_plugin(service_id, plugin_id)
