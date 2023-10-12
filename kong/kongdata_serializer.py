import logging

from django.db.models import Q
from rest_framework import serializers

from kong.models import (
    KongDataPlugin,
    KongDataService,
    KongDataTarget,
    KongDataUpstream,
)

IP_RESTRICTION_PLUGIN_NAME = "ip-restriction"
demo2_IP_RESTRICTION_PLUGIN_NAME = "demo2-ip-restriction"


class KongDataServiceSerializer(serializers.ModelSerializer):
    tags = serializers.ListField()

    class Meta:
        model = KongDataService
        fields = ["id", "protocol", "host", "tags"]


class KongDataTargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = KongDataTarget
        fields = ["id", "target"]


class KongDataPluginSerializer(serializers.ModelSerializer):
    class Meta:
        model = KongDataPlugin
        fields = ["id", "protocols", "tags", "name", "config", "enabled"]

    # def to_representation(self, instance):
    #     data = super().to_representation(instance)
    #
    #     if data["name"] == demo2_IP_RESTRICTION_PLUGIN_NAME:
    #         data["name"] = IP_RESTRICTION_PLUGIN_NAME
    #         data['config']['status'] = data['config']['deny_status'] if 'deny_status' in data['config'] else 0
    #
    #     return data


def prepare_routes_data(response_data):
    data = []
    for obj in response_data:
        route_data = {
            "id": str(obj.id),
            "hosts": obj.hosts,
            "protocols": obj.protocols,
            "tags": obj.tags,
        }
        service_obj = KongDataService.objects.filter(id=str(obj.service_id)).first()
        if service_obj:
            route_data["service"] = KongDataServiceSerializer(instance=service_obj).data
            if service_obj.host:
                upstream_obj = KongDataUpstream.objects.filter(
                    name=service_obj.host
                ).first()
                if upstream_obj:
                    route_data["upstream"] = {}
                    route_data["upstream"]["id"] = str(upstream_obj.id)
                    target_objs = KongDataTarget.objects.filter(
                        upstream_id=str(upstream_obj.id)
                    ).all()
                    if target_objs.exists():
                        route_data["upstream"]["targets"] = KongDataTargetSerializer(
                            target_objs, many=True
                        ).data

        plugins_objs = KongDataPlugin.objects.filter(
            Q(service_id=str(obj.service_id)) | Q(route_id=str(obj.id))
        ).all()
        if plugins_objs.exists():
            route_data["plugins"] = KongDataPluginSerializer(
                plugins_objs, many=True
            ).data

        data.append(route_data)

    return data
