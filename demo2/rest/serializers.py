import datetime
import json
import logging
import re

import pytz
from django.utils.timezone import make_aware
from django.utils.translation import gettext_lazy as _
from OpenSSL import crypto
from rest_framework import serializers
from rest_framework.serializers import empty
from traffic.models import Traffic

from demo2.constants import REDIRECT_DOMAIN_ACTION, UPSTREAM_DOMAIN_ACTION
from demo2.rest.models import DomainRule
from demo2.utils import check_zone_domain
from demo2.utils.cert import SSLUtils
from kong.gateway import KongServicesAdmin, KongUpstreamsAdmin
from kong.models import KongDataRoute

logger = logging.getLogger(__name__)

SERVICE_PROTOCOLS = (
    ("http", "HTTP"),
    ("https", "HTTPS"),
)


class BasePluginSerializer(serializers.Serializer):
    id = serializers.CharField(default=None, required=False, allow_null=True)
    name = serializers.CharField()
    config = serializers.JSONField()
    enabled = serializers.BooleanField()

    def validate(self, obj):
        if not obj["id"]:
            obj.pop("id", None)

        return obj


IP_RESTRICTION_PLUGIN_NAME = "ip-restriction"
RESPONSE_TRANSFORMER = "response-transformer"
demo2_IP_RESTRICTION_PLUGIN_NAME = "demo2-ip-restriction"
demo2_CHALLENGE_PLUGIN_NAME = "demo2-challenge"
demo2_REQUEST_LIMIT_PLUGIN_NAME = "demo2-request-limit"
demo2_REDIRECT_PLUGIN_NAME = "demo2-redirect"
demo2_PROXY_CACHE_PLUGIN_NAME = "demo2-proxy-cache"
demo2_GEOIP_PLUGIN_NAME = "demo2-geoip"
demo2_CUSTOM_ERROR_PAGE_PLUGIN_NAME = "demo2-custom-error-page"
demo2_UPSTREAM_HOST_PLUGIN_NAME = "demo2-upstream-host"
demo2_CROWDSEC_CAPTCHA_PLUGIN_NAME = "demo2-crowdsec-captcha"
demo2_BLACKRULES_PLUGIN_NAME = "demo2-blackrules"
demo2_SECLINK_PLUGIN_NAME = "demo2-seclink"

RECOGNIZED_PLUGINS = [
    IP_RESTRICTION_PLUGIN_NAME,
    RESPONSE_TRANSFORMER,
    demo2_IP_RESTRICTION_PLUGIN_NAME,
    demo2_CHALLENGE_PLUGIN_NAME,
    demo2_REQUEST_LIMIT_PLUGIN_NAME,
    demo2_REDIRECT_PLUGIN_NAME,
    demo2_PROXY_CACHE_PLUGIN_NAME,
    demo2_GEOIP_PLUGIN_NAME,
    demo2_CUSTOM_ERROR_PAGE_PLUGIN_NAME,
    demo2_UPSTREAM_HOST_PLUGIN_NAME,
    demo2_CHALLENGE_PLUGIN_NAME,
    demo2_BLACKRULES_PLUGIN_NAME,
    demo2_SECLINK_PLUGIN_NAME,
]


class HeaderResponseTransformerSerializer(serializers.Serializer):
    headers = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, allow_null=True
    )


class ResponseTransformerConfigPluginSerializer(serializers.Serializer):
    add = HeaderResponseTransformerSerializer()


class ResponseTransformerPluginSerializer(BasePluginSerializer):
    config = ResponseTransformerConfigPluginSerializer()


BLACKRULES_ACTIONS = (
    ("captcha", "Captcha"),
    ("ban", "Ban"),
)


class RuleField(serializers.Field):
    logical_operators = ["AND", "OR", "!AND", "!OR"]
    operators = ["==", "~=", "~~", "~*"]
    arguments = ["METHOD", "PATH", "AGENT", "REFERER"]
    default_error_messages = {
        "logical_invalid": _("Logical operator {logical_operator} is invalid"),
        "condition_invalid": _("Condition {condition} is invalid"),
        "argument_invalid": _("Argument {argument} is invalid"),
        "operator_invalid": _("Operator {operator} is invalid"),
    }

    def to_representation(self, instance):
        rules = instance["rule"]
        rules = (
            rules.replace("return ", "")
            .replace("{", "[")
            .replace("}", "]")
            .replace("'", '"')
        )
        return json.loads(rules)

    def run_validation(self, data=empty):
        if type(data) == list:
            for index in range(0, len(data)):
                # Validate logical operator
                if type(data[index]) == str:
                    logical_operator = data[index]
                    if logical_operator not in self.logical_operators:
                        self.fail("logical_invalid", logical_operator=logical_operator)
                # Validate condition
                if type(data[index]) == list:
                    condition = data[index]
                    if len(condition) < 3:
                        self.fail("condition_invalid", condition=condition)

                    if condition[0] not in self.arguments:
                        self.fail("argument_invalid", argument=condition[0])

                    operator = condition[1]
                    if len(operator) > 2:
                        if operator[0] != "!":
                            self.fail("operator_invalid", operator=operator)
                        if operator[1:] not in self.operators:
                            self.fail("operator_invalid", operator=operator)
                    elif len(operator) == 2:
                        if operator not in self.operators:
                            self.fail("operator_invalid", operator=operator)
                    else:
                        if operator not in self.operators:
                            self.fail("operator_invalid", operator=operator)
        return super().run_validation(data)

    def to_internal_value(self, data):
        data = str(data)
        data = data.replace("[", "{").replace("]", "}").replace('"', "'")
        return {"rule": f"return {data}"}


class demo2BlackrulesConfigPluginSerializer(serializers.Serializer):
    rules = RuleField()
    action = serializers.ChoiceField(choices=BLACKRULES_ACTIONS, default="captcha")
    bantime = serializers.CharField()


class demo2BlackrulesPluginSerializer(BasePluginSerializer):
    config = demo2BlackrulesConfigPluginSerializer()


class IpRestrictionConfigPluginSerializer(serializers.Serializer):
    allow = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, allow_null=True
    )
    deny = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, allow_null=True
    )

    def validate(self, data):
        if len(data.get("allow", [])) == 0 and len(data.get("deny", [])) == 0:
            raise serializers.ValidationError(
                "Allow and Deny can't be empty at the same time. Please provide a value "
                "for at least one."
            )

        return data


class IpRestrictionPluginSerializer(BasePluginSerializer):
    config = IpRestrictionConfigPluginSerializer()


class demo2SecLinkConfigPluginSerializer(serializers.Serializer):
    api_secret = serializers.CharField()
    sleep_seconds = serializers.IntegerField()
    expire_seconds = serializers.IntegerField()
    enable_sec_redirect = serializers.BooleanField()

    def validate(self, data):
        return data


class demo2SecLinkPluginSerializer(BasePluginSerializer):
    config = demo2SecLinkConfigPluginSerializer()


class demo2IpRestrictionConfigPluginSerializer(serializers.Serializer):
    allow = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, allow_null=True
    )
    deny = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, allow_null=True
    )
    allow_spiders = serializers.BooleanField(default=False, required=False)
    deny_status = serializers.IntegerField(required=False, default=0)
    message = serializers.CharField(required=False, allow_null=True, default=None)

    def validate(self, data):
        if len(data.get("allow", [])) == 0 and len(data.get("deny", [])) == 0:
            raise serializers.ValidationError(
                "Allow and Deny can't be empty at the same time. Please provide a value "
                "for at least one."
            )

        return data


class demo2IpRestrictionPluginSerializer(BasePluginSerializer):
    config = demo2IpRestrictionConfigPluginSerializer()


class demo2RequestLimitConfigPluginSerializer(serializers.Serializer):
    bantime = serializers.CharField()
    banpath = serializers.CharField()
    findtime = serializers.IntegerField()
    maxretry = serializers.IntegerField()
    only_dynamic = serializers.BooleanField()


class demo2CrowdsecCaptchaConfigPluginSerializer(serializers.Serializer):
    bantime = serializers.CharField()
    findtime = serializers.IntegerField()
    maxretry = serializers.IntegerField()


class demo2RequestLimitPluginSerializer(BasePluginSerializer):
    config = demo2RequestLimitConfigPluginSerializer()


class demo2CrowdsecCaptchaPluginSerializer(BasePluginSerializer):
    config = demo2CrowdsecCaptchaConfigPluginSerializer()


class demo2ChallengeConfigPluginSerializer(serializers.Serializer):
    challenge = serializers.CharField()


class demo2ChallengePluginSerializer(BasePluginSerializer):
    config = demo2ChallengeConfigPluginSerializer()


class demo2RedirectConfigPluginSerializer(serializers.Serializer):
    redirect_url = serializers.CharField()


class demo2RedirectPluginSerializer(BasePluginSerializer):
    config = demo2RedirectConfigPluginSerializer()


class demo2ProxyCacheConfigPluginSerializer(serializers.Serializer):
    # only required
    response_code = serializers.ListField(child=serializers.IntegerField())

    request_method = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    content_type = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    bypass_rules = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True, allow_null=True
    )

    enable_cache_control = serializers.BooleanField(required=False, default=False)

    cache_version = serializers.IntegerField(required=False, default=1)


class demo2ProxyCachePluginSerializer(BasePluginSerializer):
    config = demo2ProxyCacheConfigPluginSerializer()


class demo2UpstreamHostConfigPluginSerializer(serializers.Serializer):
    hostname = serializers.CharField()


class demo2UpstreamHostPluginSerializer(BasePluginSerializer):
    config = demo2UpstreamHostConfigPluginSerializer()


demo2_GEOIP_MODES = (
    ("Blacklist", "Blacklist"),
    ("Whitelist", "Whitelist"),
)


class demo2GeoIpConfigPluginSerializer(serializers.Serializer):
    blacklist_countries = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    whitelist_countries = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    whitelist_ips = serializers.ListField(
        child=serializers.CharField(), required=False, allow_empty=True
    )
    mode = serializers.ChoiceField(choices=demo2_GEOIP_MODES, default="Blacklist")


class demo2GeoIpPluginSerializer(BasePluginSerializer):
    config = demo2GeoIpConfigPluginSerializer()


class demo2CustomErrorPageConfigPluginSerializer(serializers.Serializer):
    error_401 = serializers.CharField(required=False, allow_null=True, default=None)
    error_425 = serializers.CharField(required=False, allow_null=True, default=None)
    error_502 = serializers.CharField(required=False, allow_null=True, default=None)


class demo2CustomErrorPagePluginSerializer(BasePluginSerializer):
    config = demo2CustomErrorPageConfigPluginSerializer()


class UpstreamTargetSerializer(serializers.Serializer):
    id = serializers.CharField(required=False)
    target = serializers.CharField()


class ServiceSerializer(serializers.Serializer):
    port = serializers.IntegerField()
    id = serializers.CharField()
    protocol = serializers.CharField()
    host = serializers.CharField()
    tags = serializers.ListField(required=False, allow_empty=True)


class DomainSerializer(serializers.Serializer):
    id = serializers.CharField(default=None)
    hosts = serializers.ListField(child=serializers.CharField())
    protocols = serializers.ListField(child=serializers.CharField())
    service = serializers.JSONField(required=False, default={})
    upstream = serializers.JSONField(default={})
    plugins = serializers.ListSerializer(
        child=BasePluginSerializer(), required=False, default=[]
    )
    tags = serializers.JSONField(required=False, default={})
    domain_name = serializers.SerializerMethodField(default=None)
    domain_action = serializers.SerializerMethodField(default=None)

    @staticmethod
    def is_domain_action_redirect(plugins):
        for p in plugins:
            if p["name"] == demo2_REDIRECT_PLUGIN_NAME:
                return True

        return False

    @staticmethod
    def get_safe_domain_name(hosts):
        return hosts[0].replace(".", "-")

    def get_service(self, service_id):
        # todo: need caching here?
        ks = KongServicesAdmin(self.context["owner"], cname=self.context["cname"])

        return ks.get(service_id)

    def get_domain_name(self, obj):
        return self.get_safe_domain_name(obj["hosts"])

    def get_domain_action(self, obj):
        if self.is_domain_action_redirect(obj.get("plugins", [])):
            return REDIRECT_DOMAIN_ACTION

        return UPSTREAM_DOMAIN_ACTION

    def validate_upstream(self, obj):
        if (
            self.context.get("fetch_relation", False)
            and "service" in self.initial_data
            and self.initial_data["service"].get("id")
        ):
            service = self.get_service(self.initial_data["service"].get("id"))

            if demo2_REDIRECT_PLUGIN_NAME in service["host"]:
                return {}

            ku = KongUpstreamsAdmin(self.context["owner"], cname=self.context["cname"])

            upstream = ku.get_by_name(service["host"])
            targets = ku.get_targets(upstream.get("id"))

            return {
                "id": upstream.get("id"),
                "targets": [UpstreamTargetSerializer(t).data for t in targets],
            }

        # exit early if plugins has demo2-redirect. if demo2-redirect is used
        # then upstream is not required
        if self.is_domain_action_redirect(self.initial_data.get("plugins", [])):
            return obj

        if not isinstance(obj["targets"], list):
            raise serializers.ValidationError(f"Upstream targets should be a list.")

        validated = []
        for t in obj["targets"]:
            if not isinstance(t, dict):
                raise serializers.ValidationError(
                    f"Upstream targets should be a dictionary with a `target` field."
                )

            if "target" in t and t["target"]:
                target_arr = t["target"].split(":")
                if len(target_arr) > 1:
                    port = int(target_arr[-1])
                    if (
                        "https" == self.initial_data["service"].get("protocol")
                        and port == 80
                    ):
                        raise serializers.ValidationError(
                            f"Upstream target is not in a valid format: {t['target']} "
                            f"should not have port 80 if using https"
                        )
                    if (
                        "http" == self.initial_data["service"].get("protocol")
                        and port == 443
                    ):
                        raise serializers.ValidationError(
                            f"Upstream target is not in a valid format: {t['target']} "
                            f"should not have port 443 if using http"
                        )

            ts = UpstreamTargetSerializer(data=t)
            if not ts.is_valid():
                raise serializers.ValidationError(
                    f"Upstream target is not in a valid format: {t['target']}"
                )

            validated.append(ts.validated_data)

        if not len(validated):
            raise serializers.ValidationError(f"Targets may not be empty")

        return {"targets": validated}

    def validate_plugins(self, plugins):
        if (
            self.context.get("fetch_relation", False)
            and "service" in self.initial_data
            and self.initial_data["service"].get("id")
        ):
            ks = KongServicesAdmin(self.context["owner"], self.context["cname"])
            plugins = ks.get_plugins(self.initial_data["service"].get("id"))

        # begin validate user data
        validated = []
        for p in plugins:
            # if p['name'] == IP_RESTRICTION_PLUGIN_NAME or p['name'] == demo2_IP_RESTRICTION_PLUGIN_NAME:
            #     if "config" in p:
            #         p["config"]["deny_status"] = 0
            #         if "status" in p["config"]:
            #             del p["config"]["status"]
            #
            #     c = demo2IpRestrictionPluginSerializer(data=p)
            if p["name"] == IP_RESTRICTION_PLUGIN_NAME:
                c = IpRestrictionPluginSerializer(data=p)
            if p["name"] == RESPONSE_TRANSFORMER:
                c = ResponseTransformerPluginSerializer(data=p)
            elif p["name"] == demo2_REQUEST_LIMIT_PLUGIN_NAME:
                c = demo2RequestLimitPluginSerializer(data=p)
            elif p["name"] == demo2_CHALLENGE_PLUGIN_NAME:
                c = demo2ChallengePluginSerializer(data=p)
            elif p["name"] == demo2_REDIRECT_PLUGIN_NAME:
                c = demo2RedirectPluginSerializer(data=p)
            elif p["name"] == demo2_PROXY_CACHE_PLUGIN_NAME:
                c = demo2ProxyCachePluginSerializer(data=p)
            elif p["name"] == demo2_GEOIP_PLUGIN_NAME:
                c = demo2GeoIpPluginSerializer(data=p)
            elif p["name"] == demo2_CUSTOM_ERROR_PAGE_PLUGIN_NAME:
                c = demo2CustomErrorPagePluginSerializer(data=p)
            elif p["name"] == demo2_UPSTREAM_HOST_PLUGIN_NAME:
                c = demo2UpstreamHostPluginSerializer(data=p)
            elif p["name"] == demo2_IP_RESTRICTION_PLUGIN_NAME:
                c = demo2IpRestrictionPluginSerializer(data=p)
            elif p["name"] == demo2_CROWDSEC_CAPTCHA_PLUGIN_NAME:
                c = demo2CrowdsecCaptchaPluginSerializer(data=p)
            elif p["name"] == demo2_BLACKRULES_PLUGIN_NAME:
                c = demo2BlackrulesPluginSerializer(data=p)
            elif p["name"] == demo2_SECLINK_PLUGIN_NAME:
                c = demo2SecLinkPluginSerializer(data=p)
            else:
                # skips the plugin if it's not recognized
                continue

            if c.is_valid():
                validated.append(c.validated_data)
            else:
                logger.info(c.initial_data)
                logger.error(c.errors)

                raise serializers.ValidationError({p["name"]: c.errors})

        return validated

    def validate_service(self, obj):
        if self.context.get("fetch_relation", False) and "id" in obj:
            return ServiceSerializer(self.get_service(obj["id"])).data

        # begin validate user data.
        # from here service data is dependent on the initial data
        if self.is_domain_action_redirect(self.initial_data.get("plugins", [])):
            # use protocol http as default, it won't matter anyway
            # because the domain is not using the upstream.
            obj.update({"host": "demo2-redirect.temp", "protocol": "http"})
            return obj

        # if initial_data does not have a hosts property then is_valid
        # will eventually return False (due to the hosts field being required).
        # so service.host will ultimately have a value
        # as long as the initial_data has the correct values
        hosts = self.initial_data.get("hosts", [])
        if not hosts:
            raise serializers.ValidationError(
                f"Service host could not be created due to missing hosts data."
            )

        obj.update({"host": self.get_safe_domain_name(hosts)})
        return obj

    def validate_hosts(self, value):
        # promote domain
        promote_domain = value[0]

        route_id = self.context.get("route_id", None)
        check_hosts = self.context.get("check_hosts", False)
        if check_hosts:
            if any(check_zone_domain(domain) for domain in value):
                raise serializers.ValidationError(
                    "Domain or shadow domain can't contain yk1.net"
                )
            if route_id:
                route = KongDataRoute.objects.get(id=route_id)
                hosts = list(set(value) - set(route.hosts))
                # Check new value doesn't exist
                if KongDataRoute.objects.filter(hosts__overlap=hosts).exists():
                    raise serializers.ValidationError(
                        f'Domain {",".join(hosts)} already exist'
                    )
                # Remove duplicate
                value = list(set(value))
            else:
                # Check new value doesn't exist
                if KongDataRoute.objects.filter(hosts__overlap=value).exists():
                    raise serializers.ValidationError(
                        f'Domain {",".join(value)} already exist'
                    )

        # set promote domain to first position of hosts list
        value.remove(promote_domain)
        if promote_domain in value:
            raise serializers.ValidationError(f"Domain {promote_domain} already exist")
        value.insert(0, promote_domain)

        return value

    def validate(self, obj):
        if self.is_domain_action_redirect(obj.get("plugins", [])):
            # remove upstream key from final data if domain action is redirect.
            # upstream is not needed for domain action redirect
            obj.pop("upstream", None)
            return obj

        if "service" not in obj:
            raise serializers.ValidationError("`service` is required")

        if not obj["service"]:
            raise serializers.ValidationError("`service` may not be empty")

        if "protocol" not in obj["service"]:
            raise serializers.ValidationError("`service.protocol` is required")

        if "upstream" not in obj:
            raise serializers.ValidationError("`upstream` is required")

        if not obj["upstream"]:
            raise serializers.ValidationError("`upstream` may not be empty")

        if "targets" not in obj["upstream"]:
            raise serializers.ValidationError("`upstream.targets` is required")

        if not len(obj["upstream"]["targets"]):
            raise serializers.ValidationError("`upstream.targets` may not be empty")

        return obj


class KongDataDomainSerializer(serializers.Serializer):
    id = serializers.CharField(default=None)
    hosts = serializers.ListField(child=serializers.CharField())
    protocols = serializers.ListField(child=serializers.CharField())
    service = serializers.JSONField(required=False, default={})
    upstream = serializers.JSONField(required=False, default={})
    plugins = serializers.ListSerializer(
        child=BasePluginSerializer(), required=False, default=[]
    )
    tags = serializers.JSONField(required=False, default={})
    domain_name = serializers.SerializerMethodField()
    domain_action = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    has_cert = serializers.SerializerMethodField()

    def validate_plugins(self, plugins):
        if (
            self.context.get("fetch_relation", False)
            and "service" in self.initial_data
            and self.initial_data["service"].get("id")
        ):
            ks = KongServicesAdmin(self.context["owner"], self.context["cname"])
            plugins = ks.get_plugins(self.initial_data["service"].get("id"))

        # begin validate user data
        validated = []
        for p in plugins:
            if p["name"] == demo2_BLACKRULES_PLUGIN_NAME:
                c = demo2BlackrulesPluginSerializer(p)
            else:
                # skips the plugin if it's not recognized
                validated.append(p)
                continue

            validated.append(c.data)

        return validated

    def get_status(self, obj):
        if "paused=1" in obj.get("tags", []):
            return "Deactivated"
        return "Running"

    @staticmethod
    def is_domain_action_redirect(plugins):
        for p in plugins:
            if p["name"] == demo2_REDIRECT_PLUGIN_NAME:
                return True

        return False

    def get_service(self, service_id):
        # todo: need caching here?
        ks = KongServicesAdmin(self.context["owner"], cname=self.context["cname"])

        return ks.get(service_id)

    def get_has_cert(self, route):
        from demo2.rest.views import DomainSslConfigRestView, KongCertificatesAdmin

        kc = KongCertificatesAdmin(self.context["owner"], cname=self.context["cname"])
        kong_certificates = DomainSslConfigRestView.find_kong_certificates(
            kc.get_by_owner(), route
        )
        acme_certificates = DomainSslConfigRestView.fetch_acme_certs(route)
        serializer = DomainCertificatesSerializer(
            data=kong_certificates + acme_certificates
        )
        if serializer.is_valid():
            certificates = serializer.data
            return len(certificates) > 0
        return False

    @staticmethod
    def get_safe_domain_name(hosts):
        return hosts[0].replace(".", "-") if hosts else ""

    def get_domain_name(self, obj):
        return self.get_safe_domain_name(obj["hosts"])

    def get_domain_action(self, obj):
        if self.is_domain_action_redirect(obj.get("plugins", [])):
            return REDIRECT_DOMAIN_ACTION

        return UPSTREAM_DOMAIN_ACTION


class DomainSslConfigSerializer(serializers.Serializer):
    force_https = serializers.BooleanField()


class DomainCertificateSerializer(serializers.Serializer):
    id = serializers.CharField()
    #  snis = serializers.ListField(child=serializers.CharField())
    snis = serializers.SerializerMethodField()
    type = serializers.SerializerMethodField()
    expired_at = serializers.SerializerMethodField()
    issue_at = serializers.SerializerMethodField()
    cert = serializers.CharField()
    status = serializers.SerializerMethodField()

    def get_type(self, instance):
        if "kong" in instance["id"]:
            return "AUTO"
        return "UPLOAD"

    def get_status(self, instance):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, instance["cert"])
        expired_at = make_aware(
            datetime.datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"),
            timezone=pytz.UTC,
        )
        now = datetime.datetime.now(pytz.UTC)
        if (expired_at - datetime.timedelta(days=14)) < now:
            return "Expiring Soon"
        elif expired_at < now:
            return "Expired"
        else:
            return "Issued"

    def get_snis(self, instance):
        return SSLUtils.certificate_sans(instance["cert"])

    def get_expired_at(self, instance):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, instance["cert"])
        return make_aware(
            datetime.datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"),
            timezone=pytz.UTC,
        )

    def get_issue_at(self, instance):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, instance["cert"])
        return make_aware(
            datetime.datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ"),
            timezone=pytz.UTC,
        )


class DomainCertificatesSerializer(serializers.ListSerializer):
    child = DomainCertificateSerializer()


class DomainCertificatePayloadSerializer(serializers.Serializer):
    domain = serializers.CharField()
    cert = serializers.CharField()
    key = serializers.CharField()


class GatewayResponseSerializer(serializers.BaseSerializer):
    def to_representation(self, instance):
        fields = instance["fields"] if "fields" in instance else {}
        if "name" in fields:
            fields["domain"] = f"{instance['name']}"
            del fields["name"]

        return {"fields": fields, "message": instance.get("message")}


CLEAR_CACHE_TASK_NAME = "CLEAR_CACHE"
FORCE_HTTPS_TASK_NAME = "FORCE_HTTPS"
ENABLE_HTTPS_TASK_NAME = "ENABLE_HTTPS"
TASK_NAMES = (
    (CLEAR_CACHE_TASK_NAME, "Clear cache"),
    (FORCE_HTTPS_TASK_NAME, "Force https"),
    (ENABLE_HTTPS_TASK_NAME, "Enable Https"),
)


class RunTaskSerializer(serializers.Serializer):
    task = serializers.ChoiceField(choices=TASK_NAMES)
    options = serializers.JSONField(required=False, allow_null=True)


class AliyunTrafficResultSerializer(serializers.Serializer):
    time = serializers.CharField()
    nout = serializers.SerializerMethodField()
    nin = serializers.SerializerMethodField()
    pv = serializers.IntegerField()
    hit_pv = serializers.IntegerField()

    def get_nout(self, instance):
        return Traffic.withloss(instance["net_out"])

    def get_nin(self, instance):
        return Traffic.withloss(instance["net_in"])


class DomainPauseRestoreSerializer(serializers.Serializer):
    hosts = serializers.ListField(child=serializers.CharField())


class DomainRuleSerializer(serializers.ModelSerializer):
    # name = serializers.SerializerMethodField()
    # description = serializers.SerializerMethodField(required=False)
    # owner = serializers.SerializerMethodField()
    # configs = serializers.JSONField(required=False, default={})

    class Meta:
        model = DomainRule
        fields = "__all__"


class DomainRuleAssignSerializer(serializers.Serializer):
    service_id = serializers.UUIDField()
    action = serializers.SerializerMethodField()
